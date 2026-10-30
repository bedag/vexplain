/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package inventory

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/scan/result"
)

// MaxEvidenceBytes is the most compressed evidence that one ImagePackages holds: 768 KiB. As
// base64, the form in which JSON carries bytes, that is 1 MiB, the length that the schema allows
// for spec.evidence. It keeps an object below etcd's limit of 1.5 MiB for a request.
const MaxEvidenceBytes = 786432

// ErrEvidenceTooLarge means that the compressed evidence of a manifest is more than
// MaxEvidenceBytes, so that no ImagePackages can hold it. Put returns it, and writes nothing.
var ErrEvidenceTooLarge = errors.New("the scan evidence is too large to store")

// PackagesInfo is what an ImagePackages says about its evidence.
type PackagesInfo struct {
	// Platform is the platform of the manifest, and ScannerImage the image of the scanner that made
	// the evidence.
	Platform, ScannerImage string
	// ScannedTime is when the scan finished, to the second.
	ScannedTime time.Time
	// CompressedBytes is the size of the evidence as stored, and UncompressedBytes its size once
	// decoded.
	CompressedBytes, UncompressedBytes int64
}

// PackagesStore keeps the evidence of the scans: one ImagePackages per platform manifest, which
// holds what a scan found in it (decision 0023). It is the only way to read, write or watch them.
// The evidence is written once. The content of a manifest can't change, so only a scan by another
// scanner image replaces it, whole.
type PackagesStore interface {
	// Get returns the evidence of a manifest, decoded, and what its object says about it. It returns
	// nil, nil, nil when there is none.
	Get(ctx context.Context, manifestDigest string) (*result.Manifest, *PackagesInfo, error)
	// Put stores one manifest's evidence. It creates the object, does nothing when an object from
	// the same scanner image exists, and replaces (delete, then create) one from another image.
	// Compressed evidence over MaxEvidenceBytes returns ErrEvidenceTooLarge and writes nothing.
	Put(ctx context.Context, scannerImage string, scannedTime time.Time, m result.Manifest) error
	// Delete removes the evidence of a manifest. No error if absent.
	Delete(ctx context.Context, manifestDigest string) error
	// Digests returns the manifest digest of every object, in no particular order.
	Digests(ctx context.Context) ([]string, error)
	// Source delivers one request per created or deleted object, named NameForDigest(manifest
	// digest). A controller watches the evidence through it.
	Source() source.Source
}

var (
	// packagesKind and packagesListKind are the kinds of the ImagePackages objects and of their
	// list, which the reads and the watch of metadata name.
	packagesKind     = inventoryv1alpha1.GroupVersion.WithKind("ImagePackages")
	packagesListKind = inventoryv1alpha1.GroupVersion.WithKind("ImagePackagesList")

	// packagesMetrics are the metrics of the writes to ImagePackages objects.
	packagesMetrics = kindMetrics{writes: metrics.PackagesWritesTotal, sizes: metrics.PackagesObjectBytes}
)

// crdPackagesStore keeps the evidence as ImagePackages custom resources.
type crdPackagesStore struct {
	api client.Client
	// informers is the cache that Source watches through, or nil for a store that never watches.
	informers cache.Cache
	// cluster returns the name of this cluster, which labels the metrics of the writes.
	cluster func() string
}

// The store reads an object, creates it, and deletes it, to remove it or to replace it. It never
// updates one: the evidence is written once. It lists the metadata of the objects, and its Source
// watches the metadata through an informer, which lists and watches.
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imagepackages,verbs=get;create;delete;list;watch

// NewCRDPackagesStore returns a PackagesStore that keeps the evidence in the ImagePackages API,
// through c.
//
// Get and Put read whole objects through c, evidence included. Pass a client that reads
// ImagePackages from the API server and not from a cache, such as the manager's client with
// setup.ClientOptions: a cache would hold the evidence of every manifest in memory. Digests reads
// the metadata of the objects only, through c, and Source watches their metadata only, through
// informers. Pass the manager's cache. A store that never watches passes nil.
//
// cluster returns the name of this cluster, the label of the metrics of the writes. The store
// reads it at each write, so that the label follows a rename.
func NewCRDPackagesStore(c client.Client, informers cache.Cache, cluster func() string) PackagesStore {
	return &crdPackagesStore{api: c, informers: informers, cluster: cluster}
}

func (s *crdPackagesStore) Get(ctx context.Context, manifestDigest string) (*result.Manifest, *PackagesInfo, error) {
	obj, err := s.read(ctx, manifestDigest)
	if err != nil || obj == nil {
		return nil, nil, err
	}
	spec := obj.Spec
	if spec.Encoding != inventoryv1alpha1.EvidenceEncodingGzipJSON {
		return nil, nil, fmt.Errorf("ImagePackages %q holds evidence in an encoding that this operator can't read: %q",
			obj.Name, spec.Encoding)
	}
	// The size once decoded bounds the decoder, so that a few bytes of gzip can't unpack into
	// gigabytes. Evidence without that bound isn't read at all.
	size := ptr.Deref(spec.UncompressedBytes, 0)
	if size <= 0 {
		return nil, nil, fmt.Errorf("ImagePackages %q doesn't say how large its evidence is once decoded", obj.Name)
	}
	m, err := result.DecodeManifest(spec.Evidence, size)
	if err != nil {
		return nil, nil, fmt.Errorf("decode the evidence of ImagePackages %q: %w", obj.Name, err)
	}
	return &m, &PackagesInfo{
		Platform:          spec.Platform,
		ScannerImage:      spec.ScannerImage,
		ScannedTime:       ptr.Deref(spec.ScannedTime, metav1.Time{}).Time,
		CompressedBytes:   int64(len(spec.Evidence)),
		UncompressedBytes: size,
	}, nil
}

func (s *crdPackagesStore) Put(ctx context.Context, scannerImage string, scannedTime time.Time, m result.Manifest) error {
	evidence, size, err := result.EncodeManifest(m)
	if err != nil {
		return fmt.Errorf("encode the evidence of manifest %q: %w", m.Digest, err)
	}
	if len(evidence) > MaxEvidenceBytes {
		return fmt.Errorf("%w: %d bytes compressed, at most %d", ErrEvidenceTooLarge, len(evidence), MaxEvidenceBytes)
	}
	// Every round reads the object again, and applies the same rule to what is there now. A delete
	// that finds the object changed since the read (a conflict), or a create that finds one made
	// since (it already exists), is the sign of another writer. Neither is an error, as long as the
	// next round works.
	return retry.OnError(retry.DefaultBackoff, isRaced, func() error {
		existing, err := s.read(ctx, m.Digest)
		if err != nil {
			return err
		}
		if existing != nil {
			if existing.Spec.ScannerImage == scannerImage {
				return nil // This scanner has found what it finds in the manifest, which can't change.
			}
			// The spec can't change, so the evidence of another scanner is replaced. It is deleted
			// only if it is still the object that was read, and then created again.
			precondition := client.Preconditions{ResourceVersion: ptr.To(existing.ResourceVersion)}
			if err = s.delete(ctx, existing, precondition); err != nil {
				return err
			}
		}
		return s.create(ctx, &inventoryv1alpha1.ImagePackages{
			ObjectMeta: metav1.ObjectMeta{Name: NameForDigest(m.Digest)},
			Spec: inventoryv1alpha1.ImagePackagesSpec{
				ManifestDigest:    m.Digest,
				Platform:          m.Platform,
				ScannerImage:      scannerImage,
				ScannedTime:       ptr.To(metav1.NewTime(scannedTime)),
				Encoding:          inventoryv1alpha1.EvidenceEncodingGzipJSON,
				Evidence:          evidence,
				UncompressedBytes: ptr.To(size),
			},
		})
	})
}

func (s *crdPackagesStore) Delete(ctx context.Context, manifestDigest string) error {
	return s.delete(ctx, &inventoryv1alpha1.ImagePackages{ObjectMeta: metav1.ObjectMeta{Name: NameForDigest(manifestDigest)}})
}

// Digests reads the metadata of the objects only: the names hold the digests, and the evidence
// stays where it is.
func (s *crdPackagesStore) Digests(ctx context.Context) ([]string, error) {
	list := &metav1.PartialObjectMetadataList{}
	list.SetGroupVersionKind(packagesListKind)
	// The objects are only read, and none leaves the store, so a cache needn't copy them.
	if err := s.api.List(ctx, list, client.UnsafeDisableDeepCopy); err != nil {
		return nil, fmt.Errorf("list ImagePackages objects: %w", err)
	}
	digests := make([]string, 0, len(list.Items))
	for i := range list.Items {
		if digest, ok := DigestForName(list.Items[i].Name); ok {
			digests = append(digests, digest)
		}
	}
	return digests, nil
}

// Source watches the metadata of the objects only, so the cache that it watches through holds no
// evidence. It enqueues the name of an object when the object is created or deleted. An object
// never changes, so an update is a resync or a change of its metadata, and enqueues nothing, unless
// the UID changed: then the object was replaced while the watch was down, and the update stands for
// a deletion and a creation.
func (s *crdPackagesStore) Source() source.Source {
	metadata := &metav1.PartialObjectMetadata{}
	metadata.SetGroupVersionKind(packagesKind)
	return source.Kind[client.Object](s.informers, metadata, &handler.EnqueueRequestForObject{},
		predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectOld.GetUID() != e.ObjectNew.GetUID()
		}})
}

// read returns the object of a manifest, or nil when there is none.
func (s *crdPackagesStore) read(ctx context.Context, manifestDigest string) (*inventoryv1alpha1.ImagePackages, error) {
	name := NameForDigest(manifestDigest)
	obj := &inventoryv1alpha1.ImagePackages{}
	if err := s.api.Get(ctx, client.ObjectKey{Name: name}, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		// A failed read is never mistaken for an absent object.
		return nil, fmt.Errorf("read ImagePackages %q: %w", name, err)
	}
	return obj, nil
}

// create makes an object, and counts and measures the write.
func (s *crdPackagesStore) create(ctx context.Context, obj *inventoryv1alpha1.ImagePackages) error {
	if err := s.api.Create(ctx, obj); err != nil {
		return fmt.Errorf("create ImagePackages %q: %w", obj.Name, err)
	}
	cluster := s.cluster()
	packagesMetrics.countWrite(cluster, opCreate)
	packagesMetrics.measure(cluster, obj)
	return nil
}

// delete removes an object, under the preconditions in opts. An object that is already gone is
// what the caller wants, so it is no error.
func (s *crdPackagesStore) delete(ctx context.Context, obj *inventoryv1alpha1.ImagePackages, opts ...client.DeleteOption) error {
	err := s.api.Delete(ctx, obj, opts...)
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("delete ImagePackages %q: %w", obj.Name, err)
	}
	packagesMetrics.countWrite(s.cluster(), opDelete)
	return nil
}
