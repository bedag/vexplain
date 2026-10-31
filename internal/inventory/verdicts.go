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
	"fmt"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/metrics"
)

// VerdictsStore keeps the result sheets: one ImageVerdicts per platform manifest, which holds what
// the hub's rules made of the findings in it (decision 0025). It is the only way to read or write
// them. A sheet is written only when it changes, so a match that finds what the sheet holds writes
// nothing (decision 0023).
type VerdictsStore interface {
	// Get returns the sheet of a manifest, or nil, nil when there is none.
	Get(ctx context.Context, manifestDigest string) (*inventoryv1alpha1.ImageVerdicts, error)
	// Put creates the sheet if needed, and writes its status only when it differs from the stored one.
	Put(ctx context.Context, manifestDigest string, status inventoryv1alpha1.ImageVerdictsStatus) error
	// Delete removes the sheet of a manifest. No error if absent.
	Delete(ctx context.Context, manifestDigest string) error
}

// verdictsMetrics are the metrics of the writes to ImageVerdicts objects.
var verdictsMetrics = kindMetrics{writes: metrics.VerdictsWritesTotal, sizes: metrics.VerdictsObjectBytes}

// crdVerdictsStore keeps the sheets as ImageVerdicts custom resources.
type crdVerdictsStore struct {
	api client.Client
	// cluster returns the name of this cluster, which labels the metrics of the writes.
	cluster func() string
}

// The store reads a sheet, creates it, deletes it and writes its status. It never updates the
// object itself: the spec never changes, and the findings live in the status. It reads one sheet at
// a time, from the API server, and never lists or watches them.
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imageverdicts,verbs=get;create;delete
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imageverdicts/status,verbs=update

// NewCRDVerdictsStore returns a VerdictsStore that keeps the sheets in the ImageVerdicts API,
// through c. Pass a client that reads ImageVerdicts from the API server and not from a cache, such
// as the manager's client with setup.ClientOptions: a sheet can hold up to about 1 MiB of findings,
// and a cache would hold every sheet in memory.
//
// A client that reads from a cache can return a sheet that a write has already changed. A write
// based on it fails, and the store then reads again and retries.
//
// cluster returns the name of this cluster, the label of the metrics of the writes. The store
// reads it at each write, so that the label follows a rename.
func NewCRDVerdictsStore(c client.Client, cluster func() string) VerdictsStore {
	return &crdVerdictsStore{api: c, cluster: cluster}
}

func (s *crdVerdictsStore) Get(ctx context.Context, manifestDigest string) (*inventoryv1alpha1.ImageVerdicts, error) {
	name := NameForDigest(manifestDigest)
	obj := &inventoryv1alpha1.ImageVerdicts{}
	if err := s.api.Get(ctx, client.ObjectKey{Name: name}, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		// A failed read is never mistaken for an absent sheet.
		return nil, fmt.Errorf("read ImageVerdicts %q: %w", name, err)
	}
	return obj, nil
}

func (s *crdVerdictsStore) Put(ctx context.Context, manifestDigest string, status inventoryv1alpha1.ImageVerdictsStatus) error {
	// Every round reads the sheet again. A write that finds the sheet changed since the read (a
	// conflict), a create that finds it made since (it already exists), and a status write that
	// finds it deleted since, which the next round creates again, are no error, as long as the next
	// round works.
	return retry.OnError(retry.DefaultBackoff, isRacedOrDeleted, func() error {
		obj, err := s.Get(ctx, manifestDigest)
		if err != nil {
			return err
		}
		if obj == nil {
			if obj, err = s.create(ctx, manifestDigest); err != nil {
				return err
			}
		}
		// Compared as equality.Semantic does, for which an empty list and none are the same.
		if equality.Semantic.DeepEqual(obj.Status, status) {
			return nil
		}
		obj.Status = *status.DeepCopy()
		return s.writeStatus(ctx, obj)
	})
}

func (s *crdVerdictsStore) Delete(ctx context.Context, manifestDigest string) error {
	obj := &inventoryv1alpha1.ImageVerdicts{ObjectMeta: metav1.ObjectMeta{Name: NameForDigest(manifestDigest)}}
	err := s.api.Delete(ctx, obj)
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return fmt.Errorf("delete ImageVerdicts %q: %w", obj.Name, err)
	}
	verdictsMetrics.countWrite(s.cluster(), opDelete)
	return nil
}

// create makes the sheet of a manifest with its spec and no status. The status is a subresource,
// so the API server would ignore one here: Put writes it in a second call.
func (s *crdVerdictsStore) create(ctx context.Context, manifestDigest string) (*inventoryv1alpha1.ImageVerdicts, error) {
	obj := &inventoryv1alpha1.ImageVerdicts{
		ObjectMeta: metav1.ObjectMeta{Name: NameForDigest(manifestDigest)},
		Spec:       inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifestDigest},
	}
	if err := s.api.Create(ctx, obj); err != nil {
		return nil, fmt.Errorf("create ImageVerdicts %q: %w", obj.Name, err)
	}
	cluster := s.cluster()
	verdictsMetrics.countWrite(cluster, opCreate)
	verdictsMetrics.measure(cluster, obj)
	return obj, nil
}

// writeStatus writes the status of a sheet that was read, so the API server refuses it if the
// sheet has changed since.
func (s *crdVerdictsStore) writeStatus(ctx context.Context, obj *inventoryv1alpha1.ImageVerdicts) error {
	if err := s.api.Status().Update(ctx, obj); err != nil {
		return fmt.Errorf("write status of ImageVerdicts %q: %w", obj.Name, err)
	}
	cluster := s.cluster()
	verdictsMetrics.countWrite(cluster, opUpdate)
	verdictsMetrics.measure(cluster, obj)
	return nil
}
