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
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/metrics"
)

// VerdictsStore keeps the result sheets: one ImageVerdicts per platform manifest and playbook, which holds
// what the rules of the playbook made of the findings in it (decisions 0025 and 0043). It is the only way to
// read or write them. A sheet is written only when it changes, so a match that finds what the sheet holds
// writes nothing (decision 0023).
type VerdictsStore interface {
	// Get returns the sheet of a manifest under a playbook, or nil, nil when there is none.
	Get(ctx context.Context, manifestDigest, playbook string) (*inventoryv1alpha1.ImageVerdicts, error)
	// Put creates the sheet of a manifest under a playbook if needed, and writes its status only when it
	// differs from the stored one. It compares the whole status, so a status that differs in its
	// findingsVersion alone is written: a caller that wants a sheet to keep the version that last changed its
	// findings passes the stored version.
	Put(ctx context.Context, manifestDigest, playbook string, status inventoryv1alpha1.ImageVerdictsStatus) error
	// Delete removes the sheet of a manifest under a playbook. No error if absent.
	Delete(ctx context.Context, manifestDigest, playbook string) error
	// List returns the sheets of a manifest under every playbook, in the order of their playbooks' names.
	List(ctx context.Context, manifestDigest string) ([]inventoryv1alpha1.ImageVerdicts, error)
	// Each calls fn with every sheet, in no set order, reading them a page at a time so that no more than a page of
	// sheets, up to about 1 MiB each, is in memory at once. It stops at the first error of fn, and returns it.
	Each(ctx context.Context, fn func(*inventoryv1alpha1.ImageVerdicts) error) error
}

// eachPage is how many sheets Each reads at a time.
const eachPage = 20

const (
	// playbookLabel labels a sheet with the name of its playbook.
	playbookLabel = "vexplain.bedag.ch/playbook"
	// manifestLabel starts the label of a sheet that names its manifest: the key is followed by the first 63
	// hex digits of the digest, which a label name can hold, and the value is empty.
	manifestLabel = "manifest.vexplain.bedag.ch/"
)

// manifestLabelOf is the label key of a manifest on its sheets.
func manifestLabelOf(manifestDigest string) string {
	hex := strings.TrimPrefix(manifestDigest, "sha256:")
	return manifestLabel + hex[:min(len(hex), 63)]
}

// verdictsMetrics are the metrics of the writes to ImageVerdicts objects.
var verdictsMetrics = kindMetrics{writes: metrics.VerdictsWritesTotal, sizes: metrics.VerdictsObjectBytes}

// crdVerdictsStore keeps the sheets as ImageVerdicts custom resources.
type crdVerdictsStore struct {
	api client.Client
	// cluster returns the name of this cluster, which labels the metrics of the writes.
	cluster func() string
}

// The store reads a sheet, lists the sheets of a manifest, creates a sheet, deletes it and writes its
// status. It never updates the object itself: the spec never changes, and the findings live in the status.
// It reads from the API server, and never watches the sheets.
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=imageverdicts,verbs=get;list;create;delete
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

func (s *crdVerdictsStore) Get(ctx context.Context, manifestDigest, playbook string) (*inventoryv1alpha1.ImageVerdicts, error) {
	name := SheetName(manifestDigest, playbook)
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

func (s *crdVerdictsStore) Put(ctx context.Context, manifestDigest, playbook string, status inventoryv1alpha1.ImageVerdictsStatus) error {
	// Every round reads the sheet again. A write that finds the sheet changed since the read (a
	// conflict), a create that finds it made since (it already exists), and a status write that
	// finds it deleted since, which the next round creates again, are no error, as long as the next
	// round works.
	return retry.OnError(retry.DefaultBackoff, isRacedOrDeleted, func() error {
		obj, err := s.Get(ctx, manifestDigest, playbook)
		if err != nil {
			return err
		}
		if obj == nil {
			if obj, err = s.create(ctx, manifestDigest, playbook); err != nil {
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

func (s *crdVerdictsStore) Delete(ctx context.Context, manifestDigest, playbook string) error {
	obj := &inventoryv1alpha1.ImageVerdicts{ObjectMeta: metav1.ObjectMeta{Name: SheetName(manifestDigest, playbook)}}
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

// List lists the sheets by the label of the manifest, and keeps those whose spec holds the manifest itself:
// the label holds all but the last hex digit of its digest.
func (s *crdVerdictsStore) List(ctx context.Context, manifestDigest string) ([]inventoryv1alpha1.ImageVerdicts, error) {
	var list inventoryv1alpha1.ImageVerdictsList
	if err := s.api.List(ctx, &list, client.HasLabels{manifestLabelOf(manifestDigest)}); err != nil {
		return nil, fmt.Errorf("list the ImageVerdicts of manifest %s: %w", manifestDigest, err)
	}
	sheets := slices.DeleteFunc(list.Items, func(sheet inventoryv1alpha1.ImageVerdicts) bool {
		return sheet.Spec.ManifestDigest != manifestDigest
	})
	slices.SortFunc(sheets, func(a, b inventoryv1alpha1.ImageVerdicts) int {
		return strings.Compare(a.Spec.Playbook, b.Spec.Playbook)
	})
	return sheets, nil
}

func (s *crdVerdictsStore) Each(ctx context.Context, fn func(*inventoryv1alpha1.ImageVerdicts) error) error {
	options := []client.ListOption{client.Limit(eachPage)}
	for {
		var list inventoryv1alpha1.ImageVerdictsList
		if err := s.api.List(ctx, &list, options...); err != nil {
			return fmt.Errorf("list the ImageVerdicts: %w", err)
		}
		for i := range list.Items {
			if err := fn(&list.Items[i]); err != nil {
				return err
			}
		}
		if list.Continue == "" {
			return nil
		}
		options = []client.ListOption{client.Limit(eachPage), client.Continue(list.Continue)}
	}
}

// create makes the sheet of a manifest under a playbook with its spec and labels, and no status. The status
// is a subresource, so the API server would ignore one here: Put writes it in a second call.
func (s *crdVerdictsStore) create(ctx context.Context, manifestDigest, playbook string) (*inventoryv1alpha1.ImageVerdicts, error) {
	obj := &inventoryv1alpha1.ImageVerdicts{
		ObjectMeta: metav1.ObjectMeta{
			Name:   SheetName(manifestDigest, playbook),
			Labels: map[string]string{playbookLabel: playbook, manifestLabelOf(manifestDigest): ""},
		},
		Spec: inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifestDigest, Playbook: playbook},
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
