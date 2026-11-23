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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
)

// LedgerStore keeps the ledgers of the agent's cases: one Ledger per case, with the name of its Assessment, which
// records the case's tool calls (design of the agent on image cases, section 5.4). It is the only way to read or write
// them. A case writes its ledger once, when it ends.
type LedgerStore interface {
	// Put writes the ledger l, under its name, in place of any ledger that the case had before.
	Put(ctx context.Context, l *inventoryv1alpha1.Ledger) error
	// Get returns the ledger of a name, or nil, nil when there is none.
	Get(ctx context.Context, name string) (*inventoryv1alpha1.Ledger, error)
	// Delete removes the ledger of a name. No error if absent.
	Delete(ctx context.Context, name string) error
}

// crdLedgerStore keeps the ledgers as Ledger custom resources.
type crdLedgerStore struct {
	api client.Client
}

// The store reads a ledger, creates it, writes it over the ledger of an earlier judgement, and deletes it. It reads
// from the API server, and never watches the ledgers.
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=ledgers,verbs=get;create;update;delete

// NewCRDLedgerStore returns a LedgerStore that keeps the ledgers in the Ledger API, through c. Pass a client that
// reads Ledgers from the API server and not from a cache, such as the manager's client with setup.ClientOptions: a
// ledger can hold a few hundred KiB, and a cache would hold every one in memory.
func NewCRDLedgerStore(c client.Client) LedgerStore {
	return &crdLedgerStore{api: c}
}

func (s *crdLedgerStore) Put(ctx context.Context, l *inventoryv1alpha1.Ledger) error {
	// Every round reads the ledger again. A write that finds it changed since the read, a create that finds one made
	// since, and an update that finds it deleted since are no error, as long as the next round works.
	return retry.OnError(retry.DefaultBackoff, isRacedOrDeleted, func() error {
		existing, err := s.Get(ctx, l.Name)
		if err != nil {
			return err
		}
		if existing == nil {
			obj := &inventoryv1alpha1.Ledger{
				ObjectMeta: metav1.ObjectMeta{Name: l.Name, Labels: l.Labels},
				Spec:       *l.Spec.DeepCopy(),
			}
			if err := s.api.Create(ctx, obj); err != nil {
				return fmt.Errorf("create Ledger %q: %w", l.Name, err)
			}
			return nil
		}
		existing.Labels = l.Labels
		existing.Spec = *l.Spec.DeepCopy()
		if err := s.api.Update(ctx, existing); err != nil {
			return fmt.Errorf("write Ledger %q: %w", l.Name, err)
		}
		return nil
	})
}

func (s *crdLedgerStore) Get(ctx context.Context, name string) (*inventoryv1alpha1.Ledger, error) {
	obj := &inventoryv1alpha1.Ledger{}
	if err := s.api.Get(ctx, client.ObjectKey{Name: name}, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		// A failed read is never mistaken for an absent ledger.
		return nil, fmt.Errorf("read Ledger %q: %w", name, err)
	}
	return obj, nil
}

func (s *crdLedgerStore) Delete(ctx context.Context, name string) error {
	obj := &inventoryv1alpha1.Ledger{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := s.api.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete Ledger %q: %w", name, err)
	}
	return nil
}
