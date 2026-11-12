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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
)

// CountsStore keeps the fleet picture's data: one PlaybookCounts per playbook and cluster, which holds what the
// playbook found in the cluster (decision 0043). The spoke of a cluster writes its own, and the hub reads them all.
// It is the only way to read, write or watch them. Counts are written only when they change.
type CountsStore interface {
	// Put creates the counts of a playbook, whose UID owns them, for a cluster if needed, and writes their status
	// when its counts differ from the stored ones. It compares the counts and not the time, so counts that are what
	// the object holds write nothing.
	Put(ctx context.Context, playbook string, playbookUID types.UID, cluster string, counts Tally) error
	// Delete removes the counts of a playbook for a cluster. No error if absent.
	Delete(ctx context.Context, playbook, cluster string) error
	// List returns the counts of a playbook for every cluster, in the order of the clusters' names.
	List(ctx context.Context, playbook string) ([]inventoryv1alpha1.PlaybookCounts, error)
	// Source delivers one request, named after the playbook, whenever the counts of a playbook are created, change
	// or are deleted. A controller of the playbooks watches the counts through it.
	Source() source.Source
}

// Tally is what a PlaybookCounts holds, as plain numbers: the resources judged and failing, the actions by step, and the
// actions by severity, where Negligible counts as Low. It is comparable, so that two tallies are the same counts, and
// it adds up, so that the counts of reports and of clusters sum.
type Tally struct {
	Judged, Failing                               int32
	Updates, Changes, Mitigations, Investigations int32
	Critical, High, Medium, Low, Unknown          int32
}

// Plus returns the sum of two tallies.
func (a Tally) Plus(b Tally) Tally {
	return Tally{a.Judged + b.Judged, a.Failing + b.Failing,
		a.Updates + b.Updates, a.Changes + b.Changes, a.Mitigations + b.Mitigations, a.Investigations + b.Investigations,
		a.Critical + b.Critical, a.High + b.High, a.Medium + b.Medium, a.Low + b.Low, a.Unknown + b.Unknown}
}

// TallyOf returns the tally of a status. A count that the status lacks is 0.
func TallyOf(s inventoryv1alpha1.PlaybookCountsStatus) Tally {
	actions, severities := ptr.Deref(s.Actions, inventoryv1alpha1.ActionCounts{}), ptr.Deref(s.Severities, inventoryv1alpha1.SeverityCounts{})
	return Tally{
		Judged: ptr.Deref(s.Judged, 0), Failing: ptr.Deref(s.Failing, 0),
		Updates: ptr.Deref(actions.Updates, 0), Changes: ptr.Deref(actions.Changes, 0),
		Mitigations: ptr.Deref(actions.Mitigations, 0), Investigations: ptr.Deref(actions.Investigations, 0),
		Critical: ptr.Deref(severities.Critical, 0), High: ptr.Deref(severities.High, 0),
		Medium: ptr.Deref(severities.Medium, 0), Low: ptr.Deref(severities.Low, 0),
		Unknown: ptr.Deref(severities.Unknown, 0),
	}
}

// Status returns the status that holds the tally, without a time.
func (a Tally) Status() inventoryv1alpha1.PlaybookCountsStatus {
	return inventoryv1alpha1.PlaybookCountsStatus{
		Judged: ptr.To(a.Judged), Failing: ptr.To(a.Failing),
		Actions: &inventoryv1alpha1.ActionCounts{Updates: ptr.To(a.Updates), Changes: ptr.To(a.Changes),
			Mitigations: ptr.To(a.Mitigations), Investigations: ptr.To(a.Investigations)},
		Severities: &inventoryv1alpha1.SeverityCounts{Critical: ptr.To(a.Critical), High: ptr.To(a.High),
			Medium: ptr.To(a.Medium), Low: ptr.To(a.Low), Unknown: ptr.To(a.Unknown)},
	}
}

// CountsName returns the name of the PlaybookCounts of a playbook for a cluster: the playbook, a dot and the
// cluster. A playbook and a cluster are named with DNS-1123 labels, which have no dot. The CRD requires this name
// with a CEL rule.
func CountsName(playbook, cluster string) string { return playbook + "." + cluster }

// crdCountsStore keeps the counts as PlaybookCounts custom resources.
type crdCountsStore struct {
	api       client.Client
	informers cache.Cache
	now       func() time.Time
}

// The store reads, lists, creates and deletes the counts, and writes their status. It never updates the object
// itself, and watches the counts through the manager's cache.
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=playbookcounts,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups=inventory.vexplain.bedag.ch,resources=playbookcounts/status,verbs=update

// NewCRDCountsStore returns a CountsStore that keeps the counts in the PlaybookCounts API, through c, and watches
// them through informers. Pass a client that reads them from the API server and not from a cache, such as the
// manager's client with setup.ClientOptions, so that a write compares with what is stored.
func NewCRDCountsStore(c client.Client, informers cache.Cache) CountsStore {
	return &crdCountsStore{api: c, informers: informers, now: time.Now}
}

func (s *crdCountsStore) Put(ctx context.Context, playbook string, playbookUID types.UID, cluster string,
	counts Tally) error {
	name := CountsName(playbook, cluster)
	return retry.OnError(retry.DefaultBackoff, isRacedOrDeleted, func() error {
		obj := &inventoryv1alpha1.PlaybookCounts{}
		err := s.api.Get(ctx, client.ObjectKey{Name: name}, obj)
		switch {
		case apierrors.IsNotFound(err):
			obj = &inventoryv1alpha1.PlaybookCounts{
				ObjectMeta: metav1.ObjectMeta{
					Name:   name,
					Labels: map[string]string{playbookLabel: playbook},
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: configv1alpha1.GroupVersion.String(), Kind: "Playbook", Name: playbook, UID: playbookUID,
					}},
				},
				Spec: inventoryv1alpha1.PlaybookCountsSpec{Playbook: playbook, Cluster: cluster},
			}
			if err := s.api.Create(ctx, obj); err != nil {
				return fmt.Errorf("create PlaybookCounts %q: %w", name, err)
			}
		case err != nil:
			return fmt.Errorf("read PlaybookCounts %q: %w", name, err)
		case !slices.ContainsFunc(obj.OwnerReferences, func(o metav1.OwnerReference) bool { return o.UID == playbookUID }):
			// Counts of a Playbook that was deleted and made again wait for Kubernetes to delete them, which would
			// delete what is written now: they are made again, owned by the new one.
			if err := s.api.Delete(ctx, obj, client.Preconditions{UID: &obj.UID}); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete PlaybookCounts %q: %w", name, err)
			}
			return apierrors.NewConflict(inventoryv1alpha1.GroupVersion.WithResource("playbookcounts").GroupResource(), name,
				fmt.Errorf("the counts belonged to another Playbook"))
		}
		// A status that has no time is the one of a new object, which has no counts yet.
		if obj.Status.UpdatedTime != nil && TallyOf(obj.Status) == counts {
			return nil
		}
		obj.Status = counts.Status()
		obj.Status.UpdatedTime = ptr.To(metav1.NewTime(s.now()))
		if err := s.api.Status().Update(ctx, obj); err != nil {
			return fmt.Errorf("write status of PlaybookCounts %q: %w", name, err)
		}
		return nil
	})
}

func (s *crdCountsStore) Delete(ctx context.Context, playbook, cluster string) error {
	obj := &inventoryv1alpha1.PlaybookCounts{ObjectMeta: metav1.ObjectMeta{Name: CountsName(playbook, cluster)}}
	if err := s.api.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete PlaybookCounts %q: %w", obj.Name, err)
	}
	return nil
}

func (s *crdCountsStore) List(ctx context.Context, playbook string) ([]inventoryv1alpha1.PlaybookCounts, error) {
	var list inventoryv1alpha1.PlaybookCountsList
	if err := s.api.List(ctx, &list, client.MatchingLabels{playbookLabel: playbook}); err != nil {
		return nil, fmt.Errorf("list the PlaybookCounts of playbook %s: %w", playbook, err)
	}
	slices.SortFunc(list.Items, func(a, b inventoryv1alpha1.PlaybookCounts) int {
		return strings.Compare(a.Spec.Cluster, b.Spec.Cluster)
	})
	return list.Items, nil
}

func (s *crdCountsStore) Source() source.Source {
	return source.Kind[client.Object](s.informers, &inventoryv1alpha1.PlaybookCounts{},
		handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
			counts, ok := obj.(*inventoryv1alpha1.PlaybookCounts)
			if !ok || counts.Spec.Playbook == "" {
				return nil
			}
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: counts.Spec.Playbook}}}
		}))
}
