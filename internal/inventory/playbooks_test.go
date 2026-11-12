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

package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache/informertest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// The Playbooks come oldest first, and two of one second by their names, so that every replica orders them alike.
func TestPlaybooksListsTheOldestFirst(t *testing.T) {
	c := newClient(t, interceptor.Funcs{})
	first := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	for name, created := range map[string]time.Time{
		"b-newest": first.Add(time.Hour), "c-oldest": first, "a-second": first.Add(time.Minute), "b-second": first.Add(time.Minute),
	} {
		require.NoError(t, c.Create(t.Context(), &configv1alpha1.Playbook{
			ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: metav1.NewTime(created)},
		}))
	}

	got, err := inventory.NewPlaybooks(c, nil).List(t.Context())

	require.NoError(t, err)
	names := make([]string, 0, len(got))
	for _, playbook := range got {
		names = append(names, playbook.Name)
	}
	require.Equal(t, []string{"c-oldest", "a-second", "b-second", "b-newest"}, names)
}

func TestPlaybooksReturnsAFailedList(t *testing.T) {
	errList := errors.New("list failed")
	c := newClient(t, interceptor.Funcs{List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
		return errList
	}})

	_, err := inventory.NewPlaybooks(c, nil).List(t.Context())

	require.ErrorIs(t, err, errList, "a failed list is never one without playbooks")
}

// A controller watches the Playbooks through the Source, as a spoke's renderer does: it delivers a request named after a
// Playbook that comes, goes or changes its spec, and none for a change of its status alone, which the hub writes.
func TestPlaybooksSourceDeliversARequestWhenAPlaybookComesGoesOrChangesItsSpec(t *testing.T) {
	informers := &informertest.FakeInformers{Scheme: newScheme(t)}
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	t.Cleanup(queue.ShutDown)
	src, ok := inventory.NewPlaybooks(newClient(t, interceptor.Funcs{}), informers).Source().(source.SyncingSource)
	require.True(t, ok, "the source waits for the cache")
	require.NoError(t, src.Start(t.Context(), queue))
	require.NoError(t, src.WaitForSync(t.Context()))
	informer, err := informers.FakeInformerFor(t.Context(), &configv1alpha1.Playbook{})
	require.NoError(t, err)
	delivered := func() []string {
		var names []string
		for queue.Len() > 0 {
			got, _ := queue.Get()
			names = append(names, got.Name)
			queue.Done(got)
			queue.Forget(got)
		}
		return names
	}

	const name = "strict"
	playbook := &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 1, ResourceVersion: "1"}}
	informer.Add(playbook)
	require.Equal(t, []string{name}, delivered(), "a Playbook that comes")

	judged := playbook.DeepCopy()
	judged.ResourceVersion = "2"
	judged.Status.ObservedGeneration = ptr.To(int64(1))
	informer.Update(playbook, judged)
	require.Empty(t, delivered(), "a change of the status alone")

	matching := judged.DeepCopy()
	matching.ResourceVersion, matching.Generation = "3", 2
	matching.Spec.Match = &configv1alpha1.PlaybookMatch{Namespaces: &metav1.LabelSelector{}}
	informer.Update(judged, matching)
	require.Equal(t, []string{name}, delivered(), "a change of the spec")

	informer.Delete(matching)
	require.Equal(t, []string{name}, delivered(), "a Playbook that goes")
}
