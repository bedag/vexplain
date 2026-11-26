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

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// measureIdle counts the hub's writes while nothing changes, for --idle.
func (m *measurement) measureIdle(ctx context.Context) error {
	begin := m.mark()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(m.opts.idle):
	}
	m.phases["idle"] = [2]int{begin, m.mark()}
	m.reportWrites("idle")
	return nil
}

// rollOut rolls 50 workloads of the first spoke out, by a new annotation on their pod templates, waits until each runs
// its new pod alone and the hub's writes stand still, and counts the writes from the first change on.
func (m *measurement) rollOut(ctx context.Context) error {
	spoke := m.spokes[0]
	begin := m.mark()
	started := time.Now()
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{%q:%q}}}}}`, rolloutAnnotation,
		started.Format(time.RFC3339))
	for _, w := range rolled() {
		deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: w.name, Namespace: w.namespace}}
		if err := spoke.api.Patch(ctx, deployment, client.RawPatch(k8stypes.MergePatchType, []byte(patch))); err != nil {
			return fmt.Errorf("roll %s/%s out: %w", w.namespace, w.name, err)
		}
	}
	err := m.waitFor(ctx, "the rollout on "+m.names[0], func(ctx context.Context) (bool, error) {
		for _, w := range rolled() {
			var found appsv1.Deployment
			if err := spoke.api.Get(ctx, client.ObjectKey{Namespace: w.namespace, Name: w.name}, &found); err != nil {
				return false, err
			}
			status := found.Status
			if status.ObservedGeneration < found.Generation || status.UpdatedReplicas != 1 || status.Replicas != 1 ||
				status.AvailableReplicas != 1 {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	m.say("the rollout of %d workloads took %s\n", len(rolled()), time.Since(started).Round(time.Second))
	if err = m.waitQuiet(ctx, begin); err != nil {
		return err
	}
	m.phases["rollout"] = [2]int{begin, m.mark()}
	m.reportWrites("rollout")
	return nil
}

// restart deletes the hub's manager pod, and measures how long the new one takes until each Spoke is Synced again:
// the wait for the old manager's lease, which it doesn't release, and the copier's first round once the new one leads.
func (m *measurement) restart(ctx context.Context) error {
	old, err := managerPod(ctx, m.hub, "")
	if err != nil {
		return err
	}
	begin := m.mark()
	deleted := time.Now()
	if err = m.hub.api.Delete(ctx, old); err != nil {
		return err
	}
	// The conditions keep whole seconds, so the tool looks five times a second and takes the time of its look. A
	// condition that turned in the second of the deletion counts as after it.
	since := deleted.Truncate(time.Second)
	synced := map[string]time.Time{}
	m.say("waiting for the Spokes to be Synced again\n")
	err = wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, m.opts.timeout, true,
		func(ctx context.Context) (bool, error) {
			for _, spokeName := range m.names {
				if _, seen := synced[spokeName]; seen {
					continue
				}
				var found configv1alpha1.Spoke
				if err := m.hub.api.Get(ctx, client.ObjectKey{Name: spokeName}, &found); err != nil {
					return false, err
				}
				c := meta.FindStatusCondition(found.Status.Conditions, configv1alpha1.ConditionSynced)
				if c != nil && c.Status == metav1.ConditionTrue && !c.LastTransitionTime.Time.Before(since) {
					synced[spokeName] = time.Now()
				}
			}
			return len(synced) == len(m.names), nil
		})
	if err != nil {
		return fmt.Errorf("waiting for the Spokes to be Synced again: %w", err)
	}
	pod, err := managerPod(ctx, m.hub, old.UID)
	if err != nil || pod == nil || len(pod.Status.ContainerStatuses) == 0 ||
		pod.Status.ContainerStatuses[0].State.Running == nil {
		return fmt.Errorf("the new manager doesn't run: %w", err)
	}
	started := pod.Status.ContainerStatuses[0].State.Running.StartedAt.Time
	lease, err := m.hub.clientset.CoordinationV1().Leases(operatorNamespace).Get(ctx, managerLease,
		metav1.GetOptions{})
	if err != nil {
		return err
	}
	if !strings.HasPrefix(ptr.Deref(lease.Spec.HolderIdentity, ""), pod.Name+"_") || lease.Spec.AcquireTime == nil {
		return errors.New("the new manager doesn't hold the lease")
	}
	acquired := lease.Spec.AcquireTime.Time
	m.say("after the deletion, the new manager's container started within %s, and it took the lease after %s\n",
		started.Sub(since), acquired.Sub(deleted).Round(10*time.Millisecond))
	for _, spokeName := range m.names {
		m.say("%s: seen Synced %s after the deletion, %s after the new manager took the lease\n", spokeName,
			synced[spokeName].Sub(deleted).Round(10*time.Millisecond),
			synced[spokeName].Sub(acquired).Round(10*time.Millisecond))
	}
	if err = m.waitQuiet(ctx, begin); err != nil {
		return err
	}
	m.phases["restart"] = [2]int{begin, m.mark()}
	m.reportWrites("restart")
	return nil
}

// managerPod returns the hub's manager pod, other than the one of the UID not, or nil while there is none.
func managerPod(ctx context.Context, c *cluster, not k8stypes.UID) (*corev1.Pod, error) {
	pods, err := c.clientset.CoreV1().Pods(operatorNamespace).List(ctx, metav1.ListOptions{LabelSelector: managerLabels})
	if err != nil {
		return nil, err
	}
	for i := range pods.Items {
		if pod := &pods.Items[i]; pod.UID != not && pod.DeletionTimestamp == nil {
			return pod, nil
		}
	}
	if not == "" {
		return nil, errors.New("the hub runs no manager")
	}
	return nil, nil
}
