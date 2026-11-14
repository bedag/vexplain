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

package spoke

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The renderer watches the namespaces through their metadata only, and reads their labels from that cache: the labels
// decide which playbooks' results the reports of a namespace hold, and stay in the cluster (design 5.7).
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=list;watch

// namespaceMetadata returns the metadata of a namespace of the name, through which the renderer watches and reads it.
func namespaceMetadata(name string) *metav1.PartialObjectMetadata {
	ns := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: name}}
	ns.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Namespace"))
	return ns
}

// namespaceLabels returns the labels of a namespace, from the cache of the metadata of the namespaces, or false when the
// cache holds no namespace of the name: it is gone, or the cache hasn't seen it yet, and its event has its reports
// rendered once the cache has it.
func (r *Reports) namespaceLabels(ctx context.Context, name string) (map[string]string, bool, error) {
	ns := namespaceMetadata(name)
	if err := r.cache.Get(ctx, client.ObjectKeyFromObject(ns), ns); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read the labels of namespace %s: %w", name, err)
	}
	return ns.Labels, true, nil
}

// namespaceChanged maps a namespace to the reports of the workloads that run in it, which its labels decide the
// playbooks of.
func (r *Reports) namespaceChanged(_ context.Context, obj client.Object) []reconcile.Request {
	var requests []reconcile.Request
	for _, name := range r.presence.RunningReports() {
		if name.Namespace == obj.GetName() {
			requests = append(requests, reconcile.Request{NamespacedName: name})
		}
	}
	return requests
}

// playbooksFor returns, of the playbooks and in their order, those whose results the reports of a namespace hold: the
// playbooks of the images in presence whose cluster selector selects the cluster's labels and whose namespace selector
// selects the namespace's labels (design 5.7). An absent match or selector selects everything, and one that doesn't
// parse selects nothing, as on the hub, which says why the playbook isn't Ready.
func playbooksFor(nsLabels, clusterLabels map[string]string, playbooks []configv1alpha1.Playbook) []configv1alpha1.Playbook {
	var out []configv1alpha1.Playbook
	for _, p := range playbooks {
		if p.Spec.Subjects.Type != evidence.TypePresence {
			continue
		}
		var clusters, namespaces *metav1.LabelSelector
		if p.Spec.Match != nil {
			clusters, namespaces = p.Spec.Match.Clusters, p.Spec.Match.Namespaces
		}
		if selects(clusters, clusterLabels) && selects(namespaces, nsLabels) {
			out = append(out, p)
		}
	}
	return out
}

// selects reports whether a selector selects the labels: an absent one selects any, and one that doesn't parse none.
func selects(selector *metav1.LabelSelector, set map[string]string) bool {
	if selector == nil {
		return true
	}
	s, err := metav1.LabelSelectorAsSelector(selector)
	return err == nil && s.Matches(labels.Set(set))
}
