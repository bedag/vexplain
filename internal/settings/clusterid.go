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

package settings

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterID returns the identity of this cluster: the UID of its kube-system namespace.
//
// Unlike spec.clusterName, which an admin can change, the UID stays the same for the life of the
// cluster, so entries written under a former cluster name can still be matched to their cluster.
func ClusterID(ctx context.Context, r client.Reader) (string, error) {
	var namespace corev1.Namespace
	if err := r.Get(ctx, client.ObjectKey{Name: metav1.NamespaceSystem}, &namespace); err != nil {
		return "", fmt.Errorf("read namespace %q: %w", metav1.NamespaceSystem, err)
	}
	// An API server always sets the UID. An empty ID would match every entry that has none, so
	// it is an error, never a value.
	if namespace.UID == "" {
		return "", fmt.Errorf("namespace %q has no UID", metav1.NamespaceSystem)
	}
	return string(namespace.UID), nil
}
