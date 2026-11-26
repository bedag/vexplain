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

	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// ClusterLabels returns the labels of each cluster that the hub serves, by the cluster's name, for the playbooks that
// match clusters by labels: the hub's own cluster's, from the OperatorConfig, and each remote cluster's, from its Spoke.
// A failed read is returned, never taken for a cluster without labels.
func ClusterLabels(ctx context.Context, r client.Reader) (map[string]map[string]string, error) {
	effective, err := Load(ctx, r)
	if err != nil {
		return nil, err
	}
	var spokes configv1alpha1.SpokeList
	if err := r.List(ctx, &spokes); err != nil {
		return nil, fmt.Errorf("list the Spokes: %w", err)
	}
	labels := make(map[string]map[string]string, len(spokes.Items)+1)
	for _, spoke := range spokes.Items {
		labels[spoke.Name] = make(map[string]string, len(spoke.Spec.Labels))
		for key, value := range spoke.Spec.Labels {
			labels[spoke.Name][key] = string(value)
		}
	}
	// The hub's own cluster keeps its labels in its OperatorConfig and has no Spoke (design of remote spokes 5.3), so
	// a Spoke of its name doesn't relabel it.
	labels[effective.ClusterName] = effective.ClusterLabels
	return labels, nil
}
