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

package collector

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// defaultCollectors are the Collectors that the operator creates when it starts.
func defaultCollectors() []*configv1alpha1.Collector {
	return []*configv1alpha1.Collector{{
		// A Collector is named after its type, in lower case. The CRD enforces that.
		ObjectMeta: metav1.ObjectMeta{Name: "workloads"},
		Spec: configv1alpha1.CollectorSpec{
			Type:      configv1alpha1.CollectorTypeWorkloads,
			Workloads: &configv1alpha1.WorkloadsCollectorSpec{},
		},
	}, {
		ObjectMeta: metav1.ObjectMeta{Name: "scanner"},
		Spec: configv1alpha1.CollectorSpec{
			Type: configv1alpha1.CollectorTypeScanner,
			// An empty object, so that the API server fills in every setting with its default.
			Scanner: &configv1alpha1.ScannerCollectorSpec{},
		},
	}}
}

// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors,verbs=create

// EnsureDefaults creates the default Collectors that don't exist. It never changes or replaces
// one that does, so an admin's edit of a default survives a restart of the operator.
//
// Deleting the workloads Collector doesn't stop the pod inventory, because that object only reports
// health. The next start of the operator creates a deleted default Collector again.
func EnsureDefaults(ctx context.Context, c client.Client) error {
	for _, defaultCollector := range defaultCollectors() {
		// Create, and treat "exists" as done, so that there is no gap between a check and the
		// write in which another start of the operator could create the object.
		if err := c.Create(ctx, defaultCollector); err != nil {
			if apierrors.IsAlreadyExists(err) {
				continue
			}
			return fmt.Errorf("create the default Collector %q: %w", defaultCollector.Name, err)
		}
		logf.FromContext(ctx).Info("Created the default Collector", "name", defaultCollector.Name)
	}
	return nil
}
