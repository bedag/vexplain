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

package collector_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector"
)

const (
	// workloadsName and scannerName are the names of the default Collectors, and the only names that
	// the API accepts for the types Workloads and Scanner.
	workloadsName = "workloads"
	scannerName   = "scanner"
)

// newClient returns a fake client that holds objs. A fake client does not validate against the CRD
// schema, so it admits objects that the API server would reject.
func newClient(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithInterceptorFuncs(funcs).Build()
}

func TestEnsureDefaultsCreatesWorkloadsAndScanner(t *testing.T) {
	c := newClient(t, interceptor.Funcs{})

	require.NoError(t, collector.EnsureDefaults(t.Context(), c))

	// These two are all there is. The Scanner asks for scanner: {}, and leaves the API server to fill
	// in its settings, so a fake client, which applies no defaults, holds an empty object.
	var list configv1alpha1.CollectorList
	require.NoError(t, c.List(t.Context(), &list))
	specs := make(map[string]configv1alpha1.CollectorSpec, len(list.Items))
	for _, item := range list.Items {
		specs[item.Name] = item.Spec
	}
	require.Equal(t, map[string]configv1alpha1.CollectorSpec{
		workloadsName: {
			Type:      configv1alpha1.CollectorTypeWorkloads,
			Workloads: &configv1alpha1.WorkloadsCollectorSpec{},
		},
		scannerName: {
			Type:    configv1alpha1.CollectorTypeScanner,
			Scanner: &configv1alpha1.ScannerCollectorSpec{},
		},
	}, specs)
}

// An operator that is updated from a version that had only the workloads Collector finds that one
// in place, and still creates the scanner.
func TestEnsureDefaultsCreatesTheScannerNextToAnExistingWorkloadsCollector(t *testing.T) {
	existing := &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: workloadsName},
		Spec: configv1alpha1.CollectorSpec{
			Type:      configv1alpha1.CollectorTypeWorkloads,
			Workloads: &configv1alpha1.WorkloadsCollectorSpec{},
		},
	}
	c := newClient(t, interceptor.Funcs{}, existing)

	require.NoError(t, collector.EnsureDefaults(t.Context(), c))

	var got configv1alpha1.Collector
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: scannerName}, &got))
	require.Equal(t, configv1alpha1.CollectorTypeScanner, got.Spec.Type)
}

func TestEnsureDefaultsLeavesAnExistingCollectorAsItIs(t *testing.T) {
	// The settings of the Scanner are an admin's to edit, so it is the Collector that needs this most.
	for _, name := range []string{workloadsName, scannerName} {
		t.Run(name, func(t *testing.T) {
			existing := &configv1alpha1.Collector{
				ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"team": "team-a"}},
				// This spec differs from the default. The API server would not admit it, but a fake
				// client does, and it shows that nothing is merged or reset.
				Spec: configv1alpha1.CollectorSpec{Type: other},
			}
			c := newClient(t, interceptor.Funcs{}, existing)

			require.NoError(t, collector.EnsureDefaults(t.Context(), c))

			var got configv1alpha1.Collector
			require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: name}, &got))
			require.Equal(t, existing.Spec, got.Spec)
			require.Equal(t, existing.Labels, got.Labels)
		})
	}
}

func TestEnsureDefaultsReturnsAFailedCreate(t *testing.T) {
	forbidden := apierrors.NewForbidden(
		configv1alpha1.GroupVersion.WithResource("collectors").GroupResource(), workloadsName, errors.New("no right to create"))
	c := newClient(t, interceptor.Funcs{
		Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
			return forbidden
		},
	})

	err := collector.EnsureDefaults(t.Context(), c)

	require.ErrorIs(t, err, forbidden)
	require.ErrorContains(t, err, workloadsName)
}
