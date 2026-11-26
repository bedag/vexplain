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

package settings_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/settings"
)

// stage is the label of a cluster that says its stage, and production and development its values.
const (
	stage       = "stage"
	production  = "prod"
	development = "dev"
)

func spoke(name string, labels map[string]configv1alpha1.LabelValue) *configv1alpha1.Spoke {
	return &configv1alpha1.Spoke{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: configv1alpha1.SpokeSpec{Labels: labels}}
}

// Each cluster has its own labels, by its name: the hub's own cluster in its OperatorConfig, and each remote cluster in
// its Spoke. The hub's own cluster has no Spoke, so one of its name doesn't relabel it.
func TestClusterLabelsHoldTheLabelsOfEachCluster(t *testing.T) {
	c := newClient(t,
		operatorConfig("default", configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To("cluster-a"),
			ClusterLabels: map[string]configv1alpha1.LabelValue{stage: production}}),
		spoke("cluster-b", map[string]configv1alpha1.LabelValue{stage: development, "zone": "a"}),
		spoke("cluster-c", nil),
		spoke("cluster-a", map[string]configv1alpha1.LabelValue{stage: development}))

	labels, err := settings.ClusterLabels(t.Context(), c)

	require.NoError(t, err)
	require.Equal(t, map[string]map[string]string{
		"cluster-a": {stage: production}, "cluster-b": {stage: development, "zone": "a"}, "cluster-c": {},
	}, labels)
}

// A read of the Spokes that fails is returned: a remote cluster taken for one without labels would lose the playbooks
// that match it.
func TestClusterLabelsReturnAFailedReadOfTheSpokes(t *testing.T) {
	errRead := errors.New("the cache is not synced yet")
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*configv1alpha1.SpokeList); ok {
				return errRead
			}
			return c.List(ctx, list, opts...)
		},
	}).Build()

	_, err := settings.ClusterLabels(t.Context(), c)

	require.ErrorIs(t, err, errRead)
}
