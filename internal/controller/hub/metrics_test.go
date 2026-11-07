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

package hub_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
)

// playbookWith returns a playbook of the name whose Ready condition has the status, or none for nil.
func playbookWith(name string, ready *metav1.ConditionStatus) *configv1alpha1.Playbook {
	obj := &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if ready != nil {
		meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{
			Type: configv1alpha1.ConditionReady, Status: *ready, Reason: "Test"})
	}
	return obj
}

// gatherGauges returns the series of each gauge that c sends, as their labels and their value under "value".
func gatherGauges(t *testing.T, c prometheus.Collector) map[string][]map[string]string {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	families, err := reg.Gather()
	require.NoError(t, err)
	out := map[string][]map[string]string{}
	for _, family := range families {
		for _, m := range family.Metric {
			series := map[string]string{"value": strconv.FormatFloat(m.GetGauge().GetValue(), 'f', -1, 64)}
			for _, l := range m.Label {
				series[l.GetName()] = l.GetValue()
			}
			out[family.GetName()] = append(out[family.GetName()], series)
		}
	}
	return out
}

func playbookSeries(playbook, value string) map[string]string {
	return map[string]string{"cluster": "cluster-a", "playbook": playbook, "value": value}
}

func TestPlaybookReadyFollowsTheReadyConditionAndGoesWithThePlaybook(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	yes, no := metav1.ConditionTrue, metav1.ConditionFalse
	gone := playbookWith("gone", &no)
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To("cluster-a")}},
		playbookWith("container-cves", &yes), playbookWith("vm-cves", &no), playbookWith("new", nil), gone,
	).Build()
	c := hub.NewPlaybooksCollector(reader, logr.Discard())

	require.ElementsMatch(t, []map[string]string{
		playbookSeries("container-cves", "1"), playbookSeries("vm-cves", "0"), playbookSeries("new", "0"),
		playbookSeries("gone", "0"),
	}, gatherGauges(t, c)["vexplain_playbook_ready"], "only a True condition is ready")

	require.NoError(t, reader.Delete(context.Background(), gone))

	require.ElementsMatch(t, []map[string]string{
		playbookSeries("container-cves", "1"), playbookSeries("vm-cves", "0"), playbookSeries("new", "0"),
	}, gatherGauges(t, c)["vexplain_playbook_ready"], "a deleted playbook has no series")
}
