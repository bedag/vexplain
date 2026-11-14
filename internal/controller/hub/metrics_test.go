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
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/inventory"
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

// clusterLabel and playbookLabel are the labels of the series that hold the name of a cluster and of a playbook.
const (
	clusterLabel  = "cluster"
	playbookLabel = "playbook"
)

// configName is the name of the OperatorConfig.
const configName = "default"

// valueKey is the key of a series' value among its labels.
const valueKey = "value"

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
			series := map[string]string{valueKey: strconv.FormatFloat(m.GetGauge().GetValue(), 'f', -1, 64)}
			for _, l := range m.Label {
				series[l.GetName()] = l.GetValue()
			}
			out[family.GetName()] = append(out[family.GetName()], series)
		}
	}
	return out
}

func playbookSeries(playbook, value string) map[string]string {
	return map[string]string{clusterLabel: localCluster, playbookLabel: playbook, valueKey: value}
}

func TestPlaybookReadyFollowsTheReadyConditionAndGoesWithThePlaybook(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	yes, no := metav1.ConditionTrue, metav1.ConditionFalse
	gone := playbookWith("gone", &no)
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: configName},
			Spec: configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(localCluster)}},
		playbookWith("container-cves", &yes), playbookWith("vm-cves", &no), playbookWith("new", nil), gone,
	).Build()
	c := hub.NewPlaybooksCollector(reader, inventory.NewCRDCountsStore(reader, nil), hub.NewRuleFindings(inventory.NewCRDVerdictsStore(reader, nil), logr.Discard()), logr.Discard())

	require.ElementsMatch(t, []map[string]string{
		playbookSeries("container-cves", "1"), playbookSeries("vm-cves", "0"), playbookSeries("new", "0"),
		playbookSeries("gone", "0"),
	}, gatherGauges(t, c)["vexplain_playbook_ready"], "only a True condition is ready")

	require.NoError(t, reader.Delete(context.Background(), gone))

	require.ElementsMatch(t, []map[string]string{
		playbookSeries("container-cves", "1"), playbookSeries("vm-cves", "0"), playbookSeries("new", "0"),
	}, gatherGauges(t, c)["vexplain_playbook_ready"], "a deleted playbook has no series")
}

// countsOf returns the counts of a playbook for a cluster, as the spoke of the cluster writes them.
func countsOf(playbook, cluster string, counts inventory.Tally) *inventoryv1alpha1.PlaybookCounts {
	return &inventoryv1alpha1.PlaybookCounts{
		ObjectMeta: metav1.ObjectMeta{Name: inventory.CountsName(playbook, cluster),
			Labels: map[string]string{"vexplain.bedag.ch/playbook": playbook}},
		Spec:   inventoryv1alpha1.PlaybookCountsSpec{Playbook: playbook, Cluster: cluster},
		Status: counts.Status(),
	}
}

// sheetOf returns the sheet of a manifest under a playbook that holds a finding of each of the statuses, decided by
// the rule, and one that no rule decided.
func sheetOf(playbook, rule string, statuses ...inventoryv1alpha1.VEXStatus) *inventoryv1alpha1.ImageVerdicts {
	sheet := &inventoryv1alpha1.ImageVerdicts{
		ObjectMeta: metav1.ObjectMeta{Name: "sha256-" + strings.Repeat("a", 64) + "." + playbook},
		Spec:       inventoryv1alpha1.ImageVerdictsSpec{Playbook: playbook},
	}
	for _, status := range statuses {
		sheet.Status.Findings = append(sheet.Status.Findings, inventoryv1alpha1.Finding{Status: status, Rule: ptr.To(rule)})
	}
	sheet.Status.Findings = append(sheet.Status.Findings, inventoryv1alpha1.Finding{Status: inventoryv1alpha1.VEXStatusUnderInvestigation})
	return sheet
}

func TestTheFleetMetricsReadTheCountsAndTheSheets(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	yes := metav1.ConditionTrue
	counts := inventory.Tally{Judged: 7, Failing: 3, Updates: 4, Mitigations: 1}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: configName},
			Spec: configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(localCluster)}},
		playbookWith("container-cves", &yes),
		countsOf("container-cves", otherCluster, counts),
		sheetOf("container-cves", "known-exploited", inventoryv1alpha1.VEXStatusAffected, inventoryv1alpha1.VEXStatusAffected,
			inventoryv1alpha1.VEXStatusNotAffected),
	).Build()
	findings := hub.NewRuleFindings(inventory.NewCRDVerdictsStore(reader, nil), logr.Discard())
	require.NoError(t, findings.Refresh(t.Context()))
	// A scrape lists no sheet: the findings are the snapshot's.
	listed := false
	reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: configName},
			Spec: configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(localCluster)}},
		playbookWith("container-cves", &yes), countsOf("container-cves", otherCluster, counts),
	).WithInterceptorFuncs(interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList,
		opts ...client.ListOption) error {
		if _, ok := list.(*inventoryv1alpha1.ImageVerdictsList); ok {
			listed = true
		}
		return c.List(ctx, list, opts...)
	}}).Build()
	series := gatherGauges(t, hub.NewPlaybooksCollector(reader, inventory.NewCRDCountsStore(reader, nil), findings, logr.Discard()))
	require.False(t, listed, "a scrape lists no sheet")

	of := func(state string, value string) map[string]string {
		return map[string]string{clusterLabel: otherCluster, playbookLabel: playbookName, "state": state, valueKey: value}
	}
	require.ElementsMatch(t, []map[string]string{of("judged", "7"), of("failing", "3")}, series["vexplain_playbook_resources"])
	step := func(step string, value string) map[string]string {
		return map[string]string{clusterLabel: otherCluster, playbookLabel: playbookName, "step": step, valueKey: value}
	}
	require.ElementsMatch(t, []map[string]string{step("Update", "4"), step("Change", "0"), step("Mitigate", "1"),
		step("Investigate", "0")}, series["vexplain_playbook_actions"])
	finding := func(status string, value string) map[string]string {
		return map[string]string{clusterLabel: localCluster, playbookLabel: playbookName, "rule": "known-exploited",
			"status": status, valueKey: value}
	}
	require.ElementsMatch(t, []map[string]string{finding("Affected", "2"), finding("NotAffected", "1")},
		series["vexplain_rule_findings"], "the hub's own cluster, and no series for a finding that no rule decided")
}

func TestAFailedCountOfTheRuleFindingsKeepsTheLastValuesAndFailsNoSeries(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	yes := metav1.ConditionTrue
	failing := false
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: configName},
			Spec: configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(localCluster)}},
		playbookWith("container-cves", &yes),
		sheetOf("container-cves", "known-exploited", inventoryv1alpha1.VEXStatusAffected),
	).WithInterceptorFuncs(interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList,
		opts ...client.ListOption) error {
		if _, ok := list.(*inventoryv1alpha1.ImageVerdictsList); ok && failing {
			return errors.New("the API server is away")
		}
		return c.List(ctx, list, opts...)
	}}).Build()
	findings := hub.NewRuleFindings(inventory.NewCRDVerdictsStore(reader, nil), logr.Discard())
	collector := hub.NewPlaybooksCollector(reader, inventory.NewCRDCountsStore(reader, nil), findings, logr.Discard())
	require.Empty(t, gatherGauges(t, collector)["vexplain_rule_findings"], "no snapshot yet, as on a replica that isn't the leader")
	require.NoError(t, findings.Refresh(t.Context()))

	failing = true
	require.Error(t, findings.Refresh(t.Context()))

	series := gatherGauges(t, collector)
	require.Len(t, series["vexplain_rule_findings"], 1, "the last snapshot stays")
	require.Equal(t, []map[string]string{playbookSeries("container-cves", "1")}, series["vexplain_playbook_ready"],
		"the other series are served")
}
