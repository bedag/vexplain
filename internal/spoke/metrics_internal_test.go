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
	"bytes"
	"strconv"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
)

// The tests of the series build them from reports' statuses, as the renderer hands them over, and read what a registry
// gathers.

const (
	cluster1 = "cluster-a"
	digest1  = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
)

func counts(affected, underInvestigation, notAffected, fixed int32) *triagev1alpha1.ReportCounts {
	return &triagev1alpha1.ReportCounts{Affected: &affected, UnderInvestigation: &underInvestigation,
		NotAffected: &notAffected, Fixed: &fixed}
}

func reported(id string, status triagev1alpha1.VEXStatus, urgency triagev1alpha1.SSVCOutcome,
	review triagev1alpha1.ReviewState) triagev1alpha1.ReportFinding {
	return triagev1alpha1.ReportFinding{VulnerabilityID: id, Status: status, Urgency: urgency, ReviewState: review,
		Package: triagev1alpha1.ReportPackage{Name: "libexample", Version: ptr.To("1.0"), Type: "deb"}}
}

func owner(source triagev1alpha1.OwnerSource, key, value string) triagev1alpha1.OwnerValue {
	return triagev1alpha1.OwnerValue{Source: source, Key: key, Value: ptr.To(value)}
}

const (
	teamA     = "team-a"
	teamB     = "team-b"
	webReport = "deployment-web"
	apiReport = "deployment-api"
	valueKey  = "value"
	ownerKey  = "team.example.com/owner"
)

// labelled returns the series of a metric with the labels, which pair names and values, and its value.
func labelled(value string, labels ...string) map[string]string {
	out := map[string]string{valueKey: value}
	for i := 0; i < len(labels); i += 2 {
		out[labels[i]] = labels[i+1]
	}
	return out
}

func findingsSeries(verdict, urgency, review, value string) map[string]string {
	return labelled(value, clusterLabel, cluster1, namespaceLabel, teamA, verdictLabel, verdict, urgencyLabel, urgency,
		reviewLabel, review)
}

func caseSeries(cve, verdict, urgency string) map[string]string {
	return labelled("1", clusterLabel, cluster1, namespaceLabel, teamA, workloadLabel, "web", digestSeries, digest1,
		cveLabel, cve, verdictLabel, verdict, urgencyLabel, urgency)
}

func stageSeries(stage, value string) map[string]string {
	return labelled(value, clusterLabel, cluster1, stageLabel, stage)
}

func readySeries(collector, value string) map[string]string {
	return labelled(value, clusterLabel, cluster1, collectorLabel, collector)
}

// gather returns the series of a collector, by metric name, each as its labels and value.
func gather(t *testing.T, c prometheus.Collector) map[string][]map[string]string {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	families, err := reg.Gather()
	require.NoError(t, err)
	out := map[string][]map[string]string{}
	for _, family := range families {
		for _, m := range family.Metric {
			series := map[string]string{valueKey: trimFloat(m.GetGauge().GetValue())}
			for _, l := range m.Label {
				series[l.GetName()] = l.GetValue()
			}
			out[family.GetName()] = append(out[family.GetName()], series)
		}
	}
	return out
}

func trimFloat(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func TestSettledFindingsAreCountedFromTheReportsCountsWithoutUrgency(t *testing.T) {
	c := NewReportsCollector()
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web",
		triagev1alpha1.WorkloadReportStatus{Counts: counts(0, 0, 5, 2)}, nil))
	c.set(types.NamespacedName{Namespace: teamA, Name: apiReport}, seriesOf(cluster1, "api",
		triagev1alpha1.WorkloadReportStatus{Counts: counts(0, 0, 4, 0)}, nil))

	series := gather(t, c)["vexplain_findings"]

	require.ElementsMatch(t, []map[string]string{
		findingsSeries("NotAffected", "None", "RuleSettled", "9"),
		findingsSeries("Fixed", "None", "RuleSettled", "2"),
	}, series, "settled findings add up per namespace, and a zero count has no series")
}

func TestOpenFindingsAreCountedByTheirUrgencyAndReviewStateAndListedAsCases(t *testing.T) {
	c := NewReportsCollector()
	status := triagev1alpha1.WorkloadReportStatus{
		Counts: counts(1, 1, 0, 0),
		Findings: []triagev1alpha1.ReportFinding{
			reported("CVE-2026-0001", triagev1alpha1.VEXStatusAffected, triagev1alpha1.SSVCOutcomeImmediate, triagev1alpha1.ReviewStateRuleSettled),
			reported("CVE-2026-0002", triagev1alpha1.VEXStatusUnderInvestigation, triagev1alpha1.SSVCOutcomeScheduled, triagev1alpha1.ReviewStateOpen),
		},
	}
	digests := map[findingKey][]string{keyOfReported(status.Findings[0]): {digest1}, keyOfReported(status.Findings[1]): {digest1}}
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web", status, digests))

	got := gather(t, c)

	require.ElementsMatch(t, []map[string]string{
		caseSeries("CVE-2026-0001", "Affected", "Immediate"),
		caseSeries("CVE-2026-0002", "UnderInvestigation", "Scheduled"),
	}, got["vexplain_open_case"])
	require.ElementsMatch(t, []map[string]string{
		findingsSeries("Affected", "Immediate", "RuleSettled", "1"),
		findingsSeries("UnderInvestigation", "Scheduled", "Open", "1"),
	}, got["vexplain_findings"])
}

func TestAFindingInTwoPackagesOfOneImageIsOneCase(t *testing.T) {
	c := NewReportsCollector()
	a := reported("CVE-2026-0001", triagev1alpha1.VEXStatusAffected, triagev1alpha1.SSVCOutcomeImmediate, triagev1alpha1.ReviewStateOpen)
	b := a
	b.Package.Name = "libother"
	status := triagev1alpha1.WorkloadReportStatus{Counts: counts(2, 0, 0, 0), Findings: []triagev1alpha1.ReportFinding{a, b}}
	digests := map[findingKey][]string{keyOfReported(a): {digest1}, keyOfReported(b): {digest1}}
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web", status, digests))

	got := gather(t, c)

	require.Len(t, got["vexplain_open_case"], 1, "the labels name no package, so equal series would be a duplicate")
	require.Equal(t, "2", got["vexplain_findings"][0]["value"], "both findings are counted")
}

func TestTheFunnelAddsUpTheCountsOfEachCluster(t *testing.T) {
	c := NewReportsCollector()
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web",
		triagev1alpha1.WorkloadReportStatus{Counts: counts(1, 2, 3, 4)}, nil))
	c.set(types.NamespacedName{Namespace: teamB, Name: apiReport}, seriesOf(cluster1, "api",
		triagev1alpha1.WorkloadReportStatus{Counts: counts(0, 1, 2, 0)}, nil))

	got := gather(t, c)["vexplain_funnel"]

	require.ElementsMatch(t, []map[string]string{
		stageSeries("Flagged", "13"), stageSeries("Settled", "9"), stageSeries("Affected", "1"),
		stageSeries("UnderInvestigation", "3"),
	}, got)
}

func TestAReportsSeriesGoWithIt(t *testing.T) {
	c := NewReportsCollector()
	key := types.NamespacedName{Namespace: teamA, Name: webReport}
	c.set(key, seriesOf(cluster1, "web", triagev1alpha1.WorkloadReportStatus{Counts: counts(0, 0, 1, 0)}, nil))
	require.NotEmpty(t, gather(t, c))

	c.delete(key)

	require.Empty(t, gather(t, c))
}

func TestOwnerInfoHasOneSeriesPerNamespaceWithSanitisedKeys(t *testing.T) {
	c := NewReportsCollector()
	status := triagev1alpha1.WorkloadReportStatus{Owner: []triagev1alpha1.OwnerValue{
		owner(triagev1alpha1.OwnerSourceNamespaceLabel, ownerKey, teamA),
		owner(triagev1alpha1.OwnerSourceNamespaceAnnotation, "contact", "team-a@artifacts.example"),
		owner(triagev1alpha1.OwnerSourceWorkloadLabel, "app", "web"),
	}}
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web", status, nil))
	c.set(types.NamespacedName{Namespace: teamA, Name: apiReport}, seriesOf(cluster1, "api", status, nil))
	c.set(types.NamespacedName{Namespace: teamB, Name: webReport}, seriesOf(cluster1, "web",
		triagev1alpha1.WorkloadReportStatus{Owner: []triagev1alpha1.OwnerValue{
			owner(triagev1alpha1.OwnerSourceNamespaceLabel, ownerKey, teamB)}}, nil))

	got := gather(t, c)["vexplain_namespace_owner_info"]

	require.ElementsMatch(t, []map[string]string{
		labelled("1", clusterLabel, cluster1, namespaceLabel, teamA, "label_team_example_com_owner", teamA,
			"annotation_contact", "team-a@artifacts.example"),
		labelled("1", clusterLabel, cluster1, namespaceLabel, teamB, "label_team_example_com_owner", teamB),
	}, got, "one series per namespace, with the namespace's keys only, not the workload's labels")
}

func TestOwnerKeysThatSanitiseToOneNameKeepTheirOwnSeriesLabel(t *testing.T) {
	c := NewReportsCollector()
	status := triagev1alpha1.WorkloadReportStatus{Owner: []triagev1alpha1.OwnerValue{
		owner(triagev1alpha1.OwnerSourceNamespaceLabel, "a.b", "dot"),
		owner(triagev1alpha1.OwnerSourceNamespaceLabel, "a-b", "dash"),
		owner(triagev1alpha1.OwnerSourceNamespaceLabel, "a_b", "underscore"),
	}}
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web", status, nil))

	got := gather(t, c)["vexplain_namespace_owner_info"]

	require.Equal(t, []map[string]string{labelled("1", clusterLabel, cluster1, namespaceLabel, teamA,
		"label_a_b", "dash", "label_a_b_2", "dot", "label_a_b_3", "underscore")}, got,
		"the keys in order, a-b, a.b and a_b, get the name and then a suffix, so none is lost and the series is valid")
}

func TestSanitiseLabelNameAsKubeStateMetricsDoes(t *testing.T) {
	require.Equal(t, "app_kubernetes_io_part_of", SanitizeLabelName("app.kubernetes.io/part-of"))
	require.Equal(t, "Team_1__", SanitizeLabelName("Team_1 ü"))
}

func TestALabelValueWithAQuoteOrANewlineIsSanitisedAndThePageParses(t *testing.T) {
	c := NewReportsCollector()
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web",
		triagev1alpha1.WorkloadReportStatus{Owner: []triagev1alpha1.OwnerValue{
			owner(triagev1alpha1.OwnerSourceNamespaceLabel, "owner", "say \"hi\"\nthen \\ go")}}, nil))
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	families, err := reg.Gather()
	require.NoError(t, err)
	var page bytes.Buffer
	for _, f := range families {
		_, err := expfmt.MetricFamilyToText(&page, f)
		require.NoError(t, err)
	}

	parser := expfmt.NewTextParser(model.UTF8Validation)
	parsed, err := parser.TextToMetricFamilies(&page)

	require.NoError(t, err, "the exposition is valid")
	labels := map[string]string{}
	for _, l := range parsed["vexplain_namespace_owner_info"].Metric[0].Label {
		labels[l.GetName()] = l.GetValue()
	}
	require.Equal(t, "say \"hi\"�then \\ go", labels["label_owner"], "the newline is replaced, and the others are escaped")
}

func collectorWith(name string, ready *metav1.ConditionStatus) *configv1alpha1.Collector {
	obj := &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if ready != nil {
		meta.SetStatusCondition(&obj.Status.Conditions, metav1.Condition{
			Type: configv1alpha1.ConditionReady, Status: *ready, Reason: "Test"})
	}
	return obj
}

func TestCollectorReadyFollowsTheReadyCondition(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	yes, no, unknown := metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionUnknown
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&configv1alpha1.OperatorConfig{ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: configv1alpha1.OperatorConfigSpec{ClusterName: ptr.To(cluster1)}},
		collectorWith("scanner", &yes), collectorWith("workloads", &no), collectorWith("matcher", &unknown),
		collectorWith("new", nil),
	).Build()

	got := gather(t, NewCollectorsCollector(reader, logr.Discard()))["vexplain_collector_ready"]

	require.ElementsMatch(t, []map[string]string{
		readySeries("scanner", "1"), readySeries("workloads", "0"), readySeries("matcher", "0"), readySeries("new", "0"),
	}, got, "only a True condition is ready")
}
