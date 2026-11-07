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
	"fmt"
	"slices"
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
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The tests of the series build them from reports' renderings, as the renderer hands them over, and read what a
// registry gathers.

const (
	cluster1 = "cluster-a"
	digest1  = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
)

// counted returns a rendering whose sheets have the counts, and nothing else.
func counted(affected, underInvestigation, notAffected, fixed int32) rendering {
	return rendering{counts: sheetCounts{affected, underInvestigation, notAffected, fixed}}
}

func reported(id string, status inventoryv1alpha1.VEXStatus, urgency triagev1alpha1.SSVCOutcome, review string) candidate {
	return candidate{id: id, status: status, urgency: urgency, reviewState: review,
		pkg: triagev1alpha1.ReportPackage{Name: "libexample", Version: ptr.To("1.0"), Type: "deb"}}
}

// owned returns a rendering whose status has the owner values, and nothing else.
func owned(values ...triagev1alpha1.OwnerValue) rendering {
	return rendering{status: triagev1alpha1.WorkloadReportStatus{Owner: values}}
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
	immediate = "Immediate"
	cve1      = "CVE-2026-0001"
	amd64     = "linux/amd64"
	arm64     = "linux/arm64"
	affected  = "Affected"
	unclear   = "UnderInvestigation"
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

func TestSettledFindingsAreCountedFromTheSheetsCountsWithoutUrgency(t *testing.T) {
	c := NewReportsCollector()
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web", counted(0, 0, 5, 2), nil))
	c.set(types.NamespacedName{Namespace: teamA, Name: apiReport}, seriesOf(cluster1, "api", counted(0, 0, 4, 0), nil))

	series := gather(t, c)["vexplain_findings"]

	require.ElementsMatch(t, []map[string]string{
		findingsSeries("NotAffected", "None", "RuleSettled", "9"),
		findingsSeries("Fixed", "None", "RuleSettled", "2"),
	}, series, "settled findings add up per namespace, and a zero count has no series")
}

func TestOpenFindingsAreCountedByTheirUrgencyAndReviewStateAndListedAsCases(t *testing.T) {
	c := NewReportsCollector()
	r := counted(1, 1, 0, 0)
	r.open = []candidate{
		reported(cve1, inventoryv1alpha1.VEXStatusAffected, triagev1alpha1.SSVCOutcomeImmediate, reviewRuleSettled),
		reported("CVE-2026-0002", inventoryv1alpha1.VEXStatusUnderInvestigation, triagev1alpha1.SSVCOutcomeScheduled, reviewOpen),
	}
	cases := []openCase{{cve1, digest1, affected, immediate}, {"CVE-2026-0002", digest1, unclear, "Scheduled"}}
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web", r, cases))

	got := gather(t, c)

	require.ElementsMatch(t, []map[string]string{
		caseSeries(cve1, affected, immediate),
		caseSeries("CVE-2026-0002", unclear, "Scheduled"),
	}, got["vexplain_open_case"])
	require.ElementsMatch(t, []map[string]string{
		findingsSeries(affected, immediate, "RuleSettled", "1"),
		findingsSeries(unclear, "Scheduled", "Open", "1"),
	}, got["vexplain_findings"])
}

func TestAFindingInTwoPackagesOfOneImageIsOneCase(t *testing.T) {
	c := NewReportsCollector()
	a := reported(cve1, inventoryv1alpha1.VEXStatusAffected, triagev1alpha1.SSVCOutcomeImmediate, reviewOpen)
	b := a
	b.pkg.Name = "libother"
	r := counted(2, 0, 0, 0)
	r.open = []candidate{a, b}
	cases := []openCase{{cve1, digest1, affected, immediate}, {cve1, digest1, affected, immediate}}
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web", r, cases))

	got := gather(t, c)

	require.Len(t, got["vexplain_open_case"], 1, "the labels name no package, so equal series would be a duplicate")
	require.Equal(t, "2", got["vexplain_findings"][0]["value"], "both findings are counted")
}

func TestTheFunnelAddsUpTheCountsOfEachCluster(t *testing.T) {
	c := NewReportsCollector()
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web", counted(1, 2, 3, 4), nil))
	c.set(types.NamespacedName{Namespace: teamB, Name: apiReport}, seriesOf(cluster1, "api", counted(0, 1, 2, 0), nil))

	got := gather(t, c)["vexplain_funnel"]

	require.ElementsMatch(t, []map[string]string{
		stageSeries("Flagged", "13"), stageSeries("Settled", "9"), stageSeries(affected, "1"),
		stageSeries(unclear, "3"),
	}, got)
}

func TestAReportsSeriesGoWithIt(t *testing.T) {
	c := NewReportsCollector()
	key := types.NamespacedName{Namespace: teamA, Name: webReport}
	c.set(key, seriesOf(cluster1, "web", counted(0, 0, 1, 0), nil))
	require.NotEmpty(t, gather(t, c))

	c.delete(key)

	require.Empty(t, gather(t, c))
}

func TestOwnerInfoHasOneSeriesPerNamespaceWithSanitisedKeys(t *testing.T) {
	c := NewReportsCollector()
	r := owned(
		owner(triagev1alpha1.OwnerSourceNamespaceLabel, ownerKey, teamA),
		owner(triagev1alpha1.OwnerSourceNamespaceAnnotation, "contact", "team-a@artifacts.example"),
		owner(triagev1alpha1.OwnerSourceWorkloadLabel, "app", "web"),
	)
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web", r, nil))
	c.set(types.NamespacedName{Namespace: teamA, Name: apiReport}, seriesOf(cluster1, "api", r, nil))
	c.set(types.NamespacedName{Namespace: teamB, Name: webReport}, seriesOf(cluster1, "web",
		owned(owner(triagev1alpha1.OwnerSourceNamespaceLabel, ownerKey, teamB)), nil))

	got := gather(t, c)["vexplain_namespace_owner_info"]

	require.ElementsMatch(t, []map[string]string{
		labelled("1", clusterLabel, cluster1, namespaceLabel, teamA, "label_team_example_com_owner", teamA,
			"annotation_contact", "team-a@artifacts.example"),
		labelled("1", clusterLabel, cluster1, namespaceLabel, teamB, "label_team_example_com_owner", teamB),
	}, got, "one series per namespace, with the namespace's keys only, not the workload's labels")
}

func TestOwnerKeysThatSanitiseToOneNameKeepTheirOwnSeriesLabel(t *testing.T) {
	c := NewReportsCollector()
	r := owned(
		owner(triagev1alpha1.OwnerSourceNamespaceLabel, "a.b", "dot"),
		owner(triagev1alpha1.OwnerSourceNamespaceLabel, "a-b", "dash"),
		owner(triagev1alpha1.OwnerSourceNamespaceLabel, "a_b", "underscore"),
	)
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, seriesOf(cluster1, "web", r, nil))

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
		owned(owner(triagev1alpha1.OwnerSourceNamespaceLabel, "owner", "say \"hi\"\nthen \\ go")), nil))
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

func shaN(n int) string { return fmt.Sprintf("sha256:%064x", n) }

func vuln(id string, status inventoryv1alpha1.VEXStatus) inventoryv1alpha1.Finding {
	return inventoryv1alpha1.Finding{
		VulnerabilityID: id,
		Package:         inventoryv1alpha1.PackageReference{ID: "id-libexample", Name: "libexample", Version: ptr.To("1.0"), Type: "deb"},
		Status:          status,
		Severity:        inventoryv1alpha1.SeverityHigh,
	}
}

// sheetWith returns the sheet of a manifest that says what it found, with the findings counted.
func sheetWith(manifest string, findings ...inventoryv1alpha1.Finding) *inventoryv1alpha1.ImageVerdicts {
	var counts inventoryv1alpha1.FindingCounts
	counts.Affected, counts.UnderInvestigation = ptr.To(int32(0)), ptr.To(int32(0))
	counts.NotAffected, counts.Fixed = ptr.To(int32(0)), ptr.To(int32(0))
	for _, f := range findings {
		switch f.Status {
		case inventoryv1alpha1.VEXStatusAffected:
			*counts.Affected++
		case inventoryv1alpha1.VEXStatusUnderInvestigation:
			*counts.UnderInvestigation++
		case inventoryv1alpha1.VEXStatusNotAffected:
			*counts.NotAffected++
		case inventoryv1alpha1.VEXStatusFixed:
			*counts.Fixed++
		}
	}
	return &inventoryv1alpha1.ImageVerdicts{
		Spec:   inventoryv1alpha1.ImageVerdictsSpec{ManifestDigest: manifest},
		Status: inventoryv1alpha1.ImageVerdictsStatus{FindingsVersion: ptr.To("v1"), Findings: findings, Counts: &counts},
	}
}

// factsWith gives an image a manifest for each platform.
func factsWith(manifests map[string]string) *inventoryv1alpha1.ImageFacts {
	facts := &inventoryv1alpha1.ImageFacts{}
	for platform, digest := range manifests {
		facts.Manifests = append(facts.Manifests, inventoryv1alpha1.ManifestFact{Platform: platform, Digest: digest})
	}
	return facts
}

// seriesOfWorkload renders a workload's report and builds what the series keep of it, as the renderer does.
func seriesOfWorkload(images []RunningImage, sheets map[string]*inventoryv1alpha1.ImageVerdicts,
	facts map[string]*inventoryv1alpha1.ImageFacts) (triagev1alpha1.WorkloadReportStatus, reportSeries) {
	cfg := settings.Effective{ClusterName: cluster1}
	exposure := configv1alpha1.SSVCExposureUnknown
	r := renderStatus(evidence.PresenceWorkload{Kind: "Deployment", Name: "web"}, images, sheets, facts,
		WorkloadExposure{SSVC: exposure}, cfg)
	return r.status, seriesOf(cluster1, "web", r, casesOf(images, sheets, facts, exposure, cfg))
}

func sumOf(series []map[string]string, verdicts ...string) (total int) {
	for _, s := range series {
		if len(verdicts) == 0 || slices.Contains(verdicts, s[verdictLabel]) {
			n, _ := strconv.Atoi(s[valueKey])
			total += n
		}
	}
	return total
}

// The report lists at most 256 actions and 5 IDs in each, which keeps its object small, but the worklist and the counts
// are no place for a cut that nobody sees.
func TestAReportThatCutsItsActionsStillHasEveryOpenFindingInTheSeries(t *testing.T) {
	findings := make([]inventoryv1alpha1.Finding, 0, 260)
	for i := range 260 {
		f := vuln(fmt.Sprintf("CVE-2026-%04d", i), inventoryv1alpha1.VEXStatusAffected)
		f.Package.Name = fmt.Sprintf("lib%03d", i%257)
		findings = append(findings, f)
	}
	images := []RunningImage{{Digest: shaN(1), Platforms: []string{amd64}}}
	status, series := seriesOfWorkload(images, map[string]*inventoryv1alpha1.ImageVerdicts{shaN(2): sheetWith(shaN(2), findings...)},
		map[string]*inventoryv1alpha1.ImageFacts{shaN(1): factsWith(map[string]string{amd64: shaN(2)})})
	require.Len(t, status.Actions, 256)
	require.EqualValues(t, 1, *status.Summary.OmittedActions, "the report cuts one action")
	c := NewReportsCollector()
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, series)

	got := gather(t, c)

	require.Equal(t, 260, sumOf(got["vexplain_findings"], affected), "the findings of the cut action are counted")
	require.Len(t, got["vexplain_open_case"], 260, "and are on the worklist")
}

// The summary of a report counts as vexplain_findings counts: an open finding once for each vulnerability and package of
// the workload, whichever images and platforms have it, and a settled one once for each manifest (decision 0038).
func TestTheSummaryCountsWhatVexplainFindingsCountsForTheWorkload(t *testing.T) {
	other := func(f inventoryv1alpha1.Finding) inventoryv1alpha1.Finding {
		f.Package.Name = "libother"
		return f
	}
	images := []RunningImage{{Digest: shaN(1), Platforms: []string{amd64, arm64}}, {Digest: shaN(5), Platforms: []string{amd64}}}
	status, series := seriesOfWorkload(images, map[string]*inventoryv1alpha1.ImageVerdicts{
		shaN(2): sheetWith(shaN(2), vuln(cve1, inventoryv1alpha1.VEXStatusAffected),
			vuln("CVE-2026-0002", inventoryv1alpha1.VEXStatusUnderInvestigation),
			vuln("CVE-2026-0003", inventoryv1alpha1.VEXStatusNotAffected), vuln("CVE-2026-0004", inventoryv1alpha1.VEXStatusFixed)),
		shaN(3): sheetWith(shaN(3), vuln(cve1, inventoryv1alpha1.VEXStatusAffected),
			vuln("CVE-2026-0003", inventoryv1alpha1.VEXStatusNotAffected)),
		shaN(6): sheetWith(shaN(6), vuln(cve1, inventoryv1alpha1.VEXStatusUnderInvestigation),
			other(vuln("CVE-2026-0005", inventoryv1alpha1.VEXStatusAffected))),
	}, map[string]*inventoryv1alpha1.ImageFacts{
		shaN(1): factsWith(map[string]string{amd64: shaN(2), arm64: shaN(3)}),
		shaN(5): factsWith(map[string]string{amd64: shaN(6)}),
	})
	c := NewReportsCollector()
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, series)

	got := gather(t, c)["vexplain_findings"]

	summary := status.Summary
	require.NotNil(t, summary)
	for verdict, count := range map[string]*int32{
		affected: summary.Affected, unclear: summary.UnderInvestigation,
		"NotAffected": summary.NotAffected, "Fixed": summary.Fixed,
	} {
		require.EqualValues(t, sumOf(got, verdict), *count, verdict)
	}
	require.EqualValues(t, 2, *summary.Affected, "CVE-2026-0001 in libexample once, though three manifests have it, and libother")
	require.EqualValues(t, 1, *summary.UnderInvestigation)
	require.EqualValues(t, 2, *summary.NotAffected, "once for each manifest")
	require.EqualValues(t, 1, *summary.Fixed)
}

// A report keeps one finding for a vulnerability and package, the Affected one, but each image's case says what its own
// sheet says.
func TestACaseCarriesTheVerdictOfItsOwnImagesSheet(t *testing.T) {
	images := []RunningImage{
		{Digest: shaN(1), Platforms: []string{amd64}}, {Digest: shaN(3), Platforms: []string{amd64}}}
	_, series := seriesOfWorkload(images, map[string]*inventoryv1alpha1.ImageVerdicts{
		shaN(2): sheetWith(shaN(2), vuln(cve1, inventoryv1alpha1.VEXStatusAffected)),
		shaN(4): sheetWith(shaN(4), vuln(cve1, inventoryv1alpha1.VEXStatusUnderInvestigation)),
	}, map[string]*inventoryv1alpha1.ImageFacts{
		shaN(1): factsWith(map[string]string{amd64: shaN(2)}),
		shaN(3): factsWith(map[string]string{amd64: shaN(4)}),
	})
	c := NewReportsCollector()
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, series)

	got := gather(t, c)

	verdictOf := map[string]string{}
	for _, s := range got["vexplain_open_case"] {
		verdictOf[s[digestSeries]] = s[verdictLabel]
	}
	require.Equal(t, map[string]string{shaN(1): affected, shaN(3): unclear}, verdictOf)
	require.Equal(t, 1, sumOf(got["vexplain_findings"]), "the finding is counted once, as the report keeps it")
}

// A vulnerability that two platforms of an image share is one finding of the workload, and two in the counts that the
// funnel adds up, one for each manifest.
func TestAVulnerabilityOnTwoPlatformsIsOneOpenFindingAndTwoInTheFunnel(t *testing.T) {
	images := []RunningImage{{Digest: shaN(1), Platforms: []string{amd64, arm64}}}
	_, series := seriesOfWorkload(images, map[string]*inventoryv1alpha1.ImageVerdicts{
		shaN(2): sheetWith(shaN(2), vuln(cve1, inventoryv1alpha1.VEXStatusAffected)),
		shaN(3): sheetWith(shaN(3), vuln(cve1, inventoryv1alpha1.VEXStatusAffected)),
	}, map[string]*inventoryv1alpha1.ImageFacts{
		shaN(1): factsWith(map[string]string{amd64: shaN(2), arm64: shaN(3)}),
	})
	c := NewReportsCollector()
	c.set(types.NamespacedName{Namespace: teamA, Name: webReport}, series)

	got := gather(t, c)

	require.Equal(t, 1, sumOf(got["vexplain_findings"], affected))
	require.Len(t, got["vexplain_open_case"], 1, "one case for the workload, digest and CVE")
	flagged := 0
	for _, s := range got["vexplain_funnel"] {
		if s[stageLabel] == affected {
			flagged, _ = strconv.Atoi(s[valueKey])
		}
	}
	require.Equal(t, 2, flagged)
}
