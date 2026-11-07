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

package spoke_test

import (
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/urgency"
)

// The tests of the series run the renderer as the reports' tests do, and read what the manager's registry serves.

// openCases returns the labels of the vexplain_open_case series of the namespace, as "cve verdict urgency digest".
func openCases(t *testing.T, namespace string) []string {
	t.Helper()
	families, err := ctrlmetrics.Registry.Gather()
	require.NoError(t, err)
	var out []string
	for _, family := range families {
		if family.GetName() != "vexplain_open_case" {
			continue
		}
		for _, m := range family.Metric {
			labels := map[string]string{}
			for _, l := range m.Label {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["namespace"] == namespace {
				out = append(out, labels["cve"]+" "+labels["verdict"]+" "+labels["urgency"]+" "+labels["digest"])
			}
		}
	}
	return out
}

// caseOf is the open case that a sheet's finding gives in an image of a workload whose exposure is unknown, in the form
// that openCases has.
func caseOf(f inventoryv1alpha1.Finding, digest string) string {
	return f.VulnerabilityID + " " + string(f.Status) + " " +
		string(urgency.Decide(urgency.FromFinding(f, configv1alpha1.SSVCExposureUnknown), nil)) + " " + digest
}

func waitForCases(t *testing.T, namespace string, want ...string) {
	t.Helper()
	require.Eventually(t, func() bool {
		got := openCases(t, namespace)
		if len(got) != len(want) {
			return false
		}
		for _, w := range want {
			found := false
			for _, g := range got {
				found = found || g == w
			}
			if !found {
				return false
			}
		}
		return true
	}, wait, tick, "the open cases of %s: %v, now %v", namespace, want, openCases(t, namespace))
}

func TestAReportsSeriesAppearChangeAndGoWithTheReport(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	s := startReporting(t, c)
	digest, manifest := newDigest(t), newDigest(t)
	web := running(ns, webName, linuxAMD64)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	setFacts(t, c, digest, manifestFacts(manifest))

	putSheet(t, manifest, sheetOf(manifest, 100, exploited(), openFinding("CVE-2026-0002", "libother")).Status)

	reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool { return len(r.Status.Actions) == 2 })
	waitForCases(t, ns, caseOf(exploited(), digest), caseOf(openFinding("CVE-2026-0002", "libother"), digest))

	// The image moves to another manifest, whose sheet lists one finding.
	other := newDigest(t)
	putSheet(t, other, sheetOf(other, 100, exploited()).Status)
	setFacts(t, c, digest, manifestFacts(other))

	reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool { return len(r.Status.Actions) == 1 })
	waitForCases(t, ns, caseOf(exploited(), digest))

	s.presence.Snapshot("workloads", nil)

	noReport(t, ns, "deployment-web")
	waitForCases(t, ns)
}

// After a start, the renderer finds a report that is as it should be and writes nothing, and the series of the new
// process still have to be there.
func TestAReportThatIsUnchangedAfterARestartStillHasItsSeries(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	digest, manifest := newDigest(t), newDigest(t)
	web := running(ns, webName, linuxAMD64)
	before := startReporting(t, c)
	before.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, 100, exploited()).Status)
	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool { return len(r.Status.Actions) == 1 })
	waitForCases(t, ns, "CVE-2026-0001 Affected Immediate "+digest)
	before.stop()

	after := startReporting(t, c)
	waitForCases(t, ns) // the new process has no series until presence knows what runs
	after.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, web)})

	waitForCases(t, ns, "CVE-2026-0001 Affected Immediate "+digest)
	require.Equal(t, report.ResourceVersion, reportOf(t, ns, "deployment-web").ResourceVersion, "the report was not rewritten")
}

// A sheet that changes in place, as the hub rewrites it, has the reports of the workloads that run its image rendered
// again, with their series.
func TestASheetThatChangesRewritesItsWorkloadsReportAndSeries(t *testing.T) {
	c := newCluster()
	ns := newNamespace(t)
	s := startReporting(t, c)
	digest, manifest := newDigest(t), newDigest(t)
	s.presence.Snapshot("workloads", []cloudevents.Event{presenceEvent(t, digest, running(ns, webName, linuxAMD64))})
	setFacts(t, c, digest, manifestFacts(manifest))
	putSheet(t, manifest, sheetOf(manifest, 100, exploited(), openFinding("CVE-2026-0002", "libother")).Status)
	reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool { return len(r.Status.Actions) == 2 })

	putSheet(t, manifest, sheetOf(manifest, 100, exploited()).Status)

	report := reportWhere(t, ns, "deployment-web", func(r *triagev1alpha1.WorkloadReport) bool { return len(r.Status.Actions) == 1 })
	require.EqualValues(t, 1, *report.Status.Summary.Affected)
	waitForCases(t, ns, caseOf(exploited(), digest))
}
