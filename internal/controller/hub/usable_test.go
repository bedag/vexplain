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
	"testing"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/controller/hub"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// These tests run the assessor with the production findings collector, CollectorFindings, over the Collectors of the
// fake client: the health of the vulnerabilities collector gates new matches, and not the sheets that its findings made (design 5.9).

// withCollectorFindings has the fixture's assessor match through CollectorFindings, which invokes match on the
// vulnerabilities collector's Collector, and returns the invoker that answers for the vulnerabilities collector: with the findings of the fixture's
// database about manifest. A restart of the fixture keeps them.
func (f *assessorFixture) withCollectorFindings(t *testing.T, manifest string) *recordingInvoker {
	t.Helper()
	invoker := &recordingInvoker{events: []cloudevents.Event{findingsEvent(t, manifest, sdkevidence.Findings{
		Version: v1, Matches: []sdkevidence.Match{exampleMatch, otherMatch, goneMatch},
	})}}
	f.assessor.Findings = hub.NewCollectorFindings(f.client, invoker, func(context.Context) (*collectorv1alpha1.Context, error) {
		return &collectorv1alpha1.Context{Cluster: localCluster, OperatorNamespace: operatorNamespace}, nil
	})
	return invoker
}

// setVulnerabilitiesReady records in the status of the vulnerabilities collector's Collector what the deployer records: its capabilities, with
// the operation match, and its Ready condition, True when it can be used and False when it can't.
func setVulnerabilitiesReady(t *testing.T, c client.Client, status metav1.ConditionStatus) {
	t.Helper()
	var collector configv1alpha1.Collector
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: vulnerabilitiesCollector}, &collector))
	collector.Status.Capabilities = vulnerabilitiesCollectorOf(vulnerabilitiesCollector).Status.Capabilities
	reason := configv1alpha1.ReasonHealthy
	if status == metav1.ConditionFalse {
		reason = configv1alpha1.ReasonCollectorFailing
	}
	meta.SetStatusCondition(&collector.Status.Conditions, metav1.Condition{
		Type: configv1alpha1.ConditionReady, Status: status, Reason: reason, Message: "As the deployer found it.",
	})
	require.NoError(t, c.Status().Update(t.Context(), &collector))
}

// invoked returns how often the invoker was asked to match.
func (i *recordingInvoker) invoked() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.requests)
}

// A vulnerabilities collector that can't be used, as one whose pod was replaced or whose settings are refused, still vouches for what it
// matched. A rule that changes meanwhile has each sheet evaluated again from its findings, and so does a start of the
// operator, which forgets what each sheet rested on: no sheet is deleted. Once the vulnerabilities collector can be used again, the
// manifests whose match failed are matched again.
func TestTheAssessorKeepsTheSheetsWhileTheFindingsCollectorCantBeUsed(t *testing.T) {
	for name, restart := range map[string]bool{"while it runs": false, "after a restart": true} {
		t.Run(name, func(t *testing.T) {
			f := newAssessor(t, interceptor.Funcs{}, nil)
			digest, manifest := digestOf(1), digestOf(101)
			invoker := f.withCollectorFindings(t, manifest)
			setVulnerabilitiesReady(t, f.client, metav1.ConditionTrue)
			f.scanned(t, digest, manifest, evidenceOf(manifest))
			f.assess(t, manifest)
			require.Equal(t, ptr.To(int32(1)), f.sheetOf(t, manifest).Status.Counts.NotAffected)
			require.Equal(t, 1, invoker.invoked())

			setVulnerabilitiesReady(t, f.client, metav1.ConditionFalse)
			tightenTheGuard(t, f.client)
			if restart {
				f.restart()
			}
			_, err := hub.Assess(f.assessor, t.Context(), manifestRequest(manifest))

			if restart {
				require.ErrorContains(t, err, "can't be used", "the match that the start calls for is tried again")
			} else {
				require.NoError(t, err, "the findings of the sheet are current, and need no match")
			}
			sheet := f.sheetOf(t, manifest)
			require.NotNil(t, sheet, "the sheet is kept")
			require.Equal(t, ptr.To(int32(0)), sheet.Status.Counts.NotAffected)
			require.Equal(t, ptr.To(int32(3)), sheet.Status.Counts.UnderInvestigation, "the rules of now made it")
			require.Equal(t, ptr.To(v1), sheet.Status.FindingsVersion)
			require.Equal(t, 1, invoker.invoked(), "nothing is asked of a vulnerabilities collector that can't be used")

			setVulnerabilitiesReady(t, f.client, metav1.ConditionTrue)
			f.assess(t, manifest)

			if restart {
				require.Equal(t, 2, invoker.invoked(), "the match that failed is made")
			} else {
				require.Equal(t, 1, invoker.invoked(), "the findings were current all along")
			}
			require.Equal(t, ptr.To(int32(3)), f.sheetOf(t, manifest).Status.Counts.UnderInvestigation)
		})
	}
}

// Once the playbook's findings collector can be used again, every manifest is assessed again at once: a match that
// failed while it couldn't would otherwise wait out the controller's back-off, which grows to a quarter of an hour.
// Another Collector that can be used again, or a findings collector that stays as it was, calls for nothing.
func TestTheAssessorAssessesEveryManifestOnceTheFindingsCollectorCanBeUsedAgain(t *testing.T) {
	f := newAssessor(t, interceptor.Funcs{}, nil)
	first, second := digestOf(101), digestOf(102)
	f.storeScans(t, scannerVersion, first, second)
	usable := vulnerabilitiesCollectorOf(vulnerabilitiesCollector)
	failing := vulnerabilitiesCollectorOf(vulnerabilitiesCollector, func(c *configv1alpha1.Collector) {
		c.Status.Conditions[0].Status, c.Status.Conditions[0].Reason = metav1.ConditionFalse, configv1alpha1.ReasonCollectorFailing
	})
	unknown := vulnerabilitiesCollectorOf(vulnerabilitiesCollector, func(c *configv1alpha1.Collector) {
		c.Status.Conditions[0].Status, c.Status.Conditions[0].Reason = metav1.ConditionUnknown, configv1alpha1.ReasonNoData
	})
	unrecorded := vulnerabilitiesCollectorOf(vulnerabilitiesCollector, func(c *configv1alpha1.Collector) { c.Status.Capabilities = nil })
	refreshed := usable.DeepCopy()
	refreshed.Status.LastSuccessTime = ptr.To(metav1.Now())

	usableAgain := hub.UsableAgain()
	for name, tc := range map[string]struct {
		before, after *configv1alpha1.Collector
		passes        bool
	}{
		"Ready turns True":                {failing, usable, true},
		"Ready turns Unknown":             {failing, unknown, true},
		"the capabilities are recorded":   {unrecorded, usable, true},
		"Ready stays True":                {usable, refreshed, false},
		"Ready turns False":               {usable, failing, false},
		"Ready stays False":               {failing, failing.DeepCopy(), false},
		"Ready turns Unknown from usable": {usable, unknown, false},
	} {
		require.Equal(t, tc.passes, usableAgain.Update(event.UpdateEvent{ObjectOld: tc.before, ObjectNew: tc.after}), name)
	}
	require.False(t, usableAgain.Create(event.CreateEvent{Object: usable}), "a Collector that comes passes another watch")
	require.False(t, usableAgain.Delete(event.DeleteEvent{Object: usable}), "a Collector that goes passes another watch")

	require.ElementsMatch(t, []reconcile.Request{manifestRequest(first), manifestRequest(second)},
		hub.ManifestsOfFindingsCollector(f.assessor, t.Context(), usable))
	other := usable.DeepCopy()
	other.Name = scanner
	require.Empty(t, hub.ManifestsOfFindingsCollector(f.assessor, t.Context(), other),
		"the scanner is no findings collector of the playbook")
}
