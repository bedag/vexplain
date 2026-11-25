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

package exposure_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/exposure"
	"github.com/bedag/vexplain/internal/rules/engine"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// The cases decide the exposure of workloads from the view, as the hub runs it, with the exposure rules of design 5.6:
// vexplain's two that don't read exposure from outside the cluster, and a source's two, which read its answers as dmz.

const (
	// exposureInput and dmzInput are the names under which the playbook of the tests supplies exposure and the
	// answers of the source dmz.
	exposureInput = "exposure"
	dmzInput      = "dmz"
	// internal is the answer of a source that publishes an entry point to an internal network only.
	internal = "Internal"
	// exposedNotPublished is the source's rule that concludes Controlled, reachableInCluster vexplain's, and
	// ownNamespaceOnly vexplain's rule that concludes Small.
	exposedNotPublished = "exposed-not-published"
	reachableInCluster  = "reachable-in-cluster"
	ownNamespaceOnly    = "own-namespace-only"
)

// manifest is the manifest of the cases of the tests.
var manifest = digestOf(40)

// exposureRule compiles an exposure rule that reads the inputs, exposure and dmz, by their names.
func exposureRule(t *testing.T, name, condition string, outcome configv1alpha1.SSVCExposure, inputs ...string) *engine.Compiled {
	t.Helper()
	types := map[string]string{exposureInput: sdkevidence.TypeExposure, dmzInput: dmzType}
	spec := configv1alpha1.RuleSpec{Condition: condition, Outcome: &configv1alpha1.RuleOutcome{Exposure: ptr.To(outcome)}}
	for _, in := range inputs {
		spec.Inputs = append(spec.Inputs, configv1alpha1.RuleInput{Name: in, Type: types[in]})
	}
	compiled, err := engine.Compile(&configv1alpha1.Rule{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: spec})
	require.NoError(t, err)
	return compiled
}

// Every way in answered, and none published to the internet: design 5.6's condition of the source's rules.
const allAnswered = `exposure.data.external.exposed && size(exposure.data.external.unchecked) == 0 &&
	size(exposure.data.external.entryPoints) > 0 &&
	exposure.data.external.entryPoints.all(e, e.subjects.all(s, dmz[s].data.publishedTo in ['Internal', 'None']))`

// sourcePlaybook returns a playbook that takes exposure, optional, from network-reach in cluster-a and the answers of
// dmz, a source, which counts for every cluster, with the source's two rules in place of exposed-outside-cluster, as
// design 5.7 shows it. No producer's evidence has a maxAge.
func sourcePlaybook(t *testing.T) exposure.PlaybookExposure {
	t.Helper()
	return exposure.PlaybookExposure{
		Steps: []*engine.Compiled{
			exposureRule(t, "published-or-unchecked", "exposure.data.external.exposed && !("+allAnswered+")",
				configv1alpha1.SSVCExposureOpen, exposureInput, dmzInput),
			exposureRule(t, exposedNotPublished, allAnswered, configv1alpha1.SSVCExposureControlled, exposureInput, dmzInput),
			exposureRule(t, reachableInCluster, "exposure.data.indirect || exposure.data.internalReach != 'Namespace'",
				configv1alpha1.SSVCExposureControlled, exposureInput),
			exposureRule(t, ownNamespaceOnly, "exposure.data.internalReach == 'Namespace'",
				configv1alpha1.SSVCExposureSmall, exposureInput),
		},
		Types:    map[string]string{exposureInput: sdkevidence.TypeExposure, dmzInput: dmzType},
		Sources:  map[string]bool{dmzInput: true},
		Optional: map[string]bool{exposureInput: true},
		Producers: map[string]map[string][]string{
			exposureInput: {clusterA: {networkReach}},
			dmzInput:      {"": {dmz}},
		},
		MaxAges: map[[3]string]time.Duration{},
	}
}

// recorded is what the cases recorded of the rules that they couldn't evaluate.
type recorded struct {
	manifest, playbook string
	notEvaluated       map[string]int
}

// caseFixture is the asker's fixture, and the cases' Exposures over its view.
type caseFixture struct {
	*fixture
	exposures cases.Exposures
	recorded  []recorded
}

// newCaseFixture returns a fixture whose cases read pe as the playbook.
func newCaseFixture(t *testing.T, pe exposure.PlaybookExposure) *caseFixture {
	t.Helper()
	f := &caseFixture{fixture: newFixture(t)}
	f.exposures = exposure.NewCaseExposures(f.view,
		func(_ context.Context, name string) (exposure.PlaybookExposure, error) {
			require.Equal(t, playbook, name)
			return pe, nil
		}, func(manifest, playbook string, notEvaluated map[string]int) {
			f.recorded = append(f.recorded, recorded{manifest: manifest, playbook: playbook, notEvaluated: notEvaluated})
		})
	return f
}

// runs stores the presence of the digest in cluster-a, which the workloads of the names run.
func (f *caseFixture) runs(digest string, names ...string) {
	f.t.Helper()
	f.runsIn(clusterA, digest, names...)
}

// runsIn stores the presence of the digest in the cluster, which the workloads of the names run there.
func (f *caseFixture) runsIn(cluster, digest string, names ...string) {
	f.t.Helper()
	subjects := make([]string, len(names))
	for i, name := range names {
		subjects[i] = workload(cluster, name)
	}
	putIn(f.t, f.store, workloadsCollector, cluster, presenceEvent(f.t, digest, subjects...))
}

// reachedIn stores the exposure of the workload of the name in cluster-a: not exposed, and reached from as far as reach
// says.
func (f *caseFixture) reachedIn(name, reach string) {
	f.t.Helper()
	putIn(f.t, f.store, networkReach, clusterA, newEvent(f.t, sdkevidence.TypeExposure, workload(clusterA, name),
		sdkevidence.Exposure{InternalReach: reach}, networkReach))
}

// answers stores the answer of dmz about a point, given at the time.
func (f *caseFixture) answers(point, publishedTo string, at time.Time) {
	f.t.Helper()
	require.NoError(f.t, f.store.Put(f.t.Context(), dmz, version, answerEvent(f.t, dmzType, point, publishedTo, dmz, at)))
}

// of returns what the cases decide of the workloads in the places of the manifest.
func (f *caseFixture) of(places ...cases.Place) map[cases.Place][]cases.WorkloadExposure {
	f.t.Helper()
	found, err := f.exposures.Of(f.t.Context(), playbook, manifest, places)
	require.NoError(f.t, err)
	return found
}

// decided returns the exposure that the rules decided for the workload of the name in cluster-a.
func decided(name string, level configv1alpha1.SSVCExposure, rules, missing []string) cases.WorkloadExposure {
	return decidedIn(clusterA, name, level, rules, missing)
}

// decidedIn returns the exposure that the rules decided for the workload of the name in the cluster.
func decidedIn(cluster, name string, level configv1alpha1.SSVCExposure, rules, missing []string) cases.WorkloadExposure {
	return cases.WorkloadExposure{Subject: workload(cluster, name),
		WorkloadExposure: engine.WorkloadExposure{Exposure: level, Rules: rules, Missing: missing}}
}

// Each workload's exposure comes from the view: exposure is the workload's record, and the source's type is a map of
// the answers about the workload's entry points, empty for a workload that has none. A place whose presence the view
// doesn't hold is unknown, and a workload that presence names without exposure is Unknown.
func TestEachWorkloadsInputsComeFromTheView(t *testing.T) {
	f := newCaseFixture(t, sourcePlaybook(t))
	digest := digestOf(41)
	f.runs(digest, "shop", "api", "batch", "gone")
	putIn(t, f.store, networkReach, clusterA, exposureEvent(t, workload(clusterA, "shop"), []string{shop, shopAddress}))
	putIn(t, f.store, networkReach, clusterA, exposureEvent(t, workload(clusterA, "api"), []string{api}))
	f.reachedIn("batch", "Namespace")
	now := time.Now()
	f.answers(shop, none, now)
	f.answers(shopAddress, internal, now)
	f.answers(api, internet, now)

	found := f.of(cases.Place{Digest: digest, Cluster: clusterA}, cases.Place{Digest: digest, Cluster: clusterB})

	require.Equal(t, map[cases.Place][]cases.WorkloadExposure{{Digest: digest, Cluster: clusterA}: {
		decided("api", configv1alpha1.SSVCExposureOpen, []string{"published-or-unchecked"}, nil),
		decided("batch", configv1alpha1.SSVCExposureSmall, []string{ownNamespaceOnly}, nil),
		decided("gone", configv1alpha1.SSVCExposureUnknown, nil, []string{dmzInput, exposureInput}),
		decided("shop", configv1alpha1.SSVCExposureControlled,
			[]string{exposedNotPublished, reachableInCluster}, nil),
	}}, found, "cluster-b's presence of the digest isn't on the hub")
}

// A rule reads an input's source as the source of its event, as a finding rule does, for exposure and for an answer.
func TestARulesSourceIsTheEventsSource(t *testing.T) {
	pe := sourcePlaybook(t)
	pe.Steps = []*engine.Compiled{exposureRule(t, "sources", `exposure.source == "/hub/collectors/network-reach" && `+
		`dmz["`+shop+`"].source == "/hub/collectors/dmz"`, configv1alpha1.SSVCExposureSmall, exposureInput, dmzInput)}
	f := newCaseFixture(t, pe)
	digest := digestOf(42)
	f.runs(digest, "shop")
	putIn(t, f.store, networkReach, clusterA, exposureEvent(t, workload(clusterA, "shop"), []string{shop}))
	f.answers(shop, none, time.Now())

	found := f.of(cases.Place{Digest: digest, Cluster: clusterA})

	require.Equal(t, []cases.WorkloadExposure{decided("shop", configv1alpha1.SSVCExposureSmall,
		[]string{"sources"}, nil)}, found[cases.Place{Digest: digest, Cluster: clusterA}])
}

// Review Focus 2: an answer past its maxAge is missing, and so is one that comes from more than a minute ahead, as from
// a source whose clock runs fast: the workload is Unknown, never Controlled.
func TestAnAnswerPastItsMaxAgeIsMissing(t *testing.T) {
	pe := sourcePlaybook(t)
	pe.MaxAges[[3]string{"", dmz, dmzType}] = time.Hour
	f := newCaseFixture(t, pe)
	digest := digestOf(43)
	f.runs(digest, "old", "ahead", "fresh")
	for name, point := range map[string]string{"old": shop, "ahead": api, "fresh": shopAddress} {
		putIn(t, f.store, networkReach, clusterA, exposureEvent(t, workload(clusterA, name), []string{point}))
	}
	now := time.Now()
	f.answers(shop, none, now.Add(-2*time.Hour))
	f.answers(api, none, now.Add(5*time.Minute))
	f.answers(shopAddress, none, now.Add(-30*time.Minute).Add(30*time.Second))

	found := f.of(cases.Place{Digest: digest, Cluster: clusterA})

	require.Equal(t, []cases.WorkloadExposure{
		decided("ahead", configv1alpha1.SSVCExposureUnknown, nil, []string{dmzInput}),
		decided("fresh", configv1alpha1.SSVCExposureControlled,
			[]string{exposedNotPublished, reachableInCluster}, nil),
		decided("old", configv1alpha1.SSVCExposureUnknown, nil, []string{dmzInput}),
	}, found[cases.Place{Digest: digest, Cluster: clusterA}])
}

// A pinned producer that doesn't count in the workload's cluster adds an input that is missing, as the finding rules
// get its evidence: the workload is Unknown, though the other producer's record would let reachable-in-cluster
// conclude Controlled.
func TestAnAbsentProducerIsAMissingInput(t *testing.T) {
	pe := sourcePlaybook(t)
	pe.Absent = map[string]map[string]bool{exposureInput: {clusterA: true}}
	f := newCaseFixture(t, pe)
	digest := digestOf(46)
	f.runs(digest, "web")
	f.reachedIn("web", "Cluster")

	found := f.of(cases.Place{Digest: digest, Cluster: clusterA})

	require.Equal(t, []cases.WorkloadExposure{decided("web", configv1alpha1.SSVCExposureUnknown, nil,
		[]string{exposureInput})}, found[cases.Place{Digest: digest, Cluster: clusterA}])
}

// A workload reads the producers of its own cluster only, and the sources, which count for every cluster (design of
// remote spokes 5.7). network-reach and four more producers of exposure run in cluster-a only: a workload of cluster-b
// gets one missing input of exposure, and not one from each of them, which would make more combinations than the rules
// run. A record that network-reach left in cluster-b counts for nothing there, and the source's answer counts.
func TestAWorkloadReadsOnlyItsOwnClustersProducers(t *testing.T) {
	pe := sourcePlaybook(t)
	pe.Producers[exposureInput] = map[string][]string{clusterA: {networkReach, "reach-2", "reach-3", "reach-4", "reach-5"}}
	f := newCaseFixture(t, pe)
	digest := digestOf(47)
	f.runsIn(clusterB, digest, "shop")
	putIn(t, f.store, networkReach, clusterB, exposureEvent(t, workload(clusterB, "shop"), []string{shop}))
	f.answers(shop, none, time.Now())
	place := cases.Place{Digest: digest, Cluster: clusterB}

	found := f.of(place)

	require.Equal(t, []cases.WorkloadExposure{decidedIn(clusterB, "shop", configv1alpha1.SSVCExposureUnknown, nil,
		[]string{exposureInput})}, found[place])
}

// A record counts within the maxAge of its producer in its own cluster, which a remote cluster's Spoke mirrors:
// network-reach's exposure in cluster-b is missing past the hour of cluster-b's network-reach, while its exposure as old
// in cluster-a, where network-reach declares no maxAge, counts.
func TestARemoteRecordExpiresByItsSpokesMaxAge(t *testing.T) {
	pe := sourcePlaybook(t)
	pe.Producers[exposureInput] = map[string][]string{clusterA: {networkReach}, clusterB: {networkReach}}
	pe.MaxAges[[3]string{clusterB, networkReach, sdkevidence.TypeExposure}] = time.Hour
	f := newCaseFixture(t, pe)
	digest := digestOf(48)
	old := time.Now().Add(-2 * time.Hour)
	for _, cluster := range []string{clusterA, clusterB} {
		f.runsIn(cluster, digest, "batch")
		putIn(t, f.store, networkReach, cluster, newEvent(t, sdkevidence.TypeExposure, workload(cluster, "batch"),
			sdkevidence.Exposure{InternalReach: "Namespace"}, networkReach, sdkevidence.WithTime(old)))
	}
	inA, inB := cases.Place{Digest: digest, Cluster: clusterA}, cases.Place{Digest: digest, Cluster: clusterB}

	found := f.of(inA, inB)

	require.Equal(t, map[cases.Place][]cases.WorkloadExposure{
		inA: {decided("batch", configv1alpha1.SSVCExposureSmall, []string{ownNamespaceOnly}, nil)},
		inB: {decidedIn(clusterB, "batch", configv1alpha1.SSVCExposureUnknown, nil, []string{exposureInput})},
	}, found)
}

// A playbook without exposure rules decides nothing: every workload is Unknown.
func TestAPlaybookWithoutExposureRulesHasEveryWorkloadUnknown(t *testing.T) {
	pe := sourcePlaybook(t)
	pe.Steps = nil
	f := newCaseFixture(t, pe)
	digest := digestOf(44)
	f.runs(digest, "batch")
	f.reachedIn("batch", "Namespace")

	found := f.of(cases.Place{Digest: digest, Cluster: clusterA})

	require.Equal(t, []cases.WorkloadExposure{decided("batch", configv1alpha1.SSVCExposureUnknown, nil, nil)},
		found[cases.Place{Digest: digest, Cluster: clusterA}])
	require.Len(t, f.recorded, 1)
	require.Empty(t, f.recorded[0].notEvaluated)
}

// The cases record, under the manifest's sheet of the playbook, the workloads that each rule couldn't be evaluated for:
// each workload once, also one that runs the manifest under two digests, and none for an optional input that is
// missing.
func TestTheCountsReachTheRecorder(t *testing.T) {
	pe := sourcePlaybook(t)
	pe.Steps = append(pe.Steps, exposureRule(t, "runtime-seen", "runtime.data.seen",
		configv1alpha1.SSVCExposureOpen, "runtime"))
	pe.Types["runtime"] = "com.example.runtime.v1alpha1"
	f := newCaseFixture(t, pe)
	index := digestOf(45)
	f.runs(manifest, "batch", "gone")
	f.runs(index, "batch")
	f.reachedIn("batch", "Namespace")

	found := f.of(cases.Place{Digest: manifest, Cluster: clusterA}, cases.Place{Digest: index, Cluster: clusterA})

	require.Len(t, found, 2)
	require.Equal(t, []recorded{{manifest: manifest, playbook: playbook, notEvaluated: map[string]int{
		"published-or-unchecked": 1, exposedNotPublished: 1, reachableInCluster: 0, ownNamespaceOnly: 0,
		"runtime-seen": 2,
	}}}, f.recorded, "gone's exposure is optional, and missing; gone's and batch's runtime is required")
}

// A source that answers about an address that two clusters name speaks of no cluster's network, so the rules get no
// answer for it: the workload stays Unknown, where one cluster naming the address, as the control shows, has the
// source's Internal answer count.
func TestAnAmbiguousAddressGivesTheRulesNoAnswer(t *testing.T) {
	f := newCaseFixture(t, sourcePlaybook(t))
	digest := digestOf(49)
	f.runs(digest, "shop")
	putIn(t, f.store, networkReach, clusterA, exposureEvent(t, workload(clusterA, "shop"), []string{shopAddress}))
	f.answers(shopAddress, internal, time.Now())
	place := cases.Place{Digest: digest, Cluster: clusterA}
	require.Equal(t, configv1alpha1.SSVCExposureControlled, f.of(place)[place][0].Exposure, "control: named once")

	putIn(t, f.store, networkReach, clusterB, exposureEvent(t, workload(clusterB, "shop"), []string{shopAddress}))

	require.Eventually(t, func() bool { return len(f.view.Ambiguous()) == 1 }, wait, poll)
	require.Equal(t, []cases.WorkloadExposure{decided("shop", configv1alpha1.SSVCExposureUnknown, nil,
		[]string{dmzInput})}, f.of(place)[place])
}
