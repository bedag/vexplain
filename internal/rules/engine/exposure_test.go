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

package engine_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/rules/engine"
)

// These tests cover exposure rules, which decide how far a workload can be reached, as SSVC's system exposure, where
// finding rules decide a finding's status (design of entry points, section 5.6). A workload rated Controlled while
// the internet reaches it is the error to avoid, so most of the cases below are about a rule that can't be evaluated,
// and must keep a lower rule from deciding.

// The values of exposure.
const (
	exposureOpen       = configv1alpha1.SSVCExposureOpen
	exposureControlled = configv1alpha1.SSVCExposureControlled
	exposureSmall      = configv1alpha1.SSVCExposureSmall
	exposureUnknown    = configv1alpha1.SSVCExposureUnknown
)

// The inputs of the exposure rules of design 5.6, their types, and where their evidence comes from: the workload's
// exposure, from network-reach on a spoke, and the answers of a source about the workload's entry points, here the
// example type of a DMZ's publications.
const (
	exposureInput     = "exposure"
	exposureType      = "ch.bedag.vexplain.exposure.v1alpha1"
	networkReachEvent = "/clusters/cluster-a/collectors/network-reach"
	dmzInput          = "dmz"
	dmzType           = "ch.example.dmz.publication.v1alpha1"
	dmzEvent          = "/collectors/dmz"
)

// The rules of design 5.6: vexplain's three, and a source's two.
const (
	exposedOutsideCluster = "exposed-outside-cluster"
	reachableInCluster    = "reachable-in-cluster"
	ownNamespaceOnly      = "own-namespace-only"
	publishedOrUnchecked  = "published-or-unchecked"
	exposedNotPublished   = "exposed-not-published"
)

// The values of an exposure's internal reach, and of a source's answer.
const (
	reachNamespace    = "Namespace"
	reachPeers        = "Peers"
	reachNamespaces   = "Namespaces"
	reachCluster      = "Cluster"
	publishedInternet = "Internet"
	publishedInternal = "Internal"
	publishedNone     = "None"
)

// Names that several tests of exposure share.
const (
	alwaysSmall    = "always-small"
	failingName    = "failing"
	removedStep    = "removed"
	otherInput     = "other"
	publishedToKey = "publishedTo"
	readsExposure  = "reads-exposure"
	readsDMZ       = "reads-dmz"
	// exposureOnly starts the refusal of an exposure rule that has more than a condition, inputs and an exposure.
	exposureOnly = "an exposure rule has no"
)

// The subjects of the entry points of design 5.1's workload: a host, and an address with its port.
const (
	shopHost    = "host/shop.app.example"
	shopAddress = "address/192.0.2.10:443"
)

// Exposure records, as the JSON of network-reach has them.
const (
	// exposedShop is design 5.1's workload: exposed through an Ingress's host and a load balancer's address, and
	// reachable across the cluster. Like every record, it lists unchecked although it is empty.
	exposedShop = `{
  "external": {
    "exposed": true,
    "entryPoints": [
      {"addresses": ["shop.app.example"], "port": 443, "protocol": "TCP",
       "objectRef": {"apiGroup": "networking.k8s.io", "kind": "Ingress", "namespace": "team-a", "name": "shop"},
       "subjects": ["host/shop.app.example"]},
      {"addresses": ["192.0.2.10"], "port": 443, "protocol": "TCP",
       "objectRef": {"apiGroup": "", "kind": "Service", "namespace": "team-a", "name": "shop-lb"},
       "subjects": ["address/192.0.2.10:443"]}
    ],
    "unchecked": []
  },
  "internalReach": "Cluster",
  "indirect": false
}`
	// hostNetworkOnly is a workload whose pods run on their nodes' network, which has no entry point to ask about.
	hostNetworkOnly = `{"external": {"exposed": true, "entryPoints": [], "unchecked": ["HostNetwork"]},
		"internalReach": "Cluster", "indirect": false}`
	// clusterWide is a workload that isn't exposed, and that the whole cluster reaches.
	clusterWide = `{"external": {"exposed": false, "entryPoints": [], "unchecked": []}, "internalReach": "Cluster",
		"indirect": false}`
	// namespaceOnly is a workload that isn't exposed, and that only its own namespace reaches.
	namespaceOnly = `{"external": {"exposed": false, "entryPoints": [], "unchecked": []}, "internalReach": "Namespace",
		"indirect": false}`
)

// ---- fixtures ----

// exposureRule returns a rule named name, which concludes exposure for a workload where condition holds, with
// inputs of the given names.
func exposureRule(name string, exposure configv1alpha1.SSVCExposure, condition string, inputs ...string) *configv1alpha1.Rule {
	r := &configv1alpha1.Rule{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: configv1alpha1.RuleSpec{
			Condition: condition, Outcome: &configv1alpha1.RuleOutcome{Exposure: ptr.To(exposure)},
		},
	}
	for _, in := range inputs {
		inputType := exposureType
		if in == dmzInput {
			inputType = dmzType
		}
		r.Spec.Inputs = append(r.Spec.Inputs, configv1alpha1.RuleInput{Name: in, Type: inputType})
	}
	return r
}

// defaultExposureRules are vexplain's three exposure rules, as design 5.6 writes them.
func defaultExposureRules() []*configv1alpha1.Rule {
	return []*configv1alpha1.Rule{
		exposureRule(exposedOutsideCluster, exposureOpen, "exposure.data.external.exposed", exposureInput),
		exposureRule(reachableInCluster, exposureControlled,
			"exposure.data.indirect || exposure.data.internalReach != 'Namespace'", exposureInput),
		exposureRule(ownNamespaceOnly, exposureSmall, "exposure.data.internalReach == 'Namespace'", exposureInput),
	}
}

// withSource is the pipeline of design 5.7 with a source: the source's two rules, as design 5.6 writes them, in
// place of exposed-outside-cluster.
func withSource() []*configv1alpha1.Rule {
	return append([]*configv1alpha1.Rule{
		exposureRule(publishedOrUnchecked, exposureOpen, `
    exposure.data.external.exposed && !(size(exposure.data.external.unchecked) == 0 &&
      size(exposure.data.external.entryPoints) > 0 &&
      exposure.data.external.entryPoints.all(e, e.subjects.all(s,
        dmz[s].data.publishedTo in ['Internal', 'None'])))`, exposureInput, dmzInput),
		exposureRule(exposedNotPublished, exposureControlled, `
    exposure.data.external.exposed && size(exposure.data.external.unchecked) == 0 &&
      size(exposure.data.external.entryPoints) > 0 &&
      exposure.data.external.entryPoints.all(e, e.subjects.all(s,
        dmz[s].data.publishedTo in ['Internal', 'None']))`, exposureInput, dmzInput),
	}, defaultExposureRules()[1:]...)
}

// exposureRecord supplies an exposure record as network-reach delivered it, with the data decoded from JSON as the
// hub decodes it.
func exposureRecord(t *testing.T, data string) []engine.Input {
	t.Helper()
	return []engine.Input{recordFrom(t, networkReachEvent, data)}
}

// recordFrom is an exposure record that the producer delivered.
func recordFrom(t *testing.T, producer, data string) engine.Input {
	t.Helper()
	var decoded any
	require.NoError(t, json.Unmarshal([]byte(data), &decoded))
	return engine.Input{Present: true, Data: decoded, Time: seen, Source: producer}
}

// answered supplies a source's answers about a workload's entry points, by subject, as the hub does: present when
// every subject of the workload has a fresh answer. Without answers, the map is empty, as for a workload without
// entry points.
func answered(present bool, publishedTo map[string]string) []engine.Input {
	subjects := make(map[string]engine.Input, len(publishedTo))
	for subject, to := range publishedTo {
		subjects[subject] = engine.Input{Data: map[string]any{publishedToKey: to}, Time: seen, Source: dmzEvent}
	}
	return []engine.Input{{Present: present, Subjects: subjects}}
}

// exposures runs the exposure steps for the workloads, checks what every workload's exposure must satisfy, and
// returns them in the order of the workloads.
func exposures(t *testing.T, steps []*engine.Compiled, workloads ...map[string][]engine.Input) []engine.WorkloadExposure {
	t.Helper()
	got := engine.EvaluateExposure(steps, workloads).Workloads
	require.Len(t, got, len(workloads))
	for _, w := range got {
		requireValidExposure(t, w)
	}
	return got
}

// requireValidExposure checks what every workload's exposure satisfies, whatever the rules say: it is one of the
// four values; the rules that concluded it are named, and none for Unknown, which no rule concludes; and the inputs
// that were missing and the rules that failed are named for Unknown only. Each list is sorted, each name once.
func requireValidExposure(t *testing.T, w engine.WorkloadExposure) {
	t.Helper()
	require.Contains(t, []configv1alpha1.SSVCExposure{exposureOpen, exposureUnknown, exposureControlled, exposureSmall}, w.Exposure)
	for _, names := range [][]string{w.Rules, w.Missing, w.Failed} {
		require.True(t, slices.IsSorted(names), "%v is sorted", names)
		require.Equal(t, slices.Compact(slices.Clone(names)), names, "%v names each once", names)
	}
	if w.Exposure == exposureUnknown {
		require.Empty(t, w.Rules, "no rule concludes Unknown")
		return
	}
	require.NotEmpty(t, w.Rules, "a rule concluded %s", w.Exposure)
	require.Empty(t, w.Missing, "only Unknown names what was missing")
	require.Empty(t, w.Failed, "only Unknown names the rules that failed")
}

// unknownFor is a workload that is Unknown because the inputs are missing.
func unknownFor(missing ...string) engine.WorkloadExposure {
	return engine.WorkloadExposure{Exposure: exposureUnknown, Missing: missing}
}

// unknownBy is a workload that is Unknown because the rules failed.
func unknownBy(failed ...string) engine.WorkloadExposure {
	return engine.WorkloadExposure{Exposure: exposureUnknown, Failed: failed}
}

// decidedBy is a workload whose exposure the rules concluded.
func decidedBy(exposure configv1alpha1.SSVCExposure, rules ...string) engine.WorkloadExposure {
	return engine.WorkloadExposure{Exposure: exposure, Rules: rules}
}

// ---- the rules of design 5.6 ----

func TestTheDefaultRulesDoWhatTheSpokesMappingDoes(t *testing.T) {
	requireTheSpokesMapping(t, compiled(t, defaultExposureRules()...))
}

// requireTheSpokesMapping checks that the steps give each workload the exposure that the spoke's exposureValue gives
// it (internal/spoke/exposure.go): exposed from outside is Open, reachable indirectly or from beyond its namespace is
// Controlled, and reachable from its own namespace alone is Small.
func requireTheSpokesMapping(t *testing.T, steps []*engine.Compiled) {
	t.Helper()
	tests := []struct {
		exposed, indirect bool
		reach             string
		want              configv1alpha1.SSVCExposure
	}{
		{true, false, reachNamespace, exposureOpen},
		{true, false, reachPeers, exposureOpen},
		{true, false, reachNamespaces, exposureOpen},
		{true, false, reachCluster, exposureOpen},
		{true, true, reachNamespace, exposureOpen},
		{true, true, reachPeers, exposureOpen},
		{true, true, reachNamespaces, exposureOpen},
		{true, true, reachCluster, exposureOpen},
		{false, true, reachNamespace, exposureControlled},
		{false, true, reachPeers, exposureControlled},
		{false, true, reachNamespaces, exposureControlled},
		{false, true, reachCluster, exposureControlled},
		{false, false, reachPeers, exposureControlled},
		{false, false, reachNamespaces, exposureControlled},
		{false, false, reachCluster, exposureControlled},
		{false, false, reachNamespace, exposureSmall},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("exposed %t, indirect %t, reach %s", tc.exposed, tc.indirect, tc.reach), func(t *testing.T) {
			data := fmt.Sprintf(`{"external": {"exposed": %t, "entryPoints": [], "unchecked": []}, "internalReach": %q,
				"indirect": %t}`, tc.exposed, tc.reach, tc.indirect)
			got := exposures(t, steps, map[string][]engine.Input{exposureInput: exposureRecord(t, data)})
			require.Equal(t, tc.want, got[0].Exposure)
		})
	}

	t.Run("a workload without an exposure record", func(t *testing.T) {
		// The spoke shows Unknown for it too.
		require.Equal(t, []engine.WorkloadExposure{unknownFor(exposureInput)}, exposures(t, steps, nil))
	})
}

func TestTheTableOfDesign56(t *testing.T) {
	published := map[string]string{shopHost: publishedInternet, shopAddress: publishedInternal}
	notPublished := map[string]string{shopHost: publishedInternal, shopAddress: publishedNone}
	tests := []struct {
		name     string
		workload map[string][]engine.Input
		want     engine.WorkloadExposure
	}{
		{
			"exposed, an entry point published to the internet",
			map[string][]engine.Input{exposureInput: exposureRecord(t, exposedShop), dmzInput: answered(true, published)},
			decidedBy(exposureOpen, publishedOrUnchecked),
		},
		{
			"exposed, every entry point answered and none published to the internet, reachable across the cluster",
			map[string][]engine.Input{exposureInput: exposureRecord(t, exposedShop), dmzInput: answered(true, notPublished)},
			decidedBy(exposureControlled, exposedNotPublished, reachableInCluster),
		},
		{
			// The hub marks the source's input as not present until every entry point has a fresh answer.
			"exposed, an entry point not answered yet, or its answer past its maxAge",
			map[string][]engine.Input{
				exposureInput: exposureRecord(t, exposedShop), dmzInput: answered(false, map[string]string{shopHost: publishedInternal}),
			},
			unknownFor(dmzInput),
		},
		{
			"exposed only through the host network",
			map[string][]engine.Input{exposureInput: exposureRecord(t, hostNetworkOnly), dmzInput: answered(true, nil)},
			decidedBy(exposureOpen, publishedOrUnchecked),
		},
		{
			"not exposed, reachable only in its namespace",
			map[string][]engine.Input{exposureInput: exposureRecord(t, namespaceOnly), dmzInput: answered(true, nil)},
			decidedBy(exposureSmall, ownNamespaceOnly),
		},
		{
			// Without an exposure record, the hub knows no entry points to give the source's answers for.
			"no exposure record",
			nil,
			unknownFor(dmzInput, exposureInput),
		},
	}
	steps := compiled(t, withSource()...)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, []engine.WorkloadExposure{tc.want}, exposures(t, steps, tc.workload))
		})
	}
}

// ---- the order of exposure ----

func TestTheHighestExposureWins(t *testing.T) {
	// In the order Open, Controlled, Small. Each rule's name sorts before the names of those higher, so that the name
	// can't be what decides.
	byExposure := []*configv1alpha1.Rule{
		exposureRule("c-open", exposureOpen, "true"),
		exposureRule("b-controlled", exposureControlled, "true"),
		exposureRule("a-small", exposureSmall, "true"),
	}
	for i := range byExposure {
		for j := i + 1; j < len(byExposure); j++ {
			t.Run(byExposure[i].Name+" over "+byExposure[j].Name, func(t *testing.T) {
				want := []engine.WorkloadExposure{decidedBy(*byExposure[i].Spec.Outcome.Exposure, byExposure[i].Name)}
				require.Equal(t, want, exposures(t, compiled(t, byExposure[j], byExposure[i]), nil))
				require.Equal(t, want, exposures(t, compiled(t, byExposure[i], byExposure[j]), nil))
			})
		}
	}
}

func TestUnknownOutranksControlled(t *testing.T) {
	// A rule that can't be evaluated might have concluded Open, so it counts as Unknown, whatever it concludes, and
	// a lower rule that applies can't decide. A rule that concludes Open still does.
	unevaluated := exposureRule("unevaluated", exposureSmall, "true", exposureInput)
	tests := []struct {
		rule *configv1alpha1.Rule
		want engine.WorkloadExposure
	}{
		{exposureRule("controlled", exposureControlled, "true"), unknownFor(exposureInput)},
		{exposureRule("small", exposureSmall, "true"), unknownFor(exposureInput)},
		{exposureRule("open", exposureOpen, "true"), decidedBy(exposureOpen, "open")},
	}
	for _, tc := range tests {
		t.Run(tc.rule.Name, func(t *testing.T) {
			require.Equal(t, []engine.WorkloadExposure{tc.want}, exposures(t, compiled(t, unevaluated, tc.rule), nil))
			require.Equal(t, []engine.WorkloadExposure{tc.want}, exposures(t, compiled(t, tc.rule, unevaluated), nil))
		})
	}
}

func TestNoRuleIsUnknown(t *testing.T) {
	unknown := []engine.WorkloadExposure{{Exposure: exposureUnknown}}

	t.Run("no rule applies", func(t *testing.T) {
		steps := compiled(t, exposureRule("never-open", exposureOpen, "false"), exposureRule("never-small", exposureSmall, "false"))
		require.Equal(t, unknown, exposures(t, steps, nil))
	})

	t.Run("a playbook without exposure rules", func(t *testing.T) {
		require.Equal(t, unknown, exposures(t, nil, nil))
		findingRules := compiled(t, ruleOf(settleName, notAffected, "true"), because(ruleOf(noteName, hint, "true"), "'noted'"))
		require.Equal(t, unknown, exposures(t, findingRules, nil), "a finding rule decides nothing about a workload")
	})

	t.Run("no workloads", func(t *testing.T) {
		got := engine.EvaluateExposure(compiled(t, exposureRule(ownNamespaceOnly, exposureSmall, "true")), nil)
		require.Empty(t, got.Workloads)
		require.Equal(t, map[string]int{ownNamespaceOnly: 0}, got.NotEvaluated)
	})
}

// ---- rules that can't be evaluated ----

func TestAMissingInputCountsAsUnknown(t *testing.T) {
	// The lower rule applies to every workload. The rule that reads exposure can't be evaluated where it is missing,
	// and a missing answer must never let a lower rule decide.
	reads := exposureRule(readsExposure, exposureOpen, "exposure.data.external.exposed", exposureInput)
	lower := exposureRule(alwaysSmall, exposureSmall, "true")
	steps := compiled(t, reads, lower)

	for name, inputs := range map[string]map[string][]engine.Input{
		"absent":             nil,
		"of no producer":     {exposureInput: nil},
		"not present":        {exposureInput: {{Present: false, Data: testData(0)}}},
		"under another name": {otherInput: exposureRecord(t, exposedShop)},
	} {
		t.Run(name, func(t *testing.T) {
			got := engine.EvaluateExposure(steps, []map[string][]engine.Input{inputs})
			require.Equal(t, []engine.WorkloadExposure{unknownFor(exposureInput)}, got.Workloads)
			require.Equal(t, map[string]int{readsExposure: 1, alwaysSmall: 0}, got.NotEvaluated)
			require.Equal(t, map[string]int{readsExposure: 0, alwaysSmall: 0}, got.TimedOut)
		})
	}

	t.Run("a missing optional input counts as Unknown, and isn't counted", func(t *testing.T) {
		// Without network-reach, the playbook runs, and every workload is Unknown (design 5.7).
		got := engine.EvaluateExposure(steps, []map[string][]engine.Input{{exposureInput: {optionalMissing}}})
		require.Equal(t, []engine.WorkloadExposure{unknownFor(exposureInput)}, got.Workloads)
		require.Equal(t, map[string]int{readsExposure: 0, alwaysSmall: 0}, got.NotEvaluated)
	})

	t.Run("a required input that is missing beside it counts", func(t *testing.T) {
		both := exposureRule("reads-both", exposureOpen, "true", exposureInput, dmzInput)
		got := engine.EvaluateExposure(compiled(t, both), []map[string][]engine.Input{{exposureInput: {optionalMissing}}})
		require.Equal(t, []engine.WorkloadExposure{unknownFor(dmzInput, exposureInput)}, got.Workloads)
		require.Equal(t, map[string]int{"reads-both": 1}, got.NotEvaluated)
	})

	t.Run("the inputs are named once", func(t *testing.T) {
		twice := exposureRule("reads-it-too", exposureControlled, "true", exposureInput)
		require.Equal(t, []engine.WorkloadExposure{unknownFor(exposureInput)}, exposures(t, compiled(t, reads, twice, lower), nil))
	})
}

func TestAFailingRuleCountsAsUnknown(t *testing.T) {
	lower := exposureRule(alwaysSmall, exposureSmall, "true")
	tests := []struct {
		name, condition string
		items           int
	}{
		{"its CEL fails", "int(exposure.data.word) > 0", 0},
		{"its condition gives no bool when it runs", "exposure.data.flag", 0},
		// Going through the 600 items once for each of them costs more than the limit of 1,000,000.
		{"it hits the cost limit", "exposure.data.items.all(x, exposure.data.items.all(y, true))", 600},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Under load the 1-second run bound could pass first, and the cost limit would count as a time-out.
			t.Cleanup(engine.SetBounds(time.Hour, time.Hour))
			failing := exposureRule(failingName, exposureControlled, tc.condition, exposureInput)
			workload := map[string][]engine.Input{exposureInput: {{Present: true, Data: testData(tc.items), Time: seen, Source: networkReachEvent}}}

			got := engine.EvaluateExposure(compiled(t, failing, lower), []map[string][]engine.Input{workload})

			require.Equal(t, []engine.WorkloadExposure{unknownBy(failingName)}, got.Workloads)
			require.Equal(t, map[string]int{failingName: 1, alwaysSmall: 0}, got.NotEvaluated)
			require.Equal(t, map[string]int{failingName: 0, alwaysSmall: 0}, got.TimedOut)
		})
	}

	t.Run("only for the workload that it fails for", func(t *testing.T) {
		failing := exposureRule(failingName, exposureControlled, "exposure.data.external.exposed", exposureInput)
		got := engine.EvaluateExposure(compiled(t, failing, lower), []map[string][]engine.Input{
			{exposureInput: {from(networkReachEvent)}},
			{exposureInput: exposureRecord(t, exposedShop)},
		})
		require.Equal(t, []engine.WorkloadExposure{unknownBy(failingName), decidedBy(exposureControlled, failingName)}, got.Workloads)
		require.Equal(t, map[string]int{failingName: 1, alwaysSmall: 0}, got.NotEvaluated)
	})

	t.Run("a step that is unavailable", func(t *testing.T) {
		// Its rule is missing or not Ready, and might be an exposure rule that concludes Open.
		steps := append(compiled(t, lower), engine.Unavailable(removedStep, "gone"))
		got := engine.EvaluateExposure(steps, []map[string][]engine.Input{nil, nil})
		require.Equal(t, []engine.WorkloadExposure{unknownBy(removedStep), unknownBy(removedStep)}, got.Workloads)
		require.Equal(t, map[string]int{removedStep: 2, alwaysSmall: 0}, got.NotEvaluated)
	})
}

func TestAnExposedWorkloadWithAMissingAnswerIsUnknown(t *testing.T) {
	// The source answered one of the workload's two entry points, as Internal. Had it answered the other as Internal
	// too, the workload would be Controlled, as reachable-in-cluster concludes.
	steps := compiled(t, withSource()...)
	got := exposures(t, steps, map[string][]engine.Input{
		exposureInput: exposureRecord(t, exposedShop),
		dmzInput:      answered(false, map[string]string{shopHost: publishedInternal}),
	})
	require.Equal(t, []engine.WorkloadExposure{unknownFor(dmzInput)}, got)

	t.Run("a map that lacks the answer fails the source's rules", func(t *testing.T) {
		// Even where the input is present by mistake, neither source rule can read the answer that isn't there.
		got := exposures(t, steps, map[string][]engine.Input{
			exposureInput: exposureRecord(t, exposedShop),
			dmzInput:      answered(true, map[string]string{shopHost: publishedInternal}),
		})
		require.Equal(t, []engine.WorkloadExposure{unknownBy(exposedNotPublished, publishedOrUnchecked)}, got)
	})

	t.Run("two sources, of which one publishes an entry point", func(t *testing.T) {
		// Each source's answers are evaluated apart, so one source can't lower what the other publishes.
		got := exposures(t, steps, map[string][]engine.Input{
			exposureInput: exposureRecord(t, exposedShop),
			dmzInput: append(answered(true, map[string]string{shopHost: publishedInternal, shopAddress: publishedNone}),
				answered(true, map[string]string{shopHost: publishedInternal, shopAddress: publishedInternet})...),
		})
		require.Equal(t, []engine.WorkloadExposure{decidedBy(exposureOpen, publishedOrUnchecked)}, got)
	})
}

// ---- the inputs of exposure rules ----

func TestAWorkloadWithoutEntryPointsHasAnEmptyMap(t *testing.T) {
	// A workload that isn't exposed has no entry points, so the source's input is an empty map, and present: the
	// source's rules can be evaluated, and neither applies.
	noEntryPoints := map[string][]engine.Input{
		exposureInput: exposureRecord(t, namespaceOnly),
		dmzInput:      answered(true, nil),
	}
	require.Equal(t, []engine.WorkloadExposure{decidedBy(exposureSmall, ownNamespaceOnly)},
		exposures(t, compiled(t, withSource()...), noEntryPoints))

	t.Run("a rule sees the empty map", func(t *testing.T) {
		empty := exposureRule("no-entry-points", exposureControlled, "size(dmz) == 0", dmzInput)
		require.Equal(t, []engine.WorkloadExposure{decidedBy(exposureControlled, "no-entry-points")},
			exposures(t, compiled(t, empty), noEntryPoints))
	})
}

func TestEachSubjectHasTheKeysOfAnInput(t *testing.T) {
	// The input's variable is a map from each subject to its record, with the keys that an input has: its data, its
	// coverage, its time and its source.
	record := exposureRule("record", exposureSmall, `size(dmz) == 1 && cel.bind(a, dmz['host/shop.app.example'],
		a.data.publishedTo == 'None' && a.coverage == 100 && a.time == timestamp('2026-10-31T12:00:00Z') &&
		a.source == '/collectors/dmz')`, dmzInput)
	answer := engine.Input{Data: map[string]any{publishedToKey: publishedNone}, Coverage: ptr.To(int32(100)), Time: seen, Source: dmzEvent}

	got := exposures(t, compiled(t, record), map[string][]engine.Input{
		dmzInput: {{Present: true, Data: map[string]any{publishedToKey: publishedInternet}, Subjects: map[string]engine.Input{shopHost: answer}}},
	})

	require.Equal(t, []engine.WorkloadExposure{decidedBy(exposureSmall, "record")}, got)
}

// ---- the names of the rules ----

func TestTheRulesThatConcludedTheWinningValueAreNamed(t *testing.T) {
	steps := compiled(t,
		exposureRule("c-controlled", exposureControlled, "true"),
		exposureRule("a-controlled", exposureControlled, "true"),
		exposureRule("b-controlled", exposureControlled, "true"),
		exposureRule("not-applying", exposureControlled, "false"),
		exposureRule("lower", exposureSmall, "true"),
	)
	require.Equal(t, []engine.WorkloadExposure{decidedBy(exposureControlled, "a-controlled", "b-controlled", "c-controlled")},
		exposures(t, steps, nil))

	t.Run("a rule that two steps run is named once", func(t *testing.T) {
		twice := exposureRule("twice", exposureOpen, "true")
		require.Equal(t, []engine.WorkloadExposure{decidedBy(exposureOpen, "twice")}, exposures(t, compiled(t, twice, twice), nil))
	})

	t.Run("in whichever combination of producers they concluded it", func(t *testing.T) {
		steps := compiled(t,
			exposureRule("from-a", exposureControlled, "exposure.source == 'a'", exposureInput),
			exposureRule("from-b", exposureControlled, "exposure.source == 'b'", exposureInput),
		)
		got := exposures(t, steps, map[string][]engine.Input{exposureInput: {from("b"), from("a")}})
		require.Equal(t, []engine.WorkloadExposure{decidedBy(exposureControlled, "from-a", "from-b")}, got)
	})
}

// ---- several producers ----

func TestEachProducerIsEvaluatedApart(t *testing.T) {
	// Two exposure collectors report on one workload, as the spoke weighs them today: the highest exposure wins.
	steps := compiled(t, defaultExposureRules()...)
	tests := []struct {
		name string
		a, b string
		want engine.WorkloadExposure
	}{
		{"one says Small, the other Open", namespaceOnly, exposedShop, decidedBy(exposureOpen, exposedOutsideCluster)},
		{"one says Small, the other Controlled", namespaceOnly, clusterWide, decidedBy(exposureControlled, reachableInCluster)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ab := map[string][]engine.Input{exposureInput: {recordFrom(t, "a", tc.a), recordFrom(t, "b", tc.b)}}
			ba := map[string][]engine.Input{exposureInput: {recordFrom(t, "b", tc.b), recordFrom(t, "a", tc.a)}}
			require.Equal(t, []engine.WorkloadExposure{tc.want, tc.want}, exposures(t, steps, ab, ba),
				"the order of the producers changes nothing")
		})
	}

	t.Run("a combination that no rule applies to", func(t *testing.T) {
		// It counts as Unknown, as a workload that no rule applies to does, which outranks the Small of the other.
		fromA := exposureRule("from-a", exposureSmall, "exposure.source == 'a'", exposureInput)
		got := exposures(t, compiled(t, fromA), map[string][]engine.Input{exposureInput: {from("a"), from("b")}})
		require.Equal(t, []engine.WorkloadExposure{{Exposure: exposureUnknown}}, got)
	})

	t.Run("a producer whose evidence is missing", func(t *testing.T) {
		// Its combination counts as Unknown, which outranks the Small of the other.
		inputs := map[string][]engine.Input{exposureInput: {recordFrom(t, "a", namespaceOnly), {Source: "b"}}}
		got := engine.EvaluateExposure(steps, []map[string][]engine.Input{inputs})
		require.Equal(t, []engine.WorkloadExposure{unknownFor(exposureInput)}, got.Workloads)
		require.Equal(t, map[string]int{exposedOutsideCluster: 1, reachableInCluster: 1, ownNamespaceOnly: 1}, got.NotEvaluated)
	})
}

func TestMoreThanFourCombinationsIsUnknown(t *testing.T) {
	steps := func(t *testing.T) []*engine.Compiled {
		return compiled(t,
			exposureRule(readsExposure, exposureSmall, "true", exposureInput), exposureRule(readsDMZ, exposureSmall, "true", dmzInput))
	}
	producers := func(n int) []engine.Input {
		inputs := make([]engine.Input, 0, n)
		for i := range n {
			inputs = append(inputs, from(string(rune('a'+i))))
		}
		return inputs
	}

	for name, inputs := range map[string]map[string][]engine.Input{
		"five producers of one input":                  {exposureInput: producers(5), dmzInput: producers(1)},
		"two producers of one input, three of another": {exposureInput: producers(2), dmzInput: producers(3)},
	} {
		t.Run(name, func(t *testing.T) {
			got := engine.EvaluateExposure(steps(t), []map[string][]engine.Input{inputs, nil})
			require.Equal(t, []engine.WorkloadExposure{unknownBy(readsDMZ, readsExposure), unknownFor(dmzInput, exposureInput)},
				got.Workloads, "no rule was evaluated for the first workload")
			require.Equal(t, map[string]int{readsExposure: 2, readsDMZ: 2}, got.NotEvaluated)
		})
	}

	for name, inputs := range map[string]map[string][]engine.Input{
		"four producers of one input":                {exposureInput: producers(4), dmzInput: producers(1)},
		"two producers of each of two inputs":        {exposureInput: producers(2), dmzInput: producers(2)},
		"five producers of an input that none reads": {exposureInput: producers(1), dmzInput: producers(1), otherInput: producers(5)},
	} {
		t.Run(name+" are evaluated", func(t *testing.T) {
			got := exposures(t, steps(t), inputs)
			require.Equal(t, []engine.WorkloadExposure{decidedBy(exposureSmall, readsDMZ, readsExposure)}, got)
		})
	}
}

// ---- bounds on time ----

func TestAWorkloadPastTheBoundIsUnknown(t *testing.T) {
	pastIt := unknownBy(exposedOutsideCluster, ownNamespaceOnly, reachableInCluster)
	for name, bounds := range map[string][2]time.Duration{
		"a run bound of 0":  {0, time.Hour},
		"a call bound of 0": {time.Hour, 0},
	} {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(engine.SetBounds(bounds[0], bounds[1]))
			workload := map[string][]engine.Input{exposureInput: exposureRecord(t, namespaceOnly)}

			got := engine.EvaluateExposure(compiled(t, defaultExposureRules()...), []map[string][]engine.Input{workload, workload})

			require.Equal(t, []engine.WorkloadExposure{pastIt, pastIt}, got.Workloads)
			require.Equal(t, map[string]int{exposedOutsideCluster: 2, reachableInCluster: 2, ownNamespaceOnly: 2}, got.TimedOut)
			require.Equal(t, got.TimedOut, got.NotEvaluated)
		})
	}

	// slow goes through 60,000 items, which costs less than the limit but takes seconds while CEL counts the cost. CEL
	// checks the bounds as it goes through them, so the run stops at its bound instead of when it would end.
	slow := exposureRule("slow", exposureControlled, "size(exposure.data.items.filter(x, x < 0)) == 0", exposureInput)
	many := map[string][]engine.Input{exposureInput: {{Present: true, Data: testData(60_000), Time: seen, Source: networkReachEvent}}}
	few := map[string][]engine.Input{exposureInput: {from(networkReachEvent)}}

	t.Run("only the workload whose run passed its bound", func(t *testing.T) {
		const bound = 200 * time.Millisecond
		t.Cleanup(engine.SetBounds(bound, time.Hour))

		start := time.Now()
		got := engine.EvaluateExposure(compiled(t, slow), []map[string][]engine.Input{many, few})

		require.Less(t, time.Since(start), 10*bound, "the run stops at its bound")
		require.Equal(t, []engine.WorkloadExposure{unknownBy("slow"), decidedBy(exposureControlled, "slow")}, got.Workloads)
		require.Equal(t, map[string]int{"slow": 1}, got.TimedOut)
	})

	t.Run("the workloads that the call doesn't reach within its bound", func(t *testing.T) {
		const bound = 200 * time.Millisecond
		t.Cleanup(engine.SetBounds(time.Hour, bound))

		start := time.Now()
		got := engine.EvaluateExposure(compiled(t, slow), []map[string][]engine.Input{many, few, few})

		require.Less(t, time.Since(start), 10*bound, "the call stops at its bound")
		require.Equal(t, []engine.WorkloadExposure{unknownBy("slow"), unknownBy("slow"), unknownBy("slow")}, got.Workloads)
		require.Equal(t, map[string]int{"slow": 3}, got.TimedOut)
	})

	t.Run("an evaluation within the bounds", func(t *testing.T) {
		got := engine.EvaluateExposure(compiled(t, defaultExposureRules()...), []map[string][]engine.Input{
			{exposureInput: exposureRecord(t, namespaceOnly)},
		})
		require.Equal(t, map[string]int{exposedOutsideCluster: 0, reachableInCluster: 0, ownNamespaceOnly: 0}, got.TimedOut)
	})
}

// ---- what is compiled ----

func TestCompileRefusesAnExposureRuleThatReadsFinding(t *testing.T) {
	// Exposure changes urgency, never a verdict (decision 0006), so an exposure rule sees its inputs only.
	for _, condition := range []string{
		"finding.knownExploited",
		"exposure.data.external.exposed && finding.severity == 'Critical'",
	} {
		t.Run(condition, func(t *testing.T) {
			c, err := engine.Compile(exposureRule(exposedOutsideCluster, exposureOpen, condition, exposureInput))
			require.ErrorContains(t, err, "finding")
			require.Nil(t, c)
		})
	}
}

func TestCompileRefusesAnExposureRuleThatCantBeEvaluatedAsWritten(t *testing.T) {
	long := "'" + strings.Repeat("a", 4095) + "' != ''" // 4103 characters
	withOutcome := func(change func(*configv1alpha1.RuleOutcome)) *configv1alpha1.Rule {
		r := exposureRule(guardName, exposureOpen, "true")
		change(r.Spec.Outcome)
		return r
	}
	tests := []struct {
		name string
		rule *configv1alpha1.Rule
		want string
	}{
		{"an exposure that a rule can't conclude", exposureRule(guardName, exposureUnknown, "true"), string(exposureUnknown)},
		{"an empty exposure", exposureRule(guardName, "", "true"), "isn't Open, Controlled or Small"},
		{"a status as well", withOutcome(func(o *configv1alpha1.RuleOutcome) { o.Status = ptr.To(underInvestigation) }), exposureOnly},
		{"a justification as well", withOutcome(func(o *configv1alpha1.RuleOutcome) {
			o.Justification = ptr.To(componentNotPresent)
		}), exposureOnly},
		{"holdAgainst as well", withOutcome(func(o *configv1alpha1.RuleOutcome) {
			o.HoldAgainst = ptr.To(configv1alpha1.HoldAgainstRules)
		}), exposureOnly},
		{"a match", matching(exposureRule(guardName, exposureOpen, "true"), "true"), exposureOnly},
		{"a reason", because(exposureRule(guardName, exposureOpen, "true"), "'why'"), exposureOnly},
		{"a condition that gives no bool", exposureRule(guardName, exposureOpen, "'yes'"), inCondition},
		{"a condition that reads what no input names", exposureRule(guardName, exposureOpen, "dmz.data.publishedTo == 'None'"), dmzInput},
		{"a call that the bounds on time can't stop", exposureRule(guardName, exposureOpen,
			"exposure.data.items.sort()[0] == 0", exposureInput), "calls sort"},
		{"an input named finding", exposureRule(guardName, exposureOpen, "true", "finding"), "finding"},
		{"two inputs of one name", exposureRule(guardName, exposureOpen, "true", exposureInput, exposureInput), exposureInput},
		{"a condition longer than 4096 characters", exposureRule(guardName, exposureOpen, long), inCondition},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := engine.Compile(tc.rule)
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, c)
		})
	}
}

func TestACompiledRuleNamesItsRuleAndItsExposure(t *testing.T) {
	exposure := compiled(t, exposureRule(ownNamespaceOnly, exposureSmall, "exposure.data.internalReach == 'Namespace'", exposureInput))[0]
	require.Equal(t, ownNamespaceOnly, exposure.Name())
	require.Equal(t, exposureSmall, exposure.Exposure())

	finding := compiled(t, ruleOf(settleName, notAffected, "true"))[0]
	require.Equal(t, settleName, finding.Name())
	require.Empty(t, finding.Exposure(), "a finding rule concludes no exposure")

	unavailable := engine.Unavailable(removedStep, "gone")
	require.Equal(t, removedStep, unavailable.Name())
	require.Empty(t, unavailable.Exposure(), "a missing rule's exposure is unknown")
}

func TestAnExposureRuleCallsWhatAFindingRuleCalls(t *testing.T) {
	// Each function that a rule can call has been checked for what one call of it can cost, in the environment of a
	// finding rule (TestTheEnvironmentOffersOnlyVettedFunctions). An exposure rule's environment offers the same.
	require.Equal(t, engine.Functions(), engine.ExposureFunctions())
}

// ---- both kinds of rule in one pipeline ----

func TestEachEvaluationIgnoresTheOtherKindOfRule(t *testing.T) {
	// A caller can pass a playbook's whole pipeline to either. The exposure rule applies to every workload, and would
	// add a note to every finding if Evaluate ran it as a rule without a status. The finding rule that holds can't be
	// evaluated, and would make every workload Unknown if EvaluateExposure ran it.
	findingSteps := compiled(t, ruleOf(settleName, notAffected, "true"), needing(ruleOf(guardName, underInvestigation, "true"), contents))
	exposureSteps := compiled(t, exposureRule(ownNamespaceOnly, exposureSmall, "true", exposureInput))
	pipeline := slices.Concat(findingSteps, exposureSteps)
	inputs := map[string][]engine.Input{exposureInput: exposureRecord(t, namespaceOnly), contents: {from(scannerEvent)}}

	findings := engine.Evaluate(pipeline, inputs, twoFindings())
	require.Equal(t, []verdict{{Status: underInvestigation, Rule: guardName}, {Status: underInvestigation, Rule: guardName}},
		verdictsOf(t, findings.Findings))
	require.Equal(t, map[string]int{settleName: 0, guardName: 0}, findings.NotEvaluated)

	workloads := engine.EvaluateExposure(pipeline, []map[string][]engine.Input{{exposureInput: exposureRecord(t, namespaceOnly)}})
	require.Equal(t, []engine.WorkloadExposure{decidedBy(exposureSmall, ownNamespaceOnly)}, workloads.Workloads)
	require.Equal(t, map[string]int{ownNamespaceOnly: 0}, workloads.NotEvaluated)

	require.Equal(t, slices.Concat(findingSteps, exposureSteps), pipeline, "neither changes the steps")
}

func TestTheStepsAndProducersInAnyOrderGiveTheSameExposures(t *testing.T) {
	steps := compiled(t, append(withSource(),
		exposureRule("fails-if-indirect", exposureSmall, "exposure.data.indirect && int(exposure.data.internalReach) > 0", exposureInput),
	)...)
	published := map[string]string{shopHost: publishedInternet, shopAddress: publishedInternal}
	notPublished := map[string]string{shopHost: publishedInternal, shopAddress: publishedNone}
	workloads := []map[string][]engine.Input{
		{exposureInput: exposureRecord(t, exposedShop), dmzInput: answered(true, notPublished)},
		{exposureInput: exposureRecord(t, exposedShop), dmzInput: append(answered(true, notPublished), answered(true, published)...)},
		{exposureInput: {recordFrom(t, "a", namespaceOnly), recordFrom(t, "b", clusterWide)}, dmzInput: answered(true, nil)},
		{exposureInput: exposureRecord(t, `{"external": {"exposed": false, "entryPoints": [], "unchecked": []},
			"internalReach": "Peers", "indirect": true}`),
			dmzInput: answered(true, nil)},
		{exposureInput: exposureRecord(t, exposedShop)},
		{exposureInput: exposureRecord(t, namespaceOnly), dmzInput: answered(true, nil)},
	}

	want := engine.EvaluateExposure(steps, workloads)
	values := make([]configv1alpha1.SSVCExposure, 0, len(want.Workloads))
	for _, w := range want.Workloads {
		values = append(values, w.Exposure)
	}
	require.Equal(t, []configv1alpha1.SSVCExposure{
		exposureControlled, exposureOpen, exposureControlled, exposureUnknown, exposureUnknown, exposureSmall,
	}, values, "the fixture has every value")

	rng := rand.New(rand.NewPCG(5, 8))
	for range 50 {
		shuffled := slices.Clone(steps)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		reordered := make([]map[string][]engine.Input, len(workloads))
		for i, w := range workloads {
			reordered[i] = map[string][]engine.Input{}
			for name, producers := range w {
				reordered[i][name] = slices.Clone(producers)
				rng.Shuffle(len(producers), func(a, b int) {
					reordered[i][name][a], reordered[i][name][b] = reordered[i][name][b], reordered[i][name][a]
				})
			}
		}
		require.Equal(t, want, engine.EvaluateExposure(shuffled, reordered))
	}
}
