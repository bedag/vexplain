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

package hub

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/conditions"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/rules/engine"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// eventActionReconcile is the action of the Warning event of a playbook that isn't Ready: what the controller was
// doing when it found the fault.
const eventActionReconcile = "Reconcile"

// The reasons that a step of a pipeline can't be evaluated at all, which each finding that the step
// holds open records.
const (
	reasonRuleMissing  = "the rule is missing"
	reasonRuleNotReady = "the rule isn't Ready"
)

// playbookCheck is what a check of a playbook against the Collectors and the Rules found: whether it can
// run, which producers of each type count, and, when it can't run, what the assessor holds back. The
// playbook controller writes the Ready condition from it, and the assessor evaluates by it, so that the
// two never disagree.
type playbookCheck struct {
	// What is at fault, each sorted: the selectors of the match that don't parse, the Collectors that an entry
	// that the playbook needs pins and that don't exist, the entries that lack a producer, the rules that are
	// missing or not Ready, and the inputs that a rule needs and the playbook doesn't supply.
	invalid, missingCollectors, notProduced, missingRules, notReadyRules, missingInputs []string
	// steps is the pipeline's finding rules: each compiled, or, for a rule that is missing or not Ready, a step
	// that can't be evaluated and might hold, so that it keeps every finding from NotAffected and Fixed.
	steps []*engine.Compiled
	// exposureSteps is the pipeline's exposure rules, in the same way, which the cases evaluate for the workloads
	// that run an image: a step that can't be evaluated counts as Unknown there. A rule is of its kind by what its
	// outcome concludes, also while it isn't Ready, and a missing rule, whose kind nothing says, is in both lists.
	exposureSteps []*engine.Compiled
	// basis says what the finding steps, the playbook and the producers of its evidence are, so that a change of
	// any shows. No sheet rests on an exposure rule.
	basis string
	// absent holds the names of the evidence that the rules don't get from any producer: a rule takes an
	// input of the name with another type.
	absent map[string]bool
	// workloadEvidence holds the names of the evidence that only exposure rules read, and that no findings producer
	// that takes part consumes. It is about workloads and their entry points, never about a manifest: the assessor
	// neither asks for it about an image nor reads it for a sheet.
	workloadEvidence map[string]bool
	// producers holds, by the name of each piece of evidence, the Collectors whose evidence of its type
	// the rules read, sorted by name.
	producers map[string][]producer
	// remote holds the collectors that each Spoke lists, by the name of its cluster, as Collectors with the
	// capabilities that the Spoke mirrors: a workload's evidence comes from the collectors of its own cluster
	// (design of remote spokes 5.7).
	remote map[string][]configv1alpha1.Collector
	// findings holds the findings producers that take part in the playbook, sorted by name, as takingPart
	// finds them.
	findings []matching
}

// matching is a findings producer that takes part in a playbook, and the names of the playbook's evidence
// that its match consumes, sorted: the piece of each type that it consumes, as a playbook names each type
// once.
type matching struct {
	collector string
	evidence  []string
}

// producer is a Collector whose evidence of a type the rules read: one that the entry pins, or else one
// whose capabilities say that it produces the type, whatever its health. Its health gates what is asked
// of it, and neither what it delivered, which stays evidence while the Collector is there (design 5.9),
// nor whether the playbook can run.
type producer struct {
	collector string
	// absent says that the rules don't get the evidence of the Collector: the entry pins it, and it
	// doesn't exist, or its capabilities don't list the type.
	absent bool
}

// ready reports whether the playbook can run: its match parses, every entry that it needs has its producers,
// and every rule exists, is Ready and gets its inputs.
func (c *playbookCheck) ready() bool {
	return len(c.invalid) == 0 && len(c.missingCollectors) == 0 && len(c.notProduced) == 0 &&
		len(c.missingRules) == 0 && len(c.notReadyRules) == 0 && len(c.missingInputs) == 0
}

// condition returns the Ready condition of the playbook, at its generation. Of the faults, the one
// first in this order decides the reason: Invalid, CollectorMissing, TypeNotProduced, RuleMissing,
// RuleNotReady and InputMissing.
func (c *playbookCheck) condition(generation int64) metav1.Condition {
	ready := metav1.Condition{Type: configv1alpha1.ConditionReady, Status: metav1.ConditionFalse, ObservedGeneration: generation}
	switch {
	case len(c.invalid) > 0:
		ready.Reason = configv1alpha1.ReasonInvalid
		ready.Message = "The playbook is invalid: " + strings.Join(c.invalid, "; ") + "."
	case len(c.missingCollectors) > 0:
		ready.Reason = configv1alpha1.ReasonCollectorMissing
		ready.Message = "Collectors that the playbook pins don't exist: " + quoted(c.missingCollectors) + "."
	case len(c.notProduced) > 0:
		ready.Reason = configv1alpha1.ReasonTypeNotProduced
		ready.Message = "Types that the playbook needs lack a producer: " + strings.Join(c.notProduced, "; ") + "."
	case len(c.missingRules) > 0:
		ready.Reason = configv1alpha1.ReasonRuleMissing
		ready.Message = "Rules that the pipeline names don't exist: " + quoted(c.missingRules) + "."
	case len(c.notReadyRules) > 0:
		ready.Reason = configv1alpha1.ReasonRuleNotReady
		ready.Message = "Rules that the pipeline names aren't Ready: " + quoted(c.notReadyRules) + "."
	case len(c.missingInputs) > 0:
		ready.Reason = configv1alpha1.ReasonInputMissing
		ready.Message = "Rules need inputs that the playbook's evidence doesn't supply: " + strings.Join(c.missingInputs, "; ") + "."
	default:
		ready.Status, ready.Reason = metav1.ConditionTrue, configv1alpha1.ReasonValid
		ready.Message = "Each type that the playbook needs has its producers, and every rule of its pipeline is Ready and gets " +
			"its inputs."
	}
	ready.Message = message(ready.Message)
	return ready
}

// quoted returns the names, each quoted, joined with commas.
func quoted(names []string) string {
	q := make([]string, len(names))
	for i, name := range names {
		q[i] = strconv.Quote(name)
	}
	return strings.Join(q, ", ")
}

// checkPlaybook checks playbook, its match, and what it names against the Collectors, the Spokes and the Rules
// that reader holds. Other playbooks play no part: several run at once, also over subjects of one type, and
// each keeps results of its own (decision 0043). A read that fails returns its error, and never a fault.
func checkPlaybook(ctx context.Context, reader client.Reader, rules *Rules, playbook *configv1alpha1.Playbook) (*playbookCheck,
	error) {
	c := &playbookCheck{absent: map[string]bool{}, producers: map[string][]producer{},
		remote: map[string][]configv1alpha1.Collector{}}
	c.checkMatch(playbook)
	c.checkAgent(playbook)
	var collectors configv1alpha1.CollectorList
	if err := reader.List(ctx, &collectors); err != nil {
		return nil, fmt.Errorf("list the Collectors: %w", err)
	}
	var spokes configv1alpha1.SpokeList
	if err := reader.List(ctx, &spokes); err != nil {
		return nil, fmt.Errorf("list the Spokes: %w", err)
	}
	for i := range spokes.Items {
		c.remote[spokes.Items[i].Name] = collectorsOf(&spokes.Items[i])
	}
	// What the findings producers that take part consume is about the manifest. So they come first, then the
	// pipeline, which finds the evidence about workloads, and then the producers, of which those of a workload's
	// evidence count in every cluster.
	c.findings = takingPart(collectors.Items, producersOf(collectors.Items, findingsTypeOf(playbook),
		playbook.Spec.Findings.Collectors), playbook.Spec.Evidence)
	if err := c.checkPipeline(ctx, reader, rules, playbook); err != nil {
		return nil, err
	}
	c.checkProducers(collectors.Items, playbook)
	findings := make([]string, len(c.findings))
	for i, m := range c.findings {
		findings[i] = m.collector + ">" + strings.Join(m.evidence, "+")
	}
	c.basis = fmt.Sprintf("%s/%s/%d|%s|findings:%s", playbook.Name, playbook.UID, playbook.Generation, c.basis,
		strings.Join(findings, ","))
	return c, nil
}

// checkMatch notes each selector of the playbook's match that doesn't parse, by its field.
func (c *playbookCheck) checkMatch(playbook *configv1alpha1.Playbook) {
	match := playbook.Spec.Match
	if match == nil {
		return
	}
	for field, selector := range map[string]*metav1.LabelSelector{"clusters": match.Clusters, "namespaces": match.Namespaces} {
		if _, err := metav1.LabelSelectorAsSelector(selector); err != nil {
			c.invalid = append(c.invalid, fmt.Sprintf("spec.match.%s: %v", field, err))
		}
	}
	slices.Sort(c.invalid)
}

// checkAgent notes each condition of the agent's matchConditions that doesn't compile, by its name.
func (c *playbookCheck) checkAgent(playbook *configv1alpha1.Playbook) {
	if playbook.Spec.Agent == nil {
		return
	}
	for _, cond := range playbook.Spec.Agent.MatchConditions {
		if _, err := engine.CompileConditions([]engine.Condition{{Name: cond.Name, Expression: cond.Expression}}); err != nil {
			c.invalid = append(c.invalid, fmt.Sprintf("spec.agent.matchConditions %q: %v", cond.Name, err))
		}
	}
	slices.Sort(c.invalid)
}

// judges reports whether the playbook judges the images in presence in a cluster with the labels: its subjects
// are presence, whatever Collector delivers them, and the cluster selector of its match selects the labels
// (decision 0043). An absent cluster selector selects every cluster, and one that doesn't parse none: the
// playbook isn't Ready then, and says why. Whether it is Ready decides only what it asks for, as Assessor says.
func judges(playbook *configv1alpha1.Playbook, clusterLabels map[string]string) bool {
	if playbook.Spec.Subjects.Type != sdkevidence.TypePresence {
		return false
	}
	if playbook.Spec.Match == nil || playbook.Spec.Match.Clusters == nil {
		return true
	}
	selector, err := metav1.LabelSelectorAsSelector(playbook.Spec.Match.Clusters)
	return err == nil && selector.Matches(labels.Set(clusterLabels))
}

// judgesIn reports whether the playbook judges the images in presence that the clusters run: whether judges says so of
// one of them, by its labels in clusterLabels, which holds each cluster's labels by its name (design of remote spokes
// 5.8). A cluster that clusterLabels doesn't name has no labels.
func judgesIn(playbook *configv1alpha1.Playbook, clusterLabels map[string]map[string]string, clusters []string) bool {
	return slices.ContainsFunc(clusters, func(cluster string) bool { return judges(playbook, clusterLabels[cluster]) })
}

// matchingClusters returns the clusters of clusterLabels in which the playbook judges the images in presence, sorted:
// the clusters whose workloads its cases count. It is nil, which counts every cluster's, when the playbook's match has
// no cluster selector.
func matchingClusters(playbook *configv1alpha1.Playbook, clusterLabels map[string]map[string]string) []string {
	if playbook.Spec.Match == nil || playbook.Spec.Match.Clusters == nil {
		return nil
	}
	matching := []string{}
	for _, cluster := range slices.Sorted(maps.Keys(clusterLabels)) {
		if judges(playbook, clusterLabels[cluster]) {
			matching = append(matching, cluster)
		}
	}
	return matching
}

// checkProducers notes, of each entry that the playbook needs, what keeps it from its producers, as the
// capabilities that the Collectors last recorded say: no Collector that produces the type and isn't being
// deleted, or a pinned Collector that doesn't exist or doesn't declare the type. The playbook needs its
// subjects, its findings from a findings producer that takes part, and each piece of evidence that is
// required or that such a producer consumes: its match needs that evidence, whatever the playbook's
// requirement says. Other optional evidence needs no producer. A producer's health plays no part (decision
// 0043): it decides only whether a spoke or the findings collector asks the producer for work, so that the
// playbook goes on with the stored evidence and the other producers while one fails. It records the
// producers whose evidence the rules read, among the local Collectors.
//
// The producers of the findings and of the evidence about images are the local Collectors, since the hub matches
// and scans every image itself (decision 0066). The subjects and the evidence about workloads come from the
// collectors of each cluster, which stream them, so that a hub that runs no presence of its own judges the spokes'
// (design of remote spokes 5.1, 5.5 and 5.7): their producers count in every cluster, the local Collectors and those
// that each Spoke lists, and a pin matches the collector of its name in any of them.
func (c *playbookCheck) checkProducers(local []configv1alpha1.Collector, playbook *configv1alpha1.Playbook) {
	everywhere := slices.Clone(local)
	for _, listed := range c.remote {
		everywhere = append(everywhere, listed...)
	}
	// need notes what keeps the entry of the label, of the type, from its producers among the collectors, and
	// reports whether anything does. Of the collectors of a pin's name, one that produces the type will do.
	need := func(label, evidenceType string, pins []string, collectors []configv1alpha1.Collector) bool {
		faults := len(c.missingCollectors) + len(c.notProduced)
		if len(pins) == 0 && len(producersOf(collectors, evidenceType, nil)) == 0 {
			c.notProduced = append(c.notProduced, fmt.Sprintf("no Collector produces %s for the %s", evidenceType, label))
		}
		for _, name := range pins {
			named := slices.DeleteFunc(slices.Clone(collectors), func(o configv1alpha1.Collector) bool { return o.Name != name })
			switch {
			case len(named) == 0:
				c.missingCollectors = append(c.missingCollectors, name)
			case slices.ContainsFunc(named, func(o configv1alpha1.Collector) bool { return produces(&o, evidenceType) }):
			case slices.ContainsFunc(named, func(o configv1alpha1.Collector) bool { return o.Status.Capabilities == nil }):
				c.notProduced = append(c.notProduced, fmt.Sprintf("%q, pinned for the %s, has recorded no capabilities yet",
					name, label))
			default:
				c.notProduced = append(c.notProduced, fmt.Sprintf("%q, pinned for the %s, produces no %s", name, label, evidenceType))
			}
		}
		return len(c.missingCollectors)+len(c.notProduced) > faults
	}

	need("subjects", playbook.Spec.Subjects.Type, playbook.Spec.Subjects.Collectors, everywhere)
	findingsType := findingsTypeOf(playbook)
	if !need("findings", findingsType, playbook.Spec.Findings.Collectors, local) && len(c.findings) == 0 {
		c.notProduced = append(c.notProduced, fmt.Sprintf("no Collector that produces %s for the findings consumes a "+
			"type of the playbook's evidence", findingsType))
	}
	consumed := c.consumed()
	for _, e := range playbook.Spec.Evidence {
		if !optional(e) || consumed[e.Name] {
			candidates := local
			if c.workloadEvidence[e.Name] {
				candidates = everywhere
			}
			need(fmt.Sprintf("evidence %q", e.Name), e.Type, e.Collectors, candidates)
		}
		c.producers[e.Name] = producersOf(local, e.Type, e.Collectors)
	}
	slices.Sort(c.missingCollectors)
	c.missingCollectors = slices.Compact(c.missingCollectors)
	slices.Sort(c.notProduced)
	c.notProduced = slices.Compact(c.notProduced)
}

// collectorsOf returns the collectors that the Spoke lists, as Collectors with the capabilities that it mirrors, so
// that a remote cluster's producers are found as the local ones are.
func collectorsOf(spoke *configv1alpha1.Spoke) []configv1alpha1.Collector {
	collectors := make([]configv1alpha1.Collector, len(spoke.Status.Collectors))
	for i, listed := range spoke.Status.Collectors {
		collectors[i] = configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: listed.Name},
			Status: configv1alpha1.CollectorStatus{Capabilities: listed.Capabilities}}
	}
	return collectors
}

// consumed returns the names of the evidence that the findings producers that take part consume.
func (c *playbookCheck) consumed() map[string]bool {
	consumed := map[string]bool{}
	for _, m := range c.findings {
		for _, name := range m.evidence {
			consumed[name] = true
		}
	}
	return consumed
}

// takingPart returns, of the producers of a playbook's findings, those that take part in it, as matching
// describes them: a producer takes part when the match that its Collector's capabilities declare consumes
// a type of the playbook's evidence (decision 0043). One that consumes none, as a checker of its own
// subjects, has nothing to add to the playbook. A Collector that has recorded no capabilities, or declares
// no match, takes no part, and neither does a pinned one that is absent. A producer's health plays no part:
// one that can't be used now still vouches for what it matched, and its matches fail until it can.
func takingPart(collectors []configv1alpha1.Collector, producers []producer,
	evidence []configv1alpha1.PlaybookEvidence) []matching {
	var found []matching
	for _, p := range producers {
		i := slices.IndexFunc(collectors, func(c configv1alpha1.Collector) bool { return c.Name == p.collector })
		if i < 0 || p.absent {
			continue
		}
		op, err := matchOf(p.collector, &collectors[i])
		if err != nil {
			continue
		}
		m := matching{collector: p.collector}
		for _, e := range evidence {
			if slices.Contains(op.Consumes, e.Type) {
				m.evidence = append(m.evidence, e.Name)
			}
		}
		if len(m.evidence) > 0 {
			slices.Sort(m.evidence)
			found = append(found, m)
		}
	}
	return found
}

// findingsTypeOf returns the type of the findings of a playbook: the core's type of findings unless it
// names another, as the API server defaults it.
func findingsTypeOf(playbook *configv1alpha1.Playbook) string {
	return cmp.Or(ptr.Deref(playbook.Spec.Findings.Type, ""), sdkevidence.TypeFindings)
}

// optional reports whether the playbook takes the evidence e as optional. A requirement that this version
// doesn't know counts as Required, which asks more of the playbook.
func optional(e configv1alpha1.PlaybookEvidence) bool {
	return ptr.Deref(e.Requirement, configv1alpha1.EvidenceRequired) == configv1alpha1.EvidenceOptional
}

// produces reports whether the capabilities that a Collector recorded say that it produces the type.
func produces(collector *configv1alpha1.Collector, evidenceType string) bool {
	return collector.Status.Capabilities != nil && slices.ContainsFunc(collector.Status.Capabilities.Produces,
		func(p configv1alpha1.ProducedType) bool { return p.Type == evidenceType })
}

// producersOf returns the producers of the type among the Collectors, sorted by name: each that pins
// names, or else every Collector whose capabilities say that it produces the type and that isn't being
// deleted. A pinned Collector that doesn't exist, or has recorded capabilities without the type, has no
// evidence for the rules.
func producersOf(collectors []configv1alpha1.Collector, evidenceType string, pins []string) []producer {
	var found []producer
	if len(pins) > 0 {
		for _, name := range pins {
			i := slices.IndexFunc(collectors, func(c configv1alpha1.Collector) bool { return c.Name == name })
			absent := i < 0 || (collectors[i].Status.Capabilities != nil && !produces(&collectors[i], evidenceType))
			found = append(found, producer{collector: name, absent: absent})
		}
	} else {
		for i := range collectors {
			if collectors[i].DeletionTimestamp.IsZero() && produces(&collectors[i], evidenceType) {
				found = append(found, producer{collector: collectors[i].Name})
			}
		}
	}
	slices.SortFunc(found, func(a, b producer) int { return strings.Compare(a.collector, b.collector) })
	return slices.CompactFunc(found, func(a, b producer) bool { return a.collector == b.collector })
}

// isProducer reports whether the Collector is a producer of the type for an entry that pins pins.
func isProducer(collector *configv1alpha1.Collector, evidenceType string, pins []string) bool {
	if len(pins) > 0 {
		return slices.Contains(pins, collector.Name)
	}
	return collector.DeletionTimestamp.IsZero() && produces(collector, evidenceType)
}

// checkPipeline compiles the rule of each step, puts it with the finding rules or with the exposure rules, notes
// the rules that are missing or not Ready, and the inputs of a rule that the playbook's evidence doesn't supply
// under the input's name and type. An input of a name that the evidence supplies with another type is absent: the
// rules never get evidence of a type that they don't read. Only the finding rules go into the basis.
func (c *playbookCheck) checkPipeline(ctx context.Context, reader client.Reader, rules *Rules, playbook *configv1alpha1.Playbook) error {
	keys := make([]string, 0, len(playbook.Spec.Pipeline))
	// aboutManifest holds the names of the evidence that a finding rule reads or a findings producer consumes, and
	// aboutWorkloads those that an exposure rule reads.
	aboutManifest, aboutWorkloads := c.consumed(), map[string]bool{}
	for _, step := range playbook.Spec.Pipeline {
		var rule configv1alpha1.Rule
		switch err := reader.Get(ctx, client.ObjectKey{Name: step.Rule}, &rule); {
		case apierrors.IsNotFound(err):
			c.missingRules = append(c.missingRules, step.Rule)
			missing := engine.Unavailable(step.Rule, reasonRuleMissing)
			c.steps, c.exposureSteps = append(c.steps, missing), append(c.exposureSteps, missing)
			keys = append(keys, step.Rule+":missing")
			continue
		case err != nil:
			return fmt.Errorf("read Rule %q: %w", step.Rule, err)
		}
		key := fmt.Sprintf("%s/%s/%d", rule.Name, rule.UID, rule.Generation)
		compiled, err := rules.Compile(&rule)
		if err != nil {
			c.notReadyRules = append(c.notReadyRules, step.Rule)
			compiled, key = engine.Unavailable(step.Rule, reasonRuleNotReady), key+":not-ready"
		}
		reads := aboutManifest
		if rule.Spec.Outcome != nil && rule.Spec.Outcome.Exposure != nil {
			c.exposureSteps, reads = append(c.exposureSteps, compiled), aboutWorkloads
		} else {
			c.steps, keys = append(c.steps, compiled), append(keys, key)
		}
		for _, in := range rule.Spec.Inputs {
			reads[in.Name] = true
			i := slices.IndexFunc(playbook.Spec.Evidence, func(e configv1alpha1.PlaybookEvidence) bool { return e.Name == in.Name })
			switch {
			case i < 0:
				c.missingInputs = append(c.missingInputs, fmt.Sprintf("%q needs %q of type %s, which the evidence doesn't name",
					rule.Name, in.Name, in.Type))
			case playbook.Spec.Evidence[i].Type != in.Type:
				c.missingInputs = append(c.missingInputs, fmt.Sprintf("%q needs %q of type %s, where the evidence is of type %s",
					rule.Name, in.Name, in.Type, playbook.Spec.Evidence[i].Type))
				c.absent[in.Name] = true
			}
		}
	}
	slices.Sort(c.missingRules)
	c.missingRules = slices.Compact(c.missingRules)
	slices.Sort(c.notReadyRules)
	c.notReadyRules = slices.Compact(c.notReadyRules)
	slices.Sort(c.missingInputs)
	c.missingInputs = slices.Compact(c.missingInputs)
	c.workloadEvidence = map[string]bool{}
	for name := range aboutWorkloads {
		if !aboutManifest[name] {
			c.workloadEvidence[name] = true
		}
	}
	absent := make([]string, 0, len(c.absent))
	for name := range c.absent {
		absent = append(absent, name)
	}
	slices.Sort(absent)
	c.basis = strings.Join(keys, ",") + "|absent:" + strings.Join(absent, ",")
	return nil
}

// PlaybookReconciler keeps the Ready condition of each Playbook (decisions 0034 and 0043). It is True with
// reason Valid when the playbook can run, and False otherwise, with the reason of the first fault: Invalid
// for a selector of its match that doesn't parse or a condition of its agent that doesn't compile, CollectorMissing for a pinned Collector that doesn't
// exist, TypeNotProduced for an entry that the playbook needs without its producers, RuleMissing,
// RuleNotReady or InputMissing. The message names what is at fault. A playbook that turns not Ready, or
// whose reason changes, gets a Warning event with the reason and message of Ready, and the gauge
// vexplain_playbook_ready shows it too (decision 0036).
//
// It also sums the counts that the spokes write for the playbook into its status, the fleet picture (design 5.6):
// the resources judged and actionable, and the actions by step and by severity, over every cluster and for each of the
// 16 most actionable.
//
// A playbook that isn't Ready still has its sheets evaluated again by the assessor, which holds back
// what the fault leaves out: see Assessor.
type PlaybookReconciler struct {
	// Client reads the Playbooks, the Collectors, the Spokes and the Rules from the manager's cache, and writes
	// the status of the Playbooks.
	Client client.Client
	// Rules compiles the rules, as the rule controller does, so that a rule is Ready here exactly when it
	// is there.
	Rules *Rules
	// Recorder records the Warning event of a playbook that isn't Ready.
	Recorder events.EventRecorder
	// Counts holds what each spoke found for the playbook in its cluster, which the controller sums into the
	// playbook's status, and which it watches.
	Counts inventory.CountsStore
}

// The controller reads the Playbooks and writes only their status, which holds the fleet picture that it sums from the
// counts of the spokes. It reads the Collectors, which produce
// the types that the playbooks name, the Spokes, which list the collectors of the other clusters, and the Rules that
// the playbooks name. The events API files the event of a
// playbook that isn't Ready: the recorder creates the event, and patches it when the same event repeats.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=playbooks,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=playbooks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=spokes,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=rules,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile sets the Ready condition of the Playbook of the request, and writes its status only when it
// changes. A deleted Playbook needs no work.
func (r *PlaybookReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var playbook configv1alpha1.Playbook
	if err := r.Client.Get(ctx, req.NamespacedName, &playbook); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	check, err := checkPlaybook(ctx, r.Client, r.Rules, &playbook)
	if err != nil {
		return ctrl.Result{}, err
	}
	ready := check.condition(playbook.Generation)
	before := meta.FindStatusCondition(playbook.Status.Conditions, configv1alpha1.ConditionReady).DeepCopy()
	// Each reason of False needs a change of the playbook, or of a Collector or Rule that it names: the
	// controller is stalled until then.
	changed := conditions.SetReady(&playbook.Status.Conditions, ready, conditions.Stalled)
	counts, err := r.Counts.List(ctx, playbook.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	summary, clusters := fleetOf(counts)
	if !equality.Semantic.DeepEqual(playbook.Status.Summary, summary) || !equality.Semantic.DeepEqual(playbook.Status.Clusters, clusters) {
		playbook.Status.Summary, playbook.Status.Clusters = summary, clusters
		changed = true
	}
	if !conditions.Observe(&playbook.Status.ObservedGeneration, playbook.Generation) && !changed {
		return ctrl.Result{}, nil
	}
	if err := r.Client.Status().Update(ctx, &playbook); err != nil {
		// NotFound means the playbook was deleted since it was read. Any other error, a conflict
		// included, is returned, and controller-runtime retries with a back-off.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	logf.FromContext(ctx).Info("Updated the Ready condition of the Playbook",
		"status", ready.Status, "reason", ready.Reason, "message", ready.Message)
	// A playbook that isn't Ready settles less than it would, and only its condition says why, on an object that
	// few people look at: the event shows it where people look. It is recorded once the status is written, so that
	// a write that fails is retried together with its event, when the playbook turns not Ready and when the reason
	// changes, and not at every reconcile.
	if ready.Status != metav1.ConditionTrue &&
		(before == nil || before.Status == metav1.ConditionTrue || before.Reason != ready.Reason) {
		r.Recorder.Eventf(&playbook, nil, corev1.EventTypeWarning, ready.Reason, eventActionReconcile, "%s", ready.Message)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PlaybookReconciler) SetupWithManager(mgr ctrl.Manager) error {
	every := handler.EnqueueRequestsFromMapFunc(r.everyPlaybook)
	return ctrl.NewControllerManagedBy(mgr).
		Named("hub-playbooks").
		// Every event of a Playbook starts a check, the controller's own status writes too. A check reads the playbook
		// from the cache, which can still lack the controller's last write: when the inputs changed back meanwhile, the
		// check finds there the status that it would write, and writes nothing. Only the write's own event, once the
		// cache holds the write, has the playbook checked against it. That check writes only what changed, so a write
		// starts one more check, and no more.
		For(&configv1alpha1.Playbook{}).
		// Every playbook, when a Collector comes, goes, starts to be deleted or records other capabilities.
		WatchesRawSource(r.Counts.Source()).
		Watches(&configv1alpha1.Collector{}, every, builder.WithPredicates(collectorChanged())).
		// Every playbook, when a Spoke comes, goes or lists other collectors, which produce the evidence about the
		// workloads of its cluster.
		Watches(&configv1alpha1.Spoke{}, every, builder.WithPredicates(spokeChanged())).
		// Every playbook, when a Rule comes, goes or changes, which changes whether it compiles.
		Watches(&configv1alpha1.Rule{}, every, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// spokeChanged passes the events of a Spoke that can change what a check of a playbook finds: it comes, it goes,
// or the collectors in its status change. Its conditions and times, which change at every sync, change nothing.
func spokeChanged() predicate.Funcs {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		before, beforeOK := e.ObjectOld.(*configv1alpha1.Spoke)
		after, afterOK := e.ObjectNew.(*configv1alpha1.Spoke)
		return !beforeOK || !afterOK || !equality.Semantic.DeepEqual(before.Status.Collectors, after.Status.Collectors)
	}}
}

// spokeOrLabelsChanged passes the events that spokeChanged passes, and a change of a Spoke's spec, whose labels say
// which playbooks judge the images that its cluster runs.
func spokeOrLabelsChanged() predicate.Predicate {
	return predicate.Or[client.Object](spokeChanged(), predicate.GenerationChangedPredicate{})
}

// collectorChanged passes the events of a Collector that can change what a check of a playbook finds: it
// comes, it goes, it starts to be deleted, which takes it out of the producers, or the capabilities in its
// status change. Its health, which the Collector controller writes every resync, changes nothing.
func collectorChanged() predicate.Funcs {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		before, beforeOK := e.ObjectOld.(*configv1alpha1.Collector)
		after, afterOK := e.ObjectNew.(*configv1alpha1.Collector)
		return !beforeOK || !afterOK || !equality.Semantic.DeepEqual(before.Status.Capabilities, after.Status.Capabilities) ||
			before.DeletionTimestamp.IsZero() != after.DeletionTimestamp.IsZero()
	}}
}

// everyPlaybook maps an event to every Playbook, as the manager's cache lists them. The cache answers
// once it has synced, and fails only when ctx ends, as the manager stops.
func (r *PlaybookReconciler) everyPlaybook(ctx context.Context, _ client.Object) []reconcile.Request {
	var playbooks configv1alpha1.PlaybookList
	if err := r.Client.List(ctx, &playbooks); err != nil {
		logf.FromContext(ctx).Error(err, "Could not list the Playbooks to check them again")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(playbooks.Items))
	for i := range playbooks.Items {
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: playbooks.Items[i].Name}})
	}
	return requests
}
