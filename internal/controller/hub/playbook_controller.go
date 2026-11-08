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
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/conditions"
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
	// conflict names the oldest of the other playbooks whose subjects are of the same type, whatever
	// Collectors produce them, and is empty when there is none.
	conflict string
	// What is at fault, each sorted: the Collectors that an entry that the playbook needs pins and that
	// don't exist, the entries that lack a Ready producer, the rules that are missing or not Ready, and
	// the inputs that a rule needs and the playbook doesn't supply.
	missingCollectors, notProduced, missingRules, notReadyRules, missingInputs []string
	// steps is the pipeline: each rule compiled, or, for a rule that is missing or not Ready, a step that
	// can't be evaluated and might hold, so that it keeps every finding from NotAffected and Fixed.
	steps []*engine.Compiled
	// basis says what the steps, the playbook and the producers of its evidence are, so that a change of
	// any shows.
	basis string
	// absent holds the names of the evidence that the rules don't get from any producer: a rule takes an
	// input of the name with another type.
	absent map[string]bool
	// producers holds, by the name of each piece of evidence, the Collectors whose evidence of its type
	// the rules read, sorted by name.
	producers map[string][]producer
	// findings holds the Collectors whose findings the playbook takes, sorted: those that it pins, or
	// else every Collector that produces its type of findings.
	findings []string
}

// producer is a Collector whose evidence of a type the rules read: one that the entry pins, or else one
// whose capabilities say that it produces the type, whatever its health. Its health gates what is asked
// of it, and not what it delivered, which stays evidence while the Collector is there (design 5.9).
type producer struct {
	collector string
	// absent says that the rules don't get the evidence of the Collector: the entry pins it, and it
	// doesn't exist, or its capabilities don't list the type.
	absent bool
}

// ready reports whether the playbook can run: it takes subjects of its type alone, every entry that it
// needs has its Ready producers, and every rule exists, is Ready and gets its inputs.
func (c *playbookCheck) ready() bool {
	return c.conflict == "" && len(c.missingCollectors) == 0 && len(c.notProduced) == 0 &&
		len(c.missingRules) == 0 && len(c.notReadyRules) == 0 && len(c.missingInputs) == 0
}

// condition returns the Ready condition of the playbook, at its generation. Of the faults, the one
// first in this order decides the reason: Conflict, CollectorMissing, TypeNotProduced, RuleMissing,
// RuleNotReady and InputMissing.
func (c *playbookCheck) condition(generation int64) metav1.Condition {
	ready := metav1.Condition{Type: configv1alpha1.ConditionReady, Status: metav1.ConditionFalse, ObservedGeneration: generation}
	switch {
	case c.conflict != "":
		ready.Reason = configv1alpha1.ReasonConflict
		ready.Message = fmt.Sprintf("The playbook %q takes subjects of the same type, and is older: only one playbook may, "+
			"so that each subject keeps one verdict.", c.conflict)
	case len(c.missingCollectors) > 0:
		ready.Reason = configv1alpha1.ReasonCollectorMissing
		ready.Message = "Collectors that the playbook pins don't exist: " + quoted(c.missingCollectors) + "."
	case len(c.notProduced) > 0:
		ready.Reason = configv1alpha1.ReasonTypeNotProduced
		ready.Message = "Types that the playbook needs lack a Ready producer: " + strings.Join(c.notProduced, "; ") + "."
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
		ready.Message = "Each type that the playbook needs has its Ready producers, and every rule of its pipeline is Ready and " +
			"gets its inputs."
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

// checkPlaybook checks playbook against the Collectors and the Rules that reader holds, and against the
// other playbooks. Two playbooks conflict when their subjects are of the same type, whatever Collectors
// produce them: a type names the same subjects, such as the images in presence, and each of them keeps
// one sheet. A read that fails returns its error, and never a fault.
func checkPlaybook(ctx context.Context, reader client.Reader, rules *Rules, playbook *configv1alpha1.Playbook,
	playbooks []configv1alpha1.Playbook) (*playbookCheck, error) {
	c := &playbookCheck{absent: map[string]bool{}, producers: map[string][]producer{}}
	for i := range playbooks {
		other := &playbooks[i]
		if other.Name != playbook.Name && other.Spec.Subjects.Type == playbook.Spec.Subjects.Type && older(other, playbook) &&
			(c.conflict == "" || older(other, playbookNamed(playbooks, c.conflict))) {
			c.conflict = other.Name
		}
	}
	if err := c.checkProducers(ctx, reader, playbook); err != nil {
		return nil, err
	}
	if err := c.checkPipeline(ctx, reader, rules, playbook); err != nil {
		return nil, err
	}
	c.basis = fmt.Sprintf("%s/%s/%d|%s|findings:%s", playbook.Name, playbook.UID, playbook.Generation, c.basis,
		strings.Join(c.findings, ","))
	return c, nil
}

// older reports whether a was created before b, and, of two created in the same second, whether its
// name comes first: an order that every replica sees alike.
func older(a, b *configv1alpha1.Playbook) bool {
	return cmp.Or(a.CreationTimestamp.Compare(b.CreationTimestamp.Time), strings.Compare(a.Name, b.Name)) < 0
}

// playbookNamed returns the playbook of the name among playbooks.
func playbookNamed(playbooks []configv1alpha1.Playbook, name string) *configv1alpha1.Playbook {
	i := slices.IndexFunc(playbooks, func(p configv1alpha1.Playbook) bool { return p.Name == name })
	return &playbooks[i]
}

// checkProducers notes, of each entry that the playbook needs, its subjects, its findings and each piece
// of required evidence, what keeps it from Ready producers: a pinned Collector that doesn't exist, one
// that can't be used or doesn't produce the type, as the capabilities in its status say, or no Collector
// that can be used and produces the type. Optional evidence needs no producer. It records the producers
// whose evidence the rules read, and whose findings the playbook takes, whatever their health.
func (c *playbookCheck) checkProducers(ctx context.Context, reader client.Reader, playbook *configv1alpha1.Playbook) error {
	var list configv1alpha1.CollectorList
	if err := reader.List(ctx, &list); err != nil {
		return fmt.Errorf("list the Collectors: %w", err)
	}
	collectors := make(map[string]*configv1alpha1.Collector, len(list.Items))
	for i := range list.Items {
		collectors[list.Items[i].Name] = &list.Items[i]
	}
	// need notes what keeps the entry of the label, of the type, from Ready producers.
	need := func(label, evidenceType string, pins []string) {
		if len(pins) == 0 {
			if !slices.ContainsFunc(list.Items, func(collector configv1alpha1.Collector) bool {
				return collectorclient.Usable(&collector) && produces(&collector, evidenceType)
			}) {
				c.notProduced = append(c.notProduced, fmt.Sprintf("no Ready Collector produces %s for the %s", evidenceType, label))
			}
			return
		}
		for _, name := range pins {
			switch collector, ok := collectors[name]; {
			case !ok:
				c.missingCollectors = append(c.missingCollectors, name)
			case !collectorclient.Usable(collector):
				c.notProduced = append(c.notProduced, fmt.Sprintf("%q, pinned for the %s, isn't Ready", name, label))
			case !produces(collector, evidenceType):
				c.notProduced = append(c.notProduced, fmt.Sprintf("%q, pinned for the %s, produces no %s", name, label, evidenceType))
			}
		}
	}

	need("subjects", playbook.Spec.Subjects.Type, playbook.Spec.Subjects.Collectors)
	findingsType := findingsTypeOf(playbook)
	need("findings", findingsType, playbook.Spec.Findings.Collectors)
	for _, p := range producersOf(list.Items, findingsType, playbook.Spec.Findings.Collectors) {
		c.findings = append(c.findings, p.collector)
	}
	for _, e := range playbook.Spec.Evidence {
		if !optional(e) {
			need(fmt.Sprintf("evidence %q", e.Name), e.Type, e.Collectors)
		}
		c.producers[e.Name] = producersOf(list.Items, e.Type, e.Collectors)
	}
	slices.Sort(c.missingCollectors)
	c.missingCollectors = slices.Compact(c.missingCollectors)
	slices.Sort(c.notProduced)
	c.notProduced = slices.Compact(c.notProduced)
	return nil
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

// checkPipeline compiles the rule of each step, notes the rules that are missing or not Ready, and the
// inputs of a rule that the playbook's evidence doesn't supply under the input's name and type. An input
// of a name that the evidence supplies with another type is absent: the rules never get evidence of a
// type that they don't read.
func (c *playbookCheck) checkPipeline(ctx context.Context, reader client.Reader, rules *Rules, playbook *configv1alpha1.Playbook) error {
	keys := make([]string, 0, len(playbook.Spec.Pipeline))
	for _, step := range playbook.Spec.Pipeline {
		var rule configv1alpha1.Rule
		switch err := reader.Get(ctx, client.ObjectKey{Name: step.Rule}, &rule); {
		case apierrors.IsNotFound(err):
			c.missingRules = append(c.missingRules, step.Rule)
			c.steps = append(c.steps, engine.Unavailable(step.Rule, reasonRuleMissing))
			keys = append(keys, step.Rule+":missing")
			continue
		case err != nil:
			return fmt.Errorf("read Rule %q: %w", step.Rule, err)
		}
		key := fmt.Sprintf("%s/%s/%d", rule.Name, rule.UID, rule.Generation)
		compiled, err := rules.Compile(&rule)
		if err != nil {
			c.notReadyRules = append(c.notReadyRules, step.Rule)
			c.steps = append(c.steps, engine.Unavailable(step.Rule, reasonRuleNotReady))
			keys = append(keys, key+":not-ready")
		} else {
			c.steps = append(c.steps, compiled)
			keys = append(keys, key)
		}
		for _, in := range rule.Spec.Inputs {
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
	absent := make([]string, 0, len(c.absent))
	for name := range c.absent {
		absent = append(absent, name)
	}
	slices.Sort(absent)
	c.basis = strings.Join(keys, ",") + "|absent:" + strings.Join(absent, ",")
	return nil
}

// PlaybookReconciler keeps the Ready condition of each Playbook (decisions 0034 and 0043). It is True with
// reason Valid when the playbook can run, and False otherwise, with the reason of the first fault: Conflict
// for the newer of two playbooks whose subjects are of the same type, CollectorMissing for a pinned
// Collector that doesn't exist, TypeNotProduced for an entry that the playbook needs without its Ready
// producers, RuleMissing, RuleNotReady or InputMissing. The message names what is at fault. A playbook
// that turns not Ready, or whose reason changes, gets a Warning event with the reason and message of Ready,
// and the gauge vexplain_playbook_ready shows it too (decision 0036).
//
// A playbook that isn't Ready still has its sheets evaluated again by the assessor, which holds back
// what the fault leaves out, unless it is in Conflict: see Assessor.
type PlaybookReconciler struct {
	// Client reads the Playbooks, the Collectors and the Rules from the manager's cache, and writes the
	// status of the Playbooks.
	Client client.Client
	// Rules compiles the rules, as the rule controller does, so that a rule is Ready here exactly when it
	// is there.
	Rules *Rules
	// Recorder records the Warning event of a playbook that isn't Ready.
	Recorder events.EventRecorder
}

// The controller reads the Playbooks and writes only their status. It reads the Collectors, which produce
// the types that the playbooks name, and the Rules that they name. The events API files the event of a
// playbook that isn't Ready: the recorder creates the event, and patches it when the same event repeats.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=playbooks,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=playbooks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=rules,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile sets the Ready condition of the Playbook of the request, and writes its status only when it
// changes. A deleted Playbook needs no work.
func (r *PlaybookReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var playbook configv1alpha1.Playbook
	if err := r.Client.Get(ctx, req.NamespacedName, &playbook); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	var playbooks configv1alpha1.PlaybookList
	if err := r.Client.List(ctx, &playbooks); err != nil {
		return ctrl.Result{}, fmt.Errorf("list the Playbooks: %w", err)
	}
	check, err := checkPlaybook(ctx, r.Client, r.Rules, &playbook, playbooks.Items)
	if err != nil {
		return ctrl.Result{}, err
	}
	ready := check.condition(playbook.Generation)
	before := meta.FindStatusCondition(playbook.Status.Conditions, configv1alpha1.ConditionReady).DeepCopy()
	// Each reason of False needs a change of the playbook, or of a Collector, Rule or playbook that it
	// names: the controller is stalled until then.
	changed := conditions.SetReady(&playbook.Status.Conditions, ready, conditions.Stalled)
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
		// A new Playbook and a changed spec need a reconcile. The controller's own status writes must not
		// start another one.
		For(&configv1alpha1.Playbook{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// Every playbook, when one comes, goes or changes its subjects: which of them is in conflict
		// changes with it.
		Watches(&configv1alpha1.Playbook{}, every, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// Every playbook, when a Collector comes, goes, records other capabilities, or can be used or not.
		Watches(&configv1alpha1.Collector{}, every, builder.WithPredicates(collectorChanged())).
		// Every playbook, when a Rule comes, goes or changes, which changes whether it compiles.
		Watches(&configv1alpha1.Rule{}, every, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// collectorChanged passes the events of a Collector that can change what a check of a playbook finds: it
// comes, it goes, the capabilities in its status change, or whether it can be used, as
// collectorclient.Usable says, which decides whether it is a Ready producer. The rest of its status, which
// the Collector controller writes every resync, changes nothing.
func collectorChanged() predicate.Funcs {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		before, beforeOK := e.ObjectOld.(*configv1alpha1.Collector)
		after, afterOK := e.ObjectNew.(*configv1alpha1.Collector)
		return !beforeOK || !afterOK || !equality.Semantic.DeepEqual(before.Status.Capabilities, after.Status.Capabilities) ||
			collectorclient.Usable(before) != collectorclient.Usable(after)
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
