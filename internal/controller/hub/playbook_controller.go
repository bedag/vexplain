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

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/rules/engine"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// The reasons that a step of a pipeline can't be evaluated at all, which each finding that the step
// holds open records.
const (
	reasonRuleMissing  = "the rule is missing"
	reasonRuleNotReady = "the rule isn't Ready"
)

// playbookCheck is what a check of a playbook against the Collectors and the Rules found: whether it can
// run, and, when it can't, what the assessor holds back. The playbook controller writes the Ready
// condition from it, and the assessor evaluates by it, so that the two never disagree.
type playbookCheck struct {
	// conflict names the oldest of the other playbooks whose subjects are of the same type, whatever
	// Collector delivers them, and is empty when there is none.
	conflict string
	// What is at fault, each sorted: the Collectors that are missing, the types that a Collector doesn't
	// produce, the rules that are missing or not Ready, and the inputs that a rule needs and the playbook
	// doesn't supply.
	missingCollectors, notProduced, missingRules, notReadyRules, missingInputs []string
	// steps is the pipeline: each rule compiled, or, for a rule that is missing or not Ready, a step that
	// can't be evaluated and might hold, so that it keeps every finding from NotAffected and Fixed.
	steps []*engine.Compiled
	// basis says what the steps and the playbook are, so that a change of either shows.
	basis string
	// absent holds the names of the evidence that the rules don't get: its Collector is missing or
	// doesn't produce its type, or a rule takes an input of the name with another type.
	absent map[string]bool
}

// ready reports whether the playbook can run: it takes subjects of its type alone, its Collectors exist and
// produce what it asks of them, and every rule exists, is Ready and gets its inputs.
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
		ready.Message = "Collectors that the playbook names don't exist: " + quoted(c.missingCollectors) + "."
	case len(c.notProduced) > 0:
		ready.Reason = configv1alpha1.ReasonTypeNotProduced
		ready.Message = "Collectors don't produce what the playbook asks of them: " + strings.Join(c.notProduced, "; ") + "."
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
		ready.Message = "The Collectors that the playbook names exist, and every rule of its pipeline is Ready and gets its inputs."
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
// deliver them: a type names the same subjects, such as the images in presence, and each of them keeps
// one sheet. A read that fails returns its error, and never a fault.
func checkPlaybook(ctx context.Context, reader client.Reader, rules *Rules, playbook *configv1alpha1.Playbook,
	playbooks []configv1alpha1.Playbook) (*playbookCheck, error) {
	c := &playbookCheck{absent: map[string]bool{}}
	for i := range playbooks {
		other := &playbooks[i]
		if other.Name != playbook.Name && other.Spec.Subjects.Type == playbook.Spec.Subjects.Type && older(other, playbook) &&
			(c.conflict == "" || older(other, playbookNamed(playbooks, c.conflict))) {
			c.conflict = other.Name
		}
	}
	if err := c.checkCollectors(ctx, reader, playbook); err != nil {
		return nil, err
	}
	if err := c.checkPipeline(ctx, reader, rules, playbook); err != nil {
		return nil, err
	}
	c.basis = fmt.Sprintf("%s/%s/%d|%s", playbook.Name, playbook.UID, playbook.Generation, c.basis)
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

// checkCollectors notes the Collectors that playbook names and that don't exist, and the types that a
// Collector doesn't produce, as the capabilities in its status say. A Collector whose capabilities
// nobody has recorded yet is taken to produce what the playbook asks of it. The evidence of such a
// Collector is absent.
func (c *playbookCheck) checkCollectors(ctx context.Context, reader client.Reader, playbook *configv1alpha1.Playbook) error {
	collectors := map[string]*configv1alpha1.Collector{}
	exists := func(name string) (*configv1alpha1.Collector, error) {
		if collector, seen := collectors[name]; seen {
			return collector, nil
		}
		var collector configv1alpha1.Collector
		switch err := reader.Get(ctx, client.ObjectKey{Name: name}, &collector); {
		case apierrors.IsNotFound(err):
			collectors[name] = nil
			c.missingCollectors = append(c.missingCollectors, name)
			return nil, nil
		case err != nil:
			return nil, fmt.Errorf("read Collector %q: %w", name, err)
		}
		collectors[name] = &collector
		return &collector, nil
	}
	// produces reports whether the collector of the name produces the type, and notes when it doesn't.
	produces := func(name, evidenceType string) (bool, error) {
		collector, err := exists(name)
		if err != nil || collector == nil {
			return false, err
		}
		capabilities := collector.Status.Capabilities
		if capabilities == nil || slices.ContainsFunc(capabilities.Produces, func(p configv1alpha1.ProducedType) bool {
			return p.Type == evidenceType
		}) {
			return true, nil
		}
		c.notProduced = append(c.notProduced, fmt.Sprintf("%q produces no %s", name, evidenceType))
		return false, nil
	}

	if _, err := produces(playbook.Spec.Subjects.Collector, playbook.Spec.Subjects.Type); err != nil {
		return err
	}
	if _, err := produces(playbook.Spec.Findings.Collector, sdkevidence.TypeFindings); err != nil {
		return err
	}
	for _, e := range playbook.Spec.Evidence {
		ok, err := produces(e.Collector, e.Type)
		if err != nil {
			return err
		}
		if !ok {
			c.absent[e.Name] = true
		}
	}
	slices.Sort(c.missingCollectors)
	slices.Sort(c.notProduced)
	c.notProduced = slices.Compact(c.notProduced)
	return nil
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

// PlaybookReconciler keeps the Ready condition of each Playbook (decision 0034). It is True with reason
// Valid when the playbook can run, and False otherwise, with the reason of the first fault: Conflict
// for the newer of two playbooks whose subjects are of the same type, CollectorMissing, TypeNotProduced,
// RuleMissing, RuleNotReady or InputMissing. The message names what is at fault.
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
}

// The controller reads the Playbooks and writes only their status. It reads the Collectors and the
// Rules that they name.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=playbooks,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=playbooks/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=collectors,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=rules,verbs=get;list;watch

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
	if !meta.SetStatusCondition(&playbook.Status.Conditions, ready) {
		return ctrl.Result{}, nil
	}
	if err := r.Client.Status().Update(ctx, &playbook); err != nil {
		// NotFound means the playbook was deleted since it was read. Any other error, a conflict
		// included, is returned, and controller-runtime retries with a back-off.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	logf.FromContext(ctx).Info("Updated the Ready condition of the Playbook",
		"status", ready.Status, "reason", ready.Reason, "message", ready.Message)
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
		// Every playbook, when a Collector comes, goes or records other capabilities.
		Watches(&configv1alpha1.Collector{}, every, builder.WithPredicates(collectorChanged())).
		// Every playbook, when a Rule comes, goes or changes, which changes whether it compiles.
		Watches(&configv1alpha1.Rule{}, every, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// collectorChanged passes the events of a Collector that can change what a playbook that names it finds:
// it comes, it goes, or the capabilities in its status change. Its health, which the Collector
// controller writes every resync, changes nothing.
func collectorChanged() predicate.Funcs {
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		before, beforeOK := e.ObjectOld.(*configv1alpha1.Collector)
		after, afterOK := e.ObjectNew.(*configv1alpha1.Collector)
		return !beforeOK || !afterOK || !equality.Semantic.DeepEqual(before.Status.Capabilities, after.Status.Capabilities)
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
