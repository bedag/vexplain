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
	"context"
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/conditions"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/internal/text"
)

// maxMessageBytes is the longest condition message that the controllers of the hub write. An error of
// CEL quotes the expression, which a Rule allows up to 4096 characters long.
const maxMessageBytes = 1024

// Rules compiles the Rules, and keeps each compiled rule until its Rule changes: the rule controller,
// the playbook controller and the assessor all ask it, so that a rule is compiled once for each of its
// generations, and not once for each manifest that a playbook assesses. A Rule is Ready exactly when it
// compiles here. It is safe for concurrent use.
type Rules struct {
	mu       sync.Mutex
	compiled map[string]compiledRule
}

// compiledRule is what Compile made of one generation of a Rule.
type compiledRule struct {
	uid        types.UID
	generation int64
	compiled   *engine.Compiled
	err        error
}

// NewRules returns a Rules that has compiled nothing yet.
func NewRules() *Rules {
	return &Rules{compiled: map[string]compiledRule{}}
}

// Compile returns the rule compiled, or the error of engine.Compile, which says why the rule can't be
// evaluated as written.
func (r *Rules) Compile(rule *configv1alpha1.Rule) (*engine.Compiled, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.compiled[rule.Name]; ok && c.uid == rule.UID && c.generation == rule.Generation {
		return c.compiled, c.err
	}
	compiled, err := engine.Compile(rule)
	r.compiled[rule.Name] = compiledRule{uid: rule.UID, generation: rule.Generation, compiled: compiled, err: err}
	return compiled, err
}

// Evaluations counts, for each rule, the findings that the last evaluation of each subject couldn't
// evaluate it for, as engine.Result.NotEvaluated gives them. The assessor records each evaluation, and
// the rule controller sets the Evaluated condition of each Rule from the count. It forgets nothing on a
// restart that it would need: the counts start again from the evaluations that follow. It is safe for
// concurrent use.
type Evaluations struct {
	mu sync.Mutex
	// bySubject holds the counts of the last evaluation of each subject that has some, by rule.
	bySubject map[string]map[string]int
	// totals holds the sum over the subjects for each rule.
	totals map[string]int
	// queue is the rule controller's work queue, once the controller has started, and changed holds
	// the rules whose count changed before then.
	queue   workqueue.TypedRateLimitingInterface[reconcile.Request]
	changed map[string]bool
}

// NewEvaluations returns an Evaluations that counts nothing yet.
func NewEvaluations() *Evaluations {
	return &Evaluations{bySubject: map[string]map[string]int{}, totals: map[string]int{}, changed: map[string]bool{}}
}

// Record replaces the counts of a subject with those of its last evaluation, and has the rule
// controller look at each rule whose count changed.
func (e *Evaluations) Record(subject string, notEvaluated map[string]int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	counts := map[string]int{}
	for rule, n := range notEvaluated {
		if n > 0 {
			counts[rule] = n
		}
	}
	e.replace(subject, counts)
}

// Forget drops the counts of a subject that is assessed no more, such as a manifest whose sheet went.
func (e *Evaluations) Forget(subject string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.replace(subject, nil)
}

// replace sets the counts of subject, and has the rule controller look at each rule whose total
// changed. The caller holds the lock.
func (e *Evaluations) replace(subject string, counts map[string]int) {
	before := e.bySubject[subject]
	for rule, n := range before {
		if counts[rule] != n {
			e.add(rule, counts[rule]-n)
		}
	}
	for rule, n := range counts {
		if _, counted := before[rule]; !counted {
			e.add(rule, n)
		}
	}
	if len(counts) == 0 {
		delete(e.bySubject, subject)
	} else {
		e.bySubject[subject] = counts
	}
}

// add changes the total of a rule by delta, and tells the rule controller. The caller holds the lock.
func (e *Evaluations) add(rule string, delta int) {
	e.totals[rule] += delta
	if e.totals[rule] == 0 {
		delete(e.totals, rule)
	}
	if e.queue == nil {
		e.changed[rule] = true
		return
	}
	e.queue.Add(ruleRequest(rule))
}

// NotEvaluated returns how many findings the last evaluations couldn't evaluate the rule for.
func (e *Evaluations) NotEvaluated(rule string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.totals[rule]
}

// Source delivers the name of each rule whose count changes. The rule controller watches it.
func (e *Evaluations) Source() source.Source {
	return source.Func(func(_ context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.queue = queue
		for rule := range e.changed {
			queue.Add(ruleRequest(rule))
		}
		clear(e.changed)
		return nil
	})
}

// ruleRequest is the request under which the rule controller reconciles a Rule: its name.
func ruleRequest(rule string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: rule}}
}

// RuleReconciler keeps the conditions of each Rule (decision 0033). Ready is True with reason Valid
// when the rule compiles, and False with reason Invalid and the error when it doesn't. Evaluated is
// False with reason EvaluationErrors while the assessor's last evaluations couldn't evaluate the rule
// for some findings, with their number in the message, and True with reason NoEvaluationErrors
// otherwise. A rule can't be evaluated for a finding when its CEL fails, hits the cost limit or runs past
// a bound on time, an input is missing that the playbook doesn't take as optional, its match fails for a
// finding of the subject, a playbook ran it while it wasn't Ready, or the producers of the playbook's
// evidence made more than 4 combinations. An optional input that is missing holds the findings that the
// rule covers, as any missing input does, but isn't counted: the playbook runs without it on purpose
// (decision 0043).
type RuleReconciler struct {
	// Client reads the Rules from the manager's cache, and writes their status.
	Client client.Client
	// Rules compiles the rules, and Evaluations counts what the assessor couldn't evaluate.
	Rules       *Rules
	Evaluations *Evaluations
}

// The controller reads the Rules and writes only their status.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=rules,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=rules/status,verbs=get;update;patch

// Reconcile sets the conditions of the Rule of the request, and writes its status only when they change.
// A deleted Rule needs no work.
func (r *RuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var rule configv1alpha1.Rule
	if err := r.Client.Get(ctx, req.NamespacedName, &rule); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ready := metav1.Condition{Type: configv1alpha1.ConditionReady, ObservedGeneration: rule.Generation}
	if _, err := r.Rules.Compile(&rule); err != nil {
		ready.Status, ready.Reason = metav1.ConditionFalse, configv1alpha1.ReasonInvalid
		ready.Message = message(err.Error())
	} else {
		ready.Status, ready.Reason = metav1.ConditionTrue, configv1alpha1.ReasonValid
		ready.Message = "The rule's CEL compiles."
	}
	evaluated := metav1.Condition{Type: configv1alpha1.ConditionEvaluated, ObservedGeneration: rule.Generation}
	// The message gives the count, and no more. A sheet says why a rule couldn't be evaluated for a finding
	// only where the rule held the finding open and the finding shows its verdict: a hint, and a rule that
	// would settle the finding, just don't apply, and leave no trace there.
	switch n := r.Evaluations.NotEvaluated(rule.Name); n {
	case 0:
		evaluated.Status, evaluated.Reason = metav1.ConditionTrue, configv1alpha1.ReasonNoEvaluationErrors
		evaluated.Message = "The rule could be evaluated for every finding of its last evaluations."
	case 1:
		evaluated.Status, evaluated.Reason = metav1.ConditionFalse, configv1alpha1.ReasonEvaluationErrors
		evaluated.Message = "1 finding couldn't be evaluated in the last evaluations."
	default:
		evaluated.Status, evaluated.Reason = metav1.ConditionFalse, configv1alpha1.ReasonEvaluationErrors
		evaluated.Message = fmt.Sprintf("%d findings couldn't be evaluated in the last evaluations.", n)
	}
	// Ready is False only for CEL that doesn't compile, which needs a change of the rule: the controller is
	// stalled. Evaluated plays no part in it.
	readyChanged := conditions.SetReady(&rule.Status.Conditions, ready, conditions.Stalled)
	evaluatedChanged := meta.SetStatusCondition(&rule.Status.Conditions, evaluated)
	observedChanged := conditions.Observe(&rule.Status.ObservedGeneration, rule.Generation)
	if !readyChanged && !evaluatedChanged && !observedChanged {
		return ctrl.Result{}, nil
	}
	if err := r.Client.Status().Update(ctx, &rule); err != nil {
		// NotFound means the rule was deleted since it was read. Any other error, a conflict included,
		// is returned, and controller-runtime retries with a back-off.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	logf.FromContext(ctx).V(1).Info("Updated the conditions of the Rule",
		"ready", ready.Status, "reason", ready.Reason, "evaluated", evaluated.Status)
	return ctrl.Result{}, nil
}

// message cuts the text of a condition to maxMessageBytes, between characters. The text comes from the
// hub's admins, who write rules and playbooks, and not from images.
func message(s string) string {
	return text.CutBytes(s, maxMessageBytes)
}

// SetupWithManager sets up the controller with the Manager.
func (r *RuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("hub-rules").
		// A new Rule and a changed spec need a reconcile. The controller's own status writes must not
		// start another one.
		For(&configv1alpha1.Rule{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// A rule whose count of findings that couldn't be evaluated changed.
		WatchesRawSource(r.Evaluations.Source()).
		Complete(r)
}
