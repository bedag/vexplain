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

package engine

import (
	"errors"
	"fmt"
	"slices"

	"github.com/google/cel-go/cel"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// errTooManyCombinations is why no rule is evaluated for a workload whose producers make more than
// maxCombinations combinations.
var errTooManyCombinations = errors.New(tooManyCombinations)

// exposureOrder is the order of exposure, the lowest first: none, from a rule whose condition doesn't hold,
// then Small, Controlled, Unknown and Open. Unknown comes above Controlled, since a rule that can't be
// evaluated might conclude Open.
var exposureOrder = []configv1alpha1.SSVCExposure{
	"", configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCExposureControlled,
	configv1alpha1.SSVCExposureUnknown, configv1alpha1.SSVCExposureOpen,
}

// compileExposure compiles an exposure rule, whose condition sees its inputs and no finding. A rule concludes
// no Unknown, which stands for what no rule decided.
func compileExposure(name string, spec configv1alpha1.RuleSpec) (*Compiled, error) {
	o := spec.Outcome
	c := &Compiled{name: name, exposure: *o.Exposure}
	switch c.exposure {
	case configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCExposureSmall:
	default:
		return nil, fmt.Errorf("the exposure %q isn't Open, Controlled or Small", c.exposure)
	}
	if o.Status != nil || o.Justification != nil || o.HoldAgainst != nil || spec.Match != nil || spec.Reason != nil {
		return nil, errors.New("an exposure rule has no status, justification, holdAgainst, match or reason")
	}
	env, inputs, err := environment(exposureEnvironment, spec.Inputs)
	if err != nil {
		return nil, err
	}
	c.inputs = inputs
	if c.condition, err = program(env, "condition", spec.Condition, cel.BoolType); err != nil {
		return nil, err
	}
	return c, nil
}

// WorkloadExposure is what the exposure rules made of one workload.
type WorkloadExposure struct {
	// Exposure is Open, Controlled, Small or Unknown.
	Exposure configv1alpha1.SSVCExposure
	// Rules are the rules that concluded Exposure, sorted, each once. No rule concludes Unknown.
	Rules []string
	// Missing and Failed say why the workload is Unknown, and are empty for any other exposure. Missing are
	// the inputs that were missing, and Failed the rules that couldn't be evaluated for another reason: their
	// CEL failed, hit the cost limit or passed a bound on time, they are unavailable, or the workload's
	// producers make more than 4 combinations. Both are sorted, each name once. A workload that no rule
	// applies to is Unknown with neither.
	Missing, Failed []string
}

// ExposureResult is what EvaluateExposure made of the workloads.
type ExposureResult struct {
	// Workloads are the exposures of the workloads, in their order.
	Workloads []WorkloadExposure
	// NotEvaluated counts, for the rule of each step that EvaluateExposure runs, by its name, the workloads
	// that it couldn't be evaluated for in some combination of producers, as Result.NotEvaluated counts
	// findings: an input was missing, other than an optional one, its CEL failed, hit the cost limit or passed
	// a bound on time, it is unavailable, or the workload's producers make more than 4 combinations. Each such
	// rule has an entry, 0 when it could be evaluated for every workload, and counts each workload once.
	NotEvaluated map[string]int
	// TimedOut counts, as NotEvaluated does, the workloads that a rule couldn't be evaluated for because a run
	// passed a bound on time, which NotEvaluated counts too.
	TimedOut map[string]int
}

// EvaluateExposure decides the exposure of each workload with the exposure rules of the steps (the design of
// entry points, section 5.6):
//   - The highest exposure that a rule concludes wins, in the order Open, Unknown, Controlled, Small.
//   - A rule that can't be evaluated for the workload counts as Unknown, where a finding rule doesn't apply:
//     an input is missing, optional or not, its CEL fails, hits the cost limit or passes a bound on time, or
//     it is unavailable. A missing answer must never let a lower rule decide.
//   - A workload that no rule applies to is Unknown, and so is every workload when the steps have no exposure
//     rule.
//   - Each combination of producers of the inputs that the rules read is evaluated apart, as Evaluate does,
//     and the highest exposure wins. A combination that no rule applies to counts as Unknown. With more than 4
//     combinations, no rule runs, and the workload is Unknown.
//
// So adding a rule never lowers a value that another rule concluded, nor a failure's Unknown: only the Unknown of a
// workload, or of a combination, that no rule applies to can become lower. The one exception is a rule whose inputs
// bring a workload past 4 combinations, which makes it Unknown. Neither the order of the steps nor that of the
// producers changes the exposure. A step that Unavailable made counts as Unknown for every workload, since
// its rule might conclude Open. The steps of finding rules are left out, so that a playbook's whole pipeline can be
// passed.
//
// Each workload holds its inputs as Evaluate's are held: by name, one for each producer. An input whose type
// comes from a source holds the source's answers in Subjects. One run of a rule for one workload may take at
// most a second, and the call at most 30 seconds for all its workloads, as Evaluate's bounds are: a run past a
// bound counts as Unknown, so the workloads that the call doesn't reach in time are Unknown. EvaluateExposure is
// pure as Evaluate is, and changes neither the steps nor the inputs.
func EvaluateExposure(steps []*Compiled, workloads []map[string][]Input) ExposureResult {
	b := startBounds()
	steps = slices.DeleteFunc(slices.Clone(steps), func(c *Compiled) bool { return c.exposure == "" && c.unavailable == nil })
	failed := failuresOf(steps, len(workloads))
	decided := make([]WorkloadExposure, len(workloads))
	for i, inputs := range workloads {
		decided[i] = exposureOf(b, steps, inputs, i, failed)
	}
	notEvaluated, timedOut := counts(failed)
	return ExposureResult{Workloads: decided, NotEvaluated: notEvaluated, TimedOut: timedOut}
}

// exposureOf decides the exposure of the i-th workload from its inputs, and records in failed the rules that
// couldn't be evaluated for it.
func exposureOf(b *bounds, steps []*Compiled, inputs map[string][]Input, i int, failed map[string]failures) WorkloadExposure {
	unknown := configv1alpha1.SSVCExposureUnknown
	combinations, ok := combinationsOf(steps, inputs)
	if !ok {
		w := WorkloadExposure{Exposure: unknown}
		for _, step := range steps {
			failed[step.name].mark(i, errTooManyCombinations)
			w.Failed = append(w.Failed, step.name)
		}
		w.Failed = sortedOnce(w.Failed)
		return w
	}
	var best configv1alpha1.SSVCExposure
	var missing, failing []string
	concluded := map[configv1alpha1.SSVCExposure][]string{}
	for _, in := range combinations {
		var top configv1alpha1.SSVCExposure
		for _, step := range steps {
			exposure, err := step.exposureIn(b, in)
			if err != nil {
				failed[step.name].mark(i, err)
				exposure = unknown
				if missed := (missingInputs{}); errors.As(err, &missed) {
					missing = append(missing, missed.names...)
				} else {
					failing = append(failing, step.name)
				}
			} else if exposure != "" {
				concluded[exposure] = append(concluded[exposure], step.name)
			}
			top = higher(top, exposure)
		}
		if top == "" {
			top = unknown
		}
		best = higher(best, top)
	}
	w := WorkloadExposure{Exposure: best, Rules: sortedOnce(concluded[best])}
	if best == unknown {
		w.Missing, w.Failed = sortedOnce(missing), sortedOnce(failing)
	}
	return w
}

// exposureIn runs an exposure step for a workload in one combination of producers. It returns the exposure
// that the step's rule concludes, "" where its condition doesn't hold, or why it can't be evaluated.
func (c *Compiled) exposureIn(b *bounds, in combination) (configv1alpha1.SSVCExposure, error) {
	vars, err := c.bind(in)
	if err != nil {
		return "", err
	}
	if o := c.evaluate(b, vars); o.err != nil || !o.applies {
		return "", o.err
	}
	return c.exposure, nil
}

// higher returns the higher of two exposures, by exposureOrder.
func higher(a, b configv1alpha1.SSVCExposure) configv1alpha1.SSVCExposure {
	if slices.Index(exposureOrder, b) > slices.Index(exposureOrder, a) {
		return b
	}
	return a
}

// sortedOnce returns the names sorted, each once.
func sortedOnce(names []string) []string {
	slices.Sort(names)
	return slices.Compact(names)
}
