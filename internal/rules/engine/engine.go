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

// Package engine evaluates the rules of a playbook for the findings of one subject. A rule is a Rule:
// CEL over a finding and the evidence that the rule names as its inputs, and the OpenVEX status that
// it concludes where its condition holds, or a status note where it has no status (decision 0033).
//
// Whatever a rule says, the engine keeps the core's guarantee (the design of collectors, evidence and
// rules, section 5.7). A finding wrongly settled as not affected is the worst error the operator can
// make, so each part of it errs towards holding a finding open:
//   - A rule applies to a finding only when every input that it names is present. Missing evidence
//     never settles anything, and neither does evidence that a playbook takes as optional and lacks.
//   - A rule fails closed when it can't be evaluated for a finding: an input is missing, its CEL fails,
//     hits the cost limit or passes a bound on time, or the step's rule is missing or not Ready. If the
//     rule concludes Affected or UnderInvestigation, or might, neither NotAffected nor Fixed applies to
//     the finding, and the finding records the rule, and why it couldn't be evaluated. A rule that would
//     settle the finding, and a hint, just don't apply. Evaluate counts, for each rule, the findings
//     that it couldn't be evaluated for, and apart those of a run that passed a bound on time.
//   - Evidence that several producers deliver is evaluated once for each combination of producers, and
//     the most cautious outcome wins, as it does between rules (decision 0043): one producer's evidence
//     can keep a finding open, but never settle it against another producer's. More than 4 combinations
//     hold every finding open, unevaluated.
//   - When the match of a rule fails for one finding, the rule can't tell which findings of the subject
//     it applies to, so it can't be evaluated for any of them.
//   - When several rules apply, the most cautious status wins: Affected, then UnderInvestigation, then
//     Fixed, then NotAffected. A finding that no rule settles or holds is UnderInvestigation, so the
//     order of the steps doesn't change the result, and a later step can't undo an earlier one's hold.
//
// The text of a finding comes from images and databases, which a crafted image can influence, and
// kubectl prints the strings of a status as they are. So every string that the engine writes into a
// finding is made printable and cut to the limits of the sheet's schema. The rules see neither change:
// they decide by the match as it comes, and by the evidence.
package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/text"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The limits of the schemas of a sheet and a report, which the findings fit.
const (
	// maxReasonLength is the most characters of a reason and of the text of a note.
	maxReasonLength = 256
	// maxNotes is the most notes that a finding carries.
	maxNotes = 4
	// The most characters of an ID, which is a vulnerability's or a package's, of a package name, of a
	// version, which is a package's or a fix's, and of a package type.
	maxIDLength      = 64
	maxNameLength    = 253
	maxVersionLength = 128
	maxTypeLength    = 32
	// maxFixedVersions is the most fixed versions that a finding lists.
	maxFixedVersions = 8
	// maxAliases is the most aliases that a finding lists, and maxAliasLength the most characters of one.
	maxAliases     = 8
	maxAliasLength = 64
	// maxCVSS is the most CVSS scores that a finding lists, and the most characters of a score's version
	// and of its vector.
	maxCVSS              = 4
	maxCVSSVersionLength = 16
	maxCVSSVectorLength  = 256
)

// notEvaluated starts the reason of a finding that a rule couldn't be evaluated for.
const notEvaluated = "could not be evaluated: "

// maxCombinations is the most combinations of producers that one call of Evaluate evaluates. Each runs every
// step for every finding, within the one bound on the time of the call, so more would leave each less time,
// and a playbook that names that many producers pins the ones that count.
const maxCombinations = 4

// tooManyCombinations is the reason of every finding of a call with more than maxCombinations combinations.
const tooManyCombinations = "more than 4 combinations of producers"

// Input is evidence that a playbook supplies to its rules under a name, as one producer delivered it.
type Input struct {
	// Present is false for evidence that the playbook names and that isn't there, such as one whose
	// collector hasn't reported yet. Such an input is missing, as one that the playbook doesn't name is.
	Present bool
	// Optional says that the playbook takes the evidence as optional (decision 0043). A rule fails closed
	// where it is missing, as where any input is, but a rule whose missing inputs are all optional isn't
	// counted as not evaluated: the playbook runs without them on purpose, which is no error of the rule.
	Optional bool
	// Data is the event's data, decoded from JSON as encoding/json decodes it into an any: objects as
	// map[string]any, arrays as []any, and numbers as float64.
	Data any
	// Coverage is the event's coverage, a whole-number percentage, or nil when the event has none.
	Coverage *int32
	// Time is when the collector saw what the evidence describes.
	Time time.Time
	// Source is the event's source.
	Source string
}

// Compiled is a step of a playbook: a rule whose CEL is compiled, or one that can't be evaluated at
// all. It is safe for concurrent use.
type Compiled struct {
	name string
	// status is what the rule concludes, and empty for a hint.
	status configv1alpha1.VEXStatus
	// justification is set exactly when status is NotAffected.
	justification configv1alpha1.VEXJustification
	// inputs are the names of the rule's inputs, sorted.
	inputs []string
	// match and reason are nil for a rule without them.
	match, condition, reason cel.Program
	// unavailable says why the step can't be evaluated at all. It is set for a step that Unavailable
	// made, and nil for one that Compile made.
	unavailable error
}

// Compile compiles a rule. Each evaluation of its match, its condition and its reason may cost at most
// 1,000,000, in CEL's units.
//
// Compile refuses a rule that it can't evaluate as written, though the API server should have refused
// most of these already: one without a name or an outcome, a status or justification that isn't one of
// OpenVEX's, a justification without NotAffected or the reverse, an input name that isn't a CEL
// identifier, that is reserved in CEL, that would hide the finding or that two inputs share, and an
// expression that doesn't compile, is longer than 4096 characters, or gives the wrong type: a bool for
// the match and the condition, and a string for the reason. An expression that can give anything, such
// as one that reads evidence, is checked when it runs. It refuses as well an expression that calls a
// function whose one call could run far past the bounds on time, which Evaluate can't stop, such as
// distinct or sort: env.go names them, and why.
func Compile(r *configv1alpha1.Rule) (*Compiled, error) {
	if r == nil {
		return nil, errors.New("no rule to compile")
	}
	if r.Name == "" {
		return nil, errors.New("the rule has no name")
	}
	c := &Compiled{name: r.Name}
	var err error
	if c.status, c.justification, err = outcomeOf(r.Spec.Outcome); err != nil {
		return nil, err
	}
	env, inputs, err := environment(r.Spec.Inputs)
	if err != nil {
		return nil, err
	}
	c.inputs = inputs
	if r.Spec.Match != nil {
		if c.match, err = program(env, "match", *r.Spec.Match, cel.BoolType); err != nil {
			return nil, err
		}
	}
	if c.condition, err = program(env, "condition", r.Spec.Condition, cel.BoolType); err != nil {
		return nil, err
	}
	if r.Spec.Reason != nil {
		if c.reason, err = program(env, "reason", *r.Spec.Reason, cel.StringType); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// justifications are OpenVEX's five.
var justifications = []configv1alpha1.VEXJustification{
	configv1alpha1.VEXJustificationComponentNotPresent,
	configv1alpha1.VEXJustificationVulnerableCodeNotPresent,
	configv1alpha1.VEXJustificationVulnerableCodeNotInExecutePath,
	configv1alpha1.VEXJustificationVulnerableCodeCannotBeControlledByAdversary,
	configv1alpha1.VEXJustificationInlineMitigationsAlreadyExist,
}

// outcomeOf returns the status and the justification of an outcome, and an error for one that no rule
// can have. A status this code doesn't know would have no place in the order of statuses.
func outcomeOf(o *configv1alpha1.RuleOutcome) (configv1alpha1.VEXStatus, configv1alpha1.VEXJustification, error) {
	if o == nil {
		return "", "", errors.New("the rule has no outcome, where a hint has an empty one")
	}
	status, justification := ptr.Deref(o.Status, ""), ptr.Deref(o.Justification, "")
	switch status {
	case "", configv1alpha1.VEXStatusAffected, configv1alpha1.VEXStatusUnderInvestigation,
		configv1alpha1.VEXStatusFixed, configv1alpha1.VEXStatusNotAffected:
	default:
		return "", "", fmt.Errorf("the status %q isn't Affected, UnderInvestigation, NotAffected or Fixed", status)
	}
	if (justification != "") != (status == configv1alpha1.VEXStatusNotAffected) {
		return "", "", errors.New("a justification is set exactly when the status is NotAffected")
	}
	if justification != "" && !slices.Contains(justifications, justification) {
		return "", "", fmt.Errorf("the justification %q isn't one of OpenVEX's", justification)
	}
	return status, justification, nil
}

// program compiles one expression of a rule, which must give want or a value whose type only its
// evaluation knows.
func program(env *cel.Env, what, expression string, want *cel.Type) (cel.Program, error) {
	ast, issues := env.Compile(expression)
	if issues.Err() != nil {
		return nil, fmt.Errorf("the %s doesn't compile: %w", what, issues.Err())
	}
	if t := ast.OutputType(); !t.IsExactType(want) && !t.IsExactType(cel.DynType) {
		return nil, fmt.Errorf("the %s gives %s, where it must give %s", what, t, want)
	}
	if err := refuseCalls(ast.NativeRep().Expr()); err != nil {
		return nil, fmt.Errorf("the %s %w", what, err)
	}
	prg, err := env.Program(ast, cel.CostLimit(costLimit), cel.InterruptCheckFrequency(interruptEvery))
	if err != nil {
		return nil, fmt.Errorf("the %s: %w", what, err)
	}
	return prg, nil
}

// Unavailable stands for a step whose rule is missing or not Ready. It can't be evaluated and might
// hold, so it keeps every finding from NotAffected and Fixed (fail closed, spec 5.7). Each finding
// records it, under the name of the step's rule, with the reason "could not be evaluated: " and why.
func Unavailable(name, reason string) *Compiled {
	if reason == "" {
		reason = "the rule is unavailable"
	}
	return &Compiled{name: name, unavailable: errors.New(reason)}
}

// Note is what a rule without a status, a hint, adds to a finding: OpenVEX's status_notes.
type Note struct{ Rule, Text string }

// Finding is one vulnerability in one package of the subject, and what the steps made of it.
type Finding struct {
	// Match is the finding as its matches describe it, merged per vulnerability and package, as phase
	// 2a merged matches, and with its text printable and cut to the schema of a sheet.
	Match evidence.Match
	// Status is Affected, UnderInvestigation, NotAffected or Fixed.
	Status configv1alpha1.VEXStatus
	// Rule is the rule that decided the status, or that couldn't be evaluated and held the finding
	// open. It is empty when no rule did, and the finding is UnderInvestigation.
	Rule string
	// Reason is the reason that the rule gave, or why it couldn't be evaluated. It may be empty.
	Reason string
	// Justification is set exactly when Status is NotAffected.
	Justification configv1alpha1.VEXJustification
	// Notes are from the hints that apply, at most 4, the first by rule name. Each has a text.
	Notes []Note
}

// Evaluate runs the steps for each finding, under the core's guarantee and the order of statuses.
// It is pure: the same input always gives the same output, whatever the order of the steps, of the
// matches and of the producers of an input, provided that no rule depends on the order in which CEL goes
// through the keys of a map,
// which CEL leaves open, and that no run passes a bound on time. It changes neither the inputs nor the
// matches, and the result shares no memory with them. The steps are those that Compile and Unavailable
// return, and none is nil.
//
// Evaluation is bounded in time as well as in cost. One run of a step for one finding, its match, its
// condition and its reason together, may take at most a second, and one call of Evaluate at most 30
// seconds for all its runs. The bounds are far above what an image takes, and only a run past one makes
// the result depend on time: the run counts as one that couldn't be evaluated, with the reason "took
// longer than" and the bound, so a rule that holds fails closed, a rule that settles doesn't apply, and
// a hint adds nothing, as for any other failure. The cost alone doesn't bound the time: while CEL counts
// the cost of a rule that goes through a list, the time grows with the square of the list's length, so
// a crafted image could otherwise hold the hub for minutes within the cost limit. The bounds are on wall
// time, so a process that is stalled or starved passes them with any rule. The result counts such runs
// apart, so that the caller can tell an evaluation whose result depends on when it ran.
//
// The bounds are checked between the items of a comprehension, every 100 of them, and after each part of
// a run: its match, its condition and its reason. A function does all its work in one call, which no
// check can stop, so Compile refuses the functions whose one call could run far past a bound.
//
// Matches of one vulnerability in one package make one finding, which is:
//   - known to be exploited, when any match says so
//   - of the most severe severity, from Critical down to Negligible, without regard to case; a
//     severity that isn't one of these is Unknown
//   - of the fix state of the match that knows most: fixed, then wont-fix, then not-fixed; any other
//     state, the empty one included, is unknown
//   - fixed by the sorted union of the fixed versions, and scored by the union of the CVSS scores, the
//     newest version first
//
// and that takes the package's name, version and type from the first of them, in the order of those
// fields. The rules see it so. The findings come sorted by vulnerability ID, then by package ID.
//
// The inputs hold, by name, the evidence of each producer that delivers it, and a name without producers
// is missing. Evaluate runs the steps once for each combination of producers of the inputs that the steps
// read: an input that no step reads changes nothing, so its producers make no combinations. Of what the
// combinations make of a finding, the most cautious wins, by the order of statuses, and a combination that
// no rule settled or held leaves the finding UnderInvestigation. So a finding that the evidence of one
// producer settles, and another's doesn't, stays open. Of two verdicts of one status, one that a rule
// decided wins over none, since it says why. The notes of every combination add up. With more than 4
// combinations, no step runs: every finding is UnderInvestigation, with the reason "more than 4
// combinations of producers", and each step's rule counts every finding as not evaluated.
//
// A finding shows each of its strings made printable, then cut to the limits of the sheet's schema. It
// lists the first 8 fixed versions, and the 4 newest CVSS scores, which urgency reads. An empty
// vulnerability ID, package ID, package name or package type becomes "unknown", which claims nothing,
// and so does the text of a note that has none.
func Evaluate(steps []*Compiled, inputs map[string][]Input, matches []evidence.Match) Result {
	b := startBounds()
	merged := merge(matches)
	failed := make(map[string]failures, len(steps))
	for _, step := range steps {
		if _, ok := failed[step.name]; !ok {
			failed[step.name] = failures{notEvaluated: make([]bool, len(merged)), timedOut: make([]bool, len(merged))}
		}
	}
	results := make([]result, len(merged))
	if combinations, ok := combinationsOf(steps, inputs); ok {
		for c, in := range combinations {
			own := make([]result, len(merged))
			for _, step := range steps {
				step.run(b, in, merged, own, failed[step.name])
			}
			for i := range results {
				if c == 0 {
					results[i] = own[i]
				} else {
					results[i].join(own[i])
				}
			}
		}
	} else {
		for i := range results {
			results[i].consider(verdict{status: configv1alpha1.VEXStatusUnderInvestigation, reason: tooManyCombinations})
		}
		for _, f := range failed {
			for i := range f.notEvaluated {
				f.notEvaluated[i] = true
			}
		}
	}

	findings := make([]Finding, 0, len(merged))
	for i, m := range merged {
		findings = append(findings, results[i].finding(shown(m)))
	}
	notEvaluated := make(map[string]int, len(failed))
	timedOut := make(map[string]int, len(failed))
	for name, f := range failed {
		notEvaluated[name], timedOut[name] = count(f.notEvaluated), count(f.timedOut)
	}
	return Result{Findings: findings, NotEvaluated: notEvaluated, TimedOut: timedOut}
}

// count returns how many of the flags are set.
func count(flags []bool) int {
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n
}

// Result is what Evaluate made of the findings of one subject.
type Result struct {
	// Findings are the findings, sorted by vulnerability ID, then by package ID.
	Findings []Finding
	// NotEvaluated counts, for each rule that a step runs, by its name, the findings that it couldn't be
	// evaluated for in some combination of producers: an input was missing, other than an optional one,
	// its CEL failed, hit the cost limit or passed a bound on time, its match failed for a finding of the
	// subject, or it is unavailable. With more than 4 combinations, it counts every finding. It counts a
	// rule of every kind, also one that would settle a finding and a hint, whose failures leave no trace
	// in the findings. Each step's rule has an entry, 0 when it could be evaluated for every finding, and
	// a rule that two steps run, or that fails in several combinations, counts each finding once.
	NotEvaluated map[string]int
	// TimedOut counts, as NotEvaluated does, the findings that a rule couldn't be evaluated for because a
	// run passed a bound on time, which NotEvaluated counts too. Only these failures depend on when the
	// evaluation ran: the others fail the same way each time. Each step's rule has an entry, 0 when no
	// run of it passed a bound.
	TimedOut map[string]int
}

// Timely reports whether every run kept within the bounds on time, so that nothing in the result depends
// on when the evaluation ran.
func (r Result) Timely() bool {
	for _, n := range r.TimedOut {
		if n > 0 {
			return false
		}
	}
	return true
}

// The bounds on the time of evaluation, which Evaluate describes.
const (
	// runBound is the most time that one step may take for one finding.
	runBound = time.Second
	// callBound is the most time that one call of Evaluate may take.
	callBound = 30 * time.Second
)

// setBounds holds the bounds of a run and of a call that SetBounds set in place of runBound and
// callBound, or nil. It is atomic, as a test sets it while evaluations may run.
var setBounds atomic.Pointer[[2]time.Duration]

// SetBounds sets the bounds on the time of a run and of a call of Evaluate in place of a second and 30
// seconds, and returns a function that restores the bounds before. It is for tests, which need small
// bounds: a bound of 0 is passed as soon as a run starts. A call of Evaluate keeps the bounds that it
// started with.
func SetBounds(run, call time.Duration) (restore func()) {
	before := setBounds.Swap(&[2]time.Duration{run, call})
	return func() { setBounds.Store(before) }
}

// interruptEvery is how many items CEL goes through in a comprehension before it checks whether the
// run has passed its bound.
const interruptEvery = 100

// bounds are the bounds on the time of one call of Evaluate, fixed when the call starts.
type bounds struct {
	run, call time.Duration
	// callEnd is when the call passes its bound.
	callEnd time.Time
}

func startBounds() *bounds {
	run, call := runBound, callBound
	if set := setBounds.Load(); set != nil {
		run, call = set[0], set[1]
	}
	return &bounds{run: run, call: call, callEnd: time.Now().Add(call)}
}

// runEnd is when a run that starts now passes a bound: its own, or the call's if that comes first.
func (b *bounds) runEnd() time.Time {
	if end := time.Now().Add(b.run); end.Before(b.callEnd) {
		return end
	}
	return b.callEnd
}

// passed returns the error of a run that ends at end once it has passed a bound, and nil before. It
// reads the clock, so a bound of 0 is passed as soon as a run starts.
func (b *bounds) passed(end time.Time) error {
	now := time.Now()
	switch {
	case !now.Before(b.callEnd):
		return tooLong{b.call}
	case !now.Before(end):
		return tooLong{b.run}
	}
	return nil
}

// timely returns the error of a part of a run that ends at end: that the run passed a bound, whatever
// the part gave, else the error of the part's CEL, with the name of the part.
func (b *bounds) timely(end time.Time, part string, err error) error {
	if passed := b.passed(end); passed != nil {
		return passed
	}
	if err != nil {
		return fmt.Errorf("%s: %w", part, err)
	}
	return nil
}

// tooLong is why a run that passed a bound on time couldn't be evaluated.
type tooLong struct{ bound time.Duration }

func (e tooLong) Error() string {
	return "took longer than " + e.bound.String()
}

// combination is what the rules see of the inputs in one combination of producers: of each input that
// a step reads, the evidence of one of its producers, as CEL's values when it is present, and the names
// of the inputs that are missing and optional.
type combination struct {
	present  map[string]ref.Val
	optional map[string]bool
}

// combinationsOf returns every combination of producers of the inputs that the steps read, and false when
// there are more than maxCombinations. An input of a name without producers is missing in each. The
// evidence of each producer is converted to CEL's values once for the call, so that a rule that goes
// through an input's lists for each finding doesn't convert them again each time, nor again in each
// combination.
func combinationsOf(steps []*Compiled, inputs map[string][]Input) ([]combination, bool) {
	var names []string
	for _, step := range steps {
		names = append(names, step.inputs...)
	}
	slices.Sort(names)
	names = slices.Compact(names)
	count := 1
	for _, name := range names {
		if count *= max(1, len(inputs[name])); count > maxCombinations {
			return nil, false
		}
	}
	converted := make(map[string][]ref.Val, len(names))
	for _, name := range names {
		values := make([]ref.Val, len(inputs[name]))
		for i, in := range inputs[name] {
			if in.Present {
				values[i] = variable(in)
			}
		}
		converted[name] = values
	}
	// choice holds, for each name, which of its producers the next combination takes, as the digits of a
	// number whose places count the producers of each name.
	choice := make([]int, len(names))
	combinations := make([]combination, 0, count)
	for range count {
		c := combination{present: map[string]ref.Val{}, optional: map[string]bool{}}
		for k, name := range names {
			if len(inputs[name]) == 0 {
				continue
			}
			switch in := inputs[name][choice[k]]; {
			case in.Present:
				c.present[name] = converted[name][choice[k]]
			case in.Optional:
				c.optional[name] = true
			}
		}
		combinations = append(combinations, c)
		for k, name := range names {
			if choice[k]++; choice[k] < len(inputs[name]) {
				break
			}
			choice[k] = 0
		}
	}
	return combinations, true
}

// outcome is what one run of a step made of one finding.
type outcome struct {
	// applies is set where the step's condition holds, and reason is the reason that it gave.
	applies bool
	reason  string
	// err says why the step couldn't be evaluated for the finding, and inMatch whether its match is
	// what failed.
	err     error
	inMatch bool
}

// failures holds, for each finding of the subject, whether a step's rule couldn't be evaluated for it, and
// whether a run that passed a bound on time is why.
type failures struct {
	notEvaluated, timedOut []bool
}

// mark records that the rule couldn't be evaluated for the i-th finding, because of err. Inputs that are
// missing and optional aren't counted: the playbook runs without them on purpose.
func (f failures) mark(i int, err error) {
	if missing := (missingInputs{}); errors.As(err, &missing) && missing.optional {
		return
	}
	f.notEvaluated[i] = true
	if past := (tooLong{}); errors.As(err, &past) {
		f.timedOut[i] = true
	}
}

// run evaluates the step for each finding of the subject, and records what it concludes in results,
// and in failed each finding that it couldn't be evaluated for. A match that fails for one finding
// keeps the step from all of them, so the step records nothing until it has run for every finding.
func (c *Compiled) run(b *bounds, in combination, findings []evidence.Match, results []result, failed failures) {
	vars, err := c.bind(in)
	if err != nil {
		c.failAll(results, failed, err)
		return
	}
	outcomes := make([]outcome, len(findings))
	for i, f := range findings {
		vars[findingVariable] = f
		if outcomes[i] = c.evaluate(b, vars); outcomes[i].inMatch {
			c.failAll(results, failed, outcomes[i].err)
			return
		}
	}
	for i, o := range outcomes {
		switch {
		case o.err != nil:
			c.fail(results, failed, i, o.err)
		case o.applies:
			c.apply(&results[i], o.reason)
		}
	}
}

// bind returns the variables of the step's inputs in a combination of producers, or why it can't be
// evaluated without looking at a finding: it is unavailable, or inputs are missing.
func (c *Compiled) bind(in combination) (map[string]any, error) {
	if c.unavailable != nil {
		return nil, c.unavailable
	}
	vars := make(map[string]any, len(c.inputs)+1)
	missing := missingInputs{optional: true}
	for _, name := range c.inputs {
		v, ok := in.present[name]
		if !ok {
			missing.names = append(missing.names, name)
			missing.optional = missing.optional && in.optional[name]
			continue
		}
		vars[name] = v
	}
	if len(missing.names) > 0 {
		return nil, missing
	}
	return vars, nil
}

// missingInputs is why a step can't be evaluated when inputs that its rule names are missing.
type missingInputs struct {
	// names are the inputs that are missing, in order.
	names []string
	// optional says that each of them is optional.
	optional bool
}

func (e missingInputs) Error() string {
	quoted := make([]string, len(e.names))
	for i, name := range e.names {
		quoted[i] = strconv.Quote(name)
	}
	if len(quoted) == 1 {
		return fmt.Sprintf("the input %s is missing", quoted[0])
	}
	return fmt.Sprintf("the inputs %s are missing", strings.Join(quoted, ", "))
}

// evaluate runs the step for one finding: its match, then its condition and its reason where the match
// holds. A run past a bound on time fails, whatever its CEL gave. CEL stops a comprehension that runs
// past the bound, and an expression that would absorb the interruption, such as one that ors it with
// true, fails all the same.
func (c *Compiled) evaluate(b *bounds, vars map[string]any) outcome {
	end := b.runEnd()
	if err := b.passed(end); err != nil {
		return outcome{err: err, inMatch: c.match != nil}
	}
	ctx, cancel := context.WithDeadline(context.Background(), end)
	defer cancel()

	if c.match != nil {
		matches, err := evalBool(ctx, c.match, vars)
		if err = b.timely(end, "match", err); err != nil {
			return outcome{err: err, inMatch: true}
		}
		if !matches {
			return outcome{}
		}
	}
	holds, err := evalBool(ctx, c.condition, vars)
	if err = b.timely(end, "condition", err); err != nil || !holds {
		return outcome{err: err}
	}
	if c.reason == nil {
		return outcome{applies: true}
	}
	reason, err := evalString(ctx, c.reason, vars)
	if err = b.timely(end, "reason", err); err != nil {
		return outcome{err: err}
	}
	return outcome{applies: true, reason: reason}
}

// evalBool evaluates an expression that must give a bool.
func evalBool(ctx context.Context, prg cel.Program, vars map[string]any) (bool, error) {
	out, _, err := prg.ContextEval(ctx, vars)
	if err != nil {
		return false, err
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, fmt.Errorf("the result is %s, not bool", out.Type().TypeName())
	}
	return bool(b), nil
}

// evalString evaluates an expression that must give a string.
func evalString(ctx context.Context, prg cel.Program, vars map[string]any) (string, error) {
	out, _, err := prg.ContextEval(ctx, vars)
	if err != nil {
		return "", err
	}
	s, ok := out.(types.String)
	if !ok {
		return "", fmt.Errorf("the result is %s, not string", out.Type().TypeName())
	}
	return string(s), nil
}

// holds reports whether the step may hold a finding open: its rule concludes Affected or
// UnderInvestigation, or it is unavailable, and so might.
func (c *Compiled) holds() bool {
	return c.unavailable != nil ||
		c.status == configv1alpha1.VEXStatusAffected || c.status == configv1alpha1.VEXStatusUnderInvestigation
}

// fail records that the step couldn't be evaluated for the i-th finding, because of err. A step that may
// hold the finding open holds it, as UnderInvestigation, since it can't claim more. A step that would
// settle it, and a hint, don't apply. Every step's failure counts, and one of a run that passed a bound
// on time counts apart as well.
func (c *Compiled) fail(results []result, failed failures, i int, err error) {
	failed.mark(i, err)
	if c.holds() {
		results[i].consider(verdict{
			status: configv1alpha1.VEXStatusUnderInvestigation, rule: c.name, reason: shownReason(notEvaluated + err.Error()),
		})
	}
}

// failAll records that the step couldn't be evaluated for any finding of the subject.
func (c *Compiled) failAll(results []result, failed failures, err error) {
	for i := range results {
		c.fail(results, failed, i, err)
	}
}

// apply records what the step concludes for a finding that its condition holds for.
func (c *Compiled) apply(r *result, reason string) {
	if c.status == "" {
		r.notes = append(r.notes, Note{Rule: c.name, Text: text.Required(reason, maxReasonLength)})
		return
	}
	r.consider(verdict{status: c.status, rule: c.name, reason: shownReason(reason), justification: c.justification})
}

// shownReason is a reason as a finding shows it.
func shownReason(s string) string {
	return text.CutChars(text.Printable(s), maxReasonLength)
}

// verdict is a status that one step concluded for a finding.
type verdict struct {
	status        configv1alpha1.VEXStatus
	rule, reason  string
	justification configv1alpha1.VEXJustification
}

// result is what the steps made of one finding so far.
type result struct {
	// decided is set once a step concluded a status, and verdict is the one that comes first.
	decided bool
	verdict verdict
	notes   []Note
}

// consider keeps v when it comes before the verdict that the result has. The order is total, so the
// verdict that stands doesn't depend on the order of the steps.
func (r *result) consider(v verdict) {
	if !r.decided || compareVerdicts(v, r.verdict) < 0 {
		r.decided, r.verdict = true, v
	}
}

// join keeps, of the verdict of r and of other, what the steps made of the same finding in another
// combination of producers, the more cautious, and adds up their notes. A combination in which no step
// decided leaves the finding UnderInvestigation. Of two verdicts of one status, one that a rule decided
// comes first, since it says why. The order is total, so the verdict that stands doesn't depend on the
// order of the combinations.
func (r *result) join(other result) {
	r.notes = append(r.notes, other.notes...)
	if before(other, *r) {
		r.decided, r.verdict = other.decided, other.verdict
	}
}

// before reports whether the verdict of a comes before the verdict of b, by the order of join.
func before(a, b result) bool {
	if ra, rb := rank(a.status()), rank(b.status()); ra != rb {
		return ra < rb
	}
	if a.decided != b.decided {
		return a.decided
	}
	return a.decided && compareVerdicts(a.verdict, b.verdict) < 0
}

// status is the status of the finding that a step decided, and UnderInvestigation when none did.
func (r result) status() configv1alpha1.VEXStatus {
	if !r.decided {
		return configv1alpha1.VEXStatusUnderInvestigation
	}
	return r.verdict.status
}

// compareVerdicts orders verdicts by their status, the most cautious first, then by the name of their
// rule. Verdicts that only steps of one name can give, which a playbook that repeats a rule has, are
// ordered by the rest.
func compareVerdicts(a, b verdict) int {
	return cmp.Or(
		cmp.Compare(rank(a.status), rank(b.status)),
		strings.Compare(a.rule, b.rule),
		strings.Compare(a.reason, b.reason),
		strings.Compare(string(a.justification), string(b.justification)),
	)
}

// rank is the place of a status in the order of caution: Affected, then UnderInvestigation, then
// Fixed, then NotAffected. Compile accepts no other status.
func rank(s configv1alpha1.VEXStatus) int {
	switch s {
	case configv1alpha1.VEXStatusAffected:
		return 0
	case configv1alpha1.VEXStatusUnderInvestigation:
		return 1
	case configv1alpha1.VEXStatusFixed:
		return 2
	}
	return 3
}

// finding is the finding of a match and of what the steps made of it.
func (r *result) finding(m evidence.Match) Finding {
	f := Finding{Match: m, Status: configv1alpha1.VEXStatusUnderInvestigation, Notes: firstNotes(r.notes)}
	if r.decided {
		f.Status, f.Rule, f.Reason, f.Justification = r.verdict.status, r.verdict.rule, r.verdict.reason, r.verdict.justification
	}
	return f
}

// firstNotes returns the first notes by rule name, then by text, each once.
func firstNotes(notes []Note) []Note {
	if len(notes) == 0 {
		return nil
	}
	sorted := slices.Clone(notes)
	slices.SortFunc(sorted, func(a, b Note) int {
		return cmp.Or(strings.Compare(a.Rule, b.Rule), strings.Compare(a.Text, b.Text))
	})
	sorted = slices.Compact(sorted)
	return slices.Clip(sorted[:min(len(sorted), maxNotes)])
}

// ---- matches ----

// The severity and the fix state of a match that says nothing that is known, as the sources spell them.
const (
	severityUnknown = "Unknown"
	fixStateUnknown = "unknown"
)

// severities lists the severities of a match from the most severe down, as the sources spell them.
var severities = []string{"Critical", "High", "Medium", "Low", "Negligible", severityUnknown}

// fixStates lists the fix states of a match from the one that knows most, as the sources spell them:
// a fix exists, none will come, none exists yet, and nothing is known.
var fixStates = []string{"fixed", "wont-fix", "not-fixed", fixStateUnknown}

// severityOf returns a severity as the sources spell it, whatever its case. Any other value is unknown.
func severityOf(s string) string {
	for _, known := range severities {
		if strings.EqualFold(s, known) {
			return known
		}
	}
	return severityUnknown
}

// fixStateOf returns a fix state as the sources spell it. An empty state is what a source writes that
// says nothing of a fix, and is unknown, like any other state that isn't one of the three.
func fixStateOf(s string) string {
	if slices.Contains(fixStates, s) {
		return s
	}
	return fixStateUnknown
}

// merge returns one match for each vulnerability and package that the matches name, sorted by
// vulnerability ID, then package ID. A source such as Grype can report one vulnerability for one
// package through several of its matchers, and each match may say something else about it.
//
// The result doesn't depend on the order of the matches, because they are sorted first, down to the
// fields that describe the package, and the merged match takes those from the first of them. It shares
// no memory with the matches.
func merge(matches []evidence.Match) []evidence.Match {
	sorted := slices.Clone(matches)
	slices.SortFunc(sorted, func(a, b evidence.Match) int {
		return cmp.Or(
			strings.Compare(a.VulnerabilityID, b.VulnerabilityID),
			strings.Compare(a.PackageID, b.PackageID),
			strings.Compare(a.PackageName, b.PackageName),
			strings.Compare(a.PackageVersion, b.PackageVersion),
			strings.Compare(a.PackageType, b.PackageType),
		)
	})

	merged := make([]evidence.Match, 0, len(sorted))
	// fixTargets and updateTargets hold the targets that the matches of each merged match name, each once. A merged
	// match keeps a target only where its matches name one and the same: two versions can't be told apart by which
	// is the source's, and a wrong target is worse than none.
	var fixTargets, updateTargets [][]string
	for _, m := range sorted {
		last := len(merged) - 1
		if last < 0 || merged[last].VulnerabilityID != m.VulnerabilityID || merged[last].PackageID != m.PackageID {
			merged = append(merged, evidence.Match{
				VulnerabilityID: m.VulnerabilityID, PackageID: m.PackageID,
				PackageName: m.PackageName, PackageVersion: m.PackageVersion, PackageType: m.PackageType,
				Severity: severityUnknown, FixState: fixStateUnknown,
			})
			fixTargets, updateTargets = append(fixTargets, nil), append(updateTargets, nil)
			last++
		}
		add(&merged[last], m)
		fixTargets[last] = withTarget(fixTargets[last], m.FixTarget)
		updateTargets[last] = withTarget(updateTargets[last], m.UpdateTarget)
	}
	for i := range merged {
		merged[i].FixTarget = only(fixTargets[i])
		merged[i].UpdateTarget = only(updateTargets[i])
		slices.Sort(merged[i].FixedVersions)
		merged[i].FixedVersions = slices.Compact(merged[i].FixedVersions)
		slices.Sort(merged[i].Aliases)
		merged[i].Aliases = slices.Compact(merged[i].Aliases)
		slices.SortFunc(merged[i].CVSS, compareCVSS)
		merged[i].CVSS = slices.Compact(merged[i].CVSS)
	}
	return merged
}

// withTarget returns targets with target in it, unless it is empty or there already.
func withTarget(targets []string, target string) []string {
	if target == "" || slices.Contains(targets, target) {
		return targets
	}
	return append(targets, target)
}

// only returns the one target in targets, and "" where there is none or are several.
func only(targets []string) string {
	if len(targets) != 1 {
		return ""
	}
	return targets[0]
}

// add merges a match into a merged one. The lists are sorted and made unique once all matches are in.
func add(merged *evidence.Match, m evidence.Match) {
	merged.KnownExploited = merged.KnownExploited || m.KnownExploited
	if s := severityOf(m.Severity); slices.Index(severities, s) < slices.Index(severities, merged.Severity) {
		merged.Severity = s
	}
	if f := fixStateOf(m.FixState); slices.Index(fixStates, f) < slices.Index(fixStates, merged.FixState) {
		merged.FixState = f
	}
	merged.FixedVersions = append(merged.FixedVersions, m.FixedVersions...)
	merged.Aliases = append(merged.Aliases, m.Aliases...)
	merged.CVSS = append(merged.CVSS, m.CVSS...)
}

// compareCVSS orders scores by their version, the newest first, then by their vector. The versions of
// CVSS, 2.0, 3.0, 3.1 and 4.0, compare as strings in the order in which they came out.
func compareCVSS(a, b evidence.CVSS) int {
	return cmp.Or(strings.Compare(b.Version, a.Version), strings.Compare(a.Vector, b.Vector))
}

// shown is a merged match as a finding shows it: each string printable, then cut to the schema's
// limits, and "unknown" where the schema requires text that the match doesn't have.
func shown(m evidence.Match) evidence.Match {
	return evidence.Match{
		VulnerabilityID: text.Required(m.VulnerabilityID, maxIDLength),
		PackageID:       text.Required(m.PackageID, maxIDLength),
		PackageName:     text.Required(m.PackageName, maxNameLength),
		PackageVersion:  text.CutChars(text.Printable(m.PackageVersion), maxVersionLength),
		PackageType:     text.Required(m.PackageType, maxTypeLength),
		Severity:        m.Severity,
		FixState:        m.FixState,
		FixedVersions:   shownVersions(m.FixedVersions),
		FixTarget:       shownTarget(m.FixTarget),
		UpdateTarget:    shownTarget(m.UpdateTarget),
		Aliases:         shownAliases(m.Aliases),
		KnownExploited:  m.KnownExploited,
		CVSS:            shownCVSS(m.CVSS),
	}
}

// shownVersions returns the first fixed versions as a finding shows them: made printable, sorted and
// made unique as they are shown, and each cut to its length.
func shownVersions(versions []string) []string {
	if len(versions) == 0 {
		return nil
	}
	listed := make([]string, len(versions))
	for i, v := range versions {
		listed[i] = text.Printable(v)
	}
	slices.Sort(listed)
	listed = slices.Compact(listed)
	listed = listed[:min(len(listed), maxFixedVersions)]
	for i, v := range listed {
		listed[i] = text.CutChars(v, maxVersionLength)
	}
	return slices.Clip(listed)
}

// shownTarget returns a target as a finding shows it, or "" where showing would change it: a version that is cut or
// holds a character that can't be printed is another version, and a wrong target is worse than none.
func shownTarget(target string) string {
	if target == "" || text.Printable(target) != target || utf8.RuneCountInString(target) > maxVersionLength {
		return ""
	}
	return target
}

// shownAliases returns the first aliases as a finding shows them, sorted and made unique. An alias that is empty,
// longer than its limit or holds a character that can't be printed is left out, as it can't be shown as it is.
func shownAliases(aliases []string) []string {
	var listed []string
	for _, a := range aliases {
		if a != "" && text.Printable(a) == a && utf8.RuneCountInString(a) <= maxAliasLength {
			listed = append(listed, a)
		}
	}
	slices.Sort(listed)
	listed = slices.Compact(listed)
	if len(listed) == 0 {
		return nil
	}
	return slices.Clip(listed[:min(len(listed), maxAliases)])
}

// Exact reports whether a match, as a finding shows it, can only have been shown from that very match:
// none of its strings is the placeholder that stands for no text, holds U+FFFD, which stands for a
// character that can't be printed, or is as long as its limit, where showing may have cut it, and it
// lists fewer fixed versions and CVSS scores than a finding holds, so that showing left none out. The
// rules then see that match again when they evaluate what a finding shows, and Evaluate gives the same
// finding, so a finding can be evaluated again from a sheet. A match that showing may have changed
// can't: a placeholder or a cut package ID could make a rule find another package than the match named,
// and settle the finding. A shown match that only might have been changed, such as one whose package ID
// is "unknown" itself, counts as changed.
func Exact(shown evidence.Match) bool {
	required := func(s string, limit int) bool { return s != text.Placeholder && untouched(s, limit) }
	if !required(shown.VulnerabilityID, maxIDLength) || !required(shown.PackageID, maxIDLength) ||
		!required(shown.PackageName, maxNameLength) || !required(shown.PackageType, maxTypeLength) ||
		!untouched(shown.PackageVersion, maxVersionLength) {
		return false
	}
	if len(shown.FixedVersions) >= maxFixedVersions || len(shown.CVSS) >= maxCVSS {
		return false
	}
	for _, v := range shown.FixedVersions {
		if !untouched(v, maxVersionLength) {
			return false
		}
	}
	for _, s := range shown.CVSS {
		if !untouched(s.Version, maxCVSSVersionLength) || !untouched(s.Vector, maxCVSSVectorLength) {
			return false
		}
	}
	return true
}

// untouched reports whether a string that a finding shows is the string that it was shown from: it is
// valid UTF-8 without U+FFFD, which stands for what showing replaced, and shorter than limit, so that
// no cut shortened it.
func untouched(s string, limit int) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, utf8.RuneError) && utf8.RuneCountInString(s) < limit
}

// shownCVSS returns the newest CVSS scores as a finding shows them: made printable and cut to their
// lengths, then sorted, the newest version first, and made unique as they are shown.
func shownCVSS(scores []evidence.CVSS) []evidence.CVSS {
	if len(scores) == 0 {
		return nil
	}
	listed := make([]evidence.CVSS, len(scores))
	for i, s := range scores {
		listed[i] = evidence.CVSS{
			Version: text.CutChars(text.Printable(s.Version), maxCVSSVersionLength),
			Vector:  text.CutChars(text.Printable(s.Vector), maxCVSSVectorLength),
		}
	}
	slices.SortFunc(listed, compareCVSS)
	listed = slices.Compact(listed)
	return slices.Clip(listed[:min(len(listed), maxCVSS)])
}
