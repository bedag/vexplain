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
//     never settles anything.
//   - A rule fails closed when it can't be evaluated for a finding: an input is missing, its CEL fails
//     or hits the cost limit, or the step's rule is missing or not Ready. If the rule concludes
//     Affected or UnderInvestigation, or might, neither NotAffected nor Fixed applies to the finding,
//     and the finding records the rule, and why it couldn't be evaluated. A rule that would settle the
//     finding, and a hint, just don't apply.
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
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
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
)

// notEvaluated starts the reason of a finding that a rule couldn't be evaluated for.
const notEvaluated = "could not be evaluated: "

// Input is evidence that a playbook supplies to its rules under a name.
type Input struct {
	// Present is false for evidence that the playbook names and that isn't there, such as one whose
	// collector hasn't reported yet. Such an input is missing, as one that the playbook doesn't name is.
	Present bool
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
// as one that reads evidence, is checked when it runs.
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
	prg, err := env.Program(ast, cel.CostLimit(costLimit))
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
// It is pure: the same input always gives the same output, whatever the order of the steps and of the
// matches, provided that no rule depends on the order in which CEL goes through the keys of a map,
// which CEL leaves open. It changes neither the inputs nor the matches, and the findings share no
// memory with them. The steps are those that Compile and Unavailable return, and none is nil.
//
// Matches of one vulnerability in one package make one finding, which is:
//   - known to be exploited, when any match says so
//   - of the most severe severity, from Critical down to Negligible, without regard to case; a
//     severity that isn't one of these is Unknown
//   - of the fix state of the match that knows most: fixed, then wont-fix, then not-fixed; any other
//     state, the empty one included, is unknown
//   - fixed by the sorted union of the fixed versions, and scored by the sorted union of the CVSS
//     scores
//
// and that takes the package's name, version and type from the first of them, in the order of those
// fields. The rules see it so. The findings come sorted by vulnerability ID, then by package ID.
//
// A finding shows each of its strings made printable, then cut to the limits of the sheet's schema,
// and lists the first 8 fixed versions. An empty vulnerability ID, package ID, package name or package
// type becomes "unknown", which claims nothing, and so does the text of a note that has none.
func Evaluate(steps []*Compiled, inputs map[string]Input, matches []evidence.Match) []Finding {
	merged := merge(matches)
	results := make([]result, len(merged))
	for _, step := range steps {
		step.run(inputs, merged, results)
	}
	findings := make([]Finding, 0, len(merged))
	for i, m := range merged {
		findings = append(findings, results[i].finding(shown(m)))
	}
	return findings
}

// run evaluates the step for each finding of the subject, and records what it concludes in results.
// It evaluates the match for every finding before any condition, because a match that fails for one
// finding keeps the step from all of them.
func (c *Compiled) run(inputs map[string]Input, findings []evidence.Match, results []result) {
	vars, err := c.variables(inputs)
	if err != nil {
		c.failAll(results, err)
		return
	}
	applies := make([]bool, len(findings))
	for i, f := range findings {
		applies[i] = true
		if c.match == nil {
			continue
		}
		vars[findingVariable] = f
		if applies[i], err = evalBool(c.match, vars); err != nil {
			c.failAll(results, fmt.Errorf("match: %w", err))
			return
		}
	}
	for i, f := range findings {
		if !applies[i] {
			continue
		}
		vars[findingVariable] = f
		reason, holds, err := c.decide(vars)
		switch {
		case err != nil:
			c.fail(&results[i], err)
		case holds:
			c.apply(&results[i], reason)
		}
	}
}

// variables returns the variables of the step's inputs, or why it can't be evaluated without
// looking at a finding: it is unavailable, or an input is missing.
func (c *Compiled) variables(inputs map[string]Input) (map[string]any, error) {
	if c.unavailable != nil {
		return nil, c.unavailable
	}
	vars := make(map[string]any, len(c.inputs)+1)
	var missing []string
	for _, name := range c.inputs {
		in, ok := inputs[name]
		if !ok || !in.Present {
			missing = append(missing, strconv.Quote(name))
			continue
		}
		vars[name] = variable(in)
	}
	switch len(missing) {
	case 0:
		return vars, nil
	case 1:
		return nil, fmt.Errorf("the input %s is missing", missing[0])
	}
	return nil, fmt.Errorf("the inputs %s are missing", strings.Join(missing, ", "))
}

// decide evaluates the condition for a finding, and the reason where the condition holds.
func (c *Compiled) decide(vars map[string]any) (reason string, holds bool, err error) {
	if holds, err = evalBool(c.condition, vars); err != nil {
		return "", false, fmt.Errorf("condition: %w", err)
	}
	if !holds || c.reason == nil {
		return "", holds, nil
	}
	if reason, err = evalString(c.reason, vars); err != nil {
		return "", false, fmt.Errorf("reason: %w", err)
	}
	return reason, true, nil
}

// evalBool evaluates an expression that must give a bool.
func evalBool(prg cel.Program, vars map[string]any) (bool, error) {
	out, _, err := prg.Eval(vars)
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
func evalString(prg cel.Program, vars map[string]any) (string, error) {
	out, _, err := prg.Eval(vars)
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

// fail records that the step couldn't be evaluated for a finding. A step that may hold the finding
// open holds it, as UnderInvestigation, since it can't claim more. A step that would settle it, and a
// hint, don't apply.
func (c *Compiled) fail(r *result, err error) {
	if c.holds() {
		r.consider(verdict{
			status: configv1alpha1.VEXStatusUnderInvestigation, rule: c.name, reason: shownReason(notEvaluated + err.Error()),
		})
	}
}

// failAll records that the step couldn't be evaluated for any finding of the subject.
func (c *Compiled) failAll(results []result, err error) {
	for i := range results {
		c.fail(&results[i], err)
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
	for _, m := range sorted {
		last := len(merged) - 1
		if last < 0 || merged[last].VulnerabilityID != m.VulnerabilityID || merged[last].PackageID != m.PackageID {
			merged = append(merged, evidence.Match{
				VulnerabilityID: m.VulnerabilityID, PackageID: m.PackageID,
				PackageName: m.PackageName, PackageVersion: m.PackageVersion, PackageType: m.PackageType,
				Severity: severityUnknown, FixState: fixStateUnknown,
			})
			last++
		}
		add(&merged[last], m)
	}
	for i := range merged {
		slices.Sort(merged[i].FixedVersions)
		merged[i].FixedVersions = slices.Compact(merged[i].FixedVersions)
		slices.SortFunc(merged[i].CVSS, compareCVSS)
		merged[i].CVSS = slices.Compact(merged[i].CVSS)
	}
	return merged
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
	merged.CVSS = append(merged.CVSS, m.CVSS...)
}

// compareCVSS orders scores by their version, then by their vector.
func compareCVSS(a, b evidence.CVSS) int {
	return cmp.Or(strings.Compare(a.Version, b.Version), strings.Compare(a.Vector, b.Vector))
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

// shownCVSS returns the CVSS scores as a finding shows them: made printable, sorted and made unique as
// they are shown.
func shownCVSS(scores []evidence.CVSS) []evidence.CVSS {
	if len(scores) == 0 {
		return nil
	}
	listed := make([]evidence.CVSS, len(scores))
	for i, s := range scores {
		listed[i] = evidence.CVSS{Version: text.Printable(s.Version), Vector: text.Printable(s.Vector)}
	}
	slices.SortFunc(listed, compareCVSS)
	return slices.Clip(slices.Compact(listed))
}
