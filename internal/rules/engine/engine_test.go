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
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/rules/engine"
	"github.com/bedag/vexplain/sdk/evidence"
)

// These tests cover the engine: the guarantee that the core keeps whatever a rule says, the order of
// the statuses, what a rule sees, which rules Compile refuses, and how the matches of one subject
// become its findings. A finding wrongly settled as not affected is the worst error the operator can
// make, so most of the cases below are about a rule that must hold a finding, or must not settle it.

const (
	affected            = configv1alpha1.VEXStatusAffected
	underInvestigation  = configv1alpha1.VEXStatusUnderInvestigation
	notAffected         = configv1alpha1.VEXStatusNotAffected
	fixed               = configv1alpha1.VEXStatusFixed
	componentNotPresent = configv1alpha1.VEXJustificationComponentNotPresent
	// hint is the status of a rule that has none.
	hint configv1alpha1.VEXStatus = ""

	someCVE = "CVE-2026-0001"
	pkgA    = "pkg-a"
	pkgB    = "pkg-b"

	// contents is the name under which the tests supply evidence, as the default playbook does.
	contents     = "contents"
	contentsType = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"
	scannerEvent = "/clusters/cluster-a/collectors/scanner"

	// The names of the rules that the tests of the engine write.
	guardName  = "guard"
	settleName = "settle"

	// notEvaluated starts the reason of a finding that a rule couldn't be evaluated for.
	notEvaluated = "could not be evaluated: "
)

// The severities and fix states of a match, as the sources spell them, and what a finding shows
// where the schema requires text that the source doesn't have.
const (
	severityCritical   = "Critical"
	severityHigh       = "High"
	severityMedium     = "Medium"
	severityLow        = "Low"
	severityNegligible = "Negligible"
	severityUnknown    = "Unknown"
	stateFixed         = "fixed"
	stateWontFix       = "wont-fix"
	stateNotFixed      = "not-fixed"
	stateUnknown       = "unknown"
	placeholder        = "unknown"
)

// The expressions of a rule, as an error names them.
const (
	inMatch     = "match"
	inCondition = "condition"
	inReason    = "reason"
)

// Names and values that several tests share.
const (
	wordKey   = "word"
	noteName  = "note"
	holdB     = "hold-b"
	aHint     = "a-hint"
	cve1      = "CVE-1"
	cve2      = "CVE-2"
	cvss31    = "3.1"
	cvss20    = "2.0"
	vectorAVL = "CVSS:3.1/AV:L"
	celNull   = "null"
	notedText = "noted"
)

// seen is when the evidence of the tests was seen.
var seen = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// Conditions that the tests give the rules. They read testData.
const (
	// failsForA fails for the finding in pkgA, because no int can be made of a word, and is false for
	// every other finding.
	failsForA = `finding.packageID == 'pkg-a' ? int(contents.data.word) > 0 : false`
	// failsForAOnly fails for the finding in pkgA, and is true for every other finding.
	failsForAOnly = `finding.packageID == 'pkg-a' ? int(contents.data.word) > 0 : true`
	// costsTooMuchForA goes through the 600 items once for each of them, but only for the finding in
	// pkgA. That costs 1,084,204, over the limit of 1,000,000.
	costsTooMuchForA = `finding.packageID == 'pkg-a' && contents.data.items.all(x, contents.data.items.all(y, true))`
	// failsForB fails for the finding in pkgB, and is true for the finding in pkgA. As a match, it
	// fails for one finding of the subject.
	failsForB = `finding.packageID == 'pkg-a' || int(contents.data.word) > 0`
)

// ---- fixtures ----

// ruleOf returns a rule named name, which concludes status where condition holds: NotAffected with
// the justification ComponentNotPresent, and a hint when status is empty.
func ruleOf(name string, status configv1alpha1.VEXStatus, condition string) *configv1alpha1.Rule {
	r := &configv1alpha1.Rule{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       configv1alpha1.RuleSpec{Condition: condition, Outcome: &configv1alpha1.RuleOutcome{}},
	}
	if status != hint {
		r.Spec.Outcome.Status = ptr.To(status)
	}
	if status == notAffected {
		r.Spec.Outcome.Justification = ptr.To(componentNotPresent)
	}
	return r
}

// needing gives r inputs of the given names, of the scanner's type.
func needing(r *configv1alpha1.Rule, names ...string) *configv1alpha1.Rule {
	for _, name := range names {
		r.Spec.Inputs = append(r.Spec.Inputs, configv1alpha1.RuleInput{Name: name, Type: contentsType})
	}
	return r
}

// matching gives r a match.
func matching(r *configv1alpha1.Rule, match string) *configv1alpha1.Rule {
	r.Spec.Match = ptr.To(match)
	return r
}

// because gives r a reason.
func because(r *configv1alpha1.Rule, reason string) *configv1alpha1.Rule {
	r.Spec.Reason = ptr.To(reason)
	return r
}

// compiled compiles the rules, in their order, as the steps of a playbook.
func compiled(t *testing.T, rules ...*configv1alpha1.Rule) []*engine.Compiled {
	t.Helper()
	steps := make([]*engine.Compiled, 0, len(rules))
	for _, r := range rules {
		c, err := engine.Compile(r)
		require.NoError(t, err, "rule %s", r.Name)
		steps = append(steps, c)
	}
	return steps
}

// testData is the data that the rules of the engine's tests read: a word that no int can be made of,
// a flag that is no bool, and n items. As encoding/json decodes JSON, its numbers are float64.
func testData(items int) map[string]any {
	list := make([]any, items)
	for i := range list {
		list[i] = float64(i)
	}
	return map[string]any{wordKey: "x", "flag": "yes", "items": list}
}

// contentsOf supplies data as the evidence named contents, with a coverage of 100.
func contentsOf(data any) map[string]engine.Input {
	return map[string]engine.Input{contents: {
		Present: true, Data: data, Coverage: ptr.To(int32(100)), Time: seen, Source: scannerEvent,
	}}
}

// matchOf is a match of a vulnerability in a package, as a findings collector reports it.
func matchOf(vulnerabilityID, packageID string) evidence.Match {
	return evidence.Match{
		VulnerabilityID: vulnerabilityID, PackageID: packageID, PackageName: "lib" + packageID,
		PackageVersion: "1.0", PackageType: "deb", Severity: severityHigh, FixState: stateNotFixed,
	}
}

// twoFindings are the matches of one vulnerability in pkgA and in pkgB.
func twoFindings() []evidence.Match {
	return []evidence.Match{matchOf(someCVE, pkgA), matchOf(someCVE, pkgB)}
}

// verdict is what the rules made of a finding, without its match.
type verdict struct {
	Status        configv1alpha1.VEXStatus
	Rule          string
	Reason        string
	Justification configv1alpha1.VEXJustification
	Notes         []engine.Note
}

func verdictOf(f engine.Finding) verdict {
	return verdict{f.Status, f.Rule, f.Reason, f.Justification, f.Notes}
}

// evaluate runs the steps, checks what every finding must satisfy, and returns the verdicts in the
// order of the findings.
func evaluate(t *testing.T, steps []*engine.Compiled, inputs map[string]engine.Input, matches []evidence.Match) []verdict {
	t.Helper()
	findings := engine.Evaluate(steps, inputs, matches)
	verdicts := make([]verdict, 0, len(findings))
	for _, f := range findings {
		requireValid(t, f)
		verdicts = append(verdicts, verdictOf(f))
	}
	return verdicts
}

// requireValid checks what every finding satisfies, whatever the rules say: a status of the four, a
// justification exactly for NotAffected, at most 4 notes in the order of their rules, and text that
// is printable and fits the schema of a sheet and a report.
func requireValid(t *testing.T, f engine.Finding) {
	t.Helper()
	require.Contains(t, []configv1alpha1.VEXStatus{affected, underInvestigation, notAffected, fixed}, f.Status)
	require.Equal(t, f.Status == notAffected, f.Justification != "", "justification is set exactly for NotAffected")
	if f.Status != underInvestigation {
		require.NotEmpty(t, f.Rule, "only a rule settles a finding or claims it affected")
	}
	require.LessOrEqual(t, utf8.RuneCountInString(f.Reason), 256)
	requirePrintable(t, "the reason", f.Reason)

	require.LessOrEqual(t, len(f.Notes), 4)
	require.True(t, slices.IsSortedFunc(f.Notes, func(a, b engine.Note) int { return strings.Compare(a.Rule, b.Rule) }),
		"notes come in the order of their rules")
	for _, n := range f.Notes {
		require.NotEmpty(t, n.Rule)
		require.NotEmpty(t, n.Text, "a note always says something")
		require.LessOrEqual(t, utf8.RuneCountInString(n.Text), 256)
		requirePrintable(t, "a note", n.Text)
	}

	m := f.Match
	for what, s := range map[string]string{
		"the vulnerability ID": m.VulnerabilityID, "the package ID": m.PackageID,
		"the package name": m.PackageName, "the package type": m.PackageType,
	} {
		require.NotEmpty(t, s, "%s is required", what)
		requirePrintable(t, what, s)
	}
	require.LessOrEqual(t, utf8.RuneCountInString(m.VulnerabilityID), 64)
	require.LessOrEqual(t, utf8.RuneCountInString(m.PackageID), 64)
	require.LessOrEqual(t, utf8.RuneCountInString(m.PackageName), 253)
	require.LessOrEqual(t, utf8.RuneCountInString(m.PackageVersion), 128)
	require.LessOrEqual(t, utf8.RuneCountInString(m.PackageType), 32)
	requirePrintable(t, "the package version", m.PackageVersion)
	require.Contains(t, []string{severityCritical, severityHigh, severityMedium, severityLow, severityNegligible, severityUnknown}, m.Severity)
	require.Contains(t, []string{stateFixed, stateWontFix, stateNotFixed, stateUnknown}, m.FixState)
	require.LessOrEqual(t, len(m.FixedVersions), 8)
	for _, v := range m.FixedVersions {
		require.LessOrEqual(t, utf8.RuneCountInString(v), 128)
		requirePrintable(t, "a fixed version", v)
	}
	for _, c := range m.CVSS {
		requirePrintable(t, "a CVSS version", c.Version)
		requirePrintable(t, "a CVSS vector", c.Vector)
	}
}

// requirePrintable checks that a string of a finding is valid UTF-8 and holds no character that Go
// doesn't call printable. A finding's text comes from images and databases, which can be crafted,
// and kubectl prints status strings as they are.
func requirePrintable(t *testing.T, what, s string) {
	t.Helper()
	require.True(t, utf8.ValidString(s), "%s is valid UTF-8", what)
	for _, r := range s {
		require.True(t, unicode.IsPrint(r), "%s has the unprintable character %U", what, r)
	}
}

// heldBy is a finding that the named rule holds open because it couldn't be evaluated for it.
func heldBy(rule, why string) verdict {
	return verdict{Status: underInvestigation, Rule: rule, Reason: notEvaluated + why}
}

// requireHeldBy checks that v is held open by the named rule, because it couldn't be evaluated for
// the finding, with a reason that starts with what failed and contains why.
func requireHeldBy(t *testing.T, v verdict, rule, failed, why string) {
	t.Helper()
	require.Equal(t, underInvestigation, v.Status)
	require.Equal(t, rule, v.Rule)
	require.Empty(t, v.Justification)
	require.True(t, strings.HasPrefix(v.Reason, notEvaluated+failed+": "), "the reason %q says what failed", v.Reason)
	require.Contains(t, v.Reason, why)
}

// settled is a finding that the rule named settle settles.
var settled = verdict{Status: notAffected, Rule: settleName, Justification: componentNotPresent}

// open is a finding that no rule settled, held or noted.
var open = verdict{Status: underInvestigation}

// ---- the core's guarantee ----

func TestAGuardThatCantBeEvaluatedKeepsAFindingFromNotAffected(t *testing.T) {
	settle := ruleOf(settleName, notAffected, "true")

	t.Run("its CEL fails for one finding", func(t *testing.T) {
		guard := needing(ruleOf(guardName, underInvestigation, failsForA), contents)
		got := evaluate(t, compiled(t, guard, settle), contentsOf(testData(0)), twoFindings())
		requireHeldBy(t, got[0], guardName, inCondition, "type conversion error")
		require.Equal(t, settled, got[1], "the guard holds back only the finding that it can't be evaluated for")
	})

	t.Run("its input is missing", func(t *testing.T) {
		guard := needing(ruleOf(guardName, underInvestigation, "true"), contents)
		missing := heldBy(guardName, `the input "contents" is missing`)
		for name, inputs := range map[string]map[string]engine.Input{
			"absent":      nil,
			"not present": {contents: {Present: false, Data: testData(0)}},
			"under another name": {"other": {
				Present: true, Data: testData(0), Coverage: ptr.To(int32(100)), Time: seen, Source: scannerEvent,
			}},
		} {
			t.Run(name, func(t *testing.T) {
				got := evaluate(t, compiled(t, guard, settle), inputs, twoFindings())
				require.Equal(t, []verdict{missing, missing}, got, "a missing input holds every finding")
			})
		}
	})

	t.Run("it hits the cost limit for one finding", func(t *testing.T) {
		guard := needing(ruleOf(guardName, underInvestigation, costsTooMuchForA), contents)
		got := evaluate(t, compiled(t, guard, settle), contentsOf(testData(600)), twoFindings())
		requireHeldBy(t, got[0], guardName, inCondition, "cost limit exceeded")
		require.Equal(t, settled, got[1])
	})

	t.Run("its reason fails", func(t *testing.T) {
		guard := because(needing(ruleOf(guardName, underInvestigation, "true"), contents), "string(int(contents.data.word))")
		got := evaluate(t, compiled(t, guard, settle), contentsOf(testData(0)), twoFindings())
		requireHeldBy(t, got[0], guardName, inReason, "type conversion error")
		requireHeldBy(t, got[1], guardName, inReason, "type conversion error")
	})

	t.Run("its reason gives no string when it runs", func(t *testing.T) {
		guard := because(needing(ruleOf(guardName, underInvestigation, "true"), contents), "contents.data.items")
		got := evaluate(t, compiled(t, guard, settle), contentsOf(testData(1)), twoFindings())
		requireHeldBy(t, got[0], guardName, inReason, "string")
		requireHeldBy(t, got[1], guardName, inReason, "string")
	})

	t.Run("its condition gives no bool when it runs", func(t *testing.T) {
		guard := needing(ruleOf(guardName, underInvestigation, "contents.data.flag"), contents)
		got := evaluate(t, compiled(t, guard, settle), contentsOf(testData(0)), twoFindings())
		requireHeldBy(t, got[0], guardName, inCondition, "bool")
		requireHeldBy(t, got[1], guardName, inCondition, "bool")
	})

	t.Run("a rule that concludes Affected holds the finding open, and claims nothing", func(t *testing.T) {
		claim := needing(ruleOf("claim", affected, failsForA), contents)
		got := evaluate(t, compiled(t, claim, settle), contentsOf(testData(0)), twoFindings())
		requireHeldBy(t, got[0], "claim", inCondition, "type conversion error")
		require.Equal(t, settled, got[1])
	})

	t.Run("it holds back Fixed as well", func(t *testing.T) {
		guard := needing(ruleOf(guardName, underInvestigation, failsForA), contents)
		fix := ruleOf("fix", fixed, "true")
		got := evaluate(t, compiled(t, guard, fix), contentsOf(testData(0)), twoFindings())
		requireHeldBy(t, got[0], guardName, inCondition, "type conversion error")
		require.Equal(t, verdict{Status: fixed, Rule: "fix"}, got[1])
	})
}

func TestAnEvaluationWithinTheCostLimitIsEvaluated(t *testing.T) {
	// The same rule as above, over 500 items, costs 753,504: within the limit of 1,000,000, so the
	// guard holds the finding in pkgA because its condition holds, and the reason says nothing failed.
	guard := because(needing(ruleOf(guardName, underInvestigation, costsTooMuchForA), contents), "'gone through'")
	got := evaluate(t, compiled(t, guard, ruleOf(settleName, notAffected, "true")), contentsOf(testData(500)), twoFindings())
	require.Equal(t, []verdict{{Status: underInvestigation, Rule: guardName, Reason: "gone through"}, settled}, got)
}

func TestASettlingRuleThatCantBeEvaluatedDoesNotApply(t *testing.T) {
	// Each rule below fails for the finding in pkgA, and applies to the finding in pkgB. Where it
	// fails, the finding is what the other rules make of it, as if the rule weren't there.
	others := []*configv1alpha1.Rule{
		because(ruleOf(noteName, hint, "true"), "'noted'"),
		ruleOf(holdB, underInvestigation, "finding.packageID == 'pkg-b'"),
	}
	notedOpen := verdict{Status: underInvestigation, Notes: []engine.Note{{Rule: noteName, Text: notedText}}}
	without := evaluate(t, compiled(t, others...), contentsOf(testData(0)), twoFindings())
	require.Equal(t, notedOpen, without[0])

	tests := []struct {
		name string
		rule *configv1alpha1.Rule
		// wantB is what the rule makes of the finding in pkgB, where it can be evaluated.
		wantB verdict
	}{
		{"NotAffected", needing(ruleOf("settle-a", notAffected, failsForAOnly), contents), verdict{
			Status: underInvestigation, Rule: holdB, Notes: notedOpen.Notes,
		}},
		{"Fixed", needing(ruleOf("fix-a", fixed, failsForAOnly), contents), verdict{
			Status: underInvestigation, Rule: holdB, Notes: notedOpen.Notes,
		}},
		{"a hint", because(needing(ruleOf("look", hint, failsForAOnly), contents), "'looked'"), verdict{
			Status: underInvestigation, Rule: holdB,
			Notes: []engine.Note{{Rule: "look", Text: "looked"}, {Rule: noteName, Text: notedText}},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluate(t, compiled(t, append(slices.Clone(others), tc.rule)...), contentsOf(testData(0)), twoFindings())
			require.Equal(t, without[0], got[0], "the rule that fails changes nothing")
			require.Equal(t, tc.wantB, got[1])
		})
	}

	t.Run("where it applies, it settles", func(t *testing.T) {
		// Without the hold on pkgB, the rule that settles does settle the finding it can be evaluated for.
		rule := needing(ruleOf("settle-a", notAffected, failsForAOnly), contents)
		got := evaluate(t, compiled(t, others[0], rule), contentsOf(testData(0)), twoFindings())
		require.Equal(t, notedOpen, got[0])
		require.Equal(t, verdict{
			Status: notAffected, Rule: "settle-a", Justification: componentNotPresent, Notes: notedOpen.Notes,
		}, got[1])
	})
}

func TestAFailingMatchHoldsEveryFinding(t *testing.T) {
	// The match fails for the finding in pkgB only, so the rule can't tell which findings of the
	// subject it applies to: it can't be evaluated for any of them.
	t.Run("a guard holds both", func(t *testing.T) {
		guard := matching(needing(ruleOf(guardName, underInvestigation, "true"), contents), failsForB)
		got := evaluate(t, compiled(t, guard, ruleOf(settleName, notAffected, "true")), contentsOf(testData(0)), twoFindings())
		requireHeldBy(t, got[0], guardName, inMatch, "type conversion error")
		requireHeldBy(t, got[1], guardName, inMatch, "type conversion error")
	})

	t.Run("a rule that settles settles neither", func(t *testing.T) {
		settle := matching(needing(ruleOf(settleName, notAffected, "true"), contents), failsForB)
		got := evaluate(t, compiled(t, settle), contentsOf(testData(0)), twoFindings())
		require.Equal(t, []verdict{open, open}, got)
	})

	t.Run("a match that holds for one finding only", func(t *testing.T) {
		// For contrast: a match that works narrows the guard to the findings that it selects.
		guard := matching(ruleOf(guardName, underInvestigation, "true"), "finding.packageID == 'pkg-a'")
		got := evaluate(t, compiled(t, guard, ruleOf(settleName, notAffected, "true")), nil, twoFindings())
		require.Equal(t, []verdict{{Status: underInvestigation, Rule: guardName}, settled}, got)
	})
}

func TestAnUnavailableStepKeepsEveryFindingFromNotAffectedAndFixed(t *testing.T) {
	steps := append(compiled(t,
		ruleOf(settleName, notAffected, "true"),
		ruleOf("fix", fixed, "true"),
		because(ruleOf(noteName, hint, "true"), "'noted'"),
	), engine.Unavailable("removed", "the rule removed doesn't exist"))

	got := evaluate(t, steps, nil, twoFindings())
	want := heldBy("removed", "the rule removed doesn't exist")
	want.Notes = []engine.Note{{Rule: noteName, Text: notedText}}
	require.Equal(t, []verdict{want, want}, got)

	t.Run("an Affected rule still wins over it", func(t *testing.T) {
		steps := append(compiled(t, ruleOf("claim", affected, "true")), engine.Unavailable("removed", "gone"))
		got := evaluate(t, steps, nil, twoFindings())
		require.Equal(t, verdict{Status: affected, Rule: "claim"}, got[0])
	})

	t.Run("a step without a reason still says why", func(t *testing.T) {
		got := evaluate(t, []*engine.Compiled{engine.Unavailable("removed", "")}, nil, twoFindings())
		require.Equal(t, heldBy("removed", "the rule is unavailable"), got[0])
	})

	t.Run("a reason that isn't printable is made so", func(t *testing.T) {
		got := evaluate(t, []*engine.Compiled{engine.Unavailable("removed", "not\nready")}, nil, twoFindings())
		require.Equal(t, heldBy("removed", "not\ufffdready"), got[0])
	})
}

// ---- the order of statuses ----

func TestTheMostCautiousStatusWins(t *testing.T) {
	// In the order of caution. Each rule's name sorts before the names of those more cautious, so
	// that the name can't be what decides.
	byCaution := []*configv1alpha1.Rule{
		ruleOf("d-affected", affected, "true"),
		ruleOf("c-hold", underInvestigation, "true"),
		ruleOf("b-fixed", fixed, "true"),
		ruleOf("a-not-affected", notAffected, "true"),
	}
	for i := range byCaution {
		for j := i + 1; j < len(byCaution); j++ {
			t.Run(byCaution[i].Name+" over "+byCaution[j].Name, func(t *testing.T) {
				got := evaluate(t, compiled(t, byCaution[j], byCaution[i]), nil, twoFindings())
				require.Equal(t, *byCaution[i].Spec.Outcome.Status, got[0].Status)
				require.Equal(t, byCaution[i].Name, got[0].Rule)
			})
		}
	}
}

func TestBetweenRulesOfOneStatusTheFirstByNameDecides(t *testing.T) {
	for _, status := range []configv1alpha1.VEXStatus{affected, underInvestigation, fixed, notAffected} {
		t.Run(string(status), func(t *testing.T) {
			first := because(ruleOf("a-first", status, "true"), "'first'")
			second := because(ruleOf("b-second", status, "true"), "'second'")
			want := verdict{Status: status, Rule: "a-first", Reason: "first"}
			if status == notAffected {
				want.Justification = componentNotPresent
			}
			require.Equal(t, want, evaluate(t, compiled(t, second, first), nil, twoFindings())[0])
			require.Equal(t, want, evaluate(t, compiled(t, first, second), nil, twoFindings())[0])
		})
	}

	t.Run("a rule that can't be evaluated counts as UnderInvestigation", func(t *testing.T) {
		// The guard fails and sorts first, so it is the one the finding records. A rule that holds
		// and sorts after it changes nothing.
		guard := needing(ruleOf("a-guard", underInvestigation, "true"), contents)
		hold := because(ruleOf("b-hold", underInvestigation, "true"), "'held'")
		got := evaluate(t, compiled(t, hold, guard), nil, twoFindings())
		require.Equal(t, heldBy("a-guard", `the input "contents" is missing`), got[0])

		// And one that sorts before it is the one that the finding records.
		hold.Name = "0-hold"
		got = evaluate(t, compiled(t, hold, guard), nil, twoFindings())
		require.Equal(t, verdict{Status: underInvestigation, Rule: "0-hold", Reason: "held"}, got[0])
	})
}

func TestAFindingThatNoRuleSettlesIsUnderInvestigation(t *testing.T) {
	got := evaluate(t, compiled(t, ruleOf(settleName, notAffected, "false"), ruleOf(guardName, underInvestigation, "false")),
		nil, twoFindings())
	require.Equal(t, []verdict{open, open}, got)

	got = evaluate(t, nil, nil, twoFindings())
	require.Equal(t, []verdict{open, open}, got, "a playbook without steps settles nothing")
}

func TestNotesAddUpToFourInTheOrderOfTheirRules(t *testing.T) {
	hints := make([]*configv1alpha1.Rule, 0, 5)
	for _, name := range []string{"e-hint", "c-hint", aHint, "d-hint", "b-hint"} {
		hints = append(hints, because(ruleOf(name, hint, "true"), "'by "+name+"'"))
	}
	want := []engine.Note{
		{Rule: aHint, Text: "by " + aHint}, {Rule: "b-hint", Text: "by b-hint"},
		{Rule: "c-hint", Text: "by c-hint"}, {Rule: "d-hint", Text: "by d-hint"},
	}
	got := evaluate(t, compiled(t, hints...), nil, twoFindings())
	require.Equal(t, verdict{Status: underInvestigation, Notes: want}, got[0], "a hint settles nothing")

	t.Run("on a settled finding too", func(t *testing.T) {
		got := evaluate(t, compiled(t, append(hints, ruleOf(settleName, notAffected, "true"))...), nil, twoFindings())
		require.Equal(t, verdict{Status: notAffected, Rule: settleName, Justification: componentNotPresent, Notes: want}, got[0])
	})

	t.Run("a hint that doesn't apply adds none", func(t *testing.T) {
		quiet := because(ruleOf("0-quiet", hint, "false"), "'never'")
		got := evaluate(t, compiled(t, quiet, hints[2]), nil, twoFindings())
		require.Equal(t, []engine.Note{{Rule: aHint, Text: "by " + aHint}}, got[0].Notes)
	})

	t.Run("a step that runs twice adds its note once", func(t *testing.T) {
		got := evaluate(t, compiled(t, hints[2], hints[2]), nil, twoFindings())
		require.Equal(t, []engine.Note{{Rule: aHint, Text: "by " + aHint}}, got[0].Notes)
	})

	t.Run("a hint without a reason says that it applied", func(t *testing.T) {
		got := evaluate(t, compiled(t, ruleOf("bare", hint, "true")), nil, twoFindings())
		require.Equal(t, []engine.Note{{Rule: "bare", Text: placeholder}}, got[0].Notes)
	})
}

// ---- what a rule sees ----

func TestARuleSeesTheFindingAndEachInputsDataCoverageTimeAndSource(t *testing.T) {
	look := because(needing(ruleOf("look", hint, "true"), contents),
		`[finding.vulnerabilityID, finding.packageID, contents.data.word, string(contents.coverage),
		  string(contents.time), contents.source].join(' ')`)
	got := evaluate(t, compiled(t, look), contentsOf(testData(0)), twoFindings()[:1])
	require.Equal(t, []engine.Note{{Rule: "look", Text: someCVE + " pkg-a x 100 2026-10-31T12:00:00Z " + scannerEvent}}, got[0].Notes)

	t.Run("the finding has the fields of a match, as its JSON names them", func(t *testing.T) {
		m := matchOf(someCVE, pkgA)
		m.FixedVersions = []string{"1.1"}
		m.KnownExploited = true
		m.CVSS = []evidence.CVSS{{Version: cvss31, Vector: "CVSS:3.1/AV:N"}}
		fields := because(ruleOf("fields", hint, "true"), `[finding.packageName, finding.packageVersion, finding.packageType,
		  finding.severity, finding.fixState, finding.fixedVersions[0], string(finding.knownExploited),
		  finding.cvss[0].version, finding.cvss[0].vector].join(' ')`)
		got := evaluate(t, compiled(t, fields), nil, []evidence.Match{m})
		require.Equal(t, "libpkg-a 1.0 deb High not-fixed 1.1 true 3.1 CVSS:3.1/AV:N", got[0].Notes[0].Text)
	})

	t.Run("an input without coverage has no coverage key", func(t *testing.T) {
		inputs := contentsOf(testData(0))
		in := inputs[contents]
		in.Coverage = nil
		inputs[contents] = in
		uncovered := needing(ruleOf("uncovered", underInvestigation, "!has(contents.coverage)"), contents)
		require.Equal(t, verdict{Status: underInvestigation, Rule: "uncovered"}, evaluate(t, compiled(t, uncovered), inputs, twoFindings())[0])

		reads := needing(ruleOf("reads", underInvestigation, "contents.coverage < 90"), contents)
		requireHeldBy(t, evaluate(t, compiled(t, reads), inputs, twoFindings())[0], "reads", inCondition, "no such key: coverage")
	})

	t.Run("a rule reads a time in UTC, whatever zone it comes in", func(t *testing.T) {
		// A time that the API server gives is in the operator's own zone, which must not change what a
		// rule decides.
		inputs := contentsOf(testData(0))
		in := inputs[contents]
		in.Time = seen.In(time.FixedZone("UTC+5", 5*60*60))
		inputs[contents] = in
		noon := needing(ruleOf("noon", underInvestigation, "contents.time.getHours() == 12"), contents)
		require.Equal(t, verdict{Status: underInvestigation, Rule: "noon"}, evaluate(t, compiled(t, noon), inputs, twoFindings())[0])
	})

	t.Run("a rule sees only the inputs that it names", func(t *testing.T) {
		_, err := engine.Compile(ruleOf("peeks", underInvestigation, "contents.coverage < 90"))
		require.ErrorContains(t, err, "contents")
	})
}

func TestARuleThatSettlesOrHintsAppliesOnlyWhenEveryInputIsPresent(t *testing.T) {
	steps := compiled(t,
		needing(ruleOf(settleName, notAffected, "true"), contents),
		because(needing(ruleOf(noteName, hint, "true"), contents, "exposure"), "'noted'"),
	)
	require.Equal(t, []verdict{open, open}, evaluate(t, steps, nil, twoFindings()))
	require.Equal(t, verdict{Status: notAffected, Rule: settleName, Justification: componentNotPresent},
		evaluate(t, steps, contentsOf(testData(0)), twoFindings())[0], "the note needs exposure as well")
}

// ---- Compile ----

func TestCompileRefusesARuleThatCantBeEvaluatedAsWritten(t *testing.T) {
	long := "'" + strings.Repeat("a", 4095) + "'" // 4097 characters
	tests := []struct {
		name string
		rule func() *configv1alpha1.Rule
		want string
	}{
		{"no rule", func() *configv1alpha1.Rule { return nil }, "no rule"},
		{"no name", func() *configv1alpha1.Rule { return ruleOf("", underInvestigation, "true") }, "name"},
		{"no outcome", func() *configv1alpha1.Rule {
			r := ruleOf(guardName, underInvestigation, "true")
			r.Spec.Outcome = nil
			return r
		}, "outcome"},
		{"a status that isn't one of the four", func() *configv1alpha1.Rule {
			return ruleOf(guardName, "Waived", "true")
		}, "Waived"},
		{"NotAffected without a justification", func() *configv1alpha1.Rule {
			r := ruleOf(settleName, notAffected, "true")
			r.Spec.Outcome.Justification = nil
			return r
		}, "justification"},
		{"a justification without NotAffected", func() *configv1alpha1.Rule {
			r := ruleOf(guardName, underInvestigation, "true")
			r.Spec.Outcome.Justification = ptr.To(componentNotPresent)
			return r
		}, "justification"},
		{"a justification that isn't one of the five", func() *configv1alpha1.Rule {
			r := ruleOf(settleName, notAffected, "true")
			r.Spec.Outcome.Justification = ptr.To(configv1alpha1.VEXJustification("Unreachable"))
			return r
		}, "Unreachable"},
		{"an input named finding", func() *configv1alpha1.Rule {
			return needing(ruleOf(guardName, underInvestigation, "true"), "finding")
		}, "finding"},
		{"an input named after a reserved word of CEL", func() *configv1alpha1.Rule {
			return needing(ruleOf(guardName, underInvestigation, "true"), "package")
		}, "package"},
		{"an input named after a literal of CEL", func() *configv1alpha1.Rule {
			return needing(ruleOf(guardName, underInvestigation, "true"), celNull)
		}, celNull},
		{"an input whose name is no identifier", func() *configv1alpha1.Rule {
			return needing(ruleOf(guardName, underInvestigation, "true"), "my-contents")
		}, "my-contents"},
		{"an input without a name", func() *configv1alpha1.Rule {
			return needing(ruleOf(guardName, underInvestigation, "true"), "")
		}, "input"},
		{"two inputs of one name", func() *configv1alpha1.Rule {
			return needing(ruleOf(guardName, underInvestigation, "true"), contents, contents)
		}, contents},
		{"no condition", func() *configv1alpha1.Rule { return ruleOf(guardName, underInvestigation, "") }, inCondition},
		{"a condition that doesn't parse", func() *configv1alpha1.Rule {
			return ruleOf(guardName, underInvestigation, "finding.packageID ==")
		}, inCondition},
		{"a condition that reads what no input names", func() *configv1alpha1.Rule {
			return ruleOf(guardName, underInvestigation, "exposure.data.indirect")
		}, "exposure"},
		{"a condition that reads a field a finding doesn't have", func() *configv1alpha1.Rule {
			return ruleOf(guardName, underInvestigation, "finding.packageId == 'a'")
		}, "packageId"},
		{"a condition that gives no bool", func() *configv1alpha1.Rule {
			return ruleOf(guardName, underInvestigation, "'yes'")
		}, inCondition},
		{"a match that gives no bool", func() *configv1alpha1.Rule {
			return matching(ruleOf(guardName, underInvestigation, "true"), "1")
		}, inMatch},
		{"a reason that gives no string", func() *configv1alpha1.Rule {
			return because(ruleOf(guardName, underInvestigation, "true"), "1")
		}, inReason},
		{"an expression longer than 4096 characters", func() *configv1alpha1.Rule {
			return because(ruleOf(guardName, underInvestigation, "true"), long)
		}, inReason},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := engine.Compile(tc.rule())
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, c)
		})
	}

	t.Run("an expression of 4096 characters is fine", func(t *testing.T) {
		_, err := engine.Compile(because(ruleOf(guardName, underInvestigation, "true"), "'"+strings.Repeat("a", 4094)+"'"))
		require.NoError(t, err)
	})

	t.Run("every reserved word of CEL", func(t *testing.T) {
		for _, word := range []string{
			"true", "false", "null", "in", "as", "break", "const", "continue", "else", "for", "function", "if",
			"import", "let", "loop", "package", "namespace", "return", "var", "void", "while",
		} {
			_, err := engine.Compile(needing(ruleOf(guardName, underInvestigation, "true"), word))
			require.ErrorContains(t, err, word, "the input %s", word)
		}
	})
}

// ---- the findings of a subject ----

func TestTheStepsInAnyOrderGiveTheSameFindings(t *testing.T) {
	rules := []*configv1alpha1.Rule{
		ruleOf("claim", affected, "finding.packageID == 'pkg-c'"),
		needing(ruleOf(guardName, underInvestigation, failsForA), contents),
		because(ruleOf("hold", underInvestigation, "finding.knownExploited"), "'exploited'"),
		ruleOf("fix", fixed, "finding.fixState == 'fixed'"),
		ruleOf(settleName, notAffected, "true"),
		because(ruleOf(noteName, hint, "finding.severity == 'High'"), "'high'"),
		because(needing(ruleOf("look", hint, failsForAOnly), contents), "'looked'"),
		matching(needing(ruleOf("narrow", underInvestigation, "true"), contents), "finding.packageID == 'pkg-d'"),
	}
	matches := slices.Concat(twoFindings(), []evidence.Match{matchOf(someCVE, "pkg-c"), matchOf(someCVE, "pkg-d")})
	matches[1].KnownExploited = true
	matches[2].FixState = stateFixed
	steps := append(compiled(t, rules...), engine.Unavailable("removed", "gone"))
	inputs := contentsOf(testData(0))

	want := engine.Evaluate(steps, inputs, matches)
	require.Len(t, want, 4)
	require.Equal(t, affected, want[2].Status, "the fixture has every status")

	reversed := slices.Clone(steps)
	slices.Reverse(reversed)
	require.Equal(t, want, engine.Evaluate(reversed, inputs, matches))

	rng := rand.New(rand.NewPCG(5, 8))
	for range 50 {
		shuffled := slices.Clone(steps)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		require.Equal(t, want, engine.Evaluate(shuffled, inputs, matches))
	}
}

func TestAPackageNameWithControlCharactersIsPrintableInTheFinding(t *testing.T) {
	m := matchOf(someCVE, pkgA)
	m.PackageName = "lib\x1b[2J\x1b[31mred\nname\u202e"
	findings := engine.Evaluate(nil, nil, []evidence.Match{m})
	require.Len(t, findings, 1)
	requireValid(t, findings[0])
	require.Equal(t, "lib\ufffd[2J\ufffd[31mred\ufffdname\ufffd", findings[0].Match.PackageName)
}

func TestARuleDecidesByTheMatchAsItComes(t *testing.T) {
	// What a finding shows is made printable, but a rule compares what the match says: a package ID
	// that holds a control character is still the ID that the evidence keys the package by.
	m := matchOf(someCVE, "pkg\x00a")
	settle := needing(ruleOf(settleName, notAffected, `contents.data.word == finding.packageID`), contents)
	findings := engine.Evaluate(compiled(t, settle), contentsOf(map[string]any{wordKey: "pkg\x00a"}), []evidence.Match{m})
	require.Len(t, findings, 1)
	require.Equal(t, settled, verdictOf(findings[0]))
	require.Equal(t, "pkg\ufffda", findings[0].Match.PackageID)
}

func TestEveryReasonIsPrintableAndCutTo256Characters(t *testing.T) {
	for name, character := range map[string]string{"one byte": "a", "two bytes": "é", "four bytes": "😀", "an escape": "\x1b"} {
		t.Run(name, func(t *testing.T) {
			long := strings.Repeat(character, 300)
			data := map[string]any{wordKey: long}
			steps := compiled(t,
				because(needing(ruleOf("hold", underInvestigation, "true"), contents), "'held: ' + contents.data.word"),
				because(needing(ruleOf(noteName, hint, "true"), contents), "'noted: ' + contents.data.word"),
			)
			got := evaluate(t, steps, contentsOf(data), twoFindings())[0]
			shown := strings.Repeat(strings.ReplaceAll(character, "\x1b", "\ufffd"), 300)
			require.Equal(t, 256, utf8.RuneCountInString(got.Reason))
			require.True(t, strings.HasPrefix("held: "+shown, got.Reason), "the reason is the start of the text")
			require.Equal(t, 256, utf8.RuneCountInString(got.Notes[0].Text))
			require.True(t, strings.HasPrefix("noted: "+shown, got.Notes[0].Text), "the note is the start of the text")
		})
	}

	t.Run("the reason of a rule that can't be evaluated", func(t *testing.T) {
		got := evaluate(t, []*engine.Compiled{engine.Unavailable("removed", "\x1b"+strings.Repeat("é", 300))}, nil, twoFindings())[0]
		require.Equal(t, 256, utf8.RuneCountInString(got.Reason))
		require.True(t, strings.HasPrefix(got.Reason, notEvaluated+"\ufffdé"))
	})
}

// ---- one finding for each vulnerability and package ----

func TestMatchesOfOneVulnerabilityAndPackageMakeOneFinding(t *testing.T) {
	const v11, v12, v13 = "1.1", "1.2", "1.3"
	a := matchOf(someCVE, pkgA)
	a.Severity, a.FixState, a.FixedVersions = severityLow, "", []string{v12, v11}
	a.CVSS = []evidence.CVSS{{Version: cvss31, Vector: vectorAVL}}
	b := matchOf(someCVE, pkgA)
	b.Severity, b.FixState, b.FixedVersions = severityCritical, stateWontFix, []string{v13, v11}
	b.CVSS = []evidence.CVSS{{Version: cvss31, Vector: vectorAVL}, {Version: cvss20, Vector: "AV:N"}}
	c := matchOf(someCVE, pkgA)
	c.Severity, c.FixState, c.KnownExploited = severityUnknown, stateNotFixed, true

	findings := engine.Evaluate(nil, nil, []evidence.Match{a, b, c})
	require.Len(t, findings, 1)
	requireValid(t, findings[0])
	m := findings[0].Match
	require.True(t, m.KnownExploited, "known exploited if any match says so")
	require.Equal(t, severityCritical, m.Severity, "the most severe")
	require.Equal(t, stateWontFix, m.FixState, "the fix state of the match that knows most")
	require.Equal(t, []string{v11, v12, v13}, m.FixedVersions, "the sorted union")
	require.Equal(t, []evidence.CVSS{{Version: cvss20, Vector: "AV:N"}, {Version: cvss31, Vector: vectorAVL}}, m.CVSS,
		"the sorted union")

	t.Run("a rule sees the merged finding", func(t *testing.T) {
		look := because(ruleOf("look", hint, "true"),
			`[string(finding.knownExploited), finding.severity, finding.fixState, finding.fixedVersions.join(',')].join(' ')`)
		got := evaluate(t, compiled(t, look), nil, []evidence.Match{c, b, a})
		require.Equal(t, "true Critical wont-fix 1.1,1.2,1.3", got[0].Notes[0].Text)
	})
}

func TestMergedSeverityIsTheMostSevereWithoutRegardToCase(t *testing.T) {
	tests := []struct {
		severities []string
		want       string
	}{
		{[]string{severityLow, severityHigh}, severityHigh},
		{[]string{severityHigh, severityCritical, severityLow}, severityCritical},
		{[]string{severityNegligible, severityMedium}, severityMedium},
		{[]string{severityUnknown, severityLow}, severityLow},
		{[]string{"", severityNegligible}, severityNegligible},
		{[]string{severityUnknown, ""}, severityUnknown},
		{[]string{"critical"}, severityCritical},
		{[]string{"HIGH"}, severityHigh},
		{[]string{"mEdIuM"}, severityMedium},
		// Anything else is unknown.
		{[]string{"Moderate"}, severityUnknown},
		{[]string{"Critical "}, severityUnknown},
	}
	for _, tc := range tests {
		matches := make([]evidence.Match, 0, len(tc.severities))
		for _, s := range tc.severities {
			m := matchOf(someCVE, pkgA)
			m.Severity = s
			matches = append(matches, m)
		}
		findings := engine.Evaluate(nil, nil, matches)
		require.Len(t, findings, 1)
		require.Equal(t, tc.want, findings[0].Match.Severity, "severities %q", tc.severities)
	}
}

func TestMergedFixStateIsFixedThenWontFixThenNotFixedThenUnknown(t *testing.T) {
	tests := []struct {
		states []string
		want   string
	}{
		{[]string{stateWontFix, stateFixed, stateNotFixed}, stateFixed},
		{[]string{stateNotFixed, stateWontFix, stateUnknown}, stateWontFix},
		{[]string{stateUnknown, stateNotFixed}, stateNotFixed},
		{[]string{"", stateNotFixed}, stateNotFixed},
		// An empty state is what a source writes that says nothing of a fix, and is unknown, like any
		// other state that isn't one of the three.
		{[]string{""}, stateUnknown},
		{[]string{"", stateUnknown, "pending"}, stateUnknown},
		{[]string{"Fixed"}, stateUnknown},
	}
	for _, tc := range tests {
		matches := make([]evidence.Match, 0, len(tc.states))
		for _, s := range tc.states {
			m := matchOf(someCVE, pkgA)
			m.FixState = s
			matches = append(matches, m)
		}
		findings := engine.Evaluate(nil, nil, matches)
		require.Len(t, findings, 1)
		require.Equal(t, tc.want, findings[0].Match.FixState, "states %q", tc.states)
	}
}

func TestEvaluateSortsByVulnerabilityThenPackage(t *testing.T) {
	matches := make([]evidence.Match, 0, 4)
	for _, ids := range [][2]string{{cve2, pkgB}, {cve1, pkgB}, {cve2, pkgA}, {cve1, pkgA}} {
		matches = append(matches, matchOf(ids[0], ids[1]))
	}
	findings := engine.Evaluate(nil, nil, matches)
	ids := make([][2]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, [2]string{f.Match.VulnerabilityID, f.Match.PackageID})
	}
	require.Equal(t, [][2]string{{cve1, pkgA}, {cve1, pkgB}, {cve2, pkgA}, {cve2, pkgB}}, ids)
}

func TestTheMatchesInAnyOrderAndRepeatedGiveTheSameFindings(t *testing.T) {
	matches := make([]evidence.Match, 0, 24)
	for _, pkg := range []string{pkgA, pkgB, "pkg-c", "pkg-d"} {
		for i, severity := range []string{severityLow, severityHigh, severityCritical} {
			m := matchOf(fmt.Sprintf("CVE-2026-%04d", 100-i), pkg)
			m.Severity = severity
			m.FixState = []string{stateFixed, stateWontFix, ""}[i]
			m.FixedVersions = []string{fmt.Sprintf("%d.%d", i, 9-i), "0.1"}
			m.KnownExploited = pkg == pkgB && i == 1
			matches = append(matches, m)
		}
	}
	// The same findings again, with other severities and fix states, and for one package with another
	// name, version and type.
	for _, m := range slices.Clone(matches) {
		m.Severity, m.FixState, m.FixedVersions = severityMedium, stateNotFixed, []string{"7.0"}
		if m.PackageID == "pkg-d" {
			m.PackageName, m.PackageVersion, m.PackageType = "libd-alias", "", "rpm"
		}
		matches = append(matches, m)
	}
	steps := compiled(t,
		ruleOf("hold", underInvestigation, "finding.knownExploited"),
		because(ruleOf(noteName, hint, "true"), "finding.packageName"),
	)

	want := engine.Evaluate(steps, nil, matches)
	require.Len(t, want, 4*3, "one finding for each vulnerability and package")
	rng := rand.New(rand.NewPCG(7, 11))
	for range 100 {
		shuffled := slices.Clone(matches)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		require.Equal(t, want, engine.Evaluate(steps, nil, shuffled))

		doubled := append(slices.Clone(shuffled), matches...)
		rng.Shuffle(len(doubled), func(i, j int) { doubled[i], doubled[j] = doubled[j], doubled[i] })
		require.Equal(t, want, engine.Evaluate(steps, nil, doubled))
	}
}

func TestEvaluateLeavesItsInputsAlone(t *testing.T) {
	a := matchOf(someCVE, pkgA)
	a.FixedVersions = []string{cvss20, "1.0"}
	a.CVSS = []evidence.CVSS{{Version: cvss31, Vector: "b"}, {Version: cvss31, Vector: "a"}}
	b := matchOf(someCVE, pkgA)
	b.FixedVersions = []string{"1.5"}
	matches := []evidence.Match{a, b, matchOf("CVE-2026-0002", pkgB)}
	data := testData(3)
	before, dataBefore := mustMarshal(t, matches), mustMarshal(t, data)

	findings := engine.Evaluate(compiled(t, needing(ruleOf("look", hint, "true"), contents)), contentsOf(data), matches)
	require.Len(t, findings, 2)
	require.JSONEq(t, string(before), string(mustMarshal(t, matches)))
	require.JSONEq(t, string(dataBefore), string(mustMarshal(t, data)))

	// The findings share nothing with the matches.
	findings[0].Match.FixedVersions[0] = "changed"
	findings[0].Match.CVSS[0].Vector = "changed"
	require.JSONEq(t, string(before), string(mustMarshal(t, matches)))
}

func TestEvaluateOfNothing(t *testing.T) {
	require.Empty(t, engine.Evaluate(nil, nil, nil))
	require.Empty(t, engine.Evaluate(compiled(t, ruleOf(guardName, underInvestigation, "true")), nil, []evidence.Match{}))
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return raw
}

// ---- text ----

// dirty is what a crafted file name or package field can carry: an escape sequence, a newline, a
// right-to-left override, a NUL and a zero-width joiner. clean is what a finding shows of it.
const (
	dirty = "a\x1b[31m\n\u202eb\x00\u200dc"
	clean = "a\ufffd[31m\ufffd\ufffdb\ufffd\ufffdc"
)

func TestEveryStringOfTheMatchIsPrintableAndFitsTheSchema(t *testing.T) {
	long := func(s string, n int) string { return strings.Repeat(s, n) }

	t.Run("too long", func(t *testing.T) {
		m := evidence.Match{
			VulnerabilityID: long("c", 100), PackageID: long("i", 100), PackageName: long("n", 300),
			PackageVersion: long("v", 200), PackageType: long("t", 50), Severity: severityHigh, FixState: stateFixed,
		}
		got := engine.Evaluate(nil, nil, []evidence.Match{m})[0].Match
		require.Equal(t, long("c", 64), got.VulnerabilityID)
		require.Equal(t, long("i", 64), got.PackageID)
		require.Equal(t, long("n", 253), got.PackageName)
		require.Equal(t, long("v", 128), got.PackageVersion)
		require.Equal(t, long("t", 32), got.PackageType)
	})

	t.Run("the schema counts characters, not bytes", func(t *testing.T) {
		m := matchOf(someCVE, pkgA)
		m.PackageName = long("é", 300)
		require.Equal(t, long("é", 253), engine.Evaluate(nil, nil, []evidence.Match{m})[0].Match.PackageName)
	})

	t.Run("not printable", func(t *testing.T) {
		m := evidence.Match{
			VulnerabilityID: dirty, PackageID: dirty, PackageName: dirty, PackageVersion: dirty, PackageType: dirty,
			Severity: severityHigh, FixState: stateFixed, CVSS: []evidence.CVSS{{Version: dirty, Vector: dirty}},
		}
		f := engine.Evaluate(nil, nil, []evidence.Match{m})[0]
		requireValid(t, f)
		require.Equal(t, evidence.Match{
			VulnerabilityID: clean, PackageID: clean, PackageName: clean, PackageVersion: clean, PackageType: clean,
			Severity: severityHigh, FixState: stateFixed, CVSS: []evidence.CVSS{{Version: clean, Vector: clean}},
		}, f.Match)
	})

	t.Run("empty where the schema requires text", func(t *testing.T) {
		f := engine.Evaluate(nil, nil, []evidence.Match{{}})[0]
		requireValid(t, f)
		require.Equal(t, evidence.Match{
			VulnerabilityID: placeholder, PackageID: placeholder, PackageName: placeholder, PackageType: placeholder,
			Severity: severityUnknown, FixState: stateUnknown,
		}, f.Match, "an absent version stays absent")
	})

	t.Run("the first eight of the sorted fixed versions, each cut", func(t *testing.T) {
		m := matchOf(someCVE, pkgA)
		for i := 9; i >= 0; i-- {
			m.FixedVersions = append(m.FixedVersions, fmt.Sprintf("1.0.%d", i))
		}
		m.FixedVersions = append(m.FixedVersions, long("9", 200))
		require.Equal(t, []string{"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7"},
			engine.Evaluate(nil, nil, []evidence.Match{m})[0].Match.FixedVersions)

		m.FixedVersions = []string{long("9", 200)}
		require.Equal(t, []string{long("9", 128)}, engine.Evaluate(nil, nil, []evidence.Match{m})[0].Match.FixedVersions)
	})

	t.Run("the fixed versions, sorted and made unique as they are shown", func(t *testing.T) {
		// As they come, "\x01x" sorts before "a", and "1.0\x01" and "1.0\x02" are two. As they are
		// shown, "\ufffdx" sorts after "a", and the other two are one.
		m := matchOf(someCVE, pkgA)
		m.FixedVersions = []string{"a", "\x01x", "1.0\x01", "1.0\x02"}
		require.Equal(t, []string{"1.0\ufffd", "a", "\ufffdx"}, engine.Evaluate(nil, nil, []evidence.Match{m})[0].Match.FixedVersions)
	})
}
