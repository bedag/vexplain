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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/rules/engine"
)

const shippedExample = `(finding.knownExploited || (has(finding.epssPermille) && finding.epssPermille >= 100)) && impact.highestExposure == "Open" && finding.fixState != "fixed"`

func caseOf(fixState string, exploited bool) engine.Case {
	return engine.Case{
		Finding: map[string]any{"vulnerabilityID": "CVE-2026-1", "knownExploited": exploited, "fixState": fixState, "status": "UnderInvestigation"},
		Subject: map[string]any{"manifestDigest": "sha256:aa", "repositories": []any{"registry.example/app"}, "platform": "linux/amd64"},
		Impact:  map[string]any{"clusters": []any{"c1"}, "highestExposure": "Open", "highestUrgency": "High"},
	}
}

func conditionsOf(t *testing.T, exprs ...string) *engine.Conditions {
	t.Helper()
	list := make([]engine.Condition, 0, len(exprs))
	for i, e := range exprs {
		list = append(list, engine.Condition{Name: "c" + string(rune('a'+i)), Expression: e})
	}
	c, err := engine.CompileConditions(list)
	require.NoError(t, err)
	return c
}

func TestTheShippedExampleSelectsEmergencyMitigation(t *testing.T) {
	c := conditionsOf(t, shippedExample)

	ok, failed, err := c.Match(caseOf("not-fixed", true))
	require.NoError(t, err)
	require.True(t, ok, failed)

	ok, _, err = c.Match(caseOf("fixed", true))
	require.NoError(t, err)
	require.False(t, ok)

	// A finding without EPSS that isn't known to be exploited isn't selected, and isn't an error either.
	ok, _, err = c.Match(caseOf("not-fixed", false))
	require.NoError(t, err)
	require.False(t, ok)
}

func TestNoConditionsMatch(t *testing.T) {
	ok, _, err := conditionsOf(t).Match(caseOf("", false))
	require.NoError(t, err)
	require.True(t, ok)
}

func TestEvidenceIsNotAVariable(t *testing.T) {
	_, err := engine.CompileConditions([]engine.Condition{{Name: "sbom-only", Expression: "sbom.data.x == 1"}})
	require.ErrorContains(t, err, "sbom-only")
}

func TestAFailingExpressionDoesNotSelect(t *testing.T) {
	c := conditionsOf(t, "1 == 1", "finding.epssPermille >= 100")

	ok, failed, err := c.Match(caseOf("", true))

	require.False(t, ok)
	require.Equal(t, "cb", failed)
	require.Error(t, err)
}

func TestANonBooleanResultDoesNotSelect(t *testing.T) {
	c := conditionsOf(t, "finding.vulnerabilityID")

	ok, failed, err := c.Match(caseOf("", true))

	require.False(t, ok)
	require.Equal(t, "ca", failed)
	require.Error(t, err)
}

func TestAConditionThatIsNotTrueDoesNotSelect(t *testing.T) {
	ok, failed, err := conditionsOf(t, "false").Match(caseOf("", true))
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, "ca", failed)
}

func TestConditionsRefuseWhatRulesRefuse(t *testing.T) {
	for _, expr := range []string{`"a".indexOf("b") == 0`, `"a".replace("a", "b") == ""`, `["a"].join(",") == ""`,
		`[1].sort() == []`, `[1].distinct() == []`, `"%d".format([1]) == ""`} {
		_, err := engine.CompileConditions([]engine.Condition{{Name: "x", Expression: expr}})
		require.ErrorContains(t, err, "bounds on time", expr)
	}
	_, err := engine.CompileConditions([]engine.Condition{{Name: "x", Expression: `finding.vulnerabilityID.matches(subject.platform)`}})
	require.ErrorContains(t, err, "isn't a literal")
}

func TestConditionsHoldTheCostLimit(t *testing.T) {
	expr := `[1,2,3,4,5,6,7,8,9,10].all(a, [1,2,3,4,5,6,7,8,9,10].all(b, [1,2,3,4,5,6,7,8,9,10].all(c, ` +
		`[1,2,3,4,5,6,7,8,9,10].all(d, [1,2,3,4,5,6,7,8,9,10].all(e, [1,2,3,4,5,6,7,8,9,10].all(f, a+b+c+d+e+f > 0))))))`
	ok, _, err := conditionsOf(t, expr).Match(caseOf("", true))
	require.False(t, ok)
	require.ErrorContains(t, err, "cost limit")
}

func TestConditionNamesAreUnique(t *testing.T) {
	_, err := engine.CompileConditions([]engine.Condition{{Name: "a", Expression: "1 == 1"}, {Name: "a", Expression: "1 == 1"}})
	require.Error(t, err)
}
