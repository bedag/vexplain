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

package urgency

import (
	"encoding/csv"
	"os"
	"testing"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
)

func TestDecideEndsOfTheTable(t *testing.T) {
	low := Inputs{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}
	if got := Decide(low, nil); got != configv1alpha1.SSVCOutcomeDefer {
		t.Errorf("lowest row = %s, want Defer", got)
	}
	high := Inputs{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactVeryHigh}
	if got := Decide(high, nil); got != configv1alpha1.SSVCOutcomeImmediate {
		t.Errorf("highest row = %s, want Immediate", got)
	}
}

func TestDecideUnknownExposureCountsAsOpen(t *testing.T) {
	in := Inputs{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh}
	want := Decide(in, nil)
	in.Exposure = configv1alpha1.SSVCExposureUnknown
	if got := Decide(in, nil); got != want {
		t.Errorf("Unknown = %s, Open = %s", got, want)
	}
}

// The published names differ from the API's, so each one is mapped, and an unknown name fails.
var (
	csvExploitation = map[string]configv1alpha1.SSVCExploitation{
		"none": configv1alpha1.SSVCExploitationNone, "public poc": configv1alpha1.SSVCExploitationPublicPoC, "active": configv1alpha1.SSVCExploitationActive,
	}
	csvExposure = map[string]configv1alpha1.SSVCExposure{
		"small": configv1alpha1.SSVCExposureSmall, "controlled": configv1alpha1.SSVCExposureControlled, "open": configv1alpha1.SSVCExposureOpen,
	}
	csvAutomatable = map[string]configv1alpha1.SSVCAutomatable{
		"no": configv1alpha1.SSVCAutomatableNo, "yes": configv1alpha1.SSVCAutomatableYes,
	}
	csvImpact = map[string]configv1alpha1.SSVCHumanImpact{
		"low": configv1alpha1.SSVCHumanImpactLow, "medium": configv1alpha1.SSVCHumanImpactMedium,
		"high": configv1alpha1.SSVCHumanImpactHigh, "very high": configv1alpha1.SSVCHumanImpactVeryHigh,
	}
	csvOutcome = map[string]configv1alpha1.SSVCOutcome{
		"defer": configv1alpha1.SSVCOutcomeDefer, "scheduled": configv1alpha1.SSVCOutcomeScheduled,
		"out-of-cycle": configv1alpha1.SSVCOutcomeOutOfCycle, "immediate": configv1alpha1.SSVCOutcomeImmediate,
	}
)

func lookup[V any](t *testing.T, m map[string]V, name string) V {
	t.Helper()
	v, ok := m[name]
	if !ok {
		t.Fatalf("the published table has a name that the test doesn't map: %q", name)
	}
	return v
}

func TestDecideMatchesPublishedTableRowForRow(t *testing.T) {
	f, err := os.Open("testdata/deployer_patch_application_priority_1_0_0.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	rows := records[1:]
	if len(rows) != 72 {
		t.Fatalf("published table has %d rows, want 72", len(rows))
	}
	if len(table) != len(rows) {
		t.Fatalf("table has %d rows, published table %d", len(table), len(rows))
	}
	for _, r := range rows {
		in := Inputs{
			Exploitation: lookup(t, csvExploitation, r[1]),
			Exposure:     lookup(t, csvExposure, r[2]),
			Automatable:  lookup(t, csvAutomatable, r[3]),
			HumanImpact:  lookup(t, csvImpact, r[4]),
		}
		want := lookup(t, csvOutcome, r[5])
		if got := Decide(in, nil); got != want {
			t.Errorf("row %s %+v = %s, want %s", r[0], in, got, want)
		}
	}
}

func TestDecideOverrideChangesOneRowOnly(t *testing.T) {
	target := Inputs{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}
	overrides := []configv1alpha1.UrgencyOverride{{
		Exploitation: target.Exploitation, Exposure: target.Exposure, Automatable: target.Automatable,
		HumanImpact: target.HumanImpact, Outcome: configv1alpha1.SSVCOutcomeImmediate,
	}}
	if got := Decide(target, overrides); got != configv1alpha1.SSVCOutcomeImmediate {
		t.Errorf("overridden row = %s, want Immediate", got)
	}
	changed := 0
	for in, want := range table {
		if got := Decide(in, overrides); got != want {
			changed++
			if in != target {
				t.Errorf("override changed %+v", in)
			}
		}
	}
	if changed != 1 {
		t.Errorf("override changed %d rows, want 1", changed)
	}
	// An override for Open covers an unknown exposure.
	open := Inputs{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}
	o := []configv1alpha1.UrgencyOverride{{
		Exploitation: open.Exploitation, Exposure: open.Exposure, Automatable: open.Automatable,
		HumanImpact: open.HumanImpact, Outcome: configv1alpha1.SSVCOutcomeImmediate,
	}}
	open.Exposure = configv1alpha1.SSVCExposureUnknown
	if got := Decide(open, o); got != configv1alpha1.SSVCOutcomeImmediate {
		t.Errorf("unknown exposure with an override for Open = %s", got)
	}
}

func s(v string) *string { return &v }

func finding(cvss ...inventoryv1alpha1.CVSS) inventoryv1alpha1.Finding {
	return inventoryv1alpha1.Finding{
		Status:         inventoryv1alpha1.VEXStatusAffected,
		KnownExploited: inventoryv1alpha1.KnownExploitedNotListed,
		FixState:       inventoryv1alpha1.FixStateNotFixed,
		CVSS:           cvss,
	}
}

func v(version, vector string) inventoryv1alpha1.CVSS {
	return inventoryv1alpha1.CVSS{Version: s(version), Vector: s(vector)}
}

func TestFromFindingExploitation(t *testing.T) {
	f := finding()
	if got := FromFinding(f, configv1alpha1.SSVCExposureOpen).Exploitation; got != configv1alpha1.SSVCExploitationNone {
		t.Errorf("not listed = %s, want None", got)
	}
	f.KnownExploited = inventoryv1alpha1.KnownExploitedListed
	in := FromFinding(f, configv1alpha1.SSVCExposureSmall)
	if in.Exploitation != configv1alpha1.SSVCExploitationActive {
		t.Errorf("listed = %s, want Active", in.Exploitation)
	}
	if in.Exposure != configv1alpha1.SSVCExposureSmall {
		t.Errorf("exposure = %s, want Small", in.Exposure)
	}
}

func TestFromFindingCVSS(t *testing.T) {
	const (
		net31   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		local31 = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
	)
	tests := []struct {
		name string
		cvss []inventoryv1alpha1.CVSS
		auto configv1alpha1.SSVCAutomatable
		hi   configv1alpha1.SSVCHumanImpact
	}{
		{"no vector", nil, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh},
		{"empty vector", []inventoryv1alpha1.CVSS{v("3.1", "")}, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh},
		{"unknown version only", []inventoryv1alpha1.CVSS{v("5.0", "AV:L/C:N/I:N/A:N")}, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh},
		{"truncated vector", []inventoryv1alpha1.CVSS{v("3.1", "CVSS:3.1/AV:L")}, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh},
		{"3.1 network, all high", []inventoryv1alpha1.CVSS{v("3.1", net31)}, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh},
		{"3.1 local, partly high", []inventoryv1alpha1.CVSS{v("3.1", local31)}, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium},
		{"3.0 network", []inventoryv1alpha1.CVSS{v("3.0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")}, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh},
		{"3.1 user interaction", []inventoryv1alpha1.CVSS{v("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N")}, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium},
		{"3.1 privileges", []inventoryv1alpha1.CVSS{v("3.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N")}, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium},
		{"4.0 network, all high", []inventoryv1alpha1.CVSS{v("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")}, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh},
		{"4.0 adjacent, low impact", []inventoryv1alpha1.CVSS{v("4.0", "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N")}, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium},
		{"2.0 network, complete", []inventoryv1alpha1.CVSS{v("2.0", "AV:N/AC:L/Au:N/C:C/I:C/A:C")}, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh},
		{"2.0 partial", []inventoryv1alpha1.CVSS{v("2.0", "AV:N/AC:M/Au:N/C:P/I:P/A:P")}, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium},
		{"2.0 authenticated", []inventoryv1alpha1.CVSS{v("2.0", "AV:N/AC:L/Au:S/C:C/I:C/A:C")}, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactHigh},
		{"disagreeing vectors take the most urgent of each", []inventoryv1alpha1.CVSS{
			v("4.0", "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
			v("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),
		}, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh},
		{"a known version beside an unknown one", []inventoryv1alpha1.CVSS{
			v("5.0", "AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"),
			v("3.1", local31),
		}, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := FromFinding(finding(tt.cvss...), configv1alpha1.SSVCExposureOpen)
			if in.Automatable != tt.auto {
				t.Errorf("automatable = %s, want %s", in.Automatable, tt.auto)
			}
			if in.HumanImpact != tt.hi {
				t.Errorf("human impact = %s, want %s", in.HumanImpact, tt.hi)
			}
		})
	}
}

var fixedIn = []string{"1.2.3"}

func TestNextStep(t *testing.T) {
	tests := []struct {
		name   string
		status inventoryv1alpha1.VEXStatus
		fix    inventoryv1alpha1.FixState
		vers   []string
		want   triagev1alpha1.NextStep
	}{
		{"fixed version", inventoryv1alpha1.VEXStatusAffected, inventoryv1alpha1.FixStateFixed, fixedIn, triagev1alpha1.NextStepUpdate},
		{"fixed version on an unclear finding", inventoryv1alpha1.VEXStatusUnderInvestigation, inventoryv1alpha1.FixStateFixed, fixedIn, triagev1alpha1.NextStepUpdate},
		{"affected, no fix", inventoryv1alpha1.VEXStatusAffected, inventoryv1alpha1.FixStateNotFixed, nil, triagev1alpha1.NextStepMitigate},
		{"affected, won't fix", inventoryv1alpha1.VEXStatusAffected, inventoryv1alpha1.FixStateWontFix, nil, triagev1alpha1.NextStepMitigate},
		{"unclear, no fix", inventoryv1alpha1.VEXStatusUnderInvestigation, inventoryv1alpha1.FixStateUnknown, nil, triagev1alpha1.NextStepInvestigate},
		{"not affected with a fix has no next step", inventoryv1alpha1.VEXStatusNotAffected, inventoryv1alpha1.FixStateFixed, fixedIn, ""},
		{"not affected, no fix", inventoryv1alpha1.VEXStatusNotAffected, inventoryv1alpha1.FixStateNotFixed, nil, ""},
		{"fixed with a fix has no next step", inventoryv1alpha1.VEXStatusFixed, inventoryv1alpha1.FixStateFixed, fixedIn, ""},
		{"fixed, no fix", inventoryv1alpha1.VEXStatusFixed, inventoryv1alpha1.FixStateNotFixed, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := finding()
			f.Status, f.FixState, f.FixedVersions = tt.status, tt.fix, tt.vers
			if got := NextStep(f); got != tt.want {
				t.Errorf("NextStep = %q, want %q", got, tt.want)
			}
		})
	}
}
