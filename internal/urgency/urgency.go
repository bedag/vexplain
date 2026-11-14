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

// Package urgency decides how urgent an update is, with the deployer tree of SSVC, the Stakeholder-Specific
// Vulnerability Categorization of CERT/CC.
package urgency

import (
	"slices"
	"strings"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
)

// Inputs are the four inputs of SSVC's deployer tree.
type Inputs struct {
	Exploitation configv1alpha1.SSVCExploitation
	Exposure     configv1alpha1.SSVCExposure
	Automatable  configv1alpha1.SSVCAutomatable
	HumanImpact  configv1alpha1.SSVCHumanImpact
}

// FromFinding derives the inputs of a finding and a workload's exposure. Exploitation is Active when the
// finding is on the catalog of known exploited vulnerabilities, and None otherwise, since no advisory
// source says more. Every input that can't be known errs towards urgency: a finding with no CVSS vector
// that this package can read is automatable and has a high human impact, and when several vectors
// disagree, the most urgent reading of each input wins.
func FromFinding(f inventoryv1alpha1.Finding, exposure configv1alpha1.SSVCExposure) Inputs {
	in := Inputs{
		Exploitation: configv1alpha1.SSVCExploitationNone,
		Exposure:     exposure,
		Automatable:  configv1alpha1.SSVCAutomatableNo,
		HumanImpact:  configv1alpha1.SSVCHumanImpactMedium,
	}
	if f.KnownExploited == inventoryv1alpha1.KnownExploitedListed {
		in.Exploitation = configv1alpha1.SSVCExploitationActive
	}
	readings := 0
	for _, c := range f.CVSS {
		r, ok := readVector(c)
		if !ok {
			continue
		}
		readings++
		if r.automatable {
			in.Automatable = configv1alpha1.SSVCAutomatableYes
		}
		if r.highImpact {
			in.HumanImpact = configv1alpha1.SSVCHumanImpactHigh
		}
	}
	if readings == 0 {
		in.Automatable = configv1alpha1.SSVCAutomatableYes
		in.HumanImpact = configv1alpha1.SSVCHumanImpactHigh
	}
	return in
}

// Decide gives the outcome of the table for the inputs. An unknown exposure counts as Open. An override
// replaces the row with the same four inputs, the last of several for one row winning. A combination that
// the table doesn't hold, as an open enum may produce, is Immediate, so that an input that isn't
// understood errs towards urgency.
func Decide(in Inputs, overrides []configv1alpha1.UrgencyOverride) configv1alpha1.SSVCOutcome {
	if in.Exposure == configv1alpha1.SSVCExposureUnknown {
		in.Exposure = configv1alpha1.SSVCExposureOpen
	}
	for _, o := range slices.Backward(overrides) {
		if o.Exploitation == in.Exploitation && o.Exposure == in.Exposure &&
			o.Automatable == in.Automatable && o.HumanImpact == in.HumanImpact {
			return o.Outcome
		}
	}
	if outcome, ok := table[in]; ok {
		return outcome
	}
	return configv1alpha1.SSVCOutcomeImmediate
}

// NextStep is what the owner of a workload does about a finding: update when a fixed version exists,
// otherwise mitigate an affected finding and investigate an unclear one. A finding that is NotAffected or
// Fixed is settled and has no next step.
func NextStep(f inventoryv1alpha1.Finding) triagev1alpha1.ResourceStep {
	switch f.Status {
	case inventoryv1alpha1.VEXStatusAffected, inventoryv1alpha1.VEXStatusUnderInvestigation:
	default:
		return ""
	}
	if f.FixState == inventoryv1alpha1.FixStateFixed || len(f.FixedVersions) > 0 {
		return triagev1alpha1.ResourceStepUpdate
	}
	if f.Status == inventoryv1alpha1.VEXStatusAffected {
		return triagev1alpha1.ResourceStepMitigate
	}
	return triagev1alpha1.ResourceStepInvestigate
}

// reading is what one CVSS vector says about the two inputs that derive from it.
type reading struct {
	automatable bool // network attack vector, low complexity, no privileges and no user interaction
	highImpact  bool // high impact on confidentiality, integrity and availability
}

// vectorSpec names the metrics that a version of CVSS uses for the two inputs. Every metric that it lists
// must be in the vector for the vector to count, and a truncated vector is an unknown reading.
type vectorSpec struct {
	automatable map[string]string
	impact      map[string]string
}

var vectorSpecs = map[string]vectorSpec{
	"2.0": {
		automatable: map[string]string{"AV": "N", "AC": "L", "Au": "N"},
		impact:      map[string]string{"C": "C", "I": "C", "A": "C"},
	},
	"3.0": cvss3,
	"3.1": cvss3,
	"4.0": {
		automatable: map[string]string{"AV": "N", "AC": "L", "PR": "N", "UI": "N"},
		impact:      map[string]string{"VC": "H", "VI": "H", "VA": "H"},
	},
}

var cvss3 = vectorSpec{
	automatable: map[string]string{"AV": "N", "AC": "L", "PR": "N", "UI": "N"},
	impact:      map[string]string{"C": "H", "I": "H", "A": "H"},
}

// readVector reads a CVSS vector of a version that this package knows. It reports false for a vector of
// another version, an empty one and one that lacks a metric that the version needs.
func readVector(c inventoryv1alpha1.CVSS) (reading, bool) {
	if c.Version == nil || c.Vector == nil {
		return reading{}, false
	}
	spec, ok := vectorSpecs[*c.Version]
	if !ok {
		return reading{}, false
	}
	metrics := map[string]string{}
	for part := range strings.SplitSeq(*c.Vector, "/") {
		if k, v, found := strings.Cut(part, ":"); found && k != "CVSS" {
			metrics[k] = v
		}
	}
	all := func(want map[string]string) (bool, bool) {
		holds := true
		for k, v := range want {
			got, present := metrics[k]
			if !present {
				return false, false
			}
			holds = holds && got == v
		}
		return holds, true
	}
	auto, okA := all(spec.automatable)
	impact, okI := all(spec.impact)
	if !okA || !okI {
		return reading{}, false
	}
	return reading{automatable: auto, highImpact: impact}, true
}
