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

package cases

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/rules"
	"github.com/bedag/vexplain/internal/rules/engine"
)

// Selection is what an investigation selects its cases by.
type Selection struct {
	// Playbook names the playbook whose sheets hold the cases.
	Playbook string
	// Vulnerabilities name the vulnerabilities in scope, each matched against a finding's ID and its aliases, ignoring
	// case. Without any, every case of the playbook is in scope.
	Vulnerabilities []string
	// PlaybookConditions are those of the playbook's agent section, and Conditions the investigation's. A case is
	// selected when one of its findings meets both. Nil holds for every case.
	PlaybookConditions, Conditions *engine.Conditions
	// SkipNotRunning leaves out a case whose image runs in no workload, before any condition: an investigation hands
	// cases to the agent, which an image that runs nowhere wastes. Rebuilding a known case leaves it unset.
	SkipNotRunning bool
	// Overrides change the table that decides the urgency, as the OperatorConfig's do.
	Overrides []configv1alpha1.UrgencyOverride
	// Exposures decides the exposure of the workloads with the playbook's exposure rules. Without it, the workloads
	// count by the exposure that the inventory holds, as the spokes decide it.
	Exposures Exposures
}

// Select returns the cases in the scope of the selection that its conditions select, and those that they don't, with
// the reason. It reads the playbook's sheets one at a time, and where the hub's inventory says each sheet's manifest
// runs. A case is selected when one of its findings meets the playbook's conditions and the investigation's: the
// verdict on the case holds for all its findings, so the case goes as a whole. A finding with a value that this
// version doesn't know, such as a severity that a newer hub wrote, selects nothing.
func Select(ctx context.Context, sheets inventory.VerdictsStore, inv inventory.Store, sel Selection) ([]Case, []Skipped, error) {
	var selected []Case
	var skipped []Skipped
	err := sheets.Each(ctx, func(sheet *inventoryv1alpha1.ImageVerdicts) error {
		if sheet.Spec.Playbook != sel.Playbook {
			return nil
		}
		groups := inScope(sheet.Status.Findings, sel.Vulnerabilities)
		if len(groups) == 0 {
			return nil
		}
		manifest := sheet.Spec.ManifestDigest
		where, err := presenceOf(ctx, inv, manifest, sel.Playbook, sel.Exposures)
		if err != nil {
			return err
		}
		subject := Subject{ManifestDigest: manifest, Repositories: where.repositories, Platform: where.platform}
		subjectVar := map[string]any{"manifestDigest": manifest, "repositories": anys(subject.Repositories),
			"platform": subject.Platform}
		for _, id := range slices.Sorted(maps.Keys(groups)) {
			c := Case{ManifestDigest: manifest, VulnerabilityID: id, Findings: groups[id], Subject: subject,
				Impact: where.impact(groups[id], sel.Overrides)}
			// An image that no workload runs costs the agent tokens for nothing, whatever the conditions say.
			reason, failed := "not running", false
			if !sel.SkipNotRunning || c.Impact.Resources > 0 {
				reason, failed = sel.reject(c, subjectVar)
			}
			if reason != "" {
				skipped = append(skipped, Skipped{ManifestDigest: manifest, VulnerabilityID: id, Reason: reason, Failed: failed})
				continue
			}
			selected = append(selected, c)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return selected, skipped, nil
}

// inScope groups the findings that the names select by their own vulnerability ID, each group sorted by package ID.
// Without names, it groups every finding.
func inScope(findings []inventoryv1alpha1.Finding, names []string) map[string][]inventoryv1alpha1.Finding {
	named := func(id string) bool {
		return slices.ContainsFunc(names, func(name string) bool { return strings.EqualFold(name, id) })
	}
	groups := map[string][]inventoryv1alpha1.Finding{}
	for _, f := range findings {
		if len(names) == 0 || named(f.VulnerabilityID) || slices.ContainsFunc(f.Aliases, named) {
			groups[f.VulnerabilityID] = append(groups[f.VulnerabilityID], f)
		}
	}
	for _, group := range groups {
		slices.SortFunc(group, func(a, b inventoryv1alpha1.Finding) int { return strings.Compare(a.Package.ID, b.Package.ID) })
	}
	return groups
}

// reject returns why the conditions select none of the case's findings, and "" when they select one: the first error of
// a condition that failed on one of them, which it reports, or else the first reason of its findings.
func (sel Selection) reject(c Case, subjectVar map[string]any) (string, bool) {
	impactVar := map[string]any{
		"clusters": int64(c.Impact.Clusters), "namespaces": int64(c.Impact.Namespaces), "resources": int64(c.Impact.Resources),
		"highestExposure": string(c.Impact.HighestExposure), "highestUrgency": string(c.Impact.HighestUrgency),
	}
	reason, failure := "", ""
	for _, f := range c.Findings {
		findingVar, ok := findingVariable(f)
		if !ok {
			reason = cmp.Or(reason, "a finding of the case holds a value that this version doesn't know")
			continue
		}
		k := engine.Case{Finding: findingVar, Subject: subjectVar, Impact: impactVar}
		why, erred := failed("the playbook's condition", sel.PlaybookConditions, k)
		if why == "" {
			why, erred = failed("the condition", sel.Conditions, k)
		}
		if why == "" {
			return "", false
		}
		reason = cmp.Or(reason, why)
		if erred {
			failure = cmp.Or(failure, why)
		}
	}
	return cmp.Or(failure, reason), failure != ""
}

// failed returns why the case doesn't meet the conditions, and "" when it does, and whether a condition failed rather
// than not holding. what says whose conditions they are.
func failed(what string, conds *engine.Conditions, k engine.Case) (string, bool) {
	if conds == nil {
		return "", false
	}
	ok, name, err := conds.Match(k)
	switch {
	case ok:
		return "", false
	case err != nil:
		return fmt.Sprintf("%s %q failed: %v", what, name, err), true
	default:
		return fmt.Sprintf("%s %q doesn't hold", what, name), false
	}
}

// findingVariable returns the finding as CEL sees it: as rules see it, the match that the sheet shows, with its JSON
// names, and the sheet's status, rule, justification and EPSS. The status is the rules' own: where the agent's verdict
// or an accepted statement changed it, the one that the agent field keeps, so that a condition on the status selects
// the same cases with or without a verdict. The rule and the justification are the sheet's, after the verdict. A match
// that showing may have changed, such as one with
// as many scores as a sheet holds, is read all the same, since conditions only select. It reports false for a finding
// with a value that this version doesn't know.
func findingVariable(f inventoryv1alpha1.Finding) (map[string]any, bool) {
	match, ok := rules.MatchOf(f)
	if !ok {
		return nil, false
	}
	raw, err := json.Marshal(match)
	if err != nil {
		return nil, false
	}
	var vars map[string]any
	if err := json.Unmarshal(raw, &vars); err != nil {
		return nil, false
	}
	vars["status"] = string(f.Status)
	if f.Agent != nil && f.Agent.RuleStatus != nil {
		vars["status"] = string(*f.Agent.RuleStatus)
	}
	if f.Rule != nil {
		vars["rule"] = *f.Rule
	}
	if f.Justification != nil {
		vars["justification"] = string(*f.Justification)
	}
	// JSON gives every number as a double, and EPSS is a whole number, which an expression compares with integers.
	if f.EPSSPermille != nil {
		vars["epssPermille"] = int64(*f.EPSSPermille)
	}
	return vars, true
}

// anys returns the strings as a list that CEL reads.
func anys(list []string) []any {
	out := make([]any, 0, len(list))
	for _, s := range list {
		out = append(out, s)
	}
	return out
}
