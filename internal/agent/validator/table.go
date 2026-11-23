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

package validator

import (
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
)

// requirement is what a verdict of one status needs, besides claims that cite entries of the ledger, which every
// verdict needs.
type requirement struct {
	// justifications are the justifications that the status takes, one of which it needs. A status without any takes
	// none: OpenVEX's justification belongs to not_affected alone.
	justifications []string
	// silences says that the status silences the case's findings, as not_affected and fixed do. Such a status needs,
	// for every package of the case, describe's answer that the package has the fix, and no rule that holds a finding
	// of the case against the agent.
	silences bool
}

// table is the validator's table in phase 4: what a verdict of each status needs (design of the agent on image
// cases, 5.5). It is the operator's, part of the code, and nobody can edit it. A status that it doesn't hold is
// rejected.
//
// Main design 6.7's other justifications need evidence that phase 4 has no tool for, such as a symbol scan or a
// config read. So not_affected takes only vulnerable_code_not_present, resting, as fixed does, on describe's fixed
// version for the package's distribution or ecosystem, which covers a distribution's backport.
var table = map[string]requirement{
	string(inventoryv1alpha1.VEXStatusNotAffected): {silences: true,
		justifications: []string{string(inventoryv1alpha1.VEXJustificationVulnerableCodeNotPresent)}},
	string(inventoryv1alpha1.VEXStatusFixed):              {silences: true},
	string(inventoryv1alpha1.VEXStatusAffected):           {},
	string(inventoryv1alpha1.VEXStatusUnderInvestigation): {},
}

// describeTool is the one tool whose output can show that a package has the fix: the operation describe of the
// collector vulnerabilities, which compares the installed version with each provider's fix itself.
const describeTool = "vulnerabilities__describe"
