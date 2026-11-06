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

import configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"

// table is SSVC's deployer decision table, row for row: CERT/CC's "Deployer Patch Application
// Priority" table, version 1.0.0, from the repository https://github.com/CERTCC/SSVC at commit
// bf3213bc0bd2bf3cf1329c9b48f72d7163a682b1, file data/csv/ssvc/deployer_patch_application_priority_1_0_0.csv.
// The published file and the licence that covers it (an MIT-style licence of Carnegie Mellon
// University's Software Engineering Institute, which requires its notice to be kept) are in testdata,
// unchanged, and a test compares every row. The rows keep the published order of the file, and
// "very high" and "out-of-cycle" are written as the API names them.
var table = map[Inputs]configv1alpha1.SSVCOutcome{
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}:                 configv1alpha1.SSVCOutcomeDefer,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium}:              configv1alpha1.SSVCOutcomeDefer,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactHigh}:                configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactVeryHigh}:            configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactLow}:                configv1alpha1.SSVCOutcomeDefer,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactMedium}:             configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh}:               configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactVeryHigh}:           configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}:            configv1alpha1.SSVCOutcomeDefer,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium}:         configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactHigh}:           configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactVeryHigh}:       configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactLow}:           configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactMedium}:        configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh}:          configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactVeryHigh}:      configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}:                  configv1alpha1.SSVCOutcomeDefer,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium}:               configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactHigh}:                 configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactVeryHigh}:             configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactLow}:                 configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactMedium}:              configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh}:                configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationNone, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactVeryHigh}:            configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}:            configv1alpha1.SSVCOutcomeDefer,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium}:         configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactHigh}:           configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactVeryHigh}:       configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactLow}:           configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactMedium}:        configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh}:          configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactVeryHigh}:      configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}:       configv1alpha1.SSVCOutcomeDefer,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium}:    configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactHigh}:      configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactVeryHigh}:  configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactLow}:      configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactMedium}:   configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh}:     configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactVeryHigh}: configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}:             configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium}:          configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactHigh}:            configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactVeryHigh}:        configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactLow}:            configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactMedium}:         configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh}:           configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationPublicPoC, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactVeryHigh}:       configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}:               configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium}:            configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactHigh}:              configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactVeryHigh}:          configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactLow}:              configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactMedium}:           configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh}:             configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureSmall, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactVeryHigh}:         configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}:          configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium}:       configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactHigh}:         configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactVeryHigh}:     configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactLow}:         configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactMedium}:      configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh}:        configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureControlled, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactVeryHigh}:    configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactLow}:                configv1alpha1.SSVCOutcomeScheduled,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactMedium}:             configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactHigh}:               configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableNo, configv1alpha1.SSVCHumanImpactVeryHigh}:           configv1alpha1.SSVCOutcomeImmediate,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactLow}:               configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactMedium}:            configv1alpha1.SSVCOutcomeOutOfCycle,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactHigh}:              configv1alpha1.SSVCOutcomeImmediate,
	{configv1alpha1.SSVCExploitationActive, configv1alpha1.SSVCExposureOpen, configv1alpha1.SSVCAutomatableYes, configv1alpha1.SSVCHumanImpactVeryHigh}:          configv1alpha1.SSVCOutcomeImmediate,
}
