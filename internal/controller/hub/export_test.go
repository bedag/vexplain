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

package hub

// The rounds and the reconciles of the hub, for the tests of package hub_test, which run them one at a
// time instead of through a controller or every interval.
var (
	// Sweep runs one round of a Janitor.
	Sweep = (*Janitor).sweep
	// RequestEvidence reconciles an image, as the assessor's controller of requests does.
	RequestEvidence = (*Assessor).requestEvidence
	// Assess reconciles a platform manifest, as the assessor's controller of sheets does.
	Assess = (*Assessor).assess
	// MarkChanged notes that the findings collector changed the findings of a subject, or of every
	// subject for an empty one, as the assessor does for what Findings.Changed delivers.
	MarkChanged = (*Assessor).changed
	// UsableAgain is the predicate of the assessor's watch of the Collectors that can be used again, and
	// ManifestsOfFindingsCollector the map of its events to the manifests to assess.
	UsableAgain                  = usableAgain
	ManifestsOfFindingsCollector = (*Assessor).manifestsOfFindingsCollector
)

// EvidenceBudget is the most decoded evidence, in bytes, that the evaluations of an assessor hold at once.
const EvidenceBudget = evidenceBudget

// WatchBudget has the assessor tell watch when an evaluation of a manifest starts to hold its share of the
// budget of decoded evidence, and when it stops. The evaluation waits for watch to return.
func WatchBudget(a *Assessor, watch func(manifest string, holds bool)) { a.holding = watch }

// ErrPassedABound is what the assessor returns for an evaluation in which a run of a rule passed a bound on time.
var ErrPassedABound = errPassedABound

// SummaryOf is the summary that the controller of the summaries makes of an image, from its object and the sheets of
// its manifests, by manifest digest.
var SummaryOf = summaryOf

// SheetChanged maps the event of a sheet to the images whose summaries read it, as the controller of the summaries
// does.
var SheetChanged = (*Summaries).sheetChanged
