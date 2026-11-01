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
	// Poll runs one read of the database of the matcher that a MatcherFindings stands for.
	Poll = (*MatcherFindings).poll
	// RequestEvidence reconciles an image, as the assessor's controller of requests does.
	RequestEvidence = (*Assessor).requestEvidence
	// Assess reconciles a platform manifest, as the assessor's controller of sheets does.
	Assess = (*Assessor).assess
	// MarkChanged notes that the findings collector changed the findings of a subject, or of every
	// subject for an empty one, as the assessor does for what Findings.Changed delivers.
	MarkChanged = (*Assessor).changed
)
