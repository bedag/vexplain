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

// The rounds of the poller and the janitor, for the tests of package hub_test, which run one round
// at a time instead of one every interval.
var (
	// Poll runs one round of a DatabasePoller: one read of the matcher's database.
	Poll = (*DatabasePoller).poll
	// Sweep runs one round of a Janitor.
	Sweep = (*Janitor).sweep
)

// EveryManifest maps a change of the OperatorConfig to the requests of the verdicts controller, as
// its watch of the OperatorConfig does.
var EveryManifest = (*VerdictsReconciler).everyManifest
