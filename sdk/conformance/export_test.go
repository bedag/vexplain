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

package conformance

import "time"

// RunWithin is RunWith with shorter limits, so that a test of a collector that never ends its snapshot, or never
// lists a pod, fails in seconds and not in a minute. snapshot is how long a Watch has to reach SnapshotEnd, and
// presence is how long the presence check waits for pods that it expects to see listed.
func RunWithin(r Reporter, target Target, snapshot, presence time.Duration) {
	lim := defaultLimits
	lim.snapshot, lim.presence = snapshot, presence
	run(r, target, lim)
}
