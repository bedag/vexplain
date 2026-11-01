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

package engine

import "time"

// SetBounds sets the bounds on the time of a run and of a call of Evaluate, for the tests of package
// engine_test, and returns a function that restores the bounds before. A bound of 0 is passed as soon
// as a run starts.
func SetBounds(run, call time.Duration) (restore func()) {
	beforeRun, beforeCall := runBound, callBound
	runBound, callBound = run, call
	return func() { runBound, callBound = beforeRun, beforeCall }
}
