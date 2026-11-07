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

package spoke

import "time"

// The executor's bounds: how long a request waits for a collector's answer, the longest scan of the scanner that it
// covers, and how many requests run at once for one collector.
const (
	InvokeDeadline = invokeDeadline
	LongestScan    = longestScan
	MaxInvokes     = maxInvokes
)

// SetInvokeDeadline sets how long a request of e waits for a collector's answer, before the first request. The tests
// shorten it.
func SetInvokeDeadline(e *Executor, d time.Duration) { e.deadline = d }
