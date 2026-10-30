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

package config

import "unicode/utf8"

// What the controllers of this package write in conditions and events.
const (
	// eventActionReconcile is the action of the Warning events that the controllers record: what
	// the controller was doing when it found the object failing.
	eventActionReconcile = "Reconcile"
	// maxMessageBytes is the longest condition message, and event note, that the controllers
	// write. The events API takes a note of 1 kB at most, and an error is text that no schema
	// bounds.
	maxMessageBytes = 1024
)

// truncate shortens s to at most maxMessageBytes. It cuts between characters, and ends the text
// with "..." when it cuts.
func truncate(s string) string {
	if len(s) <= maxMessageBytes {
		return s
	}
	const ellipsis = "..."
	cut := maxMessageBytes - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ellipsis
}
