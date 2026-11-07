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

package inventory

import "strings"

// PlatformCovers reports whether the manifest of a platform covers a platform that a pod runs on, both as
// os/architecture[/variant]. They must name the same operating system and architecture, and the same variant, or any
// variant when either names none: a node says no variant of its architecture, while an image may list its manifest
// only under one. The hub's assessor and the spoke's renderer both match by this rule, so that what one asks for, the
// other reads.
func PlatformCovers(manifest, running string) bool {
	m, r := strings.SplitN(manifest, "/", 3), strings.SplitN(running, "/", 3)
	if len(m) < 2 || len(r) < 2 || m[0] != r[0] || m[1] != r[1] {
		return false
	}
	return len(m) == 2 || len(r) == 2 || m[2] == r[2]
}
