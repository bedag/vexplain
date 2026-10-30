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

package result

import (
	"slices"
	"strings"
)

// PlatformMatches reports whether a manifest of the platform actual is one to scan for a request of
// the platform requested. Both are written os/architecture[/variant], as in Manifest.Platform. They
// match when their OS and architecture are equal, and their variant too when requested names one.
//
// This is the one rule for matching platforms: the scanner picks the manifests of an index by it,
// and the operator checks a result by it. Requests come from the labels of nodes, which name no
// variant, so linux/arm64 matches linux/arm64/v8. A string of another form matches nothing.
func PlatformMatches(requested, actual string) bool {
	r, ok := parsePlatform(requested)
	if !ok {
		return false
	}
	a, ok := parsePlatform(actual)
	if !ok {
		return false
	}
	return r.os == a.os && r.architecture == a.architecture && (r.variant == "" || r.variant == a.variant)
}

// platform is a platform written os/architecture[/variant].
type platform struct {
	os, architecture, variant string
}

// parsePlatform splits s into its parts. It returns false when s has fewer than two parts or more
// than three, or an empty one.
func parsePlatform(s string) (platform, bool) {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || len(parts) > 3 || slices.Contains(parts, "") {
		return platform{}, false
	}
	p := platform{os: parts[0], architecture: parts[1]}
	if len(parts) == 3 {
		p.variant = parts[2]
	}
	return p, true
}
