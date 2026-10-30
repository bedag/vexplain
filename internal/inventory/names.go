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

import (
	"regexp"
	"strings"
)

// namePattern matches the name of an ImageInventory: "sha256-" and 64 lowercase hex digits. It is
// the pattern of spec.digest in the CRD schema, with '-' where that has ':'.
var namePattern = regexp.MustCompile(`^sha256-[a-f0-9]{64}$`)

// NameForDigest returns the name of the ImageInventory of a digest: the digest with ':' replaced
// by '-', so that sha256:<hex> becomes sha256-<hex>. A name can't hold a ':'. The CRD requires this
// name with a CEL rule, and it is the rule that the replacement here follows.
func NameForDigest(digest string) string {
	return strings.ReplaceAll(digest, ":", "-")
}

// DigestForName is the reverse of NameForDigest. It reports false when the name isn't one that
// NameForDigest makes from a digest, so a caller can skip objects that don't belong to a digest.
func DigestForName(name string) (string, bool) {
	if !namePattern.MatchString(name) {
		return "", false
	}
	// The only '-' of a matching name is the one after the algorithm.
	return strings.Replace(name, "-", ":", 1), true
}
