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

package scan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/bedag/vexplain/collectors/scanner/internal/result"
	"github.com/bedag/vexplain/sdk/jobs"
)

// scanOutcome is what a finished scan found: a result whose every manifest passed the checks, or the reason why the
// scan failed, and never both.
type scanOutcome struct {
	// result is what the scan found. It is nil when the scan failed.
	result *result.Result
	// reason is why the scan failed, and why says it in a fixed text: nothing in it comes from the log. Both are
	// empty when the scan succeeded.
	reason, why string
}

// failedWith returns the outcome of a scan that failed for reason, for the cause why.
func failedWith(reason, why string) scanOutcome {
	return scanOutcome{reason: reason, why: why}
}

// outcomeOf returns what the Job of call came to: the result of its line, once checked, or why it failed.
func outcomeOf(r jobs.Result, call scanCall) scanOutcome {
	switch reason := r.FailureReason; {
	case reason == "":
		return resultOf(r.Line, call)
	case reason == timedOut:
		return failedWith(timedOut, "the scan Job ran past its deadline")
	case reason == internal:
		return failedWith(internal, "the scan failed for a reason of its own, or its pod said nothing that tells why")
	case reason == tooLarge:
		return failedWith(tooLarge, "the image unpacks to more than the workspace holds, or the scan's log is more "+
			"than the collector reads")
	case result.ErrorReason(reason).Valid():
		return failedWith(reason, "the scan reported why it failed")
	default:
		// The scanner prints its own reasons only, so the line is no line of the scanner's.
		return failedWith(internal, "the scan pod reported a reason that the scanner doesn't give")
	}
}

// resultOf reads the result line of a scan pod that succeeded, the only kind of pod that delivers a result. The result
// must fit the scan that call asked for in every manifest, or the scan failed: TooLarge when the result is larger than
// the collector reads, and Internal for anything else, since the scanner never prints such a result.
func resultOf(line string, call scanCall) scanOutcome {
	r, reason, err := result.Parse(line, maxResultBytes)
	switch {
	case errors.Is(err, result.ErrTooLarge):
		return failedWith(tooLarge, err.Error())
	case err != nil:
		// The errors of Parse are fixed texts.
		return failedWith(internal, err.Error())
	case reason != "":
		return failedWith(internal, "the scan pod succeeded, but printed an error line")
	}
	if why := check(r, call); why != "" {
		return failedWith(internal, why)
	}
	return scanOutcome{result: r}
}

// check returns why r doesn't fit the scan that call asked for, or "" when it does:
//   - it names the image of the --image argument, byte for byte
//   - it has 1 to 16 manifests, each of a platform of its own
//   - each manifest fits the scan, as checkManifest says
func check(r *result.Result, call scanCall) string {
	if r.Image != call.image {
		return "the result names another image than the scan asked for"
	}
	if len(r.Manifests) == 0 || len(r.Manifests) > maxManifests {
		return fmt.Sprintf("the result has %d manifests, and not 1 to %d", len(r.Manifests), maxManifests)
	}
	platforms := make(map[string]bool, len(r.Manifests))
	for _, m := range r.Manifests {
		if why := checkManifest(m, call); why != "" {
			return why
		}
		if platforms[m.Platform] {
			return "two manifests of the result have the same platform"
		}
		platforms[m.Platform] = true
	}
	return ""
}

// checkManifest returns why m doesn't fit the scan that call asked for, or "" when it does. Its digest and its
// platform must be values that the API holds. Its platform must match one that the scan asked for, unless the
// manifest is the digest of the scan itself: an image of one manifest, and no index, is scanned whatever its platform.
// Its SBOM must be a JSON object with members, and its count of ELF files a number that the API holds.
func checkManifest(m result.Manifest, call scanCall) string {
	switch {
	case !digestPattern.MatchString(m.Digest):
		return "a manifest of the result has no sha256 digest"
	case len(m.Platform) > maxPlatformLength || !platformPattern.MatchString(m.Platform):
		return "a manifest of the result has a platform that the API can't hold"
	case m.Digest != call.digest && !slices.ContainsFunc(call.platforms, func(requested string) bool {
		return result.PlatformMatches(requested, m.Platform)
	}):
		return "a manifest of the result is of a platform that the scan didn't ask for"
	case !isObjectWithMembers(m.SBOM):
		return "a manifest of the result has no SBOM"
	case m.ELF.Total < 0 || m.ELF.Total > math.MaxInt32:
		return "a manifest of the result has a count of ELF files that the API can't hold"
	}
	return ""
}

// isObjectWithMembers reports whether raw is a JSON object with at least one member. raw comes from a JSON decoder,
// which has checked that it is valid JSON, so its first characters tell.
func isObjectWithMembers(raw json.RawMessage) bool {
	const space = " \t\r\n"
	value := bytes.TrimLeft(raw, space)
	if len(value) == 0 || value[0] != '{' {
		return false
	}
	members := bytes.TrimLeft(value[1:], space)
	return len(members) > 0 && members[0] != '}'
}
