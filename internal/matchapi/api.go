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

// Package matchapi is the wire format of the matcher and the client for it (decision 0022).
//
// The matcher is the hub's one vulnerability database: an HTTP service around the Grype CLI, in
// its own Deployment. The hub's verdicts controller sends it the reduced SBOM of each image
// manifest, and turns the matches into findings. It reads the database's version, and matches
// every manifest again when the version changes.
//
// This is hub-side code, and the only package of the matcher that the manager imports. The server
// is internal/matcher, which belongs to the matcher binary alone.
package matchapi

import (
	"encoding/json"
	"errors"
	"time"
)

// The paths of the matcher's API. The server also answers /healthz and /readyz, which are for the
// kubelet and not part of this API.
const (
	// PathMatch takes a POST with a MatchRequest, and answers with a MatchResponse.
	PathMatch = "/v1/match"
	// PathDatabase takes a GET, and answers with a Database.
	PathDatabase = "/v1/database"
)

// MaxRequestBytes is the largest request the matcher reads: 64 MiB. A larger one gets 413.
const MaxRequestBytes = 64 << 20

// Match is one vulnerability that Grype reports for one package. The strings are Grype's, as it
// writes them: this package keeps them as they are, and the rules map them onto the API's enums.
type Match struct {
	// VulnerabilityID is the CVE where one exists: the matcher runs Grype with --by-cve, so that a
	// GitHub or distribution advisory with a CVE is reported under the CVE. An advisory without one
	// keeps its own ID.
	VulnerabilityID string `json:"vulnerabilityId"`
	// PackageID is the SBOM's package ID, as Grype reports it.
	PackageID string `json:"packageId"`
	// Severity is Grype's: Critical, High, Medium, Low, Negligible or Unknown.
	Severity string `json:"severity"`
	// FixState is Grype's: fixed, not-fixed, wont-fix or unknown. It is empty when the source of the
	// match, such as an NVD entry that names no fix, says nothing.
	FixState      string   `json:"fixState"`
	FixedVersions []string `json:"fixedVersions,omitempty"`
	// KnownExploited is true when Grype lists the vulnerability in the CISA catalog of known
	// exploited vulnerabilities.
	KnownExploited bool `json:"knownExploited"`
	// PackageName, PackageVersion and PackageType are the package as Grype reports it. The rules
	// need them for a package ID that the scan's evidence lacks. A package can lack a version.
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion,omitempty"`
	PackageType    string `json:"packageType"`
}

// MatchRequest is the body of a POST to PathMatch.
type MatchRequest struct {
	// SBOM is Syft's JSON, as the scanner reduces it for the hub. It must be a JSON object.
	SBOM json.RawMessage `json:"sbom"`
}

// MatchResponse is the answer to a MatchRequest.
type MatchResponse struct {
	// DatabaseVersion is the version of the database that the matches come from, as Database.Version.
	DatabaseVersion string `json:"databaseVersion"`
	// Matches is the list of matches. It is empty, and never missing, when Grype found none.
	Matches []Match `json:"matches"`
}

// Database says which vulnerability database the matcher uses.
type Database struct {
	// Version changes whenever the content of the database changes. It is Grype's schema version and
	// the build time, such as v6.1.10+2026-10-30T06:23:28Z: the schema version alone stays the same
	// across the daily builds. The hub matches every manifest again when it changes.
	Version string `json:"version"`
	// Built is when the database was built.
	Built time.Time `json:"built"`
}

// The errors of the client. Their texts are fixed: a response's body, a URL or an error's own text
// is never part of them, because the matcher's answers and Grype's output can hold text from an
// image's SBOM.
var (
	// ErrNotReady means that the matcher answered 503: it has no database yet. Try again later. A
	// request that waits for a free slot gets no 503 while its client waits: the client's own
	// timeout ends the wait, with ErrUnavailable.
	ErrNotReady = errors.New("matcher: not ready")
	// ErrUnavailable means that the matcher could not be reached, or didn't answer in time.
	ErrUnavailable = errors.New("matcher: unavailable")
)
