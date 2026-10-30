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

package matchapi

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	someCVE     = "CVE-2026-0001"
	somePackage = "libexample"
	typeAPK     = "apk"
	someVersion = "v6.1.10+2026-10-30T06:23:28Z"
	jsonNull    = "null"
)

// The wire format is the contract between the hub and the matcher, so its field names are pinned
// here, and not left to the Go field names.

func TestMatchWireFormat(t *testing.T) {
	m := Match{
		VulnerabilityID: someCVE,
		PackageID:       "d116986055f229b7",
		Severity:        "Critical",
		FixState:        "fixed",
		FixedVersions:   []string{"1.2.3-r1", "1.3.0-r0"},
		KnownExploited:  true,
		PackageName:     somePackage,
		PackageVersion:  "1.2.0-r0",
		PackageType:     typeAPK,
	}
	got, err := json.Marshal(m)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"vulnerabilityId": "CVE-2026-0001",
		"packageId": "d116986055f229b7",
		"severity": "Critical",
		"fixState": "fixed",
		"fixedVersions": ["1.2.3-r1", "1.3.0-r0"],
		"knownExploited": true,
		"packageName": "libexample",
		"packageVersion": "1.2.0-r0",
		"packageType": "apk"
	}`, string(got))

	var back Match
	require.NoError(t, json.Unmarshal(got, &back))
	require.Equal(t, m, back)
}

func TestMatchOmitsWhatIsEmpty(t *testing.T) {
	// A package can lack a version (R12), and a match need not have a fix. The other fields are
	// always there, even when they are false or empty.
	got, err := json.Marshal(Match{
		VulnerabilityID: someCVE,
		PackageID:       "p1",
		Severity:        "Unknown",
		FixState:        "",
		PackageName:     somePackage,
		PackageType:     typeAPK,
	})
	require.NoError(t, err)
	require.JSONEq(t, `{
		"vulnerabilityId": "CVE-2026-0001",
		"packageId": "p1",
		"severity": "Unknown",
		"fixState": "",
		"knownExploited": false,
		"packageName": "libexample",
		"packageType": "apk"
	}`, string(got))
}

func TestMatchResponseWireFormat(t *testing.T) {
	r := MatchResponse{
		DatabaseVersion: someVersion,
		Matches:         []Match{{VulnerabilityID: someCVE, PackageID: "p1", PackageName: somePackage}},
	}
	got, err := json.Marshal(r)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"databaseVersion": "v6.1.10+2026-10-30T06:23:28Z",
		"matches": [{
			"vulnerabilityId": "CVE-2026-0001", "packageId": "p1", "severity": "", "fixState": "",
			"knownExploited": false, "packageName": "libexample", "packageType": ""
		}]
	}`, string(got))

	var back MatchResponse
	require.NoError(t, json.Unmarshal(got, &back))
	require.Equal(t, r, back)

	// No matches is an empty list, which the client tells from a missing one.
	got, err = json.Marshal(MatchResponse{DatabaseVersion: "v1", Matches: []Match{}})
	require.NoError(t, err)
	require.JSONEq(t, `{"databaseVersion": "v1", "matches": []}`, string(got))
}

func TestDatabaseWireFormat(t *testing.T) {
	d := Database{Version: someVersion, Built: time.Date(2026, 10, 30, 6, 23, 28, 0, time.UTC)}
	got, err := json.Marshal(d)
	require.NoError(t, err)
	require.JSONEq(t, `{"version": "v6.1.10+2026-10-30T06:23:28Z", "built": "2026-10-30T06:23:28Z"}`, string(got))

	var back Database
	require.NoError(t, json.Unmarshal(got, &back))
	require.True(t, d.Built.Equal(back.Built))
	require.Equal(t, d.Version, back.Version)
}

func TestMatchRequestWireFormat(t *testing.T) {
	got, err := json.Marshal(MatchRequest{SBOM: json.RawMessage(`{"artifacts": []}`)})
	require.NoError(t, err)
	require.JSONEq(t, `{"sbom": {"artifacts": []}}`, string(got))
}

func TestTheErrorsHaveFixedTexts(t *testing.T) {
	// The texts are fixed: no body, no URL and no cause is ever part of them.
	require.EqualError(t, ErrNotReady, "matcher: not ready")
	require.EqualError(t, ErrUnavailable, "matcher: unavailable")
}
