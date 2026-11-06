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
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/collectors/scanner/internal/result"
	"github.com/bedag/vexplain/sdk/jobs"
)

// These tests cover what the line of a scan pod must prove before the scanner emits anything from it.
// The log is the trust boundary: a line proves nothing about where it came from, so every result is
// checked against the scan that the Job asked for, and anything that doesn't fit fails the scan. The
// SDK's Job runner has found the one line already: a result line of a pod that succeeded, or the
// reason of the error line of one that failed.

const (
	// requestedDigest is the digest that the Job scans: an index of two platforms.
	requestedDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// appRepository is where the image comes from, and requestedImage the --image argument of the
	// Job.
	appRepository  = "artifacts.example/team-a/app"
	requestedImage = appRepository + "@" + requestedDigest
	// The platform manifests of the index.
	amd64Manifest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	arm64Manifest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	// The platforms that the nodes of the tests say they are.
	linuxAMD64 = "linux/amd64"
	linuxARM64 = "linux/arm64"
)

// requestedScan is what the Job asked the scanner for.
func requestedScan() scanCall {
	return scanCall{digest: requestedDigest, image: requestedImage, platforms: []string{linuxAMD64, linuxARM64}}
}

// scannedManifest is what a scan found in one platform manifest.
func scannedManifest(platform, digest string) result.Manifest {
	return result.Manifest{
		Platform: platform,
		Digest:   digest,
		SBOM:     json.RawMessage(`{"artifacts":[{"id":"pkg-1","name":"libexample1","version":"1.2.3-1","type":"deb"}]}`),
		Packages: []result.PackageFacts{{ID: "pkg-1", FilesListed: 2, FilesPresent: 2, SharedLibraries: 1}},
		ELF:      result.ELFSummary{Total: 4, Owned: 3},
	}
}

// scannedIndex is the result of a scan of both platforms of the index.
func scannedIndex() result.Result {
	return result.Result{Image: requestedImage, Manifests: []result.Manifest{
		scannedManifest(linuxAMD64, amd64Manifest), scannedManifest("linux/arm64/v8", arm64Manifest),
	}}
}

// resultLine returns the result line of a scan whose result is r.
func resultLine(t *testing.T, r result.Result) string {
	t.Helper()
	line, err := result.Encode(r)
	require.NoError(t, err)
	return line
}

// rawResultLine returns the result line of a scan whose result holds the JSON raw, which no Result
// would marshal to.
func rawResultLine(t *testing.T, raw string) string {
	t.Helper()
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, err := zw.Write([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return result.ResultPrefix + base64.StdEncoding.EncodeToString(compressed.Bytes())
}

// withManifest returns the result of a scan of the index whose first manifest is changed by change.
func withManifest(change func(*result.Manifest)) result.Result {
	r := scannedIndex()
	change(&r.Manifests[0])
	return r
}

func TestASucceededScanDeliversItsCheckedResult(t *testing.T) {
	outcome := outcomeOf(jobs.Result{Line: resultLine(t, scannedIndex())}, requestedScan())

	require.Empty(t, outcome.reason, outcome.why)
	require.NotNil(t, outcome.result)
	want := scannedIndex()
	want.SchemaVersion = result.SchemaVersion
	require.Equal(t, want, *outcome.result)
}

// A requested platform names no variant, as the labels of nodes don't, and matches a manifest that
// has one: linux/arm64 asks for linux/arm64/v8.
func TestASucceededScanAcceptsAVariantOfARequestedPlatform(t *testing.T) {
	outcome := outcomeOf(jobs.Result{Line: resultLine(t, scannedIndex())}, scanCall{
		digest: requestedDigest, image: requestedImage, platforms: []string{linuxARM64, linuxAMD64},
	})

	require.Empty(t, outcome.reason, outcome.why)
	require.NotNil(t, outcome.result)
	require.Equal(t, "linux/arm64/v8", outcome.result.Manifests[1].Platform)
}

// A digest that is a single manifest, and no index, is scanned whatever its platform: the scanner
// has no index to pick from.
func TestASucceededScanOfASingleManifestTakesItsPlatform(t *testing.T) {
	single := result.Result{Image: requestedImage, Manifests: []result.Manifest{
		scannedManifest("linux/ppc64le", requestedDigest),
	}}

	outcome := outcomeOf(jobs.Result{Line: resultLine(t, single)}, requestedScan())

	require.Empty(t, outcome.reason, outcome.why)
	require.Len(t, outcome.result.Manifests, 1)
}

// Every check that the line of a succeeded scan can fail, and the reason the scan then fails with.
// Only the size of the result is TooLarge: whatever else doesn't fit is the scanner's own failure,
// Internal, and delivers nothing.
func TestASucceededScanThatFailsACheckStoresNothing(t *testing.T) {
	seventeen := scannedIndex()
	seventeen.Manifests = nil
	for i := range 17 {
		seventeen.Manifests = append(seventeen.Manifests,
			scannedManifest(fmt.Sprintf("linux/arm%d", i), fmt.Sprintf("sha256:%064x", i+1)))
	}
	single := func(platform string) result.Result {
		return result.Result{Image: requestedImage, Manifests: []result.Manifest{scannedManifest(platform, requestedDigest)}}
	}
	cases := []struct {
		name   string
		line   func(t *testing.T) string
		reason string
	}{
		{"a result larger than the scanner decodes", func(t *testing.T) string {
			return rawResultLine(t, `{"schemaVersion":1,"image":"`+strings.Repeat("a", maxResultBytes)+`"}`)
		}, tooLarge},
		{"a line of another version", func(t *testing.T) string { return "vexplain-scan-result v2 AAAA" }, internal},
		{"a payload that isn't base64", func(t *testing.T) string { return result.ResultPrefix + "%%%" }, internal},
		{"an error line", func(t *testing.T) string { return result.EncodeError(result.ErrorReasonUnauthorized) }, internal},
		{"a line that is no line of the scan", func(t *testing.T) string { return "scanner: done" }, internal},
		{"another image", func(t *testing.T) string {
			r := scannedIndex()
			r.Image = "artifacts.example/team-b/app@" + requestedDigest
			return resultLine(t, r)
		}, internal},
		{"the image written another way", func(t *testing.T) string {
			r := scannedIndex()
			r.Image = "https://" + requestedImage
			return resultLine(t, r)
		}, internal},
		{"no manifest", func(t *testing.T) string {
			return resultLine(t, result.Result{Image: requestedImage})
		}, internal},
		{"more manifests than an ImageInventory holds", func(t *testing.T) string {
			return resultLine(t, seventeen)
		}, internal},
		{"two manifests of one platform", func(t *testing.T) string {
			return resultLine(t, withManifest(func(m *result.Manifest) { m.Platform = "linux/arm64/v8" }))
		}, internal},
		{"a digest that isn't a sha256 digest", func(t *testing.T) string {
			return resultLine(t, withManifest(func(m *result.Manifest) { m.Digest = "sha256:1111" }))
		}, internal},
		{"a platform outside the API's pattern", func(t *testing.T) string {
			return resultLine(t, withManifest(func(m *result.Manifest) { m.Platform = "linux/amd64\nvexplain" }))
		}, internal},
		{"a single manifest whose platform is outside the API's pattern", func(t *testing.T) string {
			return resultLine(t, single("Linux/AMD64"))
		}, internal},
		{"a platform longer than the API holds", func(t *testing.T) string {
			return resultLine(t, single("linux/"+strings.Repeat("a", 59)))
		}, internal},
		{"a platform that wasn't asked for", func(t *testing.T) string {
			return resultLine(t, withManifest(func(m *result.Manifest) { m.Platform = "linux/s390x" }))
		}, internal},
		{"a manifest of an attestation", func(t *testing.T) string {
			return resultLine(t, withManifest(func(m *result.Manifest) { m.Platform = "unknown/unknown" }))
		}, internal},
		{"an SBOM that is null", func(t *testing.T) string {
			return resultLine(t, withManifest(func(m *result.Manifest) { m.SBOM = json.RawMessage(`null`) }))
		}, internal},
		{"no SBOM", func(t *testing.T) string {
			return rawResultLine(t, `{"schemaVersion":1,"image":"`+requestedImage+`","manifests":[`+
				`{"platform":"`+linuxAMD64+`","digest":"`+amd64Manifest+`","packages":[],"elf":{"total":0,"owned":0}}]}`)
		}, internal},
		{"an SBOM that is an empty object", func(t *testing.T) string {
			return resultLine(t, withManifest(func(m *result.Manifest) { m.SBOM = json.RawMessage(" { } ") }))
		}, internal},
		{"an SBOM that is a list", func(t *testing.T) string {
			return resultLine(t, withManifest(func(m *result.Manifest) { m.SBOM = json.RawMessage(`[{"id":"pkg-1"}]`) }))
		}, internal},
		{"an SBOM that is a string", func(t *testing.T) string {
			return resultLine(t, withManifest(func(m *result.Manifest) { m.SBOM = json.RawMessage(`"{}"`) }))
		}, internal},
		{"a negative count of ELF files", func(t *testing.T) string {
			return resultLine(t, withManifest(func(m *result.Manifest) { m.ELF = result.ELFSummary{Total: -1} }))
		}, internal},
		{"more ELF files than the API counts", func(t *testing.T) string {
			return resultLine(t, withManifest(func(m *result.Manifest) {
				m.ELF = result.ELFSummary{Total: math.MaxInt32 + 1, Owned: 1}
			}))
		}, internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outcome := outcomeOf(jobs.Result{Line: tc.line(t)}, requestedScan())

			require.Nil(t, outcome.result, "nothing is emitted")
			require.Equal(t, tc.reason, outcome.reason)
			require.NotEmpty(t, outcome.why, "the failure says why the scan failed")
		})
	}
}

// What the scanner says about a failed check is a fixed text: nothing that the line of the scan pod
// holds reaches it.
func TestAFailedCheckSaysWhyWithoutTheLine(t *testing.T) {
	r := scannedIndex()
	r.Image = "artifacts.example/forged-image@" + requestedDigest
	r.Manifests[0].Platform = "linux/forged-platform"

	outcome := outcomeOf(jobs.Result{Line: resultLine(t, r)}, requestedScan())

	require.Equal(t, internal, outcome.reason)
	require.NotContains(t, outcome.why, "forged")
}

// A failed scan pod's error line gives its reason, which is one of 2a's reasons. The Job runner adds
// TimedOut for a Job past its deadline, TooLarge for a log too long to hold a whole line, and
// Internal for a pod that said nothing that it could read.
func TestAFailedScanGivesTheReasonOfItsJob(t *testing.T) {
	for _, reason := range []string{
		string(result.ErrorReasonPullFailed), string(result.ErrorReasonUnauthorized), string(result.ErrorReasonNotFound),
		string(result.ErrorReasonNoMatchingPlatform), string(result.ErrorReasonTooLarge),
		string(result.ErrorReasonCatalogFailed), string(result.ErrorReasonInternal), "TimedOut",
	} {
		t.Run(reason, func(t *testing.T) {
			outcome := outcomeOf(jobs.Result{FailureReason: reason}, requestedScan())

			require.Nil(t, outcome.result)
			require.Equal(t, reason, outcome.reason)
			require.NotEmpty(t, outcome.why)
		})
	}
}

// The scanner prints only its own reasons. Another one, which a log can't prove anything about, is a
// failure of the scanner's own.
func TestAFailedScanForAReasonThatTheScannerDoesntGiveIsInternal(t *testing.T) {
	for _, reason := range []string{"Guess", "NotPullable", "internal", "Unauthorized\nInternal", strings.Repeat("A", 65)} {
		outcome := outcomeOf(jobs.Result{FailureReason: reason}, requestedScan())

		require.Nil(t, outcome.result)
		require.Equal(t, internal, outcome.reason, reason)
		require.NotContains(t, outcome.why, reason)
	}
}
