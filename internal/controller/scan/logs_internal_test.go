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

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/scan/result"
)

// These tests cover what a scan pod's log must prove before the runner stores anything from it.
// The log is the trust boundary: a line proves nothing about where it came from, so every result is
// checked against the scan that the Job asked for, and anything that doesn't fit fails the scan.

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

// logWith returns the log of a scan that prints line, after the progress texts that the scanner
// writes to stderr.
func logWith(line string) string {
	return "scanner: resolving the image\nscanner: manifests to scan: 2\n" + line + "\n"
}

// resultLog returns the log of a scan whose result line holds r.
func resultLog(t *testing.T, r result.Result) string {
	t.Helper()
	line, err := result.Encode(r)
	require.NoError(t, err)
	return logWith(line)
}

// rawResultLog returns the log of a scan whose result line holds the JSON raw, which no Result
// would marshal to.
func rawResultLog(t *testing.T, raw string) string {
	t.Helper()
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, err := zw.Write([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return logWith(result.ResultPrefix + base64.StdEncoding.EncodeToString(compressed.Bytes()))
}

// withManifest returns the result of a scan of the index whose first manifest is changed by change.
func withManifest(change func(*result.Manifest)) result.Result {
	r := scannedIndex()
	change(&r.Manifests[0])
	return r
}

func TestASucceededScanDeliversItsCheckedResult(t *testing.T) {
	outcome := succeededScan(resultLog(t, scannedIndex()), requestedScan())

	require.Empty(t, outcome.reason, outcome.why)
	require.NotNil(t, outcome.result)
	want := scannedIndex()
	want.SchemaVersion = result.SchemaVersion
	require.Equal(t, want, *outcome.result)
}

// A requested platform names no variant, as the labels of nodes don't, and matches a manifest that
// has one: linux/arm64 asks for linux/arm64/v8.
func TestASucceededScanAcceptsAVariantOfARequestedPlatform(t *testing.T) {
	outcome := succeededScan(resultLog(t, scannedIndex()), scanCall{
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

	outcome := succeededScan(resultLog(t, single), requestedScan())

	require.Empty(t, outcome.reason, outcome.why)
	require.Len(t, outcome.result.Manifests, 1)
}

// Every check that a succeeded scan's log can fail, and the reason the scan then fails with. Only
// the size of the log and of the result is TooLarge: whatever else doesn't fit is the operator's
// own failure, Internal, and stores nothing.
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
		log    func(t *testing.T) string
		reason inventoryv1alpha1.ScanFailureReason
	}{
		{"a log at the size limit, whose line can't be whole", func(t *testing.T) string {
			return strings.Repeat("scanner: progress\n", maxLogBytes/len("scanner: progress\n")+1)[:maxLogBytes]
		}, inventoryv1alpha1.ScanFailureReasonTooLarge},
		{"a result larger than the operator decodes", func(t *testing.T) string {
			return rawResultLog(t, `{"schemaVersion":1,"image":"`+strings.Repeat("a", maxResultBytes)+`"}`)
		}, inventoryv1alpha1.ScanFailureReasonTooLarge},
		{"no line", func(t *testing.T) string { return logWith("scanner: done") }, inventoryv1alpha1.ScanFailureReasonInternal},
		{"two lines", func(t *testing.T) string {
			return resultLog(t, scannedIndex()) + result.EncodeError(result.ErrorReasonInternal) + "\n"
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"a line of another version", func(t *testing.T) string { return logWith("vexplain-scan-result v2 AAAA") },
			inventoryv1alpha1.ScanFailureReasonInternal},
		{"a payload that isn't base64", func(t *testing.T) string { return logWith(result.ResultPrefix + "%%%") },
			inventoryv1alpha1.ScanFailureReasonInternal},
		{"an error line", func(t *testing.T) string { return logWith(result.EncodeError(result.ErrorReasonUnauthorized)) },
			inventoryv1alpha1.ScanFailureReasonInternal},
		{"another image", func(t *testing.T) string {
			r := scannedIndex()
			r.Image = "artifacts.example/team-b/app@" + requestedDigest
			return resultLog(t, r)
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"the image written another way", func(t *testing.T) string {
			r := scannedIndex()
			r.Image = "https://" + requestedImage
			return resultLog(t, r)
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"no manifest", func(t *testing.T) string {
			return resultLog(t, result.Result{Image: requestedImage})
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"more manifests than an ImageInventory holds", func(t *testing.T) string {
			return resultLog(t, seventeen)
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"two manifests of one platform", func(t *testing.T) string {
			return resultLog(t, withManifest(func(m *result.Manifest) { m.Platform = "linux/arm64/v8" }))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"a digest that isn't a sha256 digest", func(t *testing.T) string {
			return resultLog(t, withManifest(func(m *result.Manifest) { m.Digest = "sha256:1111" }))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"a platform outside the API's pattern", func(t *testing.T) string {
			return resultLog(t, withManifest(func(m *result.Manifest) { m.Platform = "linux/amd64\nvexplain" }))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"a single manifest whose platform is outside the API's pattern", func(t *testing.T) string {
			return resultLog(t, single("Linux/AMD64"))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"a platform longer than the API holds", func(t *testing.T) string {
			return resultLog(t, single("linux/"+strings.Repeat("a", 59)))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"a platform that wasn't asked for", func(t *testing.T) string {
			return resultLog(t, withManifest(func(m *result.Manifest) { m.Platform = "linux/s390x" }))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"a manifest of an attestation", func(t *testing.T) string {
			return resultLog(t, withManifest(func(m *result.Manifest) { m.Platform = "unknown/unknown" }))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"an SBOM that is null", func(t *testing.T) string {
			return resultLog(t, withManifest(func(m *result.Manifest) { m.SBOM = json.RawMessage(`null`) }))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"no SBOM", func(t *testing.T) string {
			return rawResultLog(t, `{"schemaVersion":1,"image":"`+requestedImage+`","manifests":[`+
				`{"platform":"`+linuxAMD64+`","digest":"`+amd64Manifest+`","packages":[],"elf":{"total":0,"owned":0}}]}`)
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"an SBOM that is an empty object", func(t *testing.T) string {
			return resultLog(t, withManifest(func(m *result.Manifest) { m.SBOM = json.RawMessage(" { } ") }))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"an SBOM that is a list", func(t *testing.T) string {
			return resultLog(t, withManifest(func(m *result.Manifest) { m.SBOM = json.RawMessage(`[{"id":"pkg-1"}]`) }))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"an SBOM that is a string", func(t *testing.T) string {
			return resultLog(t, withManifest(func(m *result.Manifest) { m.SBOM = json.RawMessage(`"{}"`) }))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"a negative count of ELF files", func(t *testing.T) string {
			return resultLog(t, withManifest(func(m *result.Manifest) { m.ELF = result.ELFSummary{Total: -1} }))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
		{"more ELF files than the API counts", func(t *testing.T) string {
			return resultLog(t, withManifest(func(m *result.Manifest) {
				m.ELF = result.ELFSummary{Total: math.MaxInt32 + 1, Owned: 1}
			}))
		}, inventoryv1alpha1.ScanFailureReasonInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outcome := succeededScan(tc.log(t), requestedScan())

			require.Nil(t, outcome.result, "nothing is stored")
			require.Equal(t, tc.reason, outcome.reason)
			require.NotEmpty(t, outcome.why, "the log says why the scan failed")
		})
	}
}

// What the runner logs about a failed check is a fixed text: nothing that the log of the scan pod
// holds reaches it.
func TestAFailedCheckSaysWhyWithoutTheLog(t *testing.T) {
	r := scannedIndex()
	r.Image = "artifacts.example/forged-image@" + requestedDigest
	r.Manifests[0].Platform = "linux/forged-platform"

	outcome := succeededScan(resultLog(t, r), requestedScan())

	require.Equal(t, inventoryv1alpha1.ScanFailureReasonInternal, outcome.reason)
	require.NotContains(t, outcome.why, "forged")
}

// A failed scan pod's log gives only the reason of its error line, which maps one to one to the API.
func TestAFailedScanGivesTheReasonOfItsErrorLine(t *testing.T) {
	for _, reason := range []result.ErrorReason{
		result.ErrorReasonPullFailed, result.ErrorReasonUnauthorized, result.ErrorReasonNotFound,
		result.ErrorReasonNoMatchingPlatform, result.ErrorReasonTooLarge, result.ErrorReasonCatalogFailed,
		result.ErrorReasonInternal,
	} {
		t.Run(string(reason), func(t *testing.T) {
			outcome := failedScan(logWith(result.EncodeError(reason)))

			require.Nil(t, outcome.result)
			require.Equal(t, inventoryv1alpha1.ScanFailureReason(reason), outcome.reason)
		})
	}
}

// Only a pod that succeeded can deliver a result. A failed pod that says nothing, or prints a result
// line, failed for a reason of its own; and a log at the limit can't hold a whole line.
func TestAFailedScanWithoutAnErrorLineIsInternal(t *testing.T) {
	cases := []struct {
		name   string
		log    string
		reason inventoryv1alpha1.ScanFailureReason
	}{
		{"an empty log, as an evicted pod leaves", "", inventoryv1alpha1.ScanFailureReasonInternal},
		{"progress texts only", logWith("scanner: manifest 1 of 2: unpacking"), inventoryv1alpha1.ScanFailureReasonInternal},
		{"a result line", resultLog(t, scannedIndex()), inventoryv1alpha1.ScanFailureReasonInternal},
		{"two error lines", logWith(result.EncodeError(result.ErrorReasonNotFound) + "\n" +
			result.EncodeError(result.ErrorReasonNotFound)), inventoryv1alpha1.ScanFailureReasonInternal},
		{"an unknown reason", logWith(result.ErrorPrefix + "Guess"), inventoryv1alpha1.ScanFailureReasonInternal},
		{"a log at the size limit", strings.Repeat("x", maxLogBytes), inventoryv1alpha1.ScanFailureReasonTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outcome := failedScan(tc.log)

			require.Nil(t, outcome.result)
			require.Equal(t, tc.reason, outcome.reason)
			require.NotEmpty(t, outcome.why)
		})
	}
}
