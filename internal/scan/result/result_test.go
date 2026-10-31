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

package result_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"math/rand/v2"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/scan/result"
)

// bigEnough is a limit that no test result comes near.
const bigEnough = 1 << 20

// sampleResult has every field set in its first manifest, and only what is required in its second,
// so that a round trip loses any field that a codec forgets, and keeps an omitted one omitted.
func sampleResult() result.Result {
	return result.Result{
		SchemaVersion: result.SchemaVersion,
		Image:         "registry.example/team-a/app@sha256:1111",
		Manifests: []result.Manifest{
			{
				Platform: "linux/amd64",
				Digest:   "sha256:2222",
				SBOM:     json.RawMessage(`{"artifacts":[{"id":"p1","name":"libfoo"}]}`),
				Packages: []result.PackageFacts{
					{ID: "p1", FilesListed: 12, FilesPresent: 10, SharedLibraries: 2, OtherELFFiles: 1},
				},
				ELF: result.ELFSummary{Total: 4, Owned: 3, Unowned: []string{"/opt/a.so", "/usr/local/bin/tool"}},
				Libraries: []result.Library{{
					Path: "/usr/lib/libfoo.so.1", Soname: "libfoo.so.1", PackageID: "p1",
					ReachedBy: []string{"/usr/bin/app", "/usr/bin/tool"}, ReachedCount: 25,
					NameHits: []string{"/app/load.py"}, NameHitCount: 3,
				}},
				Preload: result.Preload{LDPreload: true, LDAudit: true, EtcLdSoPreload: true},
			},
			{
				Platform:  "linux/arm64/v8",
				Digest:    "sha256:3333",
				SBOM:      json.RawMessage(`{"artifacts":[]}`),
				Libraries: []result.Library{{Path: "/lib/libbar.so", Soname: "libbar.so"}},
			},
		},
	}
}

func encode(t *testing.T, r result.Result) string {
	t.Helper()
	line, err := result.Encode(r)
	require.NoError(t, err)
	return line
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(data)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func gunzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(data))
	require.NoError(t, err)
	out, err := io.ReadAll(zr)
	require.NoError(t, err)
	return out
}

func b64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// lineOf returns a result line whose payload is the given text, gzipped and base64 encoded, however
// odd the text is. Encode can't make such a line.
func lineOf(t *testing.T, payload string) string {
	t.Helper()
	return result.ResultPrefix + b64(gzipped(t, []byte(payload)))
}

func TestEncodeParseRoundTrip(t *testing.T) {
	want := sampleResult()

	line := encode(t, want)
	require.True(t, strings.HasPrefix(line, result.ResultPrefix))
	require.NotContains(t, line, "\n", "a result is one line")

	got, reason, err := result.Parse(line+"\n", bigEnough)
	require.NoError(t, err)
	require.Empty(t, reason, "a result line has no reason")
	require.Equal(t, want, *got)
}

func TestEncodeSetsTheSchemaVersion(t *testing.T) {
	for _, set := range []int{0, 7} {
		line := encode(t, result.Result{SchemaVersion: set})

		got, _, err := result.Parse(line, bigEnough)
		require.NoError(t, err, "a line carries the version that its prefix names, whatever the caller set (%d)", set)
		require.Equal(t, result.SchemaVersion, got.SchemaVersion)
	}
}

// TestWireFormat decodes a line by hand, without Parse, to state the contract between the scanner
// and the operator apart from the codec's own reading of it: the prefixes, standard base64, gzip,
// and the names of the JSON fields.
func TestWireFormat(t *testing.T) {
	require.Equal(t, "vexplain-scan-result v1 ", result.ResultPrefix)
	require.Equal(t, "vexplain-scan-error v1 ", result.ErrorPrefix)
	require.Equal(t, 1, result.SchemaVersion)

	full := sampleResult()
	full.Manifests = full.Manifests[:1]
	payload, ok := strings.CutPrefix(encode(t, full), "vexplain-scan-result v1 ")
	require.True(t, ok, "the line starts with the v1 result prefix")
	compressed, err := base64.StdEncoding.DecodeString(payload)
	require.NoError(t, err, "the payload is standard base64")
	require.JSONEq(t, `{
		"schemaVersion": 1,
		"image": "registry.example/team-a/app@sha256:1111",
		"manifests": [{
			"platform": "linux/amd64",
			"digest": "sha256:2222",
			"sbom": {"artifacts": [{"id": "p1", "name": "libfoo"}]},
			"packages": [{"id": "p1", "filesListed": 12, "filesPresent": 10, "sharedLibraries": 2, "otherElfFiles": 1}],
			"elf": {"total": 4, "owned": 3, "unowned": ["/opt/a.so", "/usr/local/bin/tool"]},
			"libraries": [{
				"path": "/usr/lib/libfoo.so.1", "soname": "libfoo.so.1", "packageId": "p1",
				"reachedBy": ["/usr/bin/app", "/usr/bin/tool"], "reachedCount": 25,
				"nameHits": ["/app/load.py"], "nameHitCount": 3
			}],
			"preload": {"ldPreload": true, "ldAudit": true, "etcLdSoPreload": true}
		}]
	}`, string(gunzipped(t, compressed)))
}

// TestWireFormatOmitsEmptyOptionals checks the fields that the contract leaves out when empty.
func TestWireFormatOmitsEmptyOptionals(t *testing.T) {
	sparse := sampleResult()
	sparse.Manifests = sparse.Manifests[1:]
	payload, ok := strings.CutPrefix(encode(t, sparse), result.ResultPrefix)
	require.True(t, ok)
	compressed, err := base64.StdEncoding.DecodeString(payload)
	require.NoError(t, err)

	var wire struct {
		Manifests []struct {
			ELF       map[string]any   `json:"elf"`
			Libraries []map[string]any `json:"libraries"`
		} `json:"manifests"`
	}
	require.NoError(t, json.Unmarshal(gunzipped(t, compressed), &wire))
	require.Len(t, wire.Manifests, 1)
	require.Equal(t, map[string]any{"total": 0.0, "owned": 0.0}, wire.Manifests[0].ELF)
	require.Equal(t,
		[]map[string]any{{"path": "/lib/libbar.so", "soname": "libbar.so", "reachedCount": 0.0, "nameHitCount": 0.0}},
		wire.Manifests[0].Libraries)
}

func TestParseFindsTheResultAmongNoise(t *testing.T) {
	want := sampleResult()
	line := encode(t, want)

	logs := map[string]string{
		"noise before and after":                   "unpacking layer 1/3\nrunning syft\n" + line + "\nscan took 3s\n",
		"the line is last and has no newline":      "unpacking layer 1/3\n" + line,
		"the line is first":                        line + "\nscan took 3s\n",
		"carriage returns before the newlines":     "unpacking\r\n" + line + "\r\ndone\r\n",
		"blank lines around":                       "\n\n" + line + "\n\n",
		"a line that only mentions the prefix":     "note: " + result.ResultPrefix + "AAAA\n" + line + "\n",
		"an indented line that has the prefix":     "  " + result.ResultPrefix + "AAAA\n" + line + "\n",
		"a line that names the format and no more": "vexplain-scan-result: wrote 1234 bytes\n" + line + "\n",
	}
	for name, log := range logs {
		t.Run(name, func(t *testing.T) {
			got, reason, err := result.Parse(log, bigEnough)
			require.NoError(t, err)
			require.Empty(t, reason)
			require.Equal(t, want, *got)
		})
	}
}

// TestParseReadsAResultLineLongerThanAScannerLine guards against a line reader with a token limit,
// such as bufio.Scanner's 64 KiB: a result for a big image is several hundred KiB of base64 on one
// line.
func TestParseReadsAResultLineLongerThanAScannerLine(t *testing.T) {
	// Random data does not compress, so the line is about as long as the data.
	blob := make([]byte, 384<<10)
	_, err := rand.NewChaCha8([32]byte{1}).Read(blob)
	require.NoError(t, err)
	want := sampleResult()
	want.Manifests[0].SBOM = json.RawMessage(`{"blob":"` + b64(blob) + `"}`)

	line := encode(t, want)
	require.Greater(t, len(line), 256<<10, "the line is far over 64 KiB")

	got, _, err := result.Parse("progress\n"+line+"\n", 4<<20)
	require.NoError(t, err)
	require.Equal(t, want, *got)
}

func TestEncodeErrorWritesTheReason(t *testing.T) {
	require.Equal(t, "vexplain-scan-error v1 PullFailed", result.EncodeError(result.ErrorReasonPullFailed))
}

// A reason that is not one of the seven can't put anything else on the line, such as a second
// line, so it is written as Internal. The line then always parses.
func TestEncodeErrorWritesInternalForAnyOtherReason(t *testing.T) {
	others := []result.ErrorReason{
		"",
		"Exploded",
		"pullfailed",
		"Pull Failed",
		"NotPullable", // the operator sets this one, and TimedOut, and never the scanner
		"TimedOut",
		"PullFailed\n" + result.ResultPrefix + "AAAA",
	}
	for _, reason := range others {
		line := result.EncodeError(reason)
		require.Equal(t, "vexplain-scan-error v1 Internal", line, "reason %q", string(reason))

		_, got, err := result.Parse(line, bigEnough)
		require.NoError(t, err)
		require.Equal(t, result.ErrorReasonInternal, got)
	}
}

func TestParseReturnsTheReasonOfAnErrorLine(t *testing.T) {
	for _, reason := range []result.ErrorReason{
		result.ErrorReasonPullFailed,
		result.ErrorReasonUnauthorized,
		result.ErrorReasonNotFound,
		result.ErrorReasonNoMatchingPlatform,
		result.ErrorReasonTooLarge,
		result.ErrorReasonCatalogFailed,
		result.ErrorReasonInternal,
	} {
		t.Run(string(reason), func(t *testing.T) {
			line := result.EncodeError(reason)
			require.NotContains(t, line, "\n", "an error is one line")

			for _, log := range []string{line, "unpacking layer 1/3\n" + line + "\nscan took 3s\n", line + "\r\n"} {
				got, gotReason, err := result.Parse(log, bigEnough)
				require.NoError(t, err)
				require.Nil(t, got, "an error line has no result")
				require.Equal(t, reason, gotReason)
			}
		})
	}
}

// TestErrorReasonsMatchTheAPI pins the spelling of the seven reasons, in the wire format and
// against the API's enum, which this package can't import but its test can.
func TestErrorReasonsMatchTheAPI(t *testing.T) {
	cases := []struct {
		reason result.ErrorReason
		text   string
		api    inventoryv1alpha1.ScanFailureReason
	}{
		{result.ErrorReasonPullFailed, "PullFailed", inventoryv1alpha1.ScanFailureReasonPullFailed},
		{result.ErrorReasonUnauthorized, "Unauthorized", inventoryv1alpha1.ScanFailureReasonUnauthorized},
		{result.ErrorReasonNotFound, "NotFound", inventoryv1alpha1.ScanFailureReasonNotFound},
		{result.ErrorReasonNoMatchingPlatform, "NoMatchingPlatform", inventoryv1alpha1.ScanFailureReasonNoMatchingPlatform},
		{result.ErrorReasonTooLarge, "TooLarge", inventoryv1alpha1.ScanFailureReasonTooLarge},
		{result.ErrorReasonCatalogFailed, "CatalogFailed", inventoryv1alpha1.ScanFailureReasonCatalogFailed},
		{result.ErrorReasonInternal, "Internal", inventoryv1alpha1.ScanFailureReasonInternal},
	}
	for _, c := range cases {
		require.Equal(t, c.text, string(c.reason))
		require.Equal(t, string(c.api), string(c.reason))
	}
}

func TestParseFails(t *testing.T) {
	valid := encode(t, sampleResult())
	errorLine := result.EncodeError(result.ErrorReasonPullFailed)
	small := gzipped(t, []byte(`{"schemaVersion":1}`))
	damaged := slices.Clone(small)
	damaged[len(damaged)-5] ^= 0xff // a byte of the CRC-32 in the trailer

	cases := []struct {
		name string
		log  string
		want error
	}{
		{"an empty log", "", result.ErrNoLine},
		{"a log with noise only", "unpacking layer 1/3\nrunning syft\n", result.ErrNoLine},

		{"two result lines", valid + "\n" + valid + "\n", result.ErrMultipleLines},
		{"a result line and an error line", valid + "\n" + errorLine + "\n", result.ErrMultipleLines},
		{"two error lines", errorLine + "\n" + errorLine + "\n", result.ErrMultipleLines},
		{"a v1 line and a line of another version", valid + "\nvexplain-scan-error v2 PullFailed\n", result.ErrMultipleLines},

		{"a result line of another version", "vexplain-scan-result v2 " + b64(small), result.ErrUnsupportedVersion},
		{"an error line of another version", "vexplain-scan-error v2 PullFailed", result.ErrUnsupportedVersion},
		{"a result line without a version", "vexplain-scan-result " + b64(small), result.ErrUnsupportedVersion},
		{"a JSON version that its prefix does not name", lineOf(t, `{"schemaVersion":2}`), result.ErrUnsupportedVersion},
		{"a JSON without a version", lineOf(t, `{"image":"x"}`), result.ErrUnsupportedVersion},

		{"a result line without a payload", result.ResultPrefix, result.ErrMalformed},
		{"a payload that is not base64", result.ResultPrefix + "not*base64!", result.ErrMalformed},
		{"a payload that is not gzip", result.ResultPrefix + b64([]byte("hello")), result.ErrMalformed},
		{"gzip that is cut short", result.ResultPrefix + b64(small[:len(small)-10]), result.ErrMalformed},
		{"gzip with a damaged checksum", result.ResultPrefix + b64(damaged), result.ErrMalformed},
		{"gzip followed by other bytes", result.ResultPrefix + b64(append(slices.Clone(small), "junk"...)), result.ErrMalformed},
		{"gzip of text that is not JSON", lineOf(t, "not json"), result.ErrMalformed},
		{"gzip of JSON of the wrong shape", lineOf(t, `[]`), result.ErrMalformed},
		{"gzip of two JSON values", lineOf(t, `{"schemaVersion":1}{"schemaVersion":1}`), result.ErrMalformed},

		{"an error line without a reason", result.ErrorPrefix, result.ErrMalformed},
		{"an unknown reason", result.ErrorPrefix + "Exploded", result.ErrMalformed},
		{"a reason that only the operator sets", result.ErrorPrefix + "TimedOut", result.ErrMalformed},
		{"a reason in other letter case", result.ErrorPrefix + "pullfailed", result.ErrMalformed},
		{"text after the reason", result.ErrorPrefix + "PullFailed and more", result.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason, err := result.Parse(c.log, bigEnough)
			require.ErrorIs(t, err, c.want)
			require.Nil(t, got)
			require.Empty(t, reason)
		})
	}
}

// TestParseNeverQuotesItsInput checks that no error repeats what it was given: a scan log can
// carry text from an image, so the errors are fixed texts. The secret of each case is text of the
// input that a careless error would repeat. The JSON library's errors repeat a character of bad
// JSON or the number of a mismatch, and a careless message would add the version, the reason or
// the line itself.
func TestParseNeverQuotesItsInput(t *testing.T) {
	const marker = "9d2f" // text of the input that no error may repeat
	cases := []struct {
		name   string
		log    string
		secret string
	}{
		{"a syntax error in the JSON", lineOf(t, `{"image": ~}`), "~"},
		{"a number of the wrong type", lineOf(t, `{"schemaVersion":1,"manifests":[{"elf":{"total":4242424242.5}}]}`), "4242424242"},
		{"a JSON version that its prefix does not name", lineOf(t, `{"schemaVersion":4242424242}`), "4242424242"},
		{"a payload that is not base64", result.ResultPrefix + marker + "-not-base64-%%", marker},
		{"a payload that is not gzip", result.ResultPrefix + b64([]byte(marker)), marker},
		{"an unknown reason", result.ErrorPrefix + "Exploded-" + marker, marker},
		{"another version", "vexplain-scan-result v" + marker + " " + b64([]byte("x")), marker},
		{
			"a result over the limit",
			lineOf(t, `{"schemaVersion":1,"image":"quoted-`+marker+`","manifests":[`+strings.Repeat("{},", 1000)+`{}]}`),
			marker,
		},
		{"noise that carries text twice", "noise " + marker + "\n" + result.ResultPrefix + "x\n" + result.ResultPrefix + "y\n", marker},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := result.Parse(c.log, 1000)
			require.Error(t, err)
			require.NotContains(t, err.Error(), c.secret)
		})
	}
}

// TestParseRefusesMoreThanMaxBytes uses a gzip bomb: a few KiB on the wire that unpack to 4 MiB.
func TestParseRefusesMoreThanMaxBytes(t *testing.T) {
	bomb := sampleResult()
	bomb.Image = strings.Repeat("A", 4<<20)
	line := encode(t, bomb)
	require.Less(t, len(line), 64<<10, "the line is small, so only a limit on what comes out of gzip can stop it")

	_, _, err := result.Parse(line, 1<<20)
	require.ErrorIs(t, err, result.ErrTooLarge)

	got, _, err := result.Parse(line, 8<<20)
	require.NoError(t, err, "the same line is fine under a limit that holds it")
	require.Len(t, got.Image, 4<<20)
}

// TestParseStopsReadingAtTheLimit checks that the limit bounds the work and the memory, and not
// only the verdict: Parse reads through the limit, so it doesn't unpack a bomb to find that it is
// too large.
func TestParseStopsReadingAtTheLimit(t *testing.T) {
	// 32 MiB of one letter gzip to well under a MiB.
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	require.NoError(t, err)
	_, err = zw.Write([]byte(`{"schemaVersion":1,"image":"`))
	require.NoError(t, err)
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	for range 32 {
		_, err = zw.Write(chunk)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	line := result.ResultPrefix + b64(buf.Bytes())

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _, err = result.Parse(line, 64<<10)
	runtime.ReadMemStats(&after)

	require.ErrorIs(t, err, result.ErrTooLarge)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(8<<20),
		"Parse allocated for far more than its 64 KiB limit, so it unpacked the bomb")
}

func TestParseMaxBytesAtItsEdges(t *testing.T) {
	line := encode(t, sampleResult())

	got, _, err := result.Parse(line, math.MaxInt64)
	require.NoError(t, err, "the largest limit must not overflow into a refusal")
	require.NotNil(t, got)

	for _, limit := range []int64{0, -1, math.MinInt64} {
		_, _, err := result.Parse(line, limit)
		require.ErrorIs(t, err, result.ErrTooLarge, "limit %d", limit)
	}
}

func TestEncodeManifestIsGzipJSON(t *testing.T) {
	want := sampleResult().Manifests[0]

	compressed, size, err := result.EncodeManifest(want)
	require.NoError(t, err)

	raw := gunzipped(t, compressed)
	require.Equal(t, int64(len(raw)), size, "the size is that of the JSON before compression")
	var got result.Manifest
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Equal(t, want, got)
}

func TestEncodeManifestDecodeManifestRoundTrip(t *testing.T) {
	for _, want := range sampleResult().Manifests {
		compressed, size, err := result.EncodeManifest(want)
		require.NoError(t, err)

		got, err := result.DecodeManifest(compressed, size)
		require.NoError(t, err, "a limit equal to the reported size holds the manifest")
		require.Equal(t, want, got)

		_, err = result.DecodeManifest(compressed, size-1)
		require.ErrorIs(t, err, result.ErrTooLarge, "one byte less does not")
	}
}

func TestDecodeManifestFails(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"no data", nil, result.ErrMalformed},
		{"data that is not gzip", []byte("hello"), result.ErrMalformed},
		{"gzip of text that is not JSON", gzipped(t, []byte("not json")), result.ErrMalformed},
		{"gzip of JSON of the wrong shape", gzipped(t, []byte(`{"elf":[]}`)), result.ErrMalformed},
		{"gzip of two JSON values", gzipped(t, []byte(`{}{}`)), result.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := result.DecodeManifest(c.data, bigEnough)
			require.ErrorIs(t, err, c.want)
			require.Equal(t, result.Manifest{}, got)
		})
	}

	t.Run("and never quotes its input", func(t *testing.T) {
		_, err := result.DecodeManifest(gzipped(t, []byte(`{"elf":{"total":4242424242.5}}`)), bigEnough)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "4242424242")
	})
}

func TestEncodeRefusesAnSBOMThatIsNotJSON(t *testing.T) {
	r := sampleResult()
	r.Manifests[0].SBOM = json.RawMessage(`{"artifacts":`)

	_, err := result.Encode(r)
	require.Error(t, err)
	_, _, err = result.EncodeManifest(r.Manifests[0])
	require.Error(t, err)
}

func TestCompleteness(t *testing.T) {
	cases := []struct {
		name         string
		owned, total int
		want         int32
	}{
		{"no ELF files at all", 0, 0, 100},
		{"all of them", 4, 4, 100},
		{"3 of 4", 3, 4, 75},
		{"2 of 3 rounds down", 2, 3, 66},
		{"1 of 3 rounds down", 1, 3, 33},
		{"999 of 1000 is not 100", 999, 1000, 99},
		{"none of them", 0, 4, 0},
		// Counts that can't be true must not pass a completeness guard, so they give 0.
		{"more owned than found", 5, 4, 0},
		{"owned files with no ELF files", 1, 0, 0},
		{"a negative owned count", -1, 4, 0},
		{"a negative total", 0, -4, 0},
		{"two negative counts", -4, -4, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := result.Manifest{ELF: result.ELFSummary{Owned: c.owned, Total: c.total}}
			require.Equal(t, c.want, m.Completeness())
		})
	}
}

func TestCompletenessAtTheLargestCounts(t *testing.T) {
	m := result.Manifest{ELF: result.ELFSummary{Owned: math.MaxInt32, Total: math.MaxInt32}}
	require.Equal(t, int32(100), m.Completeness())

	m.ELF.Owned = math.MaxInt32 - 1
	require.Equal(t, int32(99), m.Completeness())

	// An int32 counts no more files than that, so a larger count is not a true one. The conversion
	// is at run time to keep the test building where an int has 32 bits, and wraps to a negative
	// count there, which gives 0 too.
	tooMany := int(int64(math.MaxInt32) + 1)
	m.ELF = result.ELFSummary{Owned: tooMany, Total: tooMany}
	require.Equal(t, int32(0), m.Completeness())
}

func TestPlatformMatches(t *testing.T) {
	const (
		amd64   = "linux/amd64"
		arm64   = "linux/arm64"
		arm64v8 = "linux/arm64/v8"
		armv7   = "linux/arm/v7"
	)
	cases := []struct {
		requested, actual string
		want              bool
	}{
		{amd64, amd64, true},
		// Requests come from node labels, which name no variant: one matches every variant.
		{arm64, arm64v8, true},
		{arm64, arm64, true},
		{armv7, armv7, true},
		// A variant in the request must be the manifest's.
		{armv7, "linux/arm/v6", false},
		{arm64v8, arm64, false},
		{amd64, arm64, false},
		{amd64, "windows/amd64", false},
		{amd64, "linux/amd64p32", false},
		// A string that isn't os/architecture[/variant] matches nothing, on either side.
		{"", amd64, false},
		{"linux", amd64, false},
		{"linux/", amd64, false},
		{"/amd64", amd64, false},
		{"linux//v8", "linux//v8", false},
		{"linux/arm64/", arm64v8, false},
		{"linux/arm64/v8/x", "linux/arm64/v8/x", false},
		{amd64, "", false},
		{amd64, "linux", false},
		{amd64, "linux/amd64/", false},
		{amd64, "linux/amd64/v1/x", false},
	}
	for _, c := range cases {
		t.Run(c.requested+" for "+c.actual, func(t *testing.T) {
			require.Equal(t, c.want, result.PlatformMatches(c.requested, c.actual))
		})
	}
}
