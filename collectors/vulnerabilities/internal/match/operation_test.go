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

package match_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"

	"github.com/bedag/vexplain/collectors/vulnerabilities/internal/grype"
	"github.com/bedag/vexplain/collectors/vulnerabilities/internal/match"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/conformance"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// These tests run the vulnerabilities collector on a fake Grype, which answers from memory, and call its operation and its
// Watch directly. The wrapper of the real CLI has its own tests, in internal/grype.

const (
	// wait bounds how long a test waits for what must happen, and quiet how long it watches for what must not.
	wait  = 10 * time.Second
	quiet = 200 * time.Millisecond

	collectorName = "vulnerabilities"
	version       = "0.2.0"
	clusterName   = "cluster-a"
	matchName     = "match"
	// imageContentsType is the scanner's own type of evidence, which the vulnerabilities collector doesn't consume:
	// its SBOM is evidence of the core type sbom.
	imageContentsType = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"
	// The platform of the manifest.
	platform = "linux/arm64/v8"

	notReady     = "NotReady"
	invalidInput = "InvalidInput"
	internal     = "Internal"

	pkgA, pkgB = "pkg-a", "pkg-b"
	typeAPK    = "apk"
	typeRPM    = "rpm"
	// The two packages of Alpine 3.12 that the SBOM of the manifest holds, by their names and versions, and Syft, which
	// found them.
	brotliName, brotliVersion = "brotli-libs", "1.0.9-r1"
	muslName, muslVersion     = "musl", "1.1.24-r8"
	// muslFixed is the version of musl that fixes CVE-2020-28928.
	muslFixed = "1.1.24-r10"
	syft      = "syft"
	// syftVersion is the version of Syft that made the SBOMs of the tests.
	syftVersion = "1.55.0"
	// The calls of the sink, as their names.
	callStart, callEnd, callChanged = "SnapshotStart", "SnapshotEnd", "SourceChanged"
)

var (
	// digest is the manifest that the SBOM is about.
	digest = "sha256:" + strings.Repeat("cd", 32)

	dbOne = grype.Database{Version: "v6.1.10+2026-10-30T06:23:28Z", Built: time.Date(2026, 10, 30, 6, 23, 28, 0, time.UTC)}
	dbTwo = grype.Database{Version: "v6.1.10+2026-10-31T06:24:11Z", Built: time.Date(2026, 10, 31, 6, 24, 11, 0, time.UTC)}

	critical = grype.Match{
		VulnerabilityID: "CVE-2026-111497", PackageID: pkgA, Severity: "Critical", FixState: "unknown",
		KnownExploited: true, PackageName: brotliName, PackageVersion: brotliVersion, PackageType: typeAPK,
		CVSS: []grype.CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	}
	fixed = grype.Match{
		VulnerabilityID: "CVE-2020-28928", PackageID: pkgB, Severity: "Medium", FixState: "fixed",
		FixedVersions: []string{muslFixed}, PackageName: muslName, PackageVersion: muslVersion, PackageType: typeAPK,
	}
)

// fakeGrype is a Grype that answers from memory. It is without a database until its db is set, or an update sets it
// to afterUpdate.
type fakeGrype struct {
	mu          sync.Mutex
	db          *grype.Database
	afterUpdate *grype.Database
	matches     []grype.Match
	matchErr    error
	updateErr   error
	updates     int
	// sboms holds the content of the file that each match was asked to read, and paths the paths of the files.
	sboms [][]byte
	paths []string
	// started tells that a match began, and gate, when set, holds every match until it is closed.
	started chan struct{}
	gate    chan struct{}
	// running counts the matches that run, and mostRunning the most that ran at once.
	running, mostRunning int
}

func newGrype(db *grype.Database, matches ...grype.Match) *fakeGrype {
	return &fakeGrype{db: db, matches: matches, started: make(chan struct{}, 16)}
}

func (g *fakeGrype) Match(ctx context.Context, sbomPath string) ([]grype.Match, error) {
	content, err := os.ReadFile(sbomPath)
	g.mu.Lock()
	g.sboms = append(g.sboms, content)
	g.paths = append(g.paths, sbomPath)
	g.running++
	g.mostRunning = max(g.mostRunning, g.running)
	gate, matches, matchErr := g.gate, slices.Clone(g.matches), g.matchErr
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.running--
		g.mu.Unlock()
	}()
	g.started <- struct{}{}
	if err != nil {
		return nil, err
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return matches, matchErr
}

func (g *fakeGrype) Update(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.updates++
	if g.updateErr != nil {
		return g.updateErr
	}
	if g.afterUpdate != nil {
		g.db = g.afterUpdate
	}
	return nil
}

func (g *fakeGrype) Status(context.Context) (grype.Database, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.db == nil {
		return grype.Database{}, errors.New("no database")
	}
	return *g.db, nil
}

func (g *fakeGrype) updateCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.updates
}

func (g *fakeGrype) matched() (sboms [][]byte, paths []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.sboms), slices.Clone(g.paths)
}

// clock is the vulnerabilities collector's timer: the test fires each wait of the vulnerabilities collector, and reads how long it asked to wait.
type clock struct {
	waits chan time.Duration
	fire  chan time.Time
}

func newClock() *clock {
	return &clock{waits: make(chan time.Duration, 64), fire: make(chan time.Time)}
}

func (c *clock) After(d time.Duration) <-chan time.Time {
	c.waits <- d
	return c.fire
}

// waited returns the next wait that the vulnerabilities collector asked for.
func (c *clock) waited(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-c.waits:
		return d
	case <-time.After(wait):
		require.FailNow(t, "the vulnerabilities collector asked for no wait")
		return 0
	}
}

// tick lets the wait that the vulnerabilities collector is in end.
func (c *clock) tick(t *testing.T) {
	t.Helper()
	select {
	case c.fire <- time.Now():
	case <-time.After(wait):
		require.FailNow(t, "the vulnerabilities collector waits for no time")
	}
}

// collectorOf returns the vulnerabilities collector on the fake Grype, whose database directory is dir.
func collectorOf(g *fakeGrype, dir string, c *clock) *match.Collector {
	return match.New(match.Options{Name: collectorName, Version: version, Grype: g, DBDir: dir, After: c.After})
}

// exampleSBOM is the SBOM of the manifest: two packages of Alpine 3.12, one built from a source package of another
// name, as Syft found them.
func exampleSBOM() evidence.SBOM {
	return evidence.SBOM{
		Distro: &evidence.Distro{ID: "alpine", Version: "3.12.0"},
		Packages: []evidence.SBOMPackage{
			{
				ID: pkgA, Name: brotliName, Version: brotliVersion, Type: typeAPK,
				PURL: "pkg:apk/alpine/brotli-libs@1.0.9-r1?arch=x86_64&distro=alpine-3.12.0&upstream=brotli",
				CPEs: []string{"cpe:2.3:a:brotli-libs:brotli-libs:1.0.9-r1:*:*:*:*:*:*:*"},
			},
			{
				ID: pkgB, Name: muslName, Version: muslVersion, Type: typeAPK,
				PURL: "pkg:apk/alpine/musl@1.1.24-r8?arch=x86_64&distro=alpine-3.12.0",
				CPEs: []string{"cpe:2.3:a:musl-libc:musl:1.1.24-r8:*:*:*:*:*:*:*"},
			},
		},
		Producer: evidence.Producer{Name: syft, Version: syftVersion},
	}
}

// sbomEvent returns the sbom evidence about the manifest, whose data is sbom, as the scanner delivers it.
func sbomEvent(t *testing.T, sbom any) cloudevents.Event {
	t.Helper()
	e, err := evidence.New(evidence.TypeSBOM, subject.Manifest(digest), sbom,
		evidence.WithPlatform(platform), evidence.WithCoverage(100),
		evidence.WithSource("/clusters/"+clusterName+"/collectors/scanner"))
	require.NoError(t, err)
	require.NoError(t, evidence.Validate(e))
	return e
}

// matchRequest is the request of match for the manifest, with the inputs.
func matchRequest(settings string, inputs ...cloudevents.Event) collector.InvokeRequest {
	return collector.InvokeRequest{
		Operation: matchName, Subject: subject.Manifest(digest), Parameters: json.RawMessage(`{}`),
		Settings: json.RawMessage(settings), Inputs: inputs, Role: collector.RoleHub,
		Context: collector.Context{Cluster: clusterName},
	}
}

// findingsOf returns the data of a findings event.
func findingsOf(t *testing.T, e cloudevents.Event) evidence.Findings {
	t.Helper()
	var found evidence.Findings
	require.NoError(t, json.Unmarshal(e.Data(), &found))
	return found
}

// ---- match ----

func TestMatchMakesOneFindingsEventOfTheMatchesAboutTheManifest(t *testing.T) {
	g := newGrype(&dbOne, fixed, critical)
	m := collectorOf(g, t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))

	events, failure, err := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, exampleSBOM())))

	require.NoError(t, err)
	require.Nil(t, failure)
	require.Len(t, events, 1)
	e := events[0]
	require.NoError(t, evidence.Validate(e))
	require.Equal(t, evidence.TypeFindings, e.Type())
	require.Equal(t, subject.Manifest(digest), e.Subject())
	got, ok := evidence.Platform(e)
	require.True(t, ok)
	require.Equal(t, platform, got, "the platform of the SBOM")
	require.Equal(t, "/hub/collectors/"+collectorName, e.Source())
	require.Equal(t, evidence.Findings{Version: dbOne.Version, Matches: []evidence.Match{
		{
			ID: "CVE-2020-28928/" + pkgB, Title: "CVE-2020-28928 in musl 1.1.24-r8",
			VulnerabilityID: "CVE-2020-28928", PackageID: pkgB, PackageName: muslName, PackageVersion: muslVersion,
			PackageType: typeAPK, Severity: "Medium", FixState: "fixed", FixedVersions: []string{muslFixed},
			FixTarget: muslFixed, UpdateTarget: muslFixed,
		},
		{
			ID: "CVE-2026-111497/" + pkgA, Title: "CVE-2026-111497 in brotli-libs 1.0.9-r1",
			VulnerabilityID: "CVE-2026-111497", PackageID: pkgA, PackageName: brotliName, PackageVersion: brotliVersion,
			PackageType: typeAPK, Severity: "Critical", FixState: "unknown", KnownExploited: true,
			CVSS: []evidence.CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		},
	}}, findingsOf(t, e), "severities, fix states and fixed versions, KEV and the CVSS vectors, as Grype gives them")
}

func TestMatchWithNoMatchesWritesAnEmptyList(t *testing.T) {
	m := collectorOf(newGrype(&dbOne), t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))

	events, failure, err := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, exampleSBOM())))

	require.NoError(t, err)
	require.Nil(t, failure)
	require.Len(t, events, 1)
	require.JSONEq(t, `{"version": "`+dbOne.Version+`", "matches": []}`, string(events[0].Data()))
}

// Grype reads the packages of a Syft JSON document. The vulnerabilities collector writes one of the SBOM: each package
// under its ID, which a match names, with its name, version, type, purl and CPEs, and with the source package of an
// OS package where Grype reads it from such a document, in its metadata: here the origin of an Alpine package, which
// its purl names in the qualifier upstream, and which is the package itself where the purl names none, as Syft writes
// it. The distribution is the SBOM's.
func TestMatchRunsGrypeOnADocumentOfTheSBOMAndLeavesNoFile(t *testing.T) {
	g := newGrype(&dbOne)
	m := collectorOf(g, t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))

	_, failure, err := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, exampleSBOM())))

	require.NoError(t, err)
	require.Nil(t, failure)
	sboms, paths := g.matched()
	require.Len(t, sboms, 1)
	require.JSONEq(t, `{
		"artifacts": [
			{
				"id": "pkg-a", "name": "brotli-libs", "version": "1.0.9-r1", "type": "apk",
				"cpes": ["cpe:2.3:a:brotli-libs:brotli-libs:1.0.9-r1:*:*:*:*:*:*:*"],
				"purl": "pkg:apk/alpine/brotli-libs@1.0.9-r1?arch=x86_64&distro=alpine-3.12.0&upstream=brotli",
				"metadataType": "apk-db-entry", "metadata": {"originPackage": "brotli"}
			},
			{
				"id": "pkg-b", "name": "musl", "version": "1.1.24-r8", "type": "apk",
				"cpes": ["cpe:2.3:a:musl-libc:musl:1.1.24-r8:*:*:*:*:*:*:*"],
				"purl": "pkg:apk/alpine/musl@1.1.24-r8?arch=x86_64&distro=alpine-3.12.0",
				"metadataType": "apk-db-entry", "metadata": {"originPackage": "musl"}
			}
		],
		"artifactRelationships": [],
		"distro": {"id": "alpine", "versionID": "3.12.0"},
		"descriptor": {"name": "syft", "version": "1.55.0"},
		"schema": {
			"version": "16.1.11",
			"url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.11.json"
		}
	}`, string(sboms[0]))
	require.NoFileExists(t, paths[0], "the SBOM is the image's, and stays no longer than its match")
}

func TestMatchWithoutADatabaseFailsNotReady(t *testing.T) {
	g := newGrype(nil)
	m := collectorOf(g, t.TempDir(), newClock())

	events, failure, err := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, exampleSBOM())))

	require.NoError(t, err)
	require.Empty(t, events)
	require.NotNil(t, failure)
	require.Equal(t, notReady, failure.Reason)
	sboms, _ := g.matched()
	require.Empty(t, sboms, "Grype is not run without a database")
}

func TestMatchRefusesARequestThatDoesNotFitIt(t *testing.T) {
	m := collectorOf(newGrype(&dbOne), t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))
	other := sbomEvent(t, exampleSBOM())
	other.SetSubject(subject.Manifest("sha256:" + strings.Repeat("e", 64)))
	imageRequest := matchRequest(`{}`, sbomEvent(t, exampleSBOM()))
	imageRequest.Subject = subject.Image(digest)
	contents := sbomEvent(t, exampleSBOM())
	contents.SetType(imageContentsType)

	for name, req := range map[string]collector.InvokeRequest{
		"no input":                      matchRequest(`{}`),
		"two inputs":                    matchRequest(`{}`, sbomEvent(t, exampleSBOM()), sbomEvent(t, exampleSBOM())),
		"an input about another one":    matchRequest(`{}`, other),
		"an input of the scanner's own": matchRequest(`{}`, contents),
		"a subject that is no manifest": imageRequest,
		"settings out of range":         matchRequest(`{"maxConcurrent": 9}`, sbomEvent(t, exampleSBOM())),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := m.Invoke(t.Context(), req)

			require.Error(t, err)
		})
	}
}

// An SBOM that isn't one, or names a package without an ID or a name, or two of one ID, is no input to match: Grype
// would take two packages of one ID for one, and a match must name its package by an ID of its own. The match fails,
// and runs nothing.
func TestMatchFailsForAnSBOMThatItCantMatch(t *testing.T) {
	g := newGrype(&dbOne)
	m := collectorOf(g, t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))
	withPackages := func(change func(pkgs []evidence.SBOMPackage)) evidence.SBOM {
		sbom := exampleSBOM()
		change(sbom.Packages)
		return sbom
	}

	for name, data := range map[string]any{
		"no packages":              map[string]any{"producer": map[string]any{"name": syft}},
		"packages that are null":   map[string]any{"packages": nil, "producer": map[string]any{"name": syft}},
		"no producer":              map[string]any{"packages": []any{}},
		"data that is no object":   []any{},
		"a package without an ID":  withPackages(func(pkgs []evidence.SBOMPackage) { pkgs[1].ID = "" }),
		"a package without a name": withPackages(func(pkgs []evidence.SBOMPackage) { pkgs[1].Name = "" }),
		"two packages of one ID":   withPackages(func(pkgs []evidence.SBOMPackage) { pkgs[1].ID = pkgs[0].ID }),
	} {
		t.Run(name, func(t *testing.T) {
			events, failure, err := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, data)))

			require.NoError(t, err)
			require.Empty(t, events)
			require.NotNil(t, failure)
			require.Equal(t, invalidInput, failure.Reason)
		})
	}
	sboms, _ := g.matched()
	require.Empty(t, sboms)
}

// A manifest without packages, such as that of an image of one static binary, has an SBOM all the same, in which
// Grype finds nothing.
func TestMatchOfAnSBOMWithoutPackages(t *testing.T) {
	g := newGrype(&dbOne)
	m := collectorOf(g, t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))

	events, failure, err := m.Invoke(t.Context(), matchRequest(`{}`,
		sbomEvent(t, evidence.SBOM{Producer: evidence.Producer{Name: syft}})))

	require.NoError(t, err)
	require.Nil(t, failure)
	require.Len(t, events, 1)
	sboms, _ := g.matched()
	require.Len(t, sboms, 1)
	var doc struct {
		Artifacts []any `json:"artifacts"`
	}
	require.NoError(t, json.Unmarshal(sboms[0], &doc))
	require.NotNil(t, doc.Artifacts)
	require.Empty(t, doc.Artifacts)
}

// A document that Grype can't read fails the match, as any failure of Grype does. The packages are no fallback: a
// document built from them would drop what only the producer's document holds, and match less without saying so.
func TestMatchOfADocumentThatGrypeCantReadFails(t *testing.T) {
	const unreadable = `{"bomFormat": "not CycloneDX"}`
	g := newGrype(&dbOne)
	g.matchErr = errors.New("grype match: exit status 1")
	m := collectorOf(g, t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))
	sbom := exampleSBOM()
	sbom.Document = &evidence.SBOMDocument{Format: evidence.SBOMFormatCycloneDXJSON, Content: json.RawMessage(unreadable)}

	events, failure, err := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, sbom)))

	require.ErrorContains(t, err, "exit status 1")
	require.Empty(t, events)
	require.Nil(t, failure, "no answer is not an answer of no findings")
	sboms, _ := g.matched()
	require.Len(t, sboms, 1, "Grype ran on the document, and not again on the packages")
	require.JSONEq(t, unreadable, string(sboms[0]))
}

// A document of a format that Grype doesn't read, or that is no JSON object, is no input to match: the schema refuses
// both, and so does the match, as InvalidInput, without running Grype.
func TestMatchRefusesADocumentThatIsNoSBOMDocument(t *testing.T) {
	g := newGrype(&dbOne)
	m := collectorOf(g, t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))

	for name, document := range map[string]evidence.SBOMDocument{
		"a format that Grype doesn't read": {Format: "cyclonedx-xml", Content: json.RawMessage(`{}`)},
		"content that is no object":        {Format: evidence.SBOMFormatSyftJSON, Content: json.RawMessage(`"{}"`)},
		"content that is null":             {Format: evidence.SBOMFormatSyftJSON, Content: json.RawMessage(`null`)},
	} {
		t.Run(name, func(t *testing.T) {
			sbom := exampleSBOM()
			sbom.Document = &document
			e, err := evidence.New(evidence.TypeSBOM, subject.Manifest(digest), sbom, evidence.WithPlatform(platform))
			require.NoError(t, err)
			require.Error(t, evidence.Validate(e), "the schema refuses the document")

			events, failure, err := m.Invoke(t.Context(), matchRequest(`{}`, e))

			require.NoError(t, err)
			require.Empty(t, events)
			require.NotNil(t, failure)
			require.Equal(t, invalidInput, failure.Reason)
		})
	}
	sboms, _ := g.matched()
	require.Empty(t, sboms)
}

func TestMatchReturnsAnErrorWhenGrypeFails(t *testing.T) {
	g := newGrype(&dbOne)
	g.matchErr = errors.New("grype match: exit status 1")
	m := collectorOf(g, t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))

	events, failure, err := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, exampleSBOM())))

	require.ErrorContains(t, err, "exit status 1")
	require.Empty(t, events)
	require.Nil(t, failure, "no answer is not an answer of no findings")
}

func TestMatchFailsWhenAMatchIsNoEvidence(t *testing.T) {
	// A match that names no package would be refused by the schema of the findings, and so by every reader.
	g := newGrype(&dbOne, grype.Match{VulnerabilityID: "CVE-2026-1", PackageID: pkgA})
	m := collectorOf(g, t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))

	events, failure, err := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, exampleSBOM())))

	require.NoError(t, err)
	require.Empty(t, events)
	require.NotNil(t, failure)
	require.Equal(t, internal, failure.Reason)
}

// The vulnerabilities collector runs as many matches at once as maxConcurrent says, 2 by default, and the others wait for a place.
func TestMatchesRunAtMostMaxConcurrentAtOnce(t *testing.T) {
	for name, tc := range map[string]struct {
		settings string
		most     int
	}{"the default": {`{}`, 2}, "one": {`{"maxConcurrent": 1}`, 1}, "three": {`{"maxConcurrent": 3}`, 3}} {
		t.Run(name, func(t *testing.T) {
			g := newGrype(&dbOne)
			g.gate = make(chan struct{})
			m := collectorOf(g, t.TempDir(), newClock())
			require.NoError(t, m.Load(t.Context()))
			var done sync.WaitGroup
			for range tc.most + 2 {
				done.Go(func() {
					_, failure, err := m.Invoke(t.Context(), matchRequest(tc.settings, sbomEvent(t, exampleSBOM())))
					assert.NoError(t, err)
					assert.Nil(t, failure)
				})
			}
			for range tc.most {
				<-g.started
			}
			select {
			case <-g.started:
				require.FailNow(t, "a match started above maxConcurrent")
			case <-time.After(quiet):
			}

			close(g.gate)
			done.Wait()

			require.Equal(t, tc.most, g.mostRunning)
		})
	}
}

func TestAMatchThatWaitsForAPlaceStopsWithItsContext(t *testing.T) {
	g := newGrype(&dbOne)
	g.gate = make(chan struct{})
	m := collectorOf(g, t.TempDir(), newClock())
	require.NoError(t, m.Load(t.Context()))
	ctx, cancel := context.WithCancel(t.Context())
	var done sync.WaitGroup
	done.Go(func() {
		_, _, _ = m.Invoke(t.Context(), matchRequest(`{"maxConcurrent": 1}`, sbomEvent(t, exampleSBOM())))
	})
	<-g.started
	errs := make(chan error, 1)
	go func() {
		_, _, err := m.Invoke(ctx, matchRequest(`{"maxConcurrent": 1}`, sbomEvent(t, exampleSBOM())))
		errs <- err
	}()

	cancel()

	select {
	case err := <-errs:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(wait):
		require.FailNow(t, "a match that waits for a place doesn't stop")
	}
	close(g.gate)
	done.Wait()
}

// ---- watch ----

// sink records what a Watch sends, as calls named by their kind.
type sink struct{ calls chan string }

func newSink() *sink { return &sink{calls: make(chan string, 64)} }

func (s *sink) SnapshotStart() error          { s.calls <- callStart; return nil }
func (s *sink) Event(cloudevents.Event) error { s.calls <- "Event"; return nil }
func (s *sink) Tombstone(_, _ string) error   { s.calls <- "Tombstone"; return nil }
func (s *sink) SnapshotEnd() error            { s.calls <- callEnd; return nil }
func (s *sink) SourceChanged(subjects ...string) error {
	if len(subjects) > 0 {
		s.calls <- "SourceChanged with subjects"
		return nil
	}
	s.calls <- callChanged
	return nil
}

// next returns the next call of the sink.
func (s *sink) next(t *testing.T) string {
	t.Helper()
	select {
	case call := <-s.calls:
		return call
	case <-time.After(wait):
		require.FailNow(t, "the Watch sent nothing")
		return ""
	}
}

// silent checks that the Watch sends nothing for as long as quiet.
func (s *sink) silent(t *testing.T) {
	t.Helper()
	select {
	case call := <-s.calls:
		require.FailNow(t, "the Watch sent "+call)
	case <-time.After(quiet):
	}
}

// watching starts a Watch of the vulnerabilities collector with the settings, and returns what it sends, and a stop that ends it, checks
// that it returned nil, and waits for it.
func watching(t *testing.T, m *match.Collector, settings string) (*sink, func()) {
	t.Helper()
	s := newSink()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- m.Watch(ctx, collector.WatchRequest{
			Role: collector.RoleHub, Settings: json.RawMessage(settings), Context: collector.Context{Cluster: clusterName},
		}, s)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				assert.NoError(t, err)
			case <-time.After(wait):
				assert.Fail(t, "the Watch didn't stop with its context")
			}
		})
	}
	t.Cleanup(stop)
	return s, stop
}

func TestWatchSendsAnEmptySnapshotAndThenSaysWhenItHasTheDatabase(t *testing.T) {
	g := newGrype(&dbOne)
	c := newClock()

	s, _ := watching(t, collectorOf(g, t.TempDir(), c), `{}`)

	require.Equal(t, callStart, s.next(t))
	require.Equal(t, callEnd, s.next(t))
	require.Equal(t, callChanged, s.next(t), "a manifest matched before may have been matched on another database")
	s.silent(t)
	require.Zero(t, g.updateCount(), "a database that is there needs no update at start")
}

func TestWatchWithoutADatabaseSendsTheSnapshotAndUpdates(t *testing.T) {
	g := newGrype(nil)
	g.afterUpdate = &dbOne
	c := newClock()

	s, _ := watching(t, collectorOf(g, t.TempDir(), c), `{}`)

	require.Equal(t, callStart, s.next(t))
	require.Equal(t, callEnd, s.next(t), "the snapshot is empty, and doesn't wait for a download")
	require.Equal(t, callChanged, s.next(t))
	require.Equal(t, 1, g.updateCount())
}

func TestWatchSaysSourceChangedWhenAnUpdateChangesTheVersion(t *testing.T) {
	g := newGrype(&dbOne)
	g.afterUpdate = &dbTwo
	c := newClock()
	s, _ := watching(t, collectorOf(g, t.TempDir(), c), `{"updateIntervalSeconds": 3600}`)
	require.Equal(t, []string{callStart, callEnd, callChanged}, []string{s.next(t), s.next(t), s.next(t)})
	require.Equal(t, time.Hour, c.waited(t))

	c.tick(t)

	require.Equal(t, callChanged, s.next(t))
	require.Equal(t, 1, g.updateCount())

	// An update that finds the same database says nothing.
	require.Equal(t, time.Hour, c.waited(t))
	c.tick(t)
	require.Equal(t, time.Hour, c.waited(t))
	s.silent(t)
	require.Equal(t, 2, g.updateCount())
}

func TestWatchUpdatesEverySixHoursByDefault(t *testing.T) {
	c := newClock()
	watching(t, collectorOf(newGrype(&dbOne), t.TempDir(), c), `{}`)

	require.Equal(t, 21600*time.Second, c.waited(t))
}

func TestWatchKeepsTheDatabaseWhenAnUpdateFails(t *testing.T) {
	g := newGrype(&dbOne)
	g.updateErr = errors.New("grype update: exit status 1")
	c := newClock()
	m := collectorOf(g, t.TempDir(), c)
	s, _ := watching(t, m, `{"updateIntervalSeconds": 60}`)
	require.Equal(t, []string{callStart, callEnd, callChanged}, []string{s.next(t), s.next(t), s.next(t)})
	c.waited(t)

	c.tick(t)
	c.waited(t)

	s.silent(t)
	_, failure, err := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, exampleSBOM())))
	require.NoError(t, err)
	require.Nil(t, failure, "the vulnerabilities collector still matches with the database that it has")
}

func TestWatchTriesAgainSoonWhenItStillHasNoDatabase(t *testing.T) {
	g := newGrype(nil)
	g.updateErr = errors.New("grype update: exit status 1")
	c := newClock()
	s, _ := watching(t, collectorOf(g, t.TempDir(), c), `{}`)
	require.Equal(t, []string{callStart, callEnd}, []string{s.next(t), s.next(t)})

	require.Equal(t, time.Minute, c.waited(t), "without a database the vulnerabilities collector doesn't wait for the interval")
	g.mu.Lock()
	g.updateErr, g.afterUpdate = nil, &dbOne
	g.mu.Unlock()
	c.tick(t)

	require.Equal(t, callChanged, s.next(t))
}

func TestOfflineNeverUpdates(t *testing.T) {
	for name, db := range map[string]*grype.Database{"with a database": &dbOne, "without one": nil} {
		t.Run(name, func(t *testing.T) {
			g := newGrype(db)
			g.afterUpdate = &dbTwo
			c := newClock()

			s, _ := watching(t, collectorOf(g, t.TempDir(), c), `{"databaseUpdates": "Offline", "updateIntervalSeconds": 60}`)

			require.Equal(t, callStart, s.next(t))
			require.Equal(t, callEnd, s.next(t))
			if db != nil {
				require.Equal(t, callChanged, s.next(t))
			}
			s.silent(t)
			select {
			case d := <-c.waits:
				require.FailNow(t, "an offline vulnerabilities collector waits for an interval", d.String())
			default:
			}
			require.Zero(t, g.updateCount())
		})
	}
}

// A seed is copied into the database directory when it holds no database, and the vulnerabilities collector then has one, offline too.
func TestAWatchSeedsTheDatabaseDirectoryWhenItHoldsNoDatabase(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "grype-db")
	require.NoError(t, os.MkdirAll(filepath.Join(seed, "6"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(seed, databaseFile), []byte("database"), 0o644))
	dir := filepath.Join(t.TempDir(), "db")
	g := newGrype(nil)
	// The fake's database is valid once the seeded file is there, as Grype's is.
	m := match.New(match.Options{Name: collectorName, Version: version, DBDir: dir, After: newClock().After,
		Grype: &seededGrype{fakeGrype: g, file: filepath.Join(dir, databaseFile)}})

	s, _ := watching(t, m, `{"databaseUpdates": "Offline", "seedDatabase": "`+seed+`"}`)

	require.Equal(t, []string{callStart, callEnd, callChanged}, []string{s.next(t), s.next(t), s.next(t)})
	require.FileExists(t, filepath.Join(dir, databaseFile))
	require.Zero(t, g.updateCount())
}

// databaseFile is where a database that Grype calls valid keeps its content, under the database directory.
const databaseFile = "6/vulnerability.db"

// seededGrype is a Grype whose database is valid when its file is there.
type seededGrype struct {
	*fakeGrype
	file string
}

func (g *seededGrype) Status(ctx context.Context) (grype.Database, error) {
	if _, err := os.Stat(g.file); err != nil {
		return grype.Database{}, errors.New("no database")
	}
	return dbOne, nil
}

func TestASeedIsNotCopiedOverADatabaseThatIsThere(t *testing.T) {
	seed := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(seed, "from-seed"), []byte("x"), 0o644))
	dir := t.TempDir()

	s, _ := watching(t, collectorOf(newGrype(&dbOne), dir, newClock()), `{"databaseUpdates": "Offline", "seedDatabase": "`+seed+`"}`)

	require.Equal(t, []string{callStart, callEnd, callChanged}, []string{s.next(t), s.next(t), s.next(t)})
	require.NoFileExists(t, filepath.Join(dir, "from-seed"))
}

// A Watch that opens again, for new settings or after a break, starts with a snapshot again, and says nothing of a
// database whose version it said before.
func TestANewWatchSaysSourceChangedOnlyForAVersionThatItHasNotSaid(t *testing.T) {
	g := newGrype(&dbOne)
	m := collectorOf(g, t.TempDir(), newClock())
	s, stop := watching(t, m, `{}`)
	require.Equal(t, []string{callStart, callEnd, callChanged}, []string{s.next(t), s.next(t), s.next(t)})
	stop()

	s, stop = watching(t, m, `{}`)
	require.Equal(t, []string{callStart, callEnd}, []string{s.next(t), s.next(t)})
	s.silent(t)
	stop()

	// The database changed while no Watch was open.
	g.mu.Lock()
	g.db = &dbTwo
	g.mu.Unlock()
	s, _ = watching(t, m, `{}`)
	require.Equal(t, []string{callStart, callEnd, callChanged}, []string{s.next(t), s.next(t), s.next(t)})
}

func TestWatchRefusesSettingsThatAreOutOfRange(t *testing.T) {
	m := collectorOf(newGrype(&dbOne), t.TempDir(), newClock())

	err := m.Watch(t.Context(), collector.WatchRequest{Role: collector.RoleHub, Settings: json.RawMessage(`{"databaseUpdates": "Sometimes"}`)}, newSink())

	require.Error(t, err)
}

// A match waits for the update that replaces the database's files, and the update waits for the matches that run, so
// that a match always names the version of the database that it ran on.
func TestAnUpdateWaitsForTheMatchesThatRunAndTheNextMatchNamesTheNewVersion(t *testing.T) {
	g := newGrype(&dbOne)
	g.afterUpdate = &dbTwo
	g.gate = make(chan struct{})
	c := newClock()
	m := collectorOf(g, t.TempDir(), c)
	s, _ := watching(t, m, `{"updateIntervalSeconds": 60}`)
	require.Equal(t, []string{callStart, callEnd, callChanged}, []string{s.next(t), s.next(t), s.next(t)})
	c.waited(t)
	matched := make(chan cloudevents.Event, 1)
	go func() {
		events, _, _ := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, exampleSBOM())))
		matched <- events[0]
	}()
	<-g.started

	c.tick(t)
	s.silent(t) // the update waits for the match

	close(g.gate)
	require.Equal(t, dbOne.Version, findingsOf(t, <-matched).Version, "the match ran on the old database")
	require.Equal(t, callChanged, s.next(t))
	events, _, err := m.Invoke(t.Context(), matchRequest(`{}`, sbomEvent(t, exampleSBOM())))
	require.NoError(t, err)
	require.Equal(t, dbTwo.Version, findingsOf(t, events[0]).Version)
}

// ---- what the collector declares ----

func TestTheCapabilitiesOfTheCollector(t *testing.T) {
	m := collectorOf(newGrype(nil), t.TempDir(), newClock())

	require.Equal(t, collector.Info{Name: collectorName, Version: version}, m.Info())
	caps := m.Capabilities()
	require.Equal(t, []collector.Role{collector.RoleHub}, caps.Roles)
	require.True(t, caps.Watches, "it watches, to signal the changes of its database")
	require.Equal(t, []string{evidence.TypeSBOM}, caps.Consumes)
	require.Len(t, caps.Produces, 1)
	require.Equal(t, evidence.TypeFindings, caps.Produces[0].Type)
	require.Equal(t, collector.ScopeHub, caps.Produces[0].Scope)
	schema, ok := evidence.Schema(evidence.TypeFindings)
	require.True(t, ok)
	require.Equal(t, schema, caps.Produces[0].Schema)
	require.Len(t, caps.Operations, 1)
	op := caps.Operations[0]
	require.Equal(t, matchName, op.Name)
	require.Equal(t, collector.RoleHub, op.Role)
	require.Equal(t, []string{evidence.TypeSBOM}, op.Consumes)
	require.Equal(t, []string{evidence.TypeFindings}, op.Produces)
	require.Empty(t, caps.Permissions, "the vulnerabilities collector reads nothing of the Kubernetes API")
}

// serve serves the vulnerabilities collector on a listener that only the test reaches, until the test ends, and returns a connection to
// it.
func serve(t *testing.T, m *match.Collector) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	health, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- collector.Serve(ctx, m, collector.Options{Insecure: true, GRPCListener: listener, HealthListener: health})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(wait):
			assert.Fail(t, "the vulnerabilities collector didn't stop")
		}
	})
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func validate(t *testing.T, conn *grpc.ClientConn, settings string) []string {
	t.Helper()
	resp, err := collectorv1alpha1.NewIdentityClient(conn).ValidateSettings(t.Context(),
		&collectorv1alpha1.ValidateSettingsRequest{Settings: []byte(settings)})
	require.NoError(t, err)
	return resp.GetProblems()
}

func TestTheSettingsAreChecked(t *testing.T) {
	conn := serve(t, collectorOf(newGrype(nil), t.TempDir(), newClock()))

	for _, valid := range []string{
		`{}`,
		`{"updateIntervalSeconds": 21600, "maxConcurrent": 8, "databaseUpdates": "Online"}`,
		`{"maxConcurrent": 1, "databaseUpdates": "Offline", "seedDatabase": "/opt/grype-db"}`,
	} {
		require.Empty(t, validate(t, conn, valid), valid)
	}
	for _, invalid := range []string{
		`{"maxConcurrent": 0}`,
		`{"maxConcurrent": 9}`,
		`{"maxConcurrent": 1.5}`,
		`{"updateIntervalSeconds": 0}`,
		`{"updateIntervalSeconds": -1}`,
		`{"databaseUpdates": "Sometimes"}`,
		`{"databaseUpdates": "offline"}`,
		`{"seedDatabase": ""}`,
		`{"seedDatabase": "opt/grype-db"}`,
		`{"seedDatabase": 3}`,
		`{"listen": ":8080"}`,
	} {
		require.NotEmpty(t, validate(t, conn, invalid), invalid)
	}
}

// A missing database fails each match, and is no failure of the collector: the health check that the deployer reads
// stays SERVING, since a first download can take longer than the deployer's grace.
func TestWithoutADatabaseTheHealthStaysServing(t *testing.T) {
	conn := serve(t, collectorOf(newGrype(nil), t.TempDir(), newClock()))

	resp, err := healthpb.NewHealthClient(conn).Check(t.Context(), &healthpb.HealthCheckRequest{})

	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
}

// TestConformance runs the conformance suite of the SDK against the vulnerabilities collector, on a fake Grype with a database that it
// doesn't update.
func TestConformance(t *testing.T) {
	g := newGrype(&dbOne, fixed, critical)
	m := collectorOf(g, t.TempDir(), newClock())
	conn := serve(t, m)
	conformance.Run(t, conformance.Target{
		Dial:            func(context.Context) (*grpc.ClientConn, error) { return conn, nil },
		Settings:        json.RawMessage(`{"databaseUpdates": "Offline", "updateIntervalSeconds": 3600, "maxConcurrent": 3}`),
		InvalidSettings: json.RawMessage(`{"maxConcurrent": 9}`),
		Context:         collector.Context{Cluster: clusterName},
		Invocations: []conformance.Invocation{{
			Operation: matchName, Subject: subject.Manifest(digest), Inputs: []cloudevents.Event{sbomEvent(t, exampleSBOM())},
		}},
	})
}
