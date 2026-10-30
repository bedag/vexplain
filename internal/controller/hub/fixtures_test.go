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

package hub_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/tasks"
)

// The fixtures of the tests of the hub: the images, scans and databases that they are about, and
// the fakes of what the hub talks to. The unit tests and the envtest suite share them.

const (
	// scannerImage is the image of the scanner that the spokes run, and olderScanner the one that
	// they ran before.
	scannerImage = "scanner.example/vexplain-scanner:1.1"
	olderScanner = "scanner.example/vexplain-scanner:1.0"
	// repository is where the images of the tests come from, and mirror another repository that
	// serves the same digests.
	repository = "artifacts.example/team-a/app"
	mirror     = "mirror.example/team-a/app"
	// localCluster is the cluster of the hub, and otherCluster another one that reports to it.
	localCluster = "cluster-a"
	otherCluster = "cluster-b"

	// v1, v2 and v3 are versions of the matcher's database, from three daily builds.
	v1 = "v6.1.10+2026-10-29T06:23:28Z"
	v2 = "v6.1.10+2026-10-30T06:23:28Z"
	v3 = "v6.1.10+2026-10-31T06:23:28Z"

	// guardReason is the reason of a finding that the completeness guard keeps open, for evidence of
	// 75% at the default minimum of 90%.
	guardReason = "completeness 75% is below 90%"

	// linuxAMD64 is the platform of the evidence of the tests.
	linuxAMD64 = "linux/amd64"
	// examplePackage and otherPackage are the IDs of the packages of the two libraries of the
	// evidence, with their names and versions, and deb their type.
	examplePackage = "pkg-1"
	exampleName    = "libexample1"
	exampleVersion = "1.0-1"
	otherPackage   = "pkg-2"
	otherName      = "libother2"
	otherVersion   = "2.0-1"
	deb            = "deb"
	// exampleCVE and otherCVE are the vulnerabilities in the two libraries, and otherFix the version
	// of libother2 that fixes its vulnerability.
	exampleCVE = "CVE-2026-0001"
	otherCVE   = "CVE-2026-0002"
	otherFix   = "2.0-2"
)

// t0 is the time at which a test starts, as far as its clock and its scans say.
var t0 = time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)

// digestOf returns the n-th digest of a test.
func digestOf(n int) string {
	return fmt.Sprintf("sha256:%064x", n)
}

// requestFor returns the request under which the hub reconciles digest: the name of its object.
func requestFor(digest string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(digest)}}
}

// cluster returns the name of this cluster, for the metrics of the stores.
func cluster() string { return localCluster }

// newClient returns a fake client with the kinds of the operator, and the funcs, which can make its
// calls fail or have something happen meanwhile.
func newClient(t *testing.T, funcs interceptor.Funcs) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, configv1alpha1.AddToScheme(scheme))
	require.NoError(t, inventoryv1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&inventoryv1alpha1.ImageInventory{}, &inventoryv1alpha1.ImageVerdicts{},
			&configv1alpha1.OperatorConfig{}).
		WithInterceptorFuncs(funcs).
		Build()
}

// ---- presence and facts ----

// observe reports, as the spoke of cluster does, that digest runs there, pulled from repositories.
// A digest without a repository is an image ID.
func observe(t *testing.T, store inventory.Store, digest, cluster string, repositories ...string) {
	t.Helper()
	kind := inventoryv1alpha1.DigestKindImageID
	if len(repositories) > 0 {
		kind = inventoryv1alpha1.DigestKindRepoDigest
	}
	require.NoError(t, store.Observe(context.Background(), digest, inventory.Observation{
		Cluster: cluster, ClusterID: cluster + "-id", DigestKind: kind, Repositories: repositories, NamespaceCount: 1,
	}))
}

// forget reports, as the spoke of cluster does, that digest runs there no more.
func forget(t *testing.T, store inventory.Store, digest, cluster string) {
	t.Helper()
	require.NoError(t, store.Forget(context.Background(), digest, cluster, cluster+"-id"))
}

// setFacts writes the facts of digest, as the spoke does after a scan.
func setFacts(t *testing.T, store inventory.Store, digest string, facts *inventoryv1alpha1.ImageFacts) {
	t.Helper()
	found, err := store.SetFacts(context.Background(), digest, facts)
	require.NoError(t, err)
	require.True(t, found, "the digest has an object")
}

// platforms are the platforms of the manifests of a scan, in order.
var platforms = []string{linuxAMD64, "linux/arm64"}

// scannedBy returns the facts of a successful scan by scanner, an hour before t0, that found the
// platform manifests.
func scannedBy(scanner string, manifests ...string) *inventoryv1alpha1.ImageFacts {
	facts := &inventoryv1alpha1.ImageFacts{
		ScannerImage: ptr.To(scanner),
		ScannedTime:  ptr.To(metav1.NewTime(t0.Add(-time.Hour))),
	}
	for i, manifest := range manifests {
		facts.Platforms = append(facts.Platforms, inventoryv1alpha1.PlatformFacts{
			Platform:            platforms[i],
			ManifestDigest:      manifest,
			CompletenessPercent: ptr.To(int32(100)),
			ELFFiles:            ptr.To(int32(3)),
			Packages:            ptr.To(int32(3)),
		})
	}
	return facts
}

// failedAfter returns the facts of a digest whose scans have failed attempts times in a row, the
// last one at the time failed, since a success by scanner. An empty scanner means no success.
func failedAfter(scanner string, attempts int32, failed time.Time) *inventoryv1alpha1.ImageFacts {
	facts := &inventoryv1alpha1.ImageFacts{}
	if scanner != "" {
		facts = scannedBy(scanner, digestOf(900))
	}
	facts.Failure = &inventoryv1alpha1.ScanFailure{
		Reason:   inventoryv1alpha1.ScanFailureReasonPullFailed,
		Time:     ptr.To(metav1.NewTime(failed)),
		Attempts: attempts,
	}
	return facts
}

// factsOf reads the facts of digest, with their times in UTC, as the tests write them.
func factsOf(t *testing.T, store inventory.Store, digest string) *inventoryv1alpha1.ImageFacts {
	t.Helper()
	obj, err := store.Get(context.Background(), digest)
	require.NoError(t, err)
	require.NotNil(t, obj)
	facts := obj.Status.Facts.DeepCopy()
	if facts != nil && facts.Failure != nil && facts.Failure.Time != nil {
		facts.Failure.Time = ptr.To(metav1.NewTime(facts.Failure.Time.UTC()))
	}
	return facts
}

// ---- evidence, matches and findings ----

// sbomOf returns the SBOM of the evidence of manifest: Syft's JSON with three packages. Its source
// names the manifest, so that a matcher can tell the SBOMs of two manifests apart.
func sbomOf(manifest string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"artifacts":[`+
		`{"id":"pkg-1","name":"libexample1","version":"1.0-1","type":"deb"},`+
		`{"id":"pkg-2","name":"libother2","version":"2.0-1","type":"deb"},`+
		`{"id":"pkg-3","name":"app","version":"3.0","type":"deb"}],"source":{"id":%q}}`, manifest))
}

// evidenceOf returns what a scan found in the platform manifest. Packages own all three ELF files:
// libexample1 owns a shared library that nothing loads, libother2 one that the program /usr/bin/app
// loads, and app owns that program.
func evidenceOf(manifest string) result.Manifest {
	return result.Manifest{
		Platform: linuxAMD64,
		Digest:   manifest,
		SBOM:     sbomOf(manifest),
		Packages: []result.PackageFacts{
			{ID: examplePackage, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1},
			{ID: otherPackage, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1},
			{ID: "pkg-3", FilesListed: 1, FilesPresent: 1, OtherELFFiles: 1},
		},
		ELF: result.ELFSummary{Total: 3, Owned: 3},
		Libraries: []result.Library{
			{Path: "/usr/lib/libexample.so.1", Soname: "libexample.so.1", PackageID: examplePackage},
			{Path: "/usr/lib/libother.so.2", Soname: "libother.so.2", PackageID: otherPackage,
				ReachedBy: []string{"/usr/bin/app"}, ReachedCount: 1},
		},
	}
}

// incompleteEvidenceOf is evidenceOf with a fourth ELF file that no package owns: packages account
// for 75% of the image's ELF files.
func incompleteEvidenceOf(manifest string) result.Manifest {
	m := evidenceOf(manifest)
	m.ELF = result.ELFSummary{Total: 4, Owned: 3, Unowned: []string{"/opt/tool"}}
	return m
}

// The matches of the database for the evidence: a vulnerability in each library.
var (
	exampleMatch = matchapi.Match{
		VulnerabilityID: exampleCVE, PackageID: examplePackage, Severity: "High", FixState: "not-fixed",
		PackageName: exampleName, PackageVersion: exampleVersion, PackageType: deb,
	}
	otherMatch = matchapi.Match{
		VulnerabilityID: otherCVE, PackageID: otherPackage, Severity: "Critical", FixState: "fixed",
		FixedVersions: []string{otherFix}, PackageName: otherName, PackageVersion: otherVersion, PackageType: deb,
	}
)

// exploited returns m, known to be exploited.
func exploited(m matchapi.Match) matchapi.Match {
	m.KnownExploited = true
	return m
}

// The findings that the rules make of the matches, as the sheet holds them.
var (
	// exampleNotLoadable is exampleMatch's finding when the guard lets the rules settle it: nothing
	// loads the library, so the load check suppresses it.
	exampleNotLoadable = inventoryv1alpha1.Finding{
		VulnerabilityID: exampleCVE,
		Package:         inventoryv1alpha1.PackageReference{ID: examplePackage, Name: exampleName, Version: ptr.To(exampleVersion), Type: deb},
		Outcome:         inventoryv1alpha1.OutcomeSuppressed,
		Rule:            ptr.To(inventoryv1alpha1.RuleLoadCheck),
		Justification:   ptr.To(inventoryv1alpha1.JustificationVulnerableCodeNotInExecutePath),
		Conditions:      []inventoryv1alpha1.FindingCondition{inventoryv1alpha1.FindingConditionNoPreloadEnvironment},
		Severity:        inventoryv1alpha1.SeverityHigh,
		FixState:        inventoryv1alpha1.FixStateNotFixed,
	}
	// exampleExploited is exampleMatch's finding when the vulnerability is known to be exploited.
	exampleExploited = inventoryv1alpha1.Finding{
		VulnerabilityID: exampleCVE,
		Package:         inventoryv1alpha1.PackageReference{ID: examplePackage, Name: exampleName, Version: ptr.To(exampleVersion), Type: deb},
		Outcome:         inventoryv1alpha1.OutcomeTracked,
		Rule:            ptr.To(inventoryv1alpha1.RuleKnownExploited),
		Severity:        inventoryv1alpha1.SeverityHigh,
		FixState:        inventoryv1alpha1.FixStateNotFixed,
	}
	// exampleGuarded is exampleMatch's finding in evidence below the minimum completeness.
	exampleGuarded = inventoryv1alpha1.Finding{
		VulnerabilityID: exampleCVE,
		Package:         inventoryv1alpha1.PackageReference{ID: examplePackage, Name: exampleName, Version: ptr.To(exampleVersion), Type: deb},
		Outcome:         inventoryv1alpha1.OutcomeNeedsAssessment,
		Rule:            ptr.To(inventoryv1alpha1.RuleCompletenessGuard),
		Reason:          ptr.To(guardReason),
		Severity:        inventoryv1alpha1.SeverityHigh,
		FixState:        inventoryv1alpha1.FixStateNotFixed,
	}
	// otherReached is otherMatch's finding when the guard lets the rules look: the program loads the
	// library, so the finding waits for an assessment.
	otherReached = inventoryv1alpha1.Finding{
		VulnerabilityID: otherCVE,
		Package:         inventoryv1alpha1.PackageReference{ID: otherPackage, Name: otherName, Version: ptr.To(otherVersion), Type: deb},
		Outcome:         inventoryv1alpha1.OutcomeNeedsAssessment,
		Rule:            ptr.To(inventoryv1alpha1.RuleLoadCheck),
		Reason:          ptr.To("reached by /usr/bin/app"),
		Severity:        inventoryv1alpha1.SeverityCritical,
		FixState:        inventoryv1alpha1.FixStateFixed,
		FixedVersions:   []string{otherFix},
	}
	// otherGuarded is otherMatch's finding in evidence below the minimum completeness.
	otherGuarded = inventoryv1alpha1.Finding{
		VulnerabilityID: otherCVE,
		Package:         inventoryv1alpha1.PackageReference{ID: otherPackage, Name: otherName, Version: ptr.To(otherVersion), Type: deb},
		Outcome:         inventoryv1alpha1.OutcomeNeedsAssessment,
		Rule:            ptr.To(inventoryv1alpha1.RuleCompletenessGuard),
		Reason:          ptr.To(guardReason),
		Severity:        inventoryv1alpha1.SeverityCritical,
		FixState:        inventoryv1alpha1.FixStateFixed,
		FixedVersions:   []string{otherFix},
	}
)

// counted is how many findings of each outcome a sheet counts.
type counted struct {
	suppressed, tracked, needsAssessment int32
}

// sheet returns the status of a sheet that holds findings, in order, none left out, from the match
// of the database version against the evidence of scanner.
func sheet(version, scanner string, counts counted, findings ...inventoryv1alpha1.Finding) *inventoryv1alpha1.ImageVerdictsStatus {
	return &inventoryv1alpha1.ImageVerdictsStatus{
		DatabaseVersion: ptr.To(version),
		ScannerImage:    ptr.To(scanner),
		Findings:        findings,
		OmittedFindings: ptr.To(int32(0)),
		Counts: &inventoryv1alpha1.FindingCounts{
			Suppressed:      ptr.To(counts.suppressed),
			Tracked:         ptr.To(counts.tracked),
			NeedsAssessment: ptr.To(counts.needsAssessment),
		},
	}
}

// ---- fakes ----

// fakeMatcher is a matcher whose database gives the same matches for every SBOM. It records the
// SBOMs that it is asked to match.
type fakeMatcher struct {
	mu          sync.Mutex
	version     string
	matches     []matchapi.Match
	matchErr    error
	databaseErr error
	sboms       []json.RawMessage
}

// newFakeMatcher returns a matcher whose database is v1, and gives the matches.
func newFakeMatcher(matches ...matchapi.Match) *fakeMatcher {
	m := &fakeMatcher{}
	m.set(v1, matches...)
	return m
}

// set changes the database to one of version that gives the matches.
func (m *fakeMatcher) set(version string, matches ...matchapi.Match) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.version, m.matches = version, slices.Clone(matches)
}

// failMatches makes every match fail with err, until it is called with nil.
func (m *fakeMatcher) failMatches(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.matchErr = err
}

// failDatabase makes every read of the database fail with err, until it is called with nil.
func (m *fakeMatcher) failDatabase(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.databaseErr = err
}

// Match answers as the matcher's client does: with the version and the matches of the database, and
// a list of matches that is empty, never missing, when there are none.
func (m *fakeMatcher) Match(_ context.Context, sbom json.RawMessage) (matchapi.MatchResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sboms = append(m.sboms, slices.Clone(sbom))
	if m.matchErr != nil {
		return matchapi.MatchResponse{}, m.matchErr
	}
	return matchapi.MatchResponse{DatabaseVersion: m.version, Matches: append([]matchapi.Match{}, m.matches...)}, nil
}

func (m *fakeMatcher) Database(context.Context) (matchapi.Database, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.databaseErr != nil {
		return matchapi.Database{}, m.databaseErr
	}
	return matchapi.Database{Version: m.version, Built: t0}, nil
}

// matched returns the SBOMs that the matcher was asked to match, in order.
func (m *fakeMatcher) matched() []json.RawMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.sboms)
}

// recordingExecutor records the scans that the hub asks for, as a spoke would take them.
type recordingExecutor struct {
	mu       sync.Mutex
	requests []tasks.ScanRequest
	err      error
}

// RequestScan records req, or fails with the executor's error.
func (e *recordingExecutor) RequestScan(_ context.Context, req tasks.ScanRequest) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return e.err
	}
	e.requests = append(e.requests, tasks.ScanRequest{Digest: req.Digest, Repositories: slices.Clone(req.Repositories)})
	return nil
}

// taken returns the requests that the executor took, in order.
func (e *recordingExecutor) taken() []tasks.ScanRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.requests)
}
