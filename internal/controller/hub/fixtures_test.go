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
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
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
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// The fixtures of the tests of the hub: the images, scans and findings that they are about, and the
// fakes of what the hub talks to. The unit tests and the envtest suite share them.

const (
	// scannerVersion is the version of the scanner that the spokes run, which its Collector records,
	// and olderScanner the one that they ran before. Evidence is stored at its collector's version.
	scannerVersion = "0.2.0"
	olderScanner   = "0.1.0"
	// The Collectors that the default playbook names: scanner delivers the evidence of the images,
	// vulnerabilities collector their findings, and workloads their presence.
	scanner                  = "scanner"
	vulnerabilitiesCollector = "vulnerabilities"
	workloadsCollector       = "workloads"
	// playbookName is the default playbook, and contents the name under which it supplies the
	// scanner's evidence to its rules.
	playbookName = "container-cves"
	contents     = "contents"
	// The default rules.
	knownExploitedRule = "known-exploited"
	guardRule          = "completeness-guard"
	removedRule        = "removed-in-later-layer"
	loadCheckRule      = "load-check"
	// repository is where the images of the tests come from, and mirror another repository that
	// serves the same digests.
	repository = "artifacts.example/team-a/app"
	mirror     = "mirror.example/team-a/app"
	// localCluster is the cluster of the hub, and otherCluster another one that reports to it.
	localCluster = "cluster-a"
	otherCluster = "cluster-b"

	// v1, v2 and v3 are versions of the database of the findings collector, from three daily builds.
	v1 = "v6.1.10+2026-10-29T06:23:28Z"
	v2 = "v6.1.10+2026-10-30T06:23:28Z"
	v3 = "v6.1.10+2026-10-31T06:23:28Z"

	// guardReason is the reason of a finding that the completeness guard keeps open, for evidence of
	// 75% at the default minimum of 90%.
	guardReason = "completeness 75% is below 90%"
	// unreachedReason is the note on a finding in a library that nothing in the image reaches or names.
	unreachedReason = "nothing in the image reaches or names its libraries"

	// linuxAMD64 and linuxARM64 are platforms of the manifests of the tests.
	linuxAMD64 = "linux/amd64"
	linuxARM64 = "linux/arm64"
	// examplePackage, otherPackage and gonePackage are the IDs of the packages of three libraries of the
	// evidence, with their names and versions, and deb their type. A later layer removed the files of
	// the third.
	examplePackage = "pkg-1"
	exampleName    = "libexample1"
	exampleVersion = "1.0-1"
	otherPackage   = "pkg-2"
	otherName      = "libother2"
	otherVersion   = "2.0-1"
	gonePackage    = "pkg-4"
	goneName       = "libgone4"
	goneVersion    = "4.0-1"
	deb            = "deb"
	// exampleCVE, otherCVE and goneCVE are the vulnerabilities in the three libraries, and otherFix the
	// version of libother2 that fixes its vulnerability.
	exampleCVE = "CVE-2026-0001"
	otherCVE   = "CVE-2026-0002"
	goneCVE    = "CVE-2026-0004"
	otherFix   = "2.0-2"
	// critical is the severity of the most severe vulnerabilities, and fixedState the fix state of a
	// vulnerability that a version of the package fixes, as a source spells them.
	critical   = "Critical"
	fixedState = "fixed"
)

// t0 is the time at which a test starts, as far as its clock and its scans say.
var t0 = time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)

// digestOf returns the n-th digest of a test.
func digestOf(n int) string {
	return fmt.Sprintf("sha256:%064x", n)
}

// imageRequest returns the request under which the assessor asks for the evidence of the image of
// digest: the name of its ImageInventory.
func imageRequest(digest string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: inventory.NameForDigest(digest)}}
}

// manifestRequest returns the request under which the assessor assesses a platform manifest: its
// subject, as the evidence store names it.
func manifestRequest(manifest string) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: subjects.Manifest(manifest)}}
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
			&configv1alpha1.OperatorConfig{}, &configv1alpha1.Playbook{}, &configv1alpha1.Rule{},
			&configv1alpha1.Collector{}).
		WithInterceptorFuncs(funcs).
		Build()
}

// ---- presence and facts ----

// testingT is what the fixtures need of a test: a *testing.T, or GinkgoT() in a spec.
type testingT interface {
	require.TestingT
	Helper()
}

// observe reports, as the spoke of cluster does, that digest runs there, pulled from repositories.
// A digest without a repository is an image ID.
func observe(t testingT, store inventory.Store, digest, cluster string, repositories ...string) {
	t.Helper()
	observeOn(t, store, digest, cluster, nil, repositories...)
}

// observeOn is observe for a cluster whose pods run digest on the platforms.
func observeOn(t testingT, store inventory.Store, digest, cluster string, platforms []string, repositories ...string) {
	t.Helper()
	kind := inventoryv1alpha1.DigestKindImageID
	if len(repositories) > 0 {
		kind = inventoryv1alpha1.DigestKindRepoDigest
	}
	require.NoError(t, store.Observe(context.Background(), digest, inventory.Observation{
		Cluster: cluster, ClusterID: cluster + "-id", DigestKind: kind, Repositories: repositories,
		Platforms: platforms, NamespaceCount: 1,
	}))
}

// forget reports, as the spoke of cluster does, that digest runs there no more.
func forget(t testingT, store inventory.Store, digest, cluster string) {
	t.Helper()
	require.NoError(t, store.Forget(context.Background(), digest, cluster, cluster+"-id"))
}

// setFacts writes the facts of digest, as the spoke does after a scan.
func setFacts(t testingT, store inventory.Store, digest string, facts *inventoryv1alpha1.ImageFacts) {
	t.Helper()
	found, err := store.SetFacts(context.Background(), digest, facts)
	require.NoError(t, err)
	require.True(t, found, "the digest has an object")
}

// platforms are the platforms of the manifests of a scan, in order.
var platforms = []string{linuxAMD64, linuxARM64}

// scannedBy returns the facts of a successful scan by the scanner of the version, an hour before t0,
// that found the platform manifests.
func scannedBy(version string, manifests ...string) *inventoryv1alpha1.ImageFacts {
	facts := &inventoryv1alpha1.ImageFacts{Evidence: []inventoryv1alpha1.EvidenceFact{{
		Source:           scanner,
		Type:             imagecontents.Type,
		CollectorVersion: version,
		Time:             ptr.To(metav1.NewTime(t0.Add(-time.Hour))),
		Coverage:         ptr.To(int32(100)),
	}}}
	for i, manifest := range manifests {
		facts.Manifests = append(facts.Manifests, inventoryv1alpha1.ManifestFact{Platform: platforms[i], Digest: manifest})
	}
	return facts
}

// failedAfter returns the facts of a digest whose scans have failed attempts times in a row, the
// last one at the time failed, since a success by the scanner of the version. An empty version means
// no success.
func failedAfter(version string, attempts int32, failed time.Time) *inventoryv1alpha1.ImageFacts {
	facts := &inventoryv1alpha1.ImageFacts{}
	if version != "" {
		facts = scannedBy(version, digestOf(900))
	}
	facts.Failures = []inventoryv1alpha1.ScanFailure{{
		Source:   scanner,
		Reason:   inventoryv1alpha1.ScanFailureReasonPullFailed,
		Time:     ptr.To(metav1.NewTime(failed)),
		Attempts: attempts,
	}}
	return facts
}

// factsOf reads the facts of digest.
func factsOf(t testingT, store inventory.Store, digest string) *inventoryv1alpha1.ImageFacts {
	t.Helper()
	obj, err := store.Get(context.Background(), digest)
	require.NoError(t, err)
	require.NotNil(t, obj)
	return obj.Status.Facts.DeepCopy()
}

// ---- evidence, matches and findings ----

// scanEventOf returns the scanner's evidence about m, from a scan that finished at the time scanned, as
// a spoke stores it.
func scanEventOf(scanned time.Time, m imagecontents.Manifest) cloudevents.Event {
	e, err := sdkevidence.New(imagecontents.Type, subjects.Manifest(m.Digest), m,
		sdkevidence.WithPlatform(m.Platform), sdkevidence.WithCoverage(m.Completeness()),
		sdkevidence.WithTime(scanned), sdkevidence.WithSource("/clusters/cluster-a/collectors/scanner"))
	if err != nil {
		panic(err)
	}
	return e
}

// putScan stores what a scan by the scanner of the version, which finished at the time scanned, found
// in m.
func putScan(t *testing.T, store evidence.Store, version string, scanned time.Time, m imagecontents.Manifest) {
	t.Helper()
	require.NoError(t, store.Put(t.Context(), scanner, version, scanEventOf(scanned, m)))
}

// sheetEvidenceOf returns what a sheet records of the scanner's evidence that record holds.
func sheetEvidenceOf(record *evidence.Record) inventoryv1alpha1.SheetEvidence {
	coverage, _ := sdkevidence.Coverage(record.Event)
	return inventoryv1alpha1.SheetEvidence{
		Name: contents, Source: scanner, Type: imagecontents.Type,
		Version: ptr.To(record.CollectorVersion),
		// The API keeps a time in the local zone of whoever reads it, as metav1.Time decodes it.
		Time:     ptr.To(metav1.NewTime(record.Event.Time().Truncate(time.Second).Local())),
		Coverage: ptr.To(coverage),
	}
}

// missingEvidence is what a sheet records of the scanner's evidence when the rules couldn't have it.
var missingEvidence = inventoryv1alpha1.SheetEvidence{Name: contents, Source: scanner, Type: imagecontents.Type}

// sbomOf returns the SBOM of the evidence of manifest: Syft's JSON with four packages. Its source
// names the manifest, so that two SBOMs of two manifests differ.
func sbomOf(manifest string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"artifacts":[`+
		`{"id":"pkg-1","name":"libexample1","version":"1.0-1","type":"deb"},`+
		`{"id":"pkg-2","name":"libother2","version":"2.0-1","type":"deb"},`+
		`{"id":"pkg-3","name":"app","version":"3.0","type":"deb"},`+
		`{"id":"pkg-4","name":"libgone4","version":"4.0-1","type":"deb"}],"source":{"id":%q}}`, manifest))
}

// evidenceOf returns what a scan found in the platform manifest. Packages own all three ELF files:
// libexample1 owns a shared library that nothing reaches or names, libother2 one that the program
// /usr/bin/app reaches, and app owns that program. libgone4 lists two files, which a later layer
// removed, so none is left.
func evidenceOf(manifest string) imagecontents.Manifest {
	return imagecontents.Manifest{
		Platform: linuxAMD64,
		Digest:   manifest,
		SBOM:     sbomOf(manifest),
		Packages: []imagecontents.PackageFacts{
			{ID: examplePackage, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1},
			{ID: otherPackage, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1},
			{ID: "pkg-3", FilesListed: 1, FilesPresent: 1, OtherELFFiles: 1},
			{ID: gonePackage, FilesListed: 2},
		},
		ELF: imagecontents.ELFSummary{Total: 3, Owned: 3},
		Libraries: []imagecontents.Library{
			{Path: "/usr/lib/libexample.so.1", Soname: "libexample.so.1", PackageID: examplePackage},
			{Path: "/usr/lib/libother.so.2", Soname: "libother.so.2", PackageID: otherPackage,
				ReachedBy: []string{"/usr/bin/app"}, ReachedCount: 1},
		},
	}
}

// incompleteEvidenceOf is evidenceOf with a fourth ELF file that no package owns: packages account
// for 75% of the image's ELF files.
func incompleteEvidenceOf(manifest string) imagecontents.Manifest {
	m := evidenceOf(manifest)
	m.ELF = imagecontents.ELFSummary{Total: 4, Owned: 3, Unowned: []string{"/opt/tool"}}
	return m
}

// The matches of the database for the evidence: a vulnerability in each library.
var (
	exampleMatch = sdkevidence.Match{
		VulnerabilityID: exampleCVE, PackageID: examplePackage, Severity: "High", FixState: "not-fixed",
		PackageName: exampleName, PackageVersion: exampleVersion, PackageType: deb,
	}
	otherMatch = sdkevidence.Match{
		VulnerabilityID: otherCVE, PackageID: otherPackage, Severity: critical, FixState: fixedState,
		FixedVersions: []string{otherFix}, PackageName: otherName, PackageVersion: otherVersion, PackageType: deb,
	}
	goneMatch = sdkevidence.Match{
		VulnerabilityID: goneCVE, PackageID: gonePackage, Severity: "Medium", FixState: "not-fixed",
		PackageName: goneName, PackageVersion: goneVersion, PackageType: deb,
	}
)

// exploited returns m, known to be exploited.
func exploited(m sdkevidence.Match) sdkevidence.Match {
	m.KnownExploited = true
	return m
}

// The packages of the findings.
var (
	examplePackageRef = inventoryv1alpha1.PackageReference{ID: examplePackage, Name: exampleName, Version: ptr.To(exampleVersion), Type: deb}
	otherPackageRef   = inventoryv1alpha1.PackageReference{ID: otherPackage, Name: otherName, Version: ptr.To(otherVersion), Type: deb}
	gonePackageRef    = inventoryv1alpha1.PackageReference{ID: gonePackage, Name: goneName, Version: ptr.To(goneVersion), Type: deb}
)

// notes returns the status notes of the load check with the text.
func notes(text string) []inventoryv1alpha1.StatusNote {
	return []inventoryv1alpha1.StatusNote{{Rule: loadCheckRule, Text: text}}
}

// The findings that the default rules make of the matches, as the sheet holds them.
var (
	// exampleUnreached is exampleMatch's finding when the guard lets the rules look. No rule settles it,
	// and the load check notes that nothing in the image reaches or names the library.
	exampleUnreached = inventoryv1alpha1.Finding{
		VulnerabilityID: exampleCVE,
		Package:         examplePackageRef,
		Status:          inventoryv1alpha1.VEXStatusUnderInvestigation,
		StatusNotes:     notes(unreachedReason),
		Severity:        inventoryv1alpha1.SeverityHigh,
		FixState:        inventoryv1alpha1.FixStateNotFixed,
		KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
	}
	// exampleExploited is exampleMatch's finding when the vulnerability is known to be exploited: the
	// rule known-exploited holds it open.
	exampleExploited = inventoryv1alpha1.Finding{
		VulnerabilityID: exampleCVE,
		Package:         examplePackageRef,
		Status:          inventoryv1alpha1.VEXStatusUnderInvestigation,
		Rule:            ptr.To(knownExploitedRule),
		Reason:          ptr.To("known exploited"),
		StatusNotes:     notes(unreachedReason),
		Severity:        inventoryv1alpha1.SeverityHigh,
		FixState:        inventoryv1alpha1.FixStateNotFixed,
		KnownExploited:  inventoryv1alpha1.KnownExploitedListed,
	}
	// exampleGuarded is exampleMatch's finding in evidence below the minimum completeness.
	exampleGuarded = inventoryv1alpha1.Finding{
		VulnerabilityID: exampleCVE,
		Package:         examplePackageRef,
		Status:          inventoryv1alpha1.VEXStatusUnderInvestigation,
		Rule:            ptr.To(guardRule),
		Reason:          ptr.To(guardReason),
		StatusNotes:     notes(unreachedReason),
		Severity:        inventoryv1alpha1.SeverityHigh,
		FixState:        inventoryv1alpha1.FixStateNotFixed,
		KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
	}
	// otherReached is otherMatch's finding when the guard lets the rules look. No rule settles it, and
	// the load check notes that the program reaches the library.
	otherReached = inventoryv1alpha1.Finding{
		VulnerabilityID: otherCVE,
		Package:         otherPackageRef,
		Status:          inventoryv1alpha1.VEXStatusUnderInvestigation,
		StatusNotes:     notes("reached by /usr/bin/app"),
		Severity:        inventoryv1alpha1.SeverityCritical,
		FixState:        inventoryv1alpha1.FixStateFixed,
		FixedVersions:   []string{otherFix},
		KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
	}
	// otherGuarded is otherMatch's finding in evidence below the minimum completeness.
	otherGuarded = inventoryv1alpha1.Finding{
		VulnerabilityID: otherCVE,
		Package:         otherPackageRef,
		Status:          inventoryv1alpha1.VEXStatusUnderInvestigation,
		Rule:            ptr.To(guardRule),
		Reason:          ptr.To(guardReason),
		StatusNotes:     notes("reached by /usr/bin/app"),
		Severity:        inventoryv1alpha1.SeverityCritical,
		FixState:        inventoryv1alpha1.FixStateFixed,
		FixedVersions:   []string{otherFix},
		KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
	}
	// goneSettled is goneMatch's finding when the guard lets the rules look: a later layer removed the
	// files of the package, which settles it as not affected.
	goneSettled = inventoryv1alpha1.Finding{
		VulnerabilityID: goneCVE,
		Package:         gonePackageRef,
		Status:          inventoryv1alpha1.VEXStatusNotAffected,
		Rule:            ptr.To(removedRule),
		Justification:   ptr.To(inventoryv1alpha1.VEXJustificationComponentNotPresent),
		Severity:        inventoryv1alpha1.SeverityMedium,
		FixState:        inventoryv1alpha1.FixStateNotFixed,
		KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
	}
	// goneGuarded is goneMatch's finding in evidence below the minimum completeness: the guard holds it
	// open against the rule that would settle it.
	goneGuarded = inventoryv1alpha1.Finding{
		VulnerabilityID: goneCVE,
		Package:         gonePackageRef,
		Status:          inventoryv1alpha1.VEXStatusUnderInvestigation,
		Rule:            ptr.To(guardRule),
		Reason:          ptr.To(guardReason),
		Severity:        inventoryv1alpha1.SeverityMedium,
		FixState:        inventoryv1alpha1.FixStateNotFixed,
		KnownExploited:  inventoryv1alpha1.KnownExploitedNotListed,
	}
)

// counted is how many findings of each status a sheet counts, and of the open ones how many are fixable and how
// many a rule holds, which its summary counts.
type counted struct {
	affected, underInvestigation, notAffected, fixed int32
	fixable, held                                    int32
}

// sheet returns the status of a sheet of the default playbook that holds findings, in order, none left
// out, from a match of the findings version, which rested on the evidence.
func sheet(version string, rested inventoryv1alpha1.SheetEvidence, counts counted, findings ...inventoryv1alpha1.Finding) *inventoryv1alpha1.ImageVerdictsStatus {
	return &inventoryv1alpha1.ImageVerdictsStatus{
		Playbook:        ptr.To(playbookName),
		FindingsVersion: ptr.To(version),
		Evidence:        []inventoryv1alpha1.SheetEvidence{rested},
		Findings:        findings,
		OmittedFindings: ptr.To(int32(0)),
		Counts: &inventoryv1alpha1.FindingCounts{
			Affected:           ptr.To(counts.affected),
			UnderInvestigation: ptr.To(counts.underInvestigation),
			NotAffected:        ptr.To(counts.notAffected),
			Fixed:              ptr.To(counts.fixed),
		},
		Summary: &inventoryv1alpha1.SheetSummary{
			Open:    ptr.To(counts.affected + counts.underInvestigation),
			Fixable: ptr.To(counts.fixable),
			Held:    ptr.To(counts.held),
			Settled: ptr.To(counts.notAffected + counts.fixed),
			Omitted: ptr.To(int32(0)),
		},
	}
}
