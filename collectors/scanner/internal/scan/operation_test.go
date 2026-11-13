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

package scan_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/yaml"

	"github.com/bedag/vexplain/collectors/scanner/internal/analyze"
	"github.com/bedag/vexplain/collectors/scanner/internal/result"
	"github.com/bedag/vexplain/collectors/scanner/internal/scan"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/conformance"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/jobs"
	"github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// These tests run the scanner's operation with a fake Job runner, which answers each scan as the scan Job's pod would
// have, and with pods and nodes in a fake client. The SDK's Job runner, which runs the real Jobs, has its own tests.

const (
	// wait bounds how long a test waits for what must happen, and quiet how long it watches for what must not.
	wait  = 10 * time.Second
	quiet = 300 * time.Millisecond
	// The collector: its name, version and image, and its namespace.
	collectorName = "scanner"
	version       = "0.2.0"
	ownImage      = "artifacts.example/vexplain/scanner:0.2.0"
	ownNamespace  = "vexplain-system"
	ownPodLabel   = "vexplain.bedag.ch/task"
	clusterName   = "cluster-a"
	teamNamespace = "team-a"
	repository    = "artifacts.example/team-a/app"
	mirror        = "mirror.example/team-a/app"
	amd64Node     = "node-amd64"
	arm64Node     = "node-arm64"
	linuxAMD64    = "linux/amd64"
	linuxARM64    = "linux/arm64"
	linuxARM64v8  = "linux/arm64/v8"
	unauthorized  = "Unauthorized"
	scanOperation = "scan"
	// scannerLabel names the scanner Collector whose scan a Job is.
	scannerLabel   = "vexplain.bedag.ch/scanner"
	tooLargeReason = "TooLarge"
	internalReason = "Internal"
	// examplePackage is the ID of the package that the scan finds in each manifest.
	examplePackage = "pkg-1"
)

var (
	// digest is the image that the tests scan, an index whose manifests are amd64Manifest and arm64Manifest.
	digest        = "sha256:" + strings.Repeat("a", 64)
	amd64Manifest = "sha256:" + strings.Repeat("1", 64)
	arm64Manifest = "sha256:" + strings.Repeat("2", 64)
	// ended is when the scans of the tests end, on the clock of the scanner.
	ended = time.Date(2026, time.October, 31, 9, 30, 0, 0, time.UTC)
	// dockerConfig is the config.json of the login that the fake credentials find in the pod's pull secret.
	dockerConfig = []byte(`{"auths":{"artifacts.example":{"username":"team-a-puller","password":"pull-secret-password"}}}`)
)

// adminConfig is the config.json of the login that the fake credentials find in the Secret of the name that the admin
// provides.
func adminConfig(name string) []byte {
	return []byte(`{"auths":{"artifacts.example":{"username":"` + name + `","password":"admin-secret-password"}}}`)
}

func TestMain(m *testing.M) {
	// The SDK's server logs through slog. Its lines would only crowd the output of a test that fails.
	slog.SetDefault(slog.New(slog.DiscardHandler))
	os.Exit(m.Run())
}

// ---- the fakes ----

// fakeRunner runs no Job: each Run answers as the pod of the Job of its Spec would have, through answer. A Run waits
// for hold, when it is set, and counts as an active Job with the Spec's labels meanwhile. A test adds the Jobs of other
// processes with run.
type fakeRunner struct {
	answer func(s jobs.Spec) (jobs.Result, error)
	hold   chan struct{}

	mu sync.Mutex
	// specs are the Specs of the Runs so far, jobs the labels of the Jobs that run, and selectors what Active was
	// asked to count.
	specs     []jobs.Spec
	jobs      []*map[string]string
	selectors []map[string]string
	started   chan jobs.Spec
}

func newRunner(answer func(s jobs.Spec) (jobs.Result, error)) *fakeRunner {
	return &fakeRunner{answer: answer, started: make(chan jobs.Spec, 16)}
}

// run adds a Job with the labels, as another process runs it, and returns the function that ends it.
func (r *fakeRunner) run(labels map[string]string) func() {
	r.mu.Lock()
	defer r.mu.Unlock()
	job := &labels
	r.jobs = append(r.jobs, job)
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.jobs = slices.DeleteFunc(r.jobs, func(j *map[string]string) bool { return j == job })
	}
}

func (r *fakeRunner) Run(ctx context.Context, s jobs.Spec) (jobs.Result, error) {
	r.mu.Lock()
	r.specs = append(r.specs, s)
	r.mu.Unlock()
	end := r.run(s.Labels)
	defer end()
	r.started <- s
	if r.hold != nil {
		select {
		case <-r.hold:
		case <-ctx.Done():
			return jobs.Result{}, ctx.Err()
		}
	}
	return r.answer(s)
}

// Active counts the Jobs that run with every label of the selector, as the API server's label selector does.
func (r *fakeRunner) Active(_ context.Context, selector map[string]string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.selectors = append(r.selectors, maps.Clone(selector))
	count := 0
	for _, job := range r.jobs {
		matches := true
		for key, value := range selector {
			if (*job)[key] != value {
				matches = false
			}
		}
		if matches {
			count++
		}
	}
	return count, nil
}

// ran returns the Specs of the Runs so far.
func (r *fakeRunner) ran() []jobs.Spec {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.specs)
}

// argsOf returns the values of a flag of a scan's arguments.
func argsOf(s jobs.Spec, flag string) []string {
	var values []string
	for i := 0; i+1 < len(s.Args); i++ {
		if s.Args[i] == flag {
			values = append(values, s.Args[i+1])
		}
	}
	return values
}

// manifestOf is what a scan found in the manifest of the platform: its contents and its SBOM.
func manifestOf(platform, manifest string) result.Scanned {
	return result.Scanned{
		Manifest: result.Manifest{
			Platform: platform,
			Digest:   manifest,
			Packages: []result.PackageFacts{{ID: examplePackage, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1}},
			ELF:      result.ELFSummary{Total: 4, Owned: 3, Unowned: []string{"/opt/tool"}},
			Libraries: []result.Library{
				{Path: "/usr/lib/libexample.so.1", Soname: "libexample.so.1", PackageID: examplePackage},
			},
		},
		SBOM: evidence.SBOM{
			Distro: &evidence.Distro{ID: "debian", Version: "12", Codename: "bookworm"},
			Packages: []evidence.SBOMPackage{{
				ID: examplePackage, Name: "libexample1", Version: "1.0-1", Type: "deb",
				PURL: "pkg:deb/debian/libexample1@1.0-1?arch=amd64&distro=debian-12&upstream=example",
				CPEs: []string{"cpe:2.3:a:libexample1:libexample1:1.0-1:*:*:*:*:*:*:*"},
			}},
			Producer: evidence.Producer{Name: "syft", Version: "1.55.0"},
		},
	}
}

// compressedSize is the size of data as vexplain's evidence store holds it: gzip at its best compression.
func compressedSize(t *testing.T, data []byte) int {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	require.NoError(t, err)
	_, err = zw.Write(data)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Len()
}

// maxStoredBytes is the most of an event's data that vexplain's evidence store holds once compressed.
const maxStoredBytes = 786432

// scanned answers a scan as the scanner does for the index: a manifest for each platform that the scan asks for, of
// amd64 and arm64, the latter of the variant v8.
func scanned(s jobs.Spec) (jobs.Result, error) {
	r := result.Result{Image: argsOf(s, "--image")[0]}
	for _, platform := range argsOf(s, "--platform") {
		switch platform {
		case linuxAMD64:
			r.Manifests = append(r.Manifests, manifestOf(linuxAMD64, amd64Manifest))
		case linuxARM64:
			r.Manifests = append(r.Manifests, manifestOf(linuxARM64v8, arm64Manifest))
		}
	}
	line, err := result.Encode(r)
	return jobs.Result{Line: line}, err
}

// failedFor answers every scan with a failure for the reason.
func failedFor(reason string) func(jobs.Spec) (jobs.Result, error) {
	return func(jobs.Spec) (jobs.Result, error) { return jobs.Result{FailureReason: reason}, nil }
}

// fakeCredentials finds the same logins for every pod: that of the pod's pull secret regcred, then that of each Secret
// that the admin provides. It records the pod and repository of each call.
type fakeCredentials struct {
	mu    sync.Mutex
	calls []string
}

func (c *fakeCredentials) Credentials(_ context.Context, pod *corev1.Pod, repository string,
	admin []string) (scan.Credentials, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, pod.Namespace+"/"+pod.Name+" "+repository)
	logins := make([]scan.Login, 0, 1+len(admin))
	logins = append(logins, scan.Login{Secret: pod.Namespace + "/regcred", Config: dockerConfig})
	for _, name := range admin {
		logins = append(logins, scan.Login{Secret: ownNamespace + "/" + name, Config: adminConfig(name)})
	}
	return scan.Credentials{Logins: logins}, nil
}

// ---- the cluster ----

// node returns a node whose labels say its platform.
func node(name, arch string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
		corev1.LabelOSStable: "linux", corev1.LabelArchStable: arch,
	}}}
}

// appName names the container of a running pod, and its service account in the tests of pull secrets.
const appName = "app"

// runningPod returns a pod on the node whose container reports the digest of the image, pulled from repository. An
// empty digest is a pod whose container hasn't started.
func runningPod(name, nodeName, repository, digest string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: teamNamespace, Name: name},
		Spec: corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{
			{Name: appName, Image: repository + ":1.0"},
		}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if digest != "" {
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: appName, Image: repository + ":1.0", ImageID: repository + "@" + digest,
		}}
	}
	return pod
}

// fixture is a scanner over a fake cluster, a fake Job runner and fake credentials.
type fixture struct {
	scanner     *scan.Scanner
	client      client.Client
	runner      *fakeRunner
	credentials *fakeCredentials
}

// newFixture returns a scanner whose cluster holds the objects: by default those of defaultCluster.
func newFixture(t *testing.T, runner *fakeRunner, objs ...client.Object) *fixture {
	t.Helper()
	if objs == nil {
		objs = defaultCluster()
	}
	return newFixtureNamed(t, collectorName, runner, fake.NewClientBuilder().WithObjects(objs...).Build())
}

// defaultCluster holds the amd64 and arm64 nodes, and a pod on each that runs the digest.
func defaultCluster() []client.Object {
	return []client.Object{
		node(amd64Node, "amd64"), node(arm64Node, "arm64"),
		runningPod("app-0", amd64Node, repository, digest), runningPod("app-1", arm64Node, repository, digest),
	}
}

// newFixtureNamed returns a scanner whose Collector has the name, over the cluster of c.
func newFixtureNamed(t *testing.T, name string, runner *fakeRunner, c client.Client) *fixture {
	t.Helper()
	return newFixtureFinding(t, name, runner, c, func(context.Context) (string, error) { return ownImage, nil })
}

// newFixtureFinding returns a scanner whose Collector has the name, over the cluster of c, which finds its own image
// through image.
func newFixtureFinding(t *testing.T, name string, runner *fakeRunner, c client.Client,
	image func(context.Context) (string, error)) *fixture {
	t.Helper()
	credentials := &fakeCredentials{}
	return &fixture{
		scanner: scan.New(scan.Options{
			Name:        name,
			Version:     version,
			Image:       image,
			Namespace:   ownNamespace,
			Client:      c,
			Credentials: credentials,
			Runner:      runner,
			SlotWait:    20 * time.Millisecond,
			Now:         func() time.Time { return ended },
		}),
		client:      c,
		runner:      runner,
		credentials: credentials,
	}
}

// credentialsBuilt returns how often the scanner built pull credentials.
func (f *fixture) credentialsBuilt() int {
	f.credentials.mu.Lock()
	defer f.credentials.mu.Unlock()
	return len(f.credentials.calls)
}

// parameters are the parameters of a scan: the repositories of the request, and the pods by namespace and name.
func parameters(repositories []string, pods ...string) json.RawMessage {
	type podRef struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}
	params := struct {
		Repositories []string `json:"repositories"`
		Pods         []podRef `json:"pods"`
	}{Repositories: repositories, Pods: []podRef{}}
	for _, pod := range pods {
		params.Pods = append(params.Pods, podRef{Namespace: teamNamespace, Name: pod})
	}
	raw, err := json.Marshal(params)
	if err != nil {
		panic(err)
	}
	return raw
}

// request is a scan of the digest, from the repository, with both pods, and the settings.
func request(settings string) collector.InvokeRequest {
	if settings == "" {
		settings = "{}"
	}
	return collector.InvokeRequest{
		Operation:  scanOperation,
		Subject:    subject.Image(digest),
		Parameters: parameters([]string{repository}, "app-0", "app-1"),
		Settings:   json.RawMessage(settings),
		Context: collector.Context{
			Cluster: clusterName, OperatorNamespace: ownNamespace, OwnPodLabel: ownPodLabel,
			Scope: json.RawMessage(`{}`), OwnerAttribution: json.RawMessage(`{}`),
		},
		Role: collector.RoleSpoke,
	}
}

// ---- the tests ----

// A scan gives two events about each manifest: its SBOM, which the vulnerabilities collector matches, and the
// scanner's own image contents, which the rules read. Both carry the platform, the time the scan ended and the
// coverage, which is the share of the manifest's ELF files that packages own, and each fits a record of vexplain's
// evidence store.
func TestScanGivesTheSBOMAndTheImageContentsOfEachManifest(t *testing.T) {
	f := newFixture(t, newRunner(scanned))

	events, failure, err := f.scanner.Invoke(t.Context(), request(""))

	require.NoError(t, err)
	require.Nil(t, failure)
	require.Len(t, events, 4, "two events about each of the two manifests")
	for i, want := range []result.Scanned{manifestOf(linuxAMD64, amd64Manifest), manifestOf(linuxARM64v8, arm64Manifest)} {
		for j, of := range []struct {
			eventType string
			data      any
		}{{evidence.TypeSBOM, want.SBOM}, {result.EvidenceType, want.Manifest}} {
			e := events[2*i+j]
			require.NoError(t, evidence.Validate(e))
			require.Equal(t, of.eventType, e.Type())
			require.Equal(t, subject.Manifest(want.Digest), e.Subject())
			require.Equal(t, "/clusters/"+clusterName+"/collectors/"+collectorName, e.Source())
			require.Equal(t, "urn:vexplain:schema:"+of.eventType, e.DataSchema())
			require.True(t, e.Time().Equal(ended), "the time the scan ended")
			platform, _ := evidence.Platform(e)
			require.Equal(t, want.Platform, platform)
			coverage, ok := evidence.Coverage(e)
			require.True(t, ok)
			require.Equal(t, int32(75), coverage, "the share of the ELF files that packages own")
			raw, err := json.Marshal(of.data)
			require.NoError(t, err)
			require.JSONEq(t, string(raw), string(e.Data()), "the data, unchanged")
			require.LessOrEqual(t, compressedSize(t, e.Data()), maxStoredBytes)
		}
	}
	require.NotContains(t, string(events[1].Data()), `"sbom"`, "the image contents hold no SBOM")
}

// The evidence of the analysis' fixtures fits a record of vexplain's evidence store: the SBOM, which carries Syft's
// JSON as its document, and the image contents. Each root's manifest is scanned for both platforms, so each event is
// measured as the scanner sends it.
func TestTheEvidenceOfTheFixturesFitsTheStore(t *testing.T) {
	for _, root := range []string{"apk", "dpkg", "rpm"} {
		t.Run(root, func(t *testing.T) {
			syftJSON, err := os.ReadFile(filepath.Join("..", "analyze", "testdata", "syft-"+root+".json"))
			require.NoError(t, err)
			found, err := analyze.Analyze(t.TempDir(), syftJSON, analyze.ImageConfig{})
			require.NoError(t, err)
			f := newFixture(t, newRunner(func(s jobs.Spec) (jobs.Result, error) {
				r := result.Result{Image: argsOf(s, "--image")[0]}
				for platform, digest := range map[string]string{linuxAMD64: amd64Manifest, linuxARM64v8: arm64Manifest} {
					m := found
					m.Platform, m.Digest = platform, digest
					r.Manifests = append(r.Manifests, m)
				}
				line, err := result.Encode(r)
				return jobs.Result{Line: line}, err
			}))

			events, failure, err := f.scanner.Invoke(t.Context(), request(""))

			require.NoError(t, err)
			require.Nil(t, failure)
			require.Len(t, events, 4)
			for _, e := range events[:2] {
				size := compressedSize(t, e.Data())
				t.Logf("%s: %s is %d bytes, %d compressed, of %d", root, e.Type(), len(e.Data()), size, maxStoredBytes)
				require.LessOrEqual(t, size, maxStoredBytes)
			}
			var sbom evidence.SBOM
			require.NoError(t, json.Unmarshal(events[0].Data(), &sbom))
			require.NotNil(t, sbom.Document, "the SBOM carries Syft's JSON")
		})
	}
}

// Review Focus 4: evidence that the evidence store can't hold fails the scan as TooLarge, and none of it is emitted,
// so that no verdict comes from part of the image. Each event of a manifest is held to the cap on its own. The
// failure names the type of the evidence, its size compressed, and the cap, so that a run shows how far it is over.
func TestScanFailsAsTooLargeWhenEitherEventCompressesAboveTheCap(t *testing.T) {
	// Random bytes don't compress, so 1 MiB of them is more than a record of the evidence store holds compressed.
	random := make([]byte, 1<<20)
	_, err := rand.Read(random)
	require.NoError(t, err)
	noise := base64.StdEncoding.EncodeToString(random)
	over := regexp.MustCompile(`^the evidence (\S+) of a manifest compresses to (\d+) bytes, more than the (\d+) ` +
		`that vexplain's evidence store holds$`)
	for name, tc := range map[string]struct {
		eventType string
		enlarge   func(s *result.Scanned)
	}{
		"the SBOM": {evidence.TypeSBOM, func(s *result.Scanned) {
			s.SBOM.Packages = append(s.SBOM.Packages, evidence.SBOMPackage{ID: "pkg-noise", Name: noise, Type: "deb"})
		}},
		"the image contents": {result.EvidenceType, func(s *result.Scanned) {
			s.Libraries = append(s.Libraries, result.Library{Path: "/usr/lib/" + noise, Soname: "libnoise.so.1"})
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, newRunner(func(s jobs.Spec) (jobs.Result, error) {
				small, large := manifestOf(linuxAMD64, amd64Manifest), manifestOf(linuxARM64v8, arm64Manifest)
				tc.enlarge(&large)
				line, err := result.Encode(result.Result{Image: argsOf(s, "--image")[0], Manifests: []result.Scanned{small, large}})
				return jobs.Result{Line: line}, err
			}))

			events, failure, err := f.scanner.Invoke(t.Context(), request(""))

			require.NoError(t, err)
			require.Empty(t, events, "not even the evidence that fits")
			require.NotNil(t, failure)
			require.Equal(t, tooLargeReason, failure.Reason)
			named := over.FindStringSubmatch(failure.Message)
			require.NotNil(t, named, "the failure names the evidence, its size and the cap: %q", failure.Message)
			require.Equal(t, tc.eventType, named[1])
			size, err := strconv.Atoi(named[2])
			require.NoError(t, err)
			require.Greater(t, size, maxStoredBytes)
			require.Equal(t, strconv.Itoa(maxStoredBytes), named[3])
		})
	}
}

// A cataloger of Syft that failed may have left packages out of a manifest's SBOM. So both events of the manifest
// have the coverage 0, and its SBOM names the cataloger: the completeness guard then holds every finding of the
// manifest. The other manifest keeps its coverage.
func TestAFailedCatalogerGivesBothEventsOfItsManifestTheCoverageZero(t *testing.T) {
	f := newFixture(t, newRunner(func(s jobs.Spec) (jobs.Result, error) {
		failed := manifestOf(linuxAMD64, amd64Manifest)
		failed.SBOM.FailedCatalogers = []string{"java-archive-cataloger"}
		line, err := result.Encode(result.Result{Image: argsOf(s, "--image")[0],
			Manifests: []result.Scanned{failed, manifestOf(linuxARM64v8, arm64Manifest)}})
		return jobs.Result{Line: line}, err
	}))

	events, failure, err := f.scanner.Invoke(t.Context(), request(""))

	require.NoError(t, err)
	require.Nil(t, failure)
	require.Len(t, events, 4)
	for i, want := range []int32{0, 0, 75, 75} {
		coverage, ok := evidence.Coverage(events[i])
		require.True(t, ok)
		require.Equal(t, want, coverage, "event %d, of the type %s about %s", i, events[i].Type(), events[i].Subject())
	}
	var sbom evidence.SBOM
	require.NoError(t, json.Unmarshal(events[0].Data(), &sbom))
	require.Equal(t, []string{"java-archive-cataloger"}, sbom.FailedCatalogers)
}

// A registry that refuses every login, or wants one where there is none, fails the scan with Unauthorized, as the
// scan's error line says. The failure names the registry that the scan pulled from, and the Secret of each login that
// it tried, in that order (decision 0047), and nothing of their content.
func TestScanGivesUnauthorizedWhenTheRegistryRefusesThePull(t *testing.T) {
	for name, tc := range map[string]struct {
		settings, message string
	}{
		"the workload's and the admin's logins": {`{"adminPullSecrets": ["admin-a", "admin-b"]}`,
			"registry artifacts.example: no credentials worked; tried: team-a/regcred, vexplain-system/admin-a, " +
				"vexplain-system/admin-b"},
		"a mirror's": {`{"registryMirrors": [{"host": "artifacts.example", "url": "https://mirror.example"}]}`,
			"registry mirror.example: no credentials worked; tried: team-a/regcred"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, newRunner(failedFor(unauthorized)))

			events, failure, err := f.scanner.Invoke(t.Context(), request(tc.settings))

			require.NoError(t, err)
			require.Empty(t, events)
			require.Equal(t, &collector.Failure{Reason: unauthorized, Message: tc.message}, failure)
		})
	}
}

// A scan Job that ran past its deadline timed out, and one whose pod said nothing that the runner could read failed
// for a reason of the scanner's own.
func TestScanGivesTheReasonOfTheJobsFailure(t *testing.T) {
	for _, reason := range []string{"TimedOut", internalReason, "CatalogFailed", "NoMatchingPlatform", "NotFound"} {
		t.Run(reason, func(t *testing.T) {
			f := newFixture(t, newRunner(failedFor(reason)))

			_, failure, err := f.scanner.Invoke(t.Context(), request(""))

			require.NoError(t, err)
			require.NotNil(t, failure)
			require.Equal(t, reason, failure.Reason)
		})
	}
}

// What the Job runner can't do, such as create the Job, is an error of the call, which the Job doesn't explain.
func TestScanReturnsAnErrorOfTheJobRunner(t *testing.T) {
	f := newFixture(t, newRunner(func(jobs.Spec) (jobs.Result, error) {
		return jobs.Result{}, errors.New("create the Job: the API server is away")
	}))

	events, failure, err := f.scanner.Invoke(t.Context(), request(""))

	require.Error(t, err)
	require.Empty(t, events)
	require.Nil(t, failure)
}

// The collector finds its own image, which its scan Jobs run, when a scan needs it: it starts without its permissions,
// which vexplain grants once it has read them (decision 0041). A scan whose image can't be found fails with an error
// that says so, before it reads a pod or a pull secret, and runs no Job. The next scan asks for the image again.
func TestAScanThatCantFindTheCollectorsImageFailsAlone(t *testing.T) {
	refused := errors.New(`pods "vexplain-collector-scanner-5d8f9-x2k4p" is forbidden`)
	asked := 0
	image := func(context.Context) (string, error) {
		asked++
		if asked == 1 {
			return "", refused
		}
		return ownImage, nil
	}
	runner := newRunner(scanned)
	objs := []client.Object{
		node(amd64Node, "amd64"), node(arm64Node, "arm64"),
		runningPod("app-0", amd64Node, repository, digest), runningPod("app-1", arm64Node, repository, digest),
	}
	f := newFixtureFinding(t, collectorName, runner, fake.NewClientBuilder().WithObjects(objs...).Build(), image)

	events, failure, err := f.scanner.Invoke(t.Context(), request(""))

	require.ErrorIs(t, err, refused)
	require.ErrorContains(t, err, "the image that the scan Jobs run")
	require.Nil(t, failure)
	require.Empty(t, events)
	require.Empty(t, runner.ran(), "no Job runs")
	require.Zero(t, f.credentialsBuilt(), "no pull secret is read")

	_, failure, err = f.scanner.Invoke(t.Context(), request(""))

	require.NoError(t, err)
	require.Nil(t, failure)
	require.Equal(t, 2, asked)
	require.Len(t, runner.ran(), 1)
	require.Equal(t, ownImage, runner.ran()[0].Image)
}

// The scanner runs no more scan Jobs at once than maxConcurrentScans: a third scan waits while two Jobs run, and runs
// once one of them has finished.
func TestAThirdScanWaitsWhileTwoJobsRun(t *testing.T) {
	runner := newRunner(scanned)
	runner.hold = make(chan struct{})
	f := newFixture(t, runner)
	done := make(chan error, 3)
	for range 3 {
		go func() {
			_, _, err := f.scanner.Invoke(t.Context(), request(`{"maxConcurrentScans": 2}`))
			done <- err
		}()
	}

	for range 2 {
		select {
		case <-runner.started:
		case <-time.After(wait):
			require.FailNow(t, "two scans start")
		}
	}
	select {
	case <-runner.started:
		require.FailNow(t, "a third scan Job started while two ran")
	case <-time.After(quiet):
	}

	runner.hold <- struct{}{}
	require.NoError(t, <-done)
	select {
	case <-runner.started:
	case <-time.After(wait):
		require.FailNow(t, "the third scan starts once a Job has finished")
	}
	close(runner.hold)
	require.NoError(t, <-done)
	require.NoError(t, <-done)
}

// Without the setting, four scan Jobs run at once: a fifth scan waits while four run.
func TestAFifthScanWaitsWhileFourJobsRunByDefault(t *testing.T) {
	runner := newRunner(scanned)
	runner.hold = make(chan struct{})
	f := newFixture(t, runner)
	done := make(chan error, 5)
	for range 5 {
		go func() {
			_, _, err := f.scanner.Invoke(t.Context(), request(""))
			done <- err
		}()
	}

	for range 4 {
		select {
		case <-runner.started:
		case <-time.After(wait):
			require.FailNow(t, "four scans start")
		}
	}
	select {
	case <-runner.started:
		require.FailNow(t, "a fifth scan Job started while four ran")
	case <-time.After(quiet):
	}

	close(runner.hold)
	for range 5 {
		require.NoError(t, <-done)
	}
	require.Len(t, runner.ran(), 5)
}

// A scan Job that another process of the collector runs, as one that a restart left, holds a slot too, until it has
// finished.
func TestAScanWaitsForAJobThatAnotherProcessRuns(t *testing.T) {
	runner := newRunner(scanned)
	end := runner.run(map[string]string{ownPodLabel: scanOperation, scannerLabel: collectorName})
	f := newFixture(t, runner)
	done := make(chan error, 1)
	go func() {
		_, _, err := f.scanner.Invoke(t.Context(), request(`{"maxConcurrentScans": 1}`))
		done <- err
	}()

	select {
	case <-runner.started:
		require.FailNow(t, "a scan Job started while another process's held the only slot")
	case <-time.After(quiet):
	}
	end()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(wait):
		require.FailNow(t, "the scan starts once the other Job has finished")
	}
}

// A scan whose call ends while it waits for a slot gives up, and runs no Job.
func TestAScanThatWaitsForASlotEndsWithItsCall(t *testing.T) {
	runner := newRunner(scanned)
	runner.hold = make(chan struct{})
	f := newFixture(t, runner)
	go func() { _, _, _ = f.scanner.Invoke(t.Context(), request(`{"maxConcurrentScans": 1}`)) }()
	<-runner.started
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, _, err := f.scanner.Invoke(ctx, request(`{"maxConcurrentScans": 1}`))
		done <- err
	}()

	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(wait):
		require.FailNow(t, "the waiting scan ends with its call")
	}
	close(runner.hold)
	require.Len(t, runner.ran(), 1)
}

// The scan Job runs the collector's own image with the scan subcommand and 2a's arguments, in the collector's
// namespace, with the credentials of the pod, the settings, and the label of vexplain's own
// pods, so that no presence collector takes its pod for a workload.
func TestTheScanJobIsWhatTheSettingsSay(t *testing.T) {
	f := newFixture(t, newRunner(scanned))
	settings := `{"scanTimeoutSeconds": 600, "workspaceMebibytes": 2048,
		"registryMirrors": [{"host": "artifacts.example", "url": "https://mirror.example"}],
		"adminPullSecrets": ["admin-b", "admin-a"],
		"scanPod": {"imagePullPolicy": "Always", "nodeSelector": {"kubernetes.io/os": "linux"}}}`

	_, failure, err := f.scanner.Invoke(t.Context(), request(settings))

	require.NoError(t, err)
	require.Nil(t, failure)
	specs := f.runner.ran()
	require.Len(t, specs, 1)
	s := specs[0]
	require.Regexp(t, `^scan-aaaaaaaaaaaa-[a-z0-9]{5}$`, s.Name)
	require.Equal(t, ownNamespace, s.Namespace)
	require.Equal(t, ownImage, s.Image)
	require.Equal(t, "scanner", s.Container)
	require.Equal(t, []string{
		"scan",
		"--image", repository + "@" + digest,
		"--platform", linuxAMD64, "--platform", linuxARM64,
		"--work", "/work",
		// Three quarters of the workspace: the rest is Syft's.
		"--max-bytes", "1610612736",
		"--registry-mirror", "artifacts.example=https://mirror.example",
	}, s.Args)
	require.Empty(t, s.Env, "a scan Job gets no variable beyond scanPod.env")
	require.Equal(t, []string{"team-a/app-0 " + mirror}, f.credentials.calls,
		"the logins of the mirror's host, which the scan pulls from: a registry's are never sent to its mirror")
	require.Equal(t, [][]byte{dockerConfig, adminConfig("admin-b"), adminConfig("admin-a")}, s.DockerConfigs,
		"a config for each login: the workload's first, then the admin's in their order")
	require.Equal(t, "2Gi", s.Workspace.String())
	require.Equal(t, 10*time.Minute, s.Deadline)
	require.Equal(t, corev1.PullAlways, s.Template.ImagePullPolicy, "scanPod.imagePullPolicy reaches the Job")
	require.Equal(t, map[string]string{"kubernetes.io/os": "linux"}, s.Template.NodeSelector)
	require.Equal(t, defaultResources(), s.Template.Resources, "the default resources, which the template leaves alone")
	require.Equal(t, map[string]string{
		ownPodLabel: scanOperation, scannerLabel: collectorName, "vexplain.bedag.ch/digest": strings.Repeat("a", 63),
	}, s.Labels)
	require.Equal(t, result.ResultPrefix, s.ResultPrefix)
	require.Equal(t, result.ErrorPrefix, s.ErrorPrefix)
}

// defaultResources are the resources of a scan pod whose settings set none: 2 GiB of memory, requested and as its
// limit.
func defaultResources() *corev1.ResourceRequirements {
	return &corev1.ResourceRequirements{
		Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("2Gi")},
		Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("2Gi")},
	}
}

func TestTheScanJobOfDefaultSettings(t *testing.T) {
	f := newFixture(t, newRunner(scanned))

	_, _, err := f.scanner.Invoke(t.Context(), request(""))

	require.NoError(t, err)
	s := f.runner.ran()[0]
	require.Equal(t, 30*time.Minute, s.Deadline)
	require.Equal(t, "10Gi", s.Workspace.String())
	require.Equal(t, []string{"8053063680"}, argsOf(s, "--max-bytes"))
	require.Empty(t, argsOf(s, "--registry-mirror"))
	require.Empty(t, s.Template.ImagePullPolicy, "the SDK pulls IfNotPresent when the template says nothing")
	require.Equal(t, defaultResources(), s.Template.Resources)
}

// The settings' resources are added to the default ones: memory keeps its default request and limit of 2 GiB unless
// the settings name memory, and a scan pod always has a memory limit, which is its request when the settings give a
// request alone (decision 0022: each scan Job has its own limits).
func TestTheScanPodKeepsItsDefaultMemoryUnlessTheSettingsNameMemory(t *testing.T) {
	quantity := resource.MustParse
	for name, tc := range map[string]struct {
		settings string
		want     corev1.ResourceRequirements
	}{
		"a CPU request": {
			settings: `{"requests": {"cpu": "500m"}}`,
			want: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: quantity("500m"), corev1.ResourceMemory: quantity("2Gi")},
				Limits:   corev1.ResourceList{corev1.ResourceMemory: quantity("2Gi")},
			},
		},
		"a CPU limit": {
			settings: `{"limits": {"cpu": "2"}}`,
			want: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceMemory: quantity("2Gi")},
				Limits:   corev1.ResourceList{corev1.ResourceCPU: quantity("2"), corev1.ResourceMemory: quantity("2Gi")},
			},
		},
		"a memory limit, which is also what Kubernetes requests": {
			settings: `{"limits": {"memory": "6Gi"}}`,
			want:     corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: quantity("6Gi")}},
		},
		"a memory request, which is also the limit": {
			settings: `{"requests": {"memory": "4Gi"}}`,
			want: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceMemory: quantity("4Gi")},
				Limits:   corev1.ResourceList{corev1.ResourceMemory: quantity("4Gi")},
			},
		},
		"memory of both": {
			settings: `{"requests": {"memory": "3Gi"}, "limits": {"memory": "5Gi"}}`,
			want: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceMemory: quantity("3Gi")},
				Limits:   corev1.ResourceList{corev1.ResourceMemory: quantity("5Gi")},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, newRunner(scanned))

			_, _, err := f.scanner.Invoke(t.Context(), request(`{"scanPod": {"resources": `+tc.settings+`}}`))

			require.NoError(t, err)
			got := f.runner.ran()[0].Template.Resources
			require.NotNil(t, got)
			require.Equal(t, tc.want.Requests, nonEmpty(got.Requests), "requests")
			require.Equal(t, tc.want.Limits, got.Limits, "limits")
		})
	}
}

// nonEmpty returns list, or nil for an empty one, as a test writes no requests.
func nonEmpty(list corev1.ResourceList) corev1.ResourceList {
	if len(list) == 0 {
		return nil
	}
	return list
}

// The scan takes the credentials of a pod that pulled the digest from a repository of the request, from that
// repository, since the pod's pull secrets are for that registry. The pods are taken in the order of their namespaces
// and names.
func TestTheScanTakesTheCredentialsOfAPodThatPulledFromARepositoryOfTheRequest(t *testing.T) {
	f := newFixture(t, newRunner(scanned),
		node(amd64Node, "amd64"),
		runningPod("app-0", amd64Node, mirror, digest),
		runningPod("app-1", amd64Node, repository, digest),
	)
	req := request("")
	req.Parameters = parameters([]string{repository, "other.example/team-a/app"}, "app-1", "app-0")

	_, _, err := f.scanner.Invoke(t.Context(), req)

	require.NoError(t, err)
	require.Equal(t, []string{"team-a/app-1 " + repository}, f.credentials.calls)
	require.Equal(t, []string{repository + "@" + digest}, argsOf(f.runner.ran()[0], "--image"))
}

// Without a pod that pulled from a repository of the request, the first pod pulls from the request's first.
func TestTheScanFallsBackToTheFirstPodAndRepository(t *testing.T) {
	f := newFixture(t, newRunner(scanned),
		node(amd64Node, "amd64"),
		runningPod("app-1", amd64Node, mirror, digest),
		runningPod("app-0", amd64Node, mirror, digest),
	)
	req := request("")
	req.Parameters = parameters([]string{repository}, "app-1", "app-0")

	_, _, err := f.scanner.Invoke(t.Context(), req)

	require.NoError(t, err)
	require.Equal(t, []string{"team-a/app-0 " + repository}, f.credentials.calls)
}

// Only a pod whose status says that it runs the digest gives credentials and a platform: a pod that the request
// names may have gone, or run another digest since.
func TestTheScanTakesOnlyThePodsThatRunTheDigest(t *testing.T) {
	f := newFixture(t, newRunner(scanned),
		node(amd64Node, "amd64"), node(arm64Node, "arm64"),
		runningPod("app-0", arm64Node, repository, "sha256:"+strings.Repeat("b", 64)),
		runningPod("app-1", amd64Node, repository, ""),
		runningPod("app-2", amd64Node, repository, digest),
	)
	req := request("")
	req.Parameters = parameters([]string{repository}, "app-0", "app-1", "app-2", "gone")

	_, failure, err := f.scanner.Invoke(t.Context(), req)

	require.NoError(t, err)
	require.Nil(t, failure)
	require.Equal(t, []string{"team-a/app-2 " + repository}, f.credentials.calls)
	require.Equal(t, []string{linuxAMD64}, argsOf(f.runner.ran()[0], "--platform"))
}

// A request whose pods run the digest no more has nothing to scan with, and fails with NotRunning.
func TestTheScanFailsWhenNoPodOfTheRequestRunsTheDigest(t *testing.T) {
	f := newFixture(t, newRunner(scanned),
		node(amd64Node, "amd64"), runningPod("app-0", amd64Node, repository, ""),
	)
	for name, pods := range map[string][]string{"pods that don't run it": {"app-0", "gone"}, "no pod": nil} {
		t.Run(name, func(t *testing.T) {
			req := request("")
			req.Parameters = parameters([]string{repository}, pods...)

			events, failure, err := f.scanner.Invoke(t.Context(), req)

			require.NoError(t, err)
			require.Empty(t, events)
			require.Equal(t, "NotRunning", failure.Reason)
			require.Empty(t, f.runner.ran())
		})
	}
}

// An image that presence keeps by the hash of its reference has no digest to pull by: the scan never takes a pod for
// it, whichever pod the request names, and fails with NotRunning where it would scan.
func TestTheScanNeverScansAnImageThatHasNoDigest(t *testing.T) {
	f := newFixture(t, newRunner(scanned), node(amd64Node, "amd64"), runningPod("app-0", amd64Node, repository, ""))
	req := request("")
	req.Subject = subject.Image(workloads.ReferenceDigest(repository + ":1.0"))
	req.Parameters = parameters([]string{repository + ":1.0"}, "app-0")

	events, failure, err := f.scanner.Invoke(t.Context(), req)

	require.NoError(t, err)
	require.Empty(t, events)
	require.Equal(t, "NotRunning", failure.Reason)
	require.Empty(t, f.runner.ran())
	require.Zero(t, f.credentialsBuilt())
}

// A scan needs a platform to ask for, and nodes that don't say theirs give none.
func TestTheScanFailsWhenNoNodeOfThePodsSaysItsPlatform(t *testing.T) {
	unlabelled := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: amd64Node}}
	f := newFixture(t, newRunner(scanned), unlabelled, runningPod("app-0", amd64Node, repository, digest))
	req := request("")
	req.Parameters = parameters([]string{repository}, "app-0")

	_, failure, err := f.scanner.Invoke(t.Context(), req)

	require.NoError(t, err)
	require.Equal(t, internalReason, failure.Reason)
	require.Empty(t, f.runner.ran())
}

// The label that marks vexplain's own pods comes from the context, which names it.
func TestTheScanJobCarriesTheOwnPodLabelOfTheContext(t *testing.T) {
	f := newFixture(t, newRunner(scanned))
	req := request("")
	req.Context.OwnPodLabel = "example.com/own"

	_, _, err := f.scanner.Invoke(t.Context(), req)

	require.NoError(t, err)
	require.Equal(t, scanOperation, f.runner.ran()[0].Labels["example.com/own"], "the task, which is a scan")
}

// The scanner scans images, and nothing else.
func TestTheScanRefusesASubjectThatIsNoImage(t *testing.T) {
	f := newFixture(t, newRunner(scanned))
	req := request("")
	req.Subject = subject.Manifest(amd64Manifest)

	_, _, err := f.scanner.Invoke(t.Context(), req)

	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// A scan reads the pods, their pull secrets and their nodes once it has its slot, and not before: a scan that waits
// for hours holds no pull credentials meanwhile, and doesn't scan with pods that are gone by then, or with
// credentials that expired.
func TestAWaitingScanReadsNothingUntilItHasASlot(t *testing.T) {
	runner := newRunner(scanned)
	runner.hold = make(chan struct{})
	f := newFixture(t, runner)
	first := make(chan error, 1)
	go func() {
		_, _, err := f.scanner.Invoke(t.Context(), request(`{"maxConcurrentScans": 1}`))
		first <- err
	}()
	<-runner.started
	type answer struct {
		failure *collector.Failure
		err     error
	}
	second := make(chan answer, 1)
	go func() {
		_, failure, err := f.scanner.Invoke(t.Context(), request(`{"maxConcurrentScans": 1}`))
		second <- answer{failure, err}
	}()

	require.Never(t, func() bool { return f.credentialsBuilt() > 1 }, quiet, 10*time.Millisecond,
		"the waiting scan builds no credentials")
	for _, pod := range []string{"app-0", "app-1"} {
		require.NoError(t, f.client.Delete(t.Context(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: teamNamespace, Name: pod,
		}}))
	}
	runner.hold <- struct{}{}
	require.NoError(t, <-first)

	select {
	case got := <-second:
		require.NoError(t, got.err)
		require.NotNil(t, got.failure)
		require.Equal(t, "NotRunning", got.failure.Reason, "the pods are gone by the time that the scan has its slot")
	case <-time.After(wait):
		require.FailNow(t, "the waiting scan ends once it has its slot")
	}
	require.Equal(t, 1, f.credentialsBuilt())
	require.Len(t, runner.ran(), 1)
}

// The slots of a scanner count its own scan Jobs: not the tasks of another collector that also scan, and not those of
// a second scanner Collector in the namespace.
func TestTheSlotsCountTheScanJobsOfThisCollector(t *testing.T) {
	runner := newRunner(scanned)
	end := runner.run(map[string]string{ownPodLabel: scanOperation, scannerLabel: "scanner-b"})
	defer end()
	f := newFixture(t, runner)
	ctx, cancel := context.WithTimeout(t.Context(), wait)
	defer cancel()

	_, failure, err := f.scanner.Invoke(ctx, request(`{"maxConcurrentScans": 1}`))

	require.NoError(t, err, "the scan doesn't wait for the other scanner's Job")
	require.Nil(t, failure, "the other scanner's Job holds no slot of this one")
	runner.mu.Lock()
	defer runner.mu.Unlock()
	require.NotEmpty(t, runner.selectors)
	for _, selector := range runner.selectors {
		require.Equal(t, map[string]string{ownPodLabel: scanOperation, scannerLabel: collectorName}, selector)
	}
}

// Each event travels to vexplain as one message of the collector API, which holds 16 MiB at most. Evidence that
// compresses well enough for the evidence store, and is more than a message holds, fails as TooLarge before it is
// emitted, and isn't lost in transport after a whole scan. Each event of a manifest is a message of its own. The
// failure names the type of the evidence, the size of its message, and the cap.
func TestScanFailsAsTooLargeWhenAnEventIsMoreThanAMessageHolds(t *testing.T) {
	over := regexp.MustCompile(`^the evidence (\S+) of a manifest is a message of (\d+) bytes, more than the (\d+) ` +
		`that the collector API holds$`)
	for name, tc := range map[string]struct {
		size      int
		pad       func(s *result.Scanned, padding string)
		eventType string
		failure   bool
	}{
		"17 MiB in the SBOM":           {size: 17 << 20, pad: padSBOM, eventType: evidence.TypeSBOM, failure: true},
		"17 MiB in the image contents": {size: 17 << 20, pad: padContents, eventType: result.EvidenceType, failure: true},
		"15 MiB in the SBOM":           {size: 15 << 20, pad: padSBOM},
		"15 MiB in the image contents": {size: 15 << 20, pad: padContents},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, newRunner(func(s jobs.Spec) (jobs.Result, error) {
				m := manifestOf(linuxAMD64, amd64Manifest)
				tc.pad(&m, strings.Repeat("a", tc.size))
				line, err := result.Encode(result.Result{Image: argsOf(s, "--image")[0], Manifests: []result.Scanned{m}})
				return jobs.Result{Line: line}, err
			}))
			req := request("")
			req.Parameters = parameters([]string{repository}, "app-0")

			events, failure, err := f.scanner.Invoke(t.Context(), req)

			require.NoError(t, err)
			if tc.failure {
				require.Empty(t, events)
				require.NotNil(t, failure)
				require.Equal(t, tooLargeReason, failure.Reason)
				named := over.FindStringSubmatch(failure.Message)
				require.NotNil(t, named, "the failure names the evidence, its size and the cap: %q", failure.Message)
				require.Equal(t, tc.eventType, named[1])
				size, err := strconv.Atoi(named[2])
				require.NoError(t, err)
				require.Greater(t, size, collector.MaxMessageSize)
				require.Equal(t, strconv.Itoa(collector.MaxMessageSize), named[3])
				return
			}
			require.Nil(t, failure)
			require.Len(t, events, 2)
		})
	}
}

// padSBOM puts padding into the name of a package of the SBOM, and padContents into the path of a library of the
// image contents.
func padSBOM(s *result.Scanned, padding string) { s.SBOM.Packages[0].Name = padding }

func padContents(s *result.Scanned, padding string) { s.Libraries[0].Path = "/" + padding }

// ---- the settings, through the SDK's server ----

// serve serves the scanner on a listener that only the test reaches, until the test ends, and returns a connection to
// it.
func serve(t *testing.T, s *scan.Scanner) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	health, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- collector.Serve(ctx, s, collector.Options{Insecure: true, GRPCListener: listener, HealthListener: health})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(wait):
			assert.Fail(t, "the scanner didn't stop")
		}
	})
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// validate asks the served scanner what is wrong with the settings.
func validate(t *testing.T, conn *grpc.ClientConn, settings string) []string {
	t.Helper()
	resp, err := collectorv1alpha1.NewIdentityClient(conn).ValidateSettings(t.Context(),
		&collectorv1alpha1.ValidateSettingsRequest{Settings: []byte(settings)})
	require.NoError(t, err)
	return resp.GetProblems()
}

// maxConcurrentScans goes up to 16, as many requests as vexplain's executor runs at once for one collector: more scan
// Jobs at once would never run.
func TestSettingsOutsideTheirRangesAreRefused(t *testing.T) {
	conn := serve(t, newFixture(t, newRunner(scanned)).scanner)
	for _, settings := range []string{
		`{"maxConcurrentScans": 0}`,
		`{"maxConcurrentScans": 17}`,
		`{"maxConcurrentScans": 1.5}`,
		`{"scanTimeoutSeconds": 59}`,
		`{"scanTimeoutSeconds": 21601}`,
		`{"workspaceMebibytes": 1023}`,
		`{"workspaceMebibytes": 1048577}`,
		`{"memoryLimitMebibytes": 2048}`,
		`{"scanPod": {"imagePullPolicy": "Sometimes"}}`,
		`{"scanPod": {"securityContext": {"privileged": true}}}`,
		`{"scanPod": {"resources": {"limits": {"memory": "lots"}}}}`,
		`{"scanPod": {"annotations": {"container.apparmor.security.beta.kubernetes.io/scanner": "unconfined"}}}`,
		`{"scanPod": {"annotations": {"seccomp.security.alpha.kubernetes.io/pod": "unconfined"}}}`,
		`{"scanPod": {"labels": {"team a": "x"}}}`,
		`{"scanPod": {"labels": {"team": "team a"}}}`,
		`{"scanPod": {"annotations": {"Team A": "x"}}}`,
		`{"scanPod": {"resources": {"limits": {"gpu": 1}}}}`,
		`{"scanPod": {"resources": {"requests": {"cpu": "2"}, "limits": {"cpu": "1"}}}}`,
		`{"scanPod": {"resources": {"requests": {"memory": "4Gi"}, "limits": {"memory": "2Gi"}}}}`,
		`{"registryMirrors": [{"host": "artifacts.example"}]}`,
		`{"registryMirrors": [{"host": "artifacts.example", "url": "ftp://mirror.example"}]}`,
		`{"registryMirrors": [{"host": "artifacts.example", "url": "https://mirror.example/path"}]}`,
		`{"registryMirrors": [{"host": "artifacts.example", "url": "https://user@mirror.example"}]}`,
		`{"registryMirrors": [{"host": "Artifacts Example", "url": "https://mirror.example"}]}`,
		`{"registryMirrors": [{"host": "artifacts.example", "url": "https://a.example"},` +
			` {"host": "artifacts.example", "url": "https://b.example"}]}`,
		`{"adminPullSecrets": "admin-pull"}`,
		`{"adminPullSecrets": [""]}`,
		`{"adminPullSecrets": ["Admin Pull"]}`,
		`{"adminPullSecrets": ["admin-pull/other"]}`,
		`{"adminPullSecrets": ["` + strings.Repeat("a", 254) + `"]}`,
		`{"adminPullSecrets": ["admin-pull", "admin-pull"]}`,
		`{"adminPullSecrets": ` + secretNames(17) + `}`,
	} {
		require.NotEmpty(t, validate(t, conn, settings), settings)
	}
}

// secretNames returns the JSON of a list of n names of Secrets.
func secretNames(n int) string {
	names := make([]string, 0, n)
	for i := range n {
		names = append(names, fmt.Sprintf("admin-pull-%d", i))
	}
	raw, err := json.Marshal(names)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// A memory limit of 0 means no memory limit, and a memory request alone is the limit too, so either would let a scan
// pod run without one (decision 0022: each scan Job has its own limits). The settings are refused, and say why, and a
// scan that carries them runs no Job. A scan pod reserves the memory that it needs, so a request of 0 is refused even
// below a limit.
func TestAScanPodWithoutAMemoryLimitIsRefused(t *testing.T) {
	f := newFixture(t, newRunner(scanned))
	conn := serve(t, f.scanner)
	for name, resources := range map[string]string{
		"a limit of 0":                 `{"limits": {"memory": "0"}}`,
		"a limit of 0, as a number":    `{"limits": {"memory": 0}}`,
		"a request of 0":               `{"requests": {"memory": "0"}}`,
		"both of 0":                    `{"requests": {"memory": "0Gi"}, "limits": {"memory": "0"}}`,
		"a request of 0 below a limit": `{"requests": {"memory": "0"}, "limits": {"memory": "2Gi"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			settings := `{"scanPod": {"resources": ` + resources + `}}`

			problems := validate(t, conn, settings)

			require.NotEmpty(t, problems)
			require.Contains(t, strings.Join(problems, "\n"), "must be more than 0")
			require.Contains(t, strings.Join(problems, "\n"), "no memory limit", "the problem says why")
			_, _, err := f.scanner.Invoke(t.Context(), request(settings))
			require.Equal(t, codes.InvalidArgument, status.Code(err))
			require.Empty(t, f.runner.ran(), "no scan Job runs without a memory limit")
		})
	}
}

func TestSettingsAtTheEndsOfTheirRangesAreAccepted(t *testing.T) {
	conn := serve(t, newFixture(t, newRunner(scanned)).scanner)
	for _, settings := range []string{
		``,
		`{}`,
		`{"maxConcurrentScans": 1, "scanTimeoutSeconds": 60, "workspaceMebibytes": 1024}`,
		`{"maxConcurrentScans": 16, "scanTimeoutSeconds": 21600, "workspaceMebibytes": 1048576}`,
		`{"registryMirrors": [{"host": "localhost:5001", "url": "http://registry.example:5000"},` +
			` {"host": "docker.io", "url": "https://mirror.example"}]}`,
		`{"adminPullSecrets": []}`,
		`{"adminPullSecrets": ` + secretNames(16) + `}`,
		`{"adminPullSecrets": ["admin-pull.registry-a", "` + strings.Repeat("a", 253) + `"]}`,
		`{"scanPod": {"imagePullPolicy": "Never", "resources": {"requests": {"memory": "1Gi", "cpu": 1}},` +
			` "tolerations": [{"key": "dedicated", "operator": "Equal", "value": "scans", "effect": "NoSchedule"}],` +
			` "priorityClassName": "batch-low", "runtimeClassName": "gvisor", "labels": {"team": "team-a"}}}`,
	} {
		require.Empty(t, validate(t, conn, settings), settings)
	}
}

// maxConcurrentScans of 0 would let no scan run: the settings are refused, and so is an Invoke that carries them.
func TestAScanWithMaxConcurrentScansOfZeroIsRefused(t *testing.T) {
	f := newFixture(t, newRunner(scanned))
	conn := serve(t, f.scanner)

	stream, err := collectorv1alpha1.NewEvidenceClient(conn).Invoke(t.Context(), &collectorv1alpha1.InvokeRequest{
		Operation: scanOperation, Subject: subject.Image(digest), Role: collectorv1alpha1.Role_ROLE_SPOKE,
		Parameters: parameters([]string{repository}, "app-0"), Settings: []byte(`{"maxConcurrentScans": 0}`),
	})
	require.NoError(t, err)
	_, err = stream.Recv()

	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Empty(t, f.runner.ran())
}

// The sample of the scanner's Collector, which the documentation shows, holds settings that the scanner accepts.
func TestTheSettingsOfTheSampleCollectorAreValid(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "config", "samples", "config_v1alpha1_collector_scanner.yaml"))
	require.NoError(t, err)
	var sample struct {
		Spec struct {
			Settings json.RawMessage `json:"settings"`
		} `json:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &sample))
	require.NotEmpty(t, sample.Spec.Settings)
	conn := serve(t, newFixture(t, newRunner(scanned)).scanner)

	require.Empty(t, validate(t, conn, string(sample.Spec.Settings)))
}

// ---- the contract ----

// TestConformance runs the conformance suite of the SDK against the scanner, with a scan that a fake Job runner
// answers.
func TestConformance(t *testing.T) {
	f := newFixture(t, newRunner(scanned))
	conn := serve(t, f.scanner)
	conformance.Run(t, conformance.Target{
		Dial: func(context.Context) (*grpc.ClientConn, error) { return conn, nil },
		Settings: json.RawMessage(`{"maxConcurrentScans": 3,
			"registryMirrors": [{"host": "artifacts.example", "url": "https://mirror.example"}],
			"adminPullSecrets": ["admin-pull"],
			"scanPod": {"imagePullPolicy": "Always"}}`),
		InvalidSettings: json.RawMessage(`{"maxConcurrentScans": 0}`),
		Context:         collector.Context{Cluster: clusterName, OperatorNamespace: ownNamespace, OwnPodLabel: ownPodLabel},
		Invocations: []conformance.Invocation{{
			Operation: scanOperation, Subject: subject.Image(digest),
			Parameters: parameters([]string{repository}, "app-0", "app-1"),
		}},
	})
}

// The capabilities say what the brief of the collector and vexplain's install agree on: the spoke role, the operation
// scan, which consumes nothing and produces the sbom type and the scanner's own type, both with scope Hub, and the
// permissions that the install binds.
func TestTheCapabilitiesOfTheScanner(t *testing.T) {
	s := newFixture(t, newRunner(scanned)).scanner

	require.Equal(t, collector.Info{Name: collectorName, Version: version}, s.Info())
	caps := s.Capabilities()
	require.Equal(t, []collector.Role{collector.RoleSpoke}, caps.Roles)
	require.False(t, caps.Watches)
	require.Empty(t, caps.Consumes)
	sbomSchema, ok := evidence.Schema(evidence.TypeSBOM)
	require.True(t, ok)
	require.Equal(t, []collector.EvidenceType{
		{Type: evidence.TypeSBOM, Scope: collector.ScopeHub, Schema: sbomSchema},
		{Type: result.EvidenceType, Scope: collector.ScopeHub, Schema: result.Schema()},
	}, caps.Produces, "the core's SBOM, which the vulnerabilities collector consumes, and the scanner's own type")
	require.Len(t, caps.Operations, 1)
	op := caps.Operations[0]
	require.Equal(t, scanOperation, op.Name)
	require.Equal(t, collector.RoleSpoke, op.Role)
	require.Equal(t, []string{evidence.TypeSBOM, result.EvidenceType}, op.Produces)
	require.Empty(t, op.Consumes)
	const get, secrets = "get", "secrets"
	require.ElementsMatch(t, []collector.Permission{
		{APIGroups: []string{""}, Resources: []string{"pods", "nodes", secrets, "serviceaccounts"}, Verbs: []string{get}},
		{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"create", get, "list", "watch", "delete"},
			Namespaced: true},
		{APIGroups: []string{""}, Resources: []string{secrets}, Verbs: []string{"create", get, "delete"}, Namespaced: true},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{get, "list"}, Namespaced: true},
		{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{get}, Namespaced: true},
	}, caps.Permissions)
}

// ---- environment variables of the scan pods (decision 0037) ----

// scanPodEnv is the scanPod setting that gives a scan pod a proxy: one variable with a value, one from a key of a
// Secret in the pod's namespace, which is vexplain's.
const scanPodEnv = `{"scanPod": {"env": [
	{"name": "HTTP_PROXY", "value": "http://proxy.example:3128"},
	{"name": "NO_PROXY", "valueFrom": {"secretKeyRef": {"name": "proxy-settings", "key": "no-proxy"}}}]}}`

// scanPodEnvVars are the variables that scanPodEnv sets.
func scanPodEnvVars() []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "HTTP_PROXY", Value: "http://proxy.example:3128"},
		{Name: "NO_PROXY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "proxy-settings"}, Key: "no-proxy",
		}}},
	}
}

// The Job that a scan makes has the environment of scanPod after the collector's own variables, and keeps 0022's
// isolation: no API token, no service links, a user without privilege, a read-only root filesystem.
func TestTheScanJobsContainerGetsTheEnvironmentOfScanPodAndStaysIsolated(t *testing.T) {
	f := newFixture(t, newRunner(scanned))
	_, failure, err := f.scanner.Invoke(t.Context(), request(scanPodEnv))
	require.NoError(t, err)
	require.Nil(t, failure)
	spec := f.runner.ran()[0]
	require.Equal(t, scanPodEnvVars(), spec.Template.Env)

	// The real runner builds the Job from the Spec. Its context ends as the Job is created, which is all that this
	// test needs of it.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var created *batchv1.Job
	c := interceptor.NewClient(fake.NewClientBuilder().Build(), interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if job, ok := obj.(*batchv1.Job); ok {
				created = job.DeepCopy()
				cancel()
			}
			return c.Create(ctx, obj, opts...)
		},
	})
	_, _ = jobs.NewRunner(c, nil, ownNamespace).Run(ctx, spec)

	require.NotNil(t, created)
	pod := created.Spec.Template.Spec
	require.Equal(t, ptr.To(false), pod.AutomountServiceAccountToken)
	require.Equal(t, ptr.To(false), pod.EnableServiceLinks)
	require.Equal(t, ptr.To(true), pod.SecurityContext.RunAsNonRoot)
	require.Len(t, pod.Containers, 1)
	container := pod.Containers[0]
	require.Equal(t, ptr.To(true), container.SecurityContext.ReadOnlyRootFilesystem)
	require.Equal(t, ptr.To(false), container.SecurityContext.AllowPrivilegeEscalation)
	want := append([]corev1.EnvVar{{Name: "DOCKER_CONFIG", Value: "/creds"}}, scanPodEnvVars()...)
	require.Equal(t, want, container.Env)
}

// A variable that the scanner sets on a scan pod itself is a problem of the settings. The proxy variables are not
// among them, in any case, and the answer never depends on the scanner's own environment.
func TestTheSettingsRefuseAScanPodVariableThatTheScannerSetsAndTakeTheProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	f := newFixture(t, newRunner(scanned))
	require.Empty(t, f.scanner.ValidateSettings(json.RawMessage(scanPodEnv)))

	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		require.Empty(t, f.scanner.ValidateSettings(json.RawMessage(
			`{"scanPod": {"env": [{"name": "`+name+`", "value": "x"}]}}`)), name)
	}
	problems := f.scanner.ValidateSettings(json.RawMessage(
		`{"scanPod": {"env": [{"name": "DOCKER_CONFIG", "value": "x"}]}}`))
	require.Len(t, problems, 1)
	require.Contains(t, problems[0], "scanPod.env[0].name")
}

// ---- the metrics ----

// gathered returns what g gathers, by the name and the labels of each series: the value of a counter, and the count
// and the sum of a histogram.
func gathered(t *testing.T, g prometheus.Gatherer) map[string]float64 {
	t.Helper()
	families, err := g.Gather()
	require.NoError(t, err)
	got := map[string]float64{}
	for _, family := range families {
		for _, m := range family.GetMetric() {
			labels := make([]string, 0, len(m.GetLabel()))
			for _, label := range m.GetLabel() {
				labels = append(labels, label.GetName()+"="+label.GetValue())
			}
			series := family.GetName() + "{" + strings.Join(labels, ",") + "}"
			switch family.GetType() {
			case dto.MetricType_COUNTER:
				got[series] = m.GetCounter().GetValue()
			case dto.MetricType_HISTOGRAM:
				got[series+" count"] = float64(m.GetHistogram().GetSampleCount())
				got[series+" sum"] = m.GetHistogram().GetSampleSum()
			default:
				require.Failf(t, "a series of another type", "%s is a %s", series, family.GetType())
			}
		}
	}
	return got
}

// The scanner counts each scan that held a slot, by the cluster that its request names and its result: Succeeded,
// the reason of its failure, or Error for a scan that couldn't run. It observes how long each held its slot: here, the
// five minutes of each scan Job. A request refused before it waits for a slot is no scan.
func TestTheMetricsCountTheScansByResult(t *testing.T) {
	var mu sync.Mutex
	at := ended
	answers := []func(jobs.Spec) (jobs.Result, error){
		scanned, failedFor(unauthorized), failedFor(unauthorized),
		func(jobs.Spec) (jobs.Result, error) {
			return jobs.Result{}, errors.New("create the Job: the API server is away")
		},
		scanned,
	}
	runner := newRunner(func(s jobs.Spec) (jobs.Result, error) {
		mu.Lock()
		at = at.Add(5 * time.Minute)
		answer := answers[0]
		answers = answers[1:]
		mu.Unlock()
		return answer(s)
	})
	metrics := scan.NewMetrics()
	registry := prometheus.NewPedanticRegistry()
	require.NoError(t, registry.Register(metrics))
	scanner := scan.New(scan.Options{
		Name: collectorName, Version: version, Image: func(context.Context) (string, error) { return ownImage, nil },
		Namespace: ownNamespace, Client: fake.NewClientBuilder().WithObjects(defaultCluster()...).Build(),
		Credentials: &fakeCredentials{}, Runner: runner, Metrics: metrics, SlotWait: 20 * time.Millisecond,
		Now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return at
		},
	})

	for _, cluster := range []string{clusterName, clusterName, clusterName, clusterName, "cluster-b"} {
		req := request("")
		req.Context.Cluster = cluster
		_, _, _ = scanner.Invoke(t.Context(), req)
	}
	refused := request("")
	refused.Subject = subject.Manifest(amd64Manifest)
	_, _, err := scanner.Invoke(t.Context(), refused)
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	const scans, durations = "vexplain_scanner_scans_total", "vexplain_scanner_scan_duration_seconds"
	require.Equal(t, map[string]float64{
		scans + "{cluster=cluster-a,result=Error}":                  1,
		scans + "{cluster=cluster-a,result=Succeeded}":              1,
		scans + "{cluster=cluster-a,result=Unauthorized}":           2,
		scans + "{cluster=cluster-b,result=Succeeded}":              1,
		durations + "{cluster=cluster-a,result=Error} count":        1,
		durations + "{cluster=cluster-a,result=Error} sum":          300,
		durations + "{cluster=cluster-a,result=Succeeded} count":    1,
		durations + "{cluster=cluster-a,result=Succeeded} sum":      300,
		durations + "{cluster=cluster-a,result=Unauthorized} count": 2,
		durations + "{cluster=cluster-a,result=Unauthorized} sum":   600,
		durations + "{cluster=cluster-b,result=Succeeded} count":    1,
		durations + "{cluster=cluster-b,result=Succeeded} sum":      300,
	}, gathered(t, registry))
}

// ---- the secrecy of the pull secrets ----

// canariesOf returns the values of logins that must never show: each username, password and identity token, and the
// base64 of username:password, as a pull secret's auth holds it.
func canariesOf(logins ...registryLogin) []string {
	var canaries []string
	for _, login := range logins {
		canaries = append(canaries, login.username, login.password,
			base64.StdEncoding.EncodeToString([]byte(login.username+":"+login.password)))
		if login.identityToken != "" {
			canaries = append(canaries, login.identityToken)
		}
	}
	return canaries
}

// The values of the pull secrets never leave the scan Job's Secret: they are never logged, nor emitted in an error, a
// failure (which the image's status shows), an event or a metric (decision 0047). A scan whose registry refused every
// login fails with Unauthorized, and its message names the registry and the Secrets, and holds none of the canary
// values of the Secrets; nor does anything that the scanner logs, its metrics, or the error of a Secret that doesn't
// parse. The conformance suite's canaries check evidence in the same way.
func TestAFailedPullNeverShowsTheContentOfThePullSecrets(t *testing.T) {
	capture, ctx := captureLogs(t)
	podLogin := registryLogin{username: "canary-pod-user", password: "canary-pod-password",
		identityToken: "canary-pod-token"}
	saLogin := registryLogin{username: "canary-sa-user", password: "canary-sa-password"}
	adminLogin := registryLogin{username: "canary-admin-user", password: "canary-admin-password"}
	// The parser's error of a Secret whose registry is no URL quotes the registry.
	const brokenCanary = "canary-broken-registry"
	broken := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ownNamespace, Name: "admin-broken"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"` + brokenCanary +
			`\u007f":{"auth":"Y2FuYXJ5OmJyb2tlbg=="}}}`)},
	}
	otherLogin := registryLogin{username: "canary-other-user", password: "canary-other-password"}
	const opaqueCanary = "canary-opaque-value"
	credentials := newCredentials(
		pullSecret("regcred", map[string]registryLogin{privateRegistry: podLogin}),
		pullSecret("sacred", map[string]registryLogin{privateRegistry: saLogin}),
		serviceAccount(appName, "sacred"),
		pullSecretIn(ownNamespace, "admin-pull", map[string]registryLogin{privateRegistry: adminLogin}),
		pullSecretIn(ownNamespace, "admin-other", map[string]registryLogin{otherRegistry: otherLogin}),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: ownNamespace, Name: adminOpaque},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"password": []byte(opaqueCanary)},
		},
		broken)
	objs := defaultCluster()
	for _, obj := range objs {
		if pod, ok := obj.(*corev1.Pod); ok {
			pod.Spec.ServiceAccountName = appName
			pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "regcred"}}
		}
	}
	runner := newRunner(failedFor(unauthorized))
	metrics := scan.NewMetrics()
	registry := prometheus.NewPedanticRegistry()
	require.NoError(t, registry.Register(metrics))
	scanner := scan.New(scan.Options{
		Name: collectorName, Version: version, Image: func(context.Context) (string, error) { return ownImage, nil },
		Namespace: ownNamespace, Client: fake.NewClientBuilder().WithObjects(objs...).Build(), Credentials: credentials,
		Runner: runner, Metrics: metrics, SlotWait: 20 * time.Millisecond, Now: func() time.Time { return ended },
	})

	events, failure, err := scanner.Invoke(ctx,
		request(`{"adminPullSecrets": ["admin-pull", "admin-missing", "admin-other", "admin-opaque"]}`))

	require.NoError(t, err)
	require.Empty(t, events)
	require.Equal(t, &collector.Failure{Reason: unauthorized, Message: "registry artifacts.example: no credentials " +
		"worked; adminPullSecrets not found: admin-missing; adminPullSecrets without a login for it: admin-other, " +
		"admin-opaque; tried: team-a/regcred, team-a/sacred, vexplain-system/admin-pull"}, failure)
	require.Len(t, runner.ran(), 1)
	configs := string(bytes.Join(runner.ran()[0].DockerConfigs, nil))
	for _, login := range []registryLogin{podLogin, saLogin, adminLogin} {
		require.Contains(t, configs, login.password, "the scan Job's Secret holds the logins, which nothing else shows")
	}

	_, _, brokenErr := scanner.Invoke(ctx, request(`{"adminPullSecrets": ["admin-broken"]}`))

	require.ErrorContains(t, brokenErr, "vexplain-system/admin-broken", "the Secret that doesn't parse is named")
	shown := failure.Message + "\n" + brokenErr.Error() + "\n" + capture.String() + "\n" +
		fmt.Sprint(gathered(t, registry))
	for _, canary := range append(canariesOf(podLogin, saLogin, adminLogin, otherLogin), opaqueCanary, brokenCanary,
		"Y2FuYXJ5OmJyb2tlbg==") {
		require.NotContains(t, shown, canary)
	}
}

// A registry that wants a login where no pull secret holds one fails the scan with Unauthorized, which says so, and
// names the Secret of adminPullSecrets that doesn't exist: the scan pulled without credentials, and its Job had no
// Secret.
func TestScanWithoutALoginSaysThatNoPullSecretHoldsOne(t *testing.T) {
	runner := newRunner(failedFor(unauthorized))
	scanner := scan.New(scan.Options{
		Name: collectorName, Version: version, Image: func(context.Context) (string, error) { return ownImage, nil },
		Namespace: ownNamespace, Client: fake.NewClientBuilder().WithObjects(defaultCluster()...).Build(),
		Credentials: newCredentials(), Runner: runner, SlotWait: 20 * time.Millisecond,
	})

	_, failure, err := scanner.Invoke(t.Context(), request(`{"adminPullSecrets": ["admin-pull"]}`))

	require.NoError(t, err)
	require.Equal(t, &collector.Failure{Reason: unauthorized, Message: "registry artifacts.example: no credentials " +
		"worked, no pull secret holds a login for it; adminPullSecrets not found: admin-pull"}, failure)
	require.Empty(t, runner.ran()[0].DockerConfigs)
}

// The spoke keeps 256 characters of a failure's message. The registry and the Secrets of adminPullSecrets that gave no
// login, which the admin is to see, come first, then the Secrets whose logins the scan tried, as many as fit, with a
// count of the rest: with many Secrets, the whole message is kept, it names the missing ones, and it holds none of the
// content of the Secrets.
func TestTheMessageOfAPullWithManySecretsKeepsTheAdminsSecretsInWhatTheSpokeKeeps(t *testing.T) {
	const pullSecretCount = 10
	logins := make([]registryLogin, 0, pullSecretCount)
	objs := make([]runtime.Object, 0, pullSecretCount+2)
	objs = append(objs, serviceAccount(appName))
	pullSecrets := make([]corev1.LocalObjectReference, 0, pullSecretCount)
	for i := range pullSecretCount {
		name := fmt.Sprintf("pull-secret-of-the-team-%02d", i)
		login := registryLogin{username: fmt.Sprintf("canary-user-%02d", i), password: fmt.Sprintf("canary-password-%02d", i)}
		logins = append(logins, login)
		objs = append(objs, pullSecret(name, map[string]registryLogin{privateRegistry: login}))
		pullSecrets = append(pullSecrets, corev1.LocalObjectReference{Name: name})
	}
	objs = append(objs, pullSecretIn(ownNamespace, "admin-other", map[string]registryLogin{otherRegistry: logins[0]}))
	cluster := defaultCluster()
	for _, obj := range cluster {
		if pod, ok := obj.(*corev1.Pod); ok {
			pod.Spec.ServiceAccountName = appName
			pod.Spec.ImagePullSecrets = pullSecrets
		}
	}
	long := strings.Repeat("x", 240)
	for name, tc := range map[string]struct {
		settings string
		begins   string
	}{
		"a missing Secret and one without a login": {`{"adminPullSecrets": ["admin-missing", "admin-other"]}`,
			"registry artifacts.example: no credentials worked; adminPullSecrets not found: admin-missing; " +
				"adminPullSecrets without a login for it: admin-other; tried: team-a/pull-secret-of-the-team-00, "},
		"Secrets that don't exist, of names longer than the message": {
			`{"adminPullSecrets": ["` + long + `-a", "` + long + `-b"]}`,
			"registry artifacts.example: no credentials worked; adminPullSecrets not found: 2 Secrets; tried: " +
				"team-a/pull-secret-of-the-team-00, "},
	} {
		t.Run(name, func(t *testing.T) {
			scanner := scan.New(scan.Options{
				Name: collectorName, Version: version, Image: func(context.Context) (string, error) { return ownImage, nil },
				Namespace: ownNamespace, Client: fake.NewClientBuilder().WithObjects(cluster...).Build(),
				Credentials: newCredentials(objs...), Runner: newRunner(failedFor(unauthorized)),
				SlotWait: 20 * time.Millisecond,
			})

			_, failure, err := scanner.Invoke(t.Context(), request(tc.settings))

			require.NoError(t, err)
			require.NotNil(t, failure)
			require.Equal(t, unauthorized, failure.Reason)
			require.LessOrEqual(t, len(failure.Message), 256, "the spoke keeps the whole message: %s", failure.Message)
			require.True(t, strings.HasPrefix(failure.Message, tc.begins), failure.Message)
			require.Regexp(t, ` and [0-9]+ more$`, failure.Message, "the tried Secrets that don't fit are counted")
			for _, canary := range canariesOf(logins...) {
				require.NotContains(t, failure.Message, canary)
			}
		})
	}
}
