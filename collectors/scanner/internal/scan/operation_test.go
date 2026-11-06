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
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	"github.com/bedag/vexplain/collectors/scanner/internal/result"
	"github.com/bedag/vexplain/collectors/scanner/internal/scan"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/conformance"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/jobs"
	"github.com/bedag/vexplain/sdk/subject"
)

// These tests run the scanner's operation with a fake Job runner, which answers each scan as the scan Job's pod would
// have, and with pods and nodes in a fake client. The SDK's Job runner, which runs the real Jobs, has its own tests.

const (
	// wait bounds how long a test waits for what must happen, and quiet how long it watches for what must not.
	wait  = 10 * time.Second
	quiet = 300 * time.Millisecond
	// The collector: its name, version and image, and its namespace.
	collectorName  = "scanner"
	version        = "0.2.0"
	ownImage       = "artifacts.example/vexplain/scanner:0.2.0"
	ownNamespace   = "vexplain-system"
	ownPodLabel    = "vexplain.bedag.ch/task"
	clusterName    = "cluster-a"
	teamNamespace  = "team-a"
	repository     = "artifacts.example/team-a/app"
	mirror         = "mirror.example/team-a/app"
	amd64Node      = "node-amd64"
	arm64Node      = "node-arm64"
	linuxAMD64     = "linux/amd64"
	linuxARM64     = "linux/arm64"
	linuxARM64v8   = "linux/arm64/v8"
	unauthorized   = "Unauthorized"
	scanOperation  = "scan"
	tooLargeReason = "TooLarge"
	internalReason = "Internal"
)

var (
	// digest is the image that the tests scan, an index whose manifests are amd64Manifest and arm64Manifest.
	digest        = "sha256:" + strings.Repeat("a", 64)
	amd64Manifest = "sha256:" + strings.Repeat("1", 64)
	arm64Manifest = "sha256:" + strings.Repeat("2", 64)
	// ended is when the scans of the tests end, on the clock of the scanner.
	ended = time.Date(2026, time.October, 31, 9, 30, 0, 0, time.UTC)
	// dockerConfig is the config.json that the fake credentials build.
	dockerConfig = []byte(`{"auths":{"artifacts.example":{"username":"team-a-puller","password":"pull-secret-password"}}}`)
	// proxyEnv is the proxy of the collector, which its Jobs get.
	proxyEnv = []corev1.EnvVar{{Name: "HTTPS_PROXY", Value: "http://proxy.example:3128"}}
)

func TestMain(m *testing.M) {
	// The SDK's server logs through slog. Its lines would only crowd the output of a test that fails.
	slog.SetDefault(slog.New(slog.DiscardHandler))
	os.Exit(m.Run())
}

// ---- the fakes ----

// fakeRunner runs no Job: each Run answers as the pod of the Job of its Spec would have, through answer. A Run waits
// for hold, when it is set, and counts as an active Job meanwhile.
type fakeRunner struct {
	answer func(s jobs.Spec) (jobs.Result, error)
	hold   chan struct{}

	mu      sync.Mutex
	specs   []jobs.Spec
	active  int
	started chan jobs.Spec
}

func newRunner(answer func(s jobs.Spec) (jobs.Result, error)) *fakeRunner {
	return &fakeRunner{answer: answer, started: make(chan jobs.Spec, 16)}
}

func (r *fakeRunner) Run(ctx context.Context, s jobs.Spec) (jobs.Result, error) {
	r.mu.Lock()
	r.specs = append(r.specs, s)
	r.active++
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.active--
		r.mu.Unlock()
	}()
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

func (r *fakeRunner) Active(context.Context, map[string]string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active, nil
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

// manifestOf is what a scan found in the manifest of the platform.
func manifestOf(platform, manifest string) result.Manifest {
	return result.Manifest{
		Platform: platform,
		Digest:   manifest,
		SBOM:     json.RawMessage(`{"artifacts":[{"id":"pkg-1","name":"libexample1","version":"1.0-1","type":"deb"}]}`),
		Packages: []result.PackageFacts{{ID: "pkg-1", FilesListed: 2, FilesPresent: 2, SharedLibraries: 1}},
		ELF:      result.ELFSummary{Total: 4, Owned: 3, Unowned: []string{"/opt/tool"}},
		Libraries: []result.Library{
			{Path: "/usr/lib/libexample.so.1", Soname: "libexample.so.1", PackageID: "pkg-1"},
		},
	}
}

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

// fakeCredentials builds the same config.json for every pod, and records the pod and repository of each call.
type fakeCredentials struct {
	mu    sync.Mutex
	calls []string
}

func (c *fakeCredentials) DockerConfig(_ context.Context, pod *corev1.Pod, repository string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, pod.Namespace+"/"+pod.Name+" "+repository)
	return dockerConfig, nil
}

// ---- the cluster ----

// node returns a node whose labels say its platform.
func node(name, arch string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
		corev1.LabelOSStable: "linux", corev1.LabelArchStable: arch,
	}}}
}

// runningPod returns a pod on the node whose container reports the digest of the image, pulled from repository. An
// empty digest is a pod whose container hasn't started.
func runningPod(name, nodeName, repository, digest string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: teamNamespace, Name: name},
		Spec: corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{
			{Name: "app", Image: repository + ":1.0"},
		}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if digest != "" {
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: "app", Image: repository + ":1.0", ImageID: repository + "@" + digest,
		}}
	}
	return pod
}

// fixture is a scanner over a fake cluster, a fake Job runner and fake credentials.
type fixture struct {
	scanner     *scan.Scanner
	runner      *fakeRunner
	credentials *fakeCredentials
}

// newFixture returns a scanner whose cluster holds the objects: by default the amd64 and arm64 nodes, and a pod on
// each that runs the digest.
func newFixture(t *testing.T, runner *fakeRunner, objs ...client.Object) *fixture {
	t.Helper()
	if objs == nil {
		objs = []client.Object{
			node(amd64Node, "amd64"), node(arm64Node, "arm64"),
			runningPod("app-0", amd64Node, repository, digest), runningPod("app-1", arm64Node, repository, digest),
		}
	}
	credentials := &fakeCredentials{}
	return &fixture{
		scanner: scan.New(scan.Options{
			Name:        collectorName,
			Version:     version,
			Image:       ownImage,
			Namespace:   ownNamespace,
			ProxyEnv:    proxyEnv,
			Client:      fake.NewClientBuilder().WithObjects(objs...).Build(),
			Credentials: credentials,
			Runner:      runner,
			SlotWait:    20 * time.Millisecond,
			Now:         func() time.Time { return ended },
		}),
		runner:      runner,
		credentials: credentials,
	}
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

func TestScanGivesOneEventPerManifestWithItsPlatformAndCoverage(t *testing.T) {
	f := newFixture(t, newRunner(scanned))

	events, failure, err := f.scanner.Invoke(t.Context(), request(""))

	require.NoError(t, err)
	require.Nil(t, failure)
	require.Len(t, events, 2)
	for i, want := range []result.Manifest{manifestOf(linuxAMD64, amd64Manifest), manifestOf(linuxARM64v8, arm64Manifest)} {
		e := events[i]
		require.NoError(t, evidence.Validate(e))
		require.Equal(t, result.EvidenceType, e.Type())
		require.Equal(t, subject.Manifest(want.Digest), e.Subject())
		require.Equal(t, "/clusters/"+clusterName+"/collectors/"+collectorName, e.Source())
		require.Equal(t, "urn:vexplain:schema:"+result.EvidenceType, e.DataSchema())
		require.True(t, e.Time().Equal(ended), "the time the scan ended")
		platform, _ := evidence.Platform(e)
		require.Equal(t, want.Platform, platform)
		coverage, ok := evidence.Coverage(e)
		require.True(t, ok)
		require.Equal(t, int32(75), coverage, "the share of the ELF files that packages own")
		raw, err := json.Marshal(want)
		require.NoError(t, err)
		require.JSONEq(t, string(raw), string(e.Data()), "the manifest's JSON, unchanged")
	}
}

// Review Focus 4: evidence that the evidence store can't hold fails the scan as TooLarge, and none of it is emitted,
// so that no verdict comes from part of the image.
func TestScanFailsAsTooLargeWhenEvidenceCompressesAboveTheCap(t *testing.T) {
	// Random bytes don't compress, so 1 MiB of them is more than a record of the evidence store holds compressed.
	noise := make([]byte, 1<<20)
	_, err := rand.Read(noise)
	require.NoError(t, err)
	sbom, err := json.Marshal(map[string]any{"artifacts": []any{}, "noise": base64.StdEncoding.EncodeToString(noise)})
	require.NoError(t, err)
	f := newFixture(t, newRunner(func(s jobs.Spec) (jobs.Result, error) {
		small, large := manifestOf(linuxAMD64, amd64Manifest), manifestOf(linuxARM64v8, arm64Manifest)
		large.SBOM = sbom
		line, err := result.Encode(result.Result{Image: argsOf(s, "--image")[0], Manifests: []result.Manifest{small, large}})
		return jobs.Result{Line: line}, err
	}))

	events, failure, err := f.scanner.Invoke(t.Context(), request(""))

	require.NoError(t, err)
	require.Empty(t, events, "not even the evidence that fits")
	require.NotNil(t, failure)
	require.Equal(t, tooLargeReason, failure.Reason)
	require.NotEmpty(t, failure.Message)
}

// A registry that refuses the credentials, or wants some, fails the scan with Unauthorized, as the scan's error line
// says.
func TestScanGivesUnauthorizedWhenTheRegistryRefusesThePull(t *testing.T) {
	f := newFixture(t, newRunner(failedFor(unauthorized)))

	events, failure, err := f.scanner.Invoke(t.Context(), request(""))

	require.NoError(t, err)
	require.Empty(t, events)
	require.Equal(t, &collector.Failure{Reason: unauthorized, Message: failure.Message}, failure)
	require.NotEmpty(t, failure.Message)
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

// A scan Job that another process of the collector runs, as one that a restart left, holds a slot too, until it has
// finished.
func TestAScanWaitsForAJobThatAnotherProcessRuns(t *testing.T) {
	runner := newRunner(scanned)
	runner.mu.Lock()
	runner.active = 1
	runner.mu.Unlock()
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
	runner.mu.Lock()
	runner.active = 0
	runner.mu.Unlock()

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
// namespace, with the credentials of the pod, the collector's proxy, the settings, and the label of vexplain's own
// pods, so that no presence collector takes its pod for a workload.
func TestTheScanJobIsWhatTheSettingsSay(t *testing.T) {
	f := newFixture(t, newRunner(scanned))
	settings := `{"scanTimeoutSeconds": 600, "workspaceMebibytes": 2048,
		"registryMirrors": [{"host": "artifacts.example", "url": "https://mirror.example"}],
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
	require.Equal(t, proxyEnv, s.Env)
	require.Equal(t, dockerConfig, s.DockerConfig)
	require.Equal(t, "2Gi", s.Workspace.String())
	require.Equal(t, 10*time.Minute, s.Deadline)
	require.Equal(t, corev1.PullAlways, s.Template.ImagePullPolicy, "scanPod.imagePullPolicy reaches the Job")
	require.Equal(t, map[string]string{"kubernetes.io/os": "linux"}, s.Template.NodeSelector)
	require.Equal(t, defaultResources(), s.Template.Resources, "the default resources, which the template leaves alone")
	require.Equal(t, map[string]string{ownPodLabel: scanOperation, "vexplain.bedag.ch/digest": strings.Repeat("a", 63)},
		s.Labels)
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

// Resources that the settings give replace the default ones.
func TestTheScanPodsResourcesReplaceTheDefault(t *testing.T) {
	f := newFixture(t, newRunner(scanned))

	_, _, err := f.scanner.Invoke(t.Context(), request(`{"scanPod": {"resources": {"limits": {"memory": "6Gi"}}}}`))

	require.NoError(t, err)
	require.Equal(t, &corev1.ResourceRequirements{
		Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("6Gi")},
	}, f.runner.ran()[0].Template.Resources)
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

func TestSettingsOutsideTheirRangesAreRefused(t *testing.T) {
	conn := serve(t, newFixture(t, newRunner(scanned)).scanner)
	for _, settings := range []string{
		`{"maxConcurrentScans": 0}`,
		`{"maxConcurrentScans": 33}`,
		`{"maxConcurrentScans": 1.5}`,
		`{"scanTimeoutSeconds": 59}`,
		`{"scanTimeoutSeconds": 21601}`,
		`{"workspaceMebibytes": 1023}`,
		`{"workspaceMebibytes": 1048577}`,
		`{"memoryLimitMebibytes": 2048}`,
		`{"scanPod": {"imagePullPolicy": "Sometimes"}}`,
		`{"scanPod": {"securityContext": {"privileged": true}}}`,
		`{"scanPod": {"resources": {"limits": {"memory": "lots"}}}}`,
		`{"registryMirrors": [{"host": "artifacts.example"}]}`,
		`{"registryMirrors": [{"host": "artifacts.example", "url": "ftp://mirror.example"}]}`,
		`{"registryMirrors": [{"host": "artifacts.example", "url": "https://mirror.example/path"}]}`,
		`{"registryMirrors": [{"host": "artifacts.example", "url": "https://user@mirror.example"}]}`,
		`{"registryMirrors": [{"host": "Artifacts Example", "url": "https://mirror.example"}]}`,
		`{"registryMirrors": [{"host": "artifacts.example", "url": "https://a.example"},` +
			` {"host": "artifacts.example", "url": "https://b.example"}]}`,
	} {
		require.NotEmpty(t, validate(t, conn, settings), settings)
	}
}

func TestSettingsAtTheEndsOfTheirRangesAreAccepted(t *testing.T) {
	conn := serve(t, newFixture(t, newRunner(scanned)).scanner)
	for _, settings := range []string{
		``,
		`{}`,
		`{"maxConcurrentScans": 1, "scanTimeoutSeconds": 60, "workspaceMebibytes": 1024}`,
		`{"maxConcurrentScans": 32, "scanTimeoutSeconds": 21600, "workspaceMebibytes": 1048576}`,
		`{"registryMirrors": [{"host": "localhost:5001", "url": "http://registry.example:5000"},` +
			` {"host": "docker.io", "url": "https://mirror.example"}]}`,
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
// scan, which consumes nothing and produces the scanner's type with scope Hub, and the permissions that the install
// binds.
func TestTheCapabilitiesOfTheScanner(t *testing.T) {
	s := newFixture(t, newRunner(scanned)).scanner

	require.Equal(t, collector.Info{Name: collectorName, Version: version}, s.Info())
	caps := s.Capabilities()
	require.Equal(t, []collector.Role{collector.RoleSpoke}, caps.Roles)
	require.False(t, caps.Watches)
	require.Empty(t, caps.Consumes)
	require.Len(t, caps.Produces, 1)
	require.Equal(t, result.EvidenceType, caps.Produces[0].Type)
	require.Equal(t, collector.ScopeHub, caps.Produces[0].Scope)
	require.Equal(t, result.Schema(), caps.Produces[0].Schema)
	require.Len(t, caps.Operations, 1)
	op := caps.Operations[0]
	require.Equal(t, scanOperation, op.Name)
	require.Equal(t, collector.RoleSpoke, op.Role)
	require.Equal(t, []string{result.EvidenceType}, op.Produces)
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
