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

package chain_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/testenv/imagecontents"
	"github.com/bedag/vexplain/sdk/collector"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// ---- serving the collectors ----

// collectorRoutes is where the suite serves each collector, by the address of its Service, which the manager's pool
// dials.
type collectorRoutes struct {
	mu     sync.Mutex
	routes map[string]string
}

// route makes the pool reach the collector of the name at listen.
func (r *collectorRoutes) route(name, listen string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[net.JoinHostPort(certs.ServerName(name, operatorNamespace), "9443")] = listen
}

func (r *collectorRoutes) dial(ctx context.Context, address string) (net.Conn, error) {
	r.mu.Lock()
	listen, ok := r.routes[address]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no collector is served at %s", address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", listen)
}

// collectors routes the manager's collector pool to the collectors that the suite serves.
var collectors = &collectorRoutes{routes: map[string]string{}}

// install creates the Collector of the name, as a manifest of the install does, serves c as its Deployment would
// serve it, with the certificates that the manager issued for it, and makes its Deployment available, until the
// spec ends. envtest runs no Deployment controller and no kubelet, so the status is written by hand.
func install(name string, c collector.Collector) {
	GinkgoHelper()
	pkg := "artifacts.example/collectors/" + name + ":0.1.0"
	collectorObject := &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       configv1alpha1.CollectorSpec{Package: pkg},
	}
	Expect(k8sClient.Create(ctx, collectorObject)).To(Succeed())
	DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, collectorObject))).To(Succeed()) })

	var secret corev1.Secret
	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: certs.SecretName(name)}, &secret)
	}, startup, poll).Should(Succeed())
	dir := GinkgoT().TempDir()
	for _, file := range []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey, "ca.crt"} {
		Expect(os.WriteFile(filepath.Join(dir, file), secret.Data[file], 0o600)).To(Succeed())
	}
	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	healthListener, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	serving, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- collector.Serve(serving, c, collector.Options{
			TLSDir: dir, GRPCListener: grpcListener, HealthListener: healthListener,
		})
	}()
	DeferCleanup(func() {
		cancel()
		Eventually(done, startup).Should(Receive(BeNil()))
	})
	collectors.route(name, grpcListener.Addr().String())

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: operatorNamespace, Name: certs.ServiceName(name) + "-5d8f9-x2k4p",
			Labels: map[string]string{"vexplain.bedag.ch/collector": name},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "collector", Image: pkg}}},
	}
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, pod, client.GracePeriodSeconds(0)))).To(Succeed())
	})
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "collector", Image: pkg, Ready: true,
		ImageID: "artifacts.example/collectors/" + name + "@" + digestOf(399),
	}}}
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

	key := client.ObjectKey{Namespace: operatorNamespace, Name: certs.ServiceName(name)}
	Eventually(func(g Gomega) {
		var d appsv1.Deployment
		g.Expect(k8sClient.Get(ctx, key, &d)).To(Succeed())
		d.Status = appsv1.DeploymentStatus{
			ObservedGeneration: d.Generation, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue, Reason: "MinimumReplicasAvailable"},
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
			},
		}
		g.Expect(k8sClient.Status().Update(ctx, &d)).To(Succeed())
	}, startup, poll).Should(Succeed())
}

// digestOf returns the n-th digest of the specs.
func digestOf(n int) string {
	return fmt.Sprintf("sha256:%064x", n)
}

// permissive is the schema of the data of a type that the stand-ins produce: the real collectors declare the strict one.
var permissive = []byte(`{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}`)

// ---- the workloads collector ----

// standInVersion is the version that every stand-in reports.
const standInVersion = "0.1.0"

const (
	// repository and the platform of the pod that runs each image.
	repository = "artifacts.example/team-a/web"
	platform   = "linux/arm64"
)

// workloadsStandIn stands for the workloads collector: it watches in the spoke role, and its snapshot says that a
// Deployment of team-a runs each of its images.
type workloadsStandIn struct{ images []string }

func (w *workloadsStandIn) Info() collector.Info {
	return collector.Info{Name: "workloads", Version: standInVersion}
}

func (w *workloadsStandIn) Capabilities() collector.Capabilities {
	schema, _ := sdkevidence.Schema(sdkevidence.TypePresence)
	return collector.Capabilities{
		Roles:    []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{{Type: sdkevidence.TypePresence, Scope: collector.ScopeSpoke, Schema: schema}},
		Watches:  true,
	}
}

func (w *workloadsStandIn) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	if err := sink.SnapshotStart(); err != nil {
		return err
	}
	for i, image := range w.images {
		e, err := sdkevidence.New(sdkevidence.TypePresence, subjects.Image(image), sdkevidence.Presence{
			DigestKind:   "RepoDigest",
			Repositories: []string{repository},
			Workloads: []sdkevidence.PresenceWorkload{{
				APIGroup: "apps", Kind: "Deployment", Namespace: "team-a", Name: fmt.Sprintf("web-%d", i), UID: fmt.Sprintf("uid-%d", i),
				Pods: []sdkevidence.PresencePod{{Name: fmt.Sprintf("web-%d-5d8f9-x2k4p", i), Node: "node-arm64", Platform: platform}},
			}},
		}, sdkevidence.WithSource("/clusters/"+req.Context.Cluster+"/collectors/workloads"))
		if err != nil {
			return err
		}
		if err := sink.Event(e); err != nil {
			return err
		}
	}
	if err := sink.SnapshotEnd(); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

// ---- the scanner collector ----

// scannerParameters are the parameters of scan, as the scanner declares them and the spoke's executor sends them.
const scannerParameters = `{
  "type": "object", "additionalProperties": false, "required": ["repositories"],
  "properties": {
    "repositories": {"type": "array", "minItems": 1, "items": {"type": "string"}},
    "pods": {"type": "array", "items": {"type": "object", "required": ["namespace", "name"],
      "properties": {"namespace": {"type": "string"}, "name": {"type": "string"}}}}
  }
}`

// scanCall is what the executor asked of the scanner: the image, and what the parameters named.
type scanCall struct {
	Subject      string
	Repositories []string
	Pods         []string
	Settings     string
	Role         collector.Role
}

// scannerStandIn stands for the scanner collector: it takes the spoke role, has the operation scan, which produces
// the scanner's evidence, and doesn't watch. It finds the same package in every image, in the platform manifest that
// manifestOf names for the image.
type scannerStandIn struct {
	manifestOf func(image string) string

	mu    sync.Mutex
	calls []scanCall
}

func (s *scannerStandIn) Info() collector.Info {
	return collector.Info{Name: "scanner", Version: standInVersion}
}

func (s *scannerStandIn) Capabilities() collector.Capabilities {
	return collector.Capabilities{
		Roles:    []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{{Type: imagecontents.Type, Scope: collector.ScopeHub, Schema: permissive}},
		Operations: []collector.Operation{{
			Name: "scan", Description: "Scans an image digest.", Role: collector.RoleSpoke,
			Produces: []string{imagecontents.Type}, ParameterSchema: []byte(scannerParameters),
		}},
	}
}

func (s *scannerStandIn) Invoke(_ context.Context, req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure,
	error) {
	var params struct {
		Repositories []string `json:"repositories"`
		Pods         []struct{ Namespace, Name string }
	}
	if err := json.Unmarshal(req.Parameters, &params); err != nil {
		return nil, nil, err
	}
	call := scanCall{Subject: req.Subject, Repositories: params.Repositories, Settings: string(req.Settings), Role: req.Role}
	for _, pod := range params.Pods {
		call.Pods = append(call.Pods, pod.Namespace+"/"+pod.Name)
	}
	s.mu.Lock()
	s.calls = append(s.calls, call)
	s.mu.Unlock()

	about, err := subjects.Parse(req.Subject)
	if err != nil {
		return nil, nil, err
	}
	manifest := s.manifestOf(about.Digest)
	e, err := sdkevidence.New(imagecontents.Type, subjects.Manifest(manifest), imagecontents.Manifest{
		Platform: platform,
		Digest:   manifest,
		SBOM:     json.RawMessage(`{"artifacts":[{"id":"pkg-1","name":"libexample1","version":"1.0-1","type":"deb"}]}`),
		Packages: []imagecontents.PackageFacts{{ID: packageID, FilesListed: 2, FilesPresent: 2, SharedLibraries: 1}},
		ELF:      imagecontents.ELFSummary{Total: 1, Owned: 1},
		Libraries: []imagecontents.Library{
			{Path: "/usr/lib/libexample.so.1", Soname: "libexample.so.1", PackageID: packageID},
		},
	}, sdkevidence.WithPlatform(platform), sdkevidence.WithCoverage(100),
		sdkevidence.WithSource("/clusters/"+req.Context.Cluster+"/collectors/scanner"))
	if err != nil {
		return nil, nil, err
	}
	return []cloudevents.Event{e}, nil, nil
}

// scanned returns what the executor asked of the scanner so far.
func (s *scannerStandIn) scanned() []scanCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// ---- the matcher collector ----

// matchCall is what the findings collector asked of the matcher.
type matchCall struct {
	Subject  string
	Inputs   []string
	Platform string
	Role     collector.Role
}

// matcherStandIn stands for the matcher collector: it takes the hub role, consumes the scanner's evidence and
// produces findings with the operation match, and watches only to say that its database changed. Its database is a
// version and the matches that it gives for every manifest.
type matcherStandIn struct {
	mu      sync.Mutex
	version string
	matches []sdkevidence.Match
	calls   []matchCall
	changes chan struct{}
}

func newMatcherStandIn(version string, matches ...sdkevidence.Match) *matcherStandIn {
	return &matcherStandIn{version: version, matches: matches, changes: make(chan struct{}, 16)}
}

func (m *matcherStandIn) Info() collector.Info {
	return collector.Info{Name: "matcher", Version: standInVersion}
}

func (m *matcherStandIn) Capabilities() collector.Capabilities {
	schema, _ := sdkevidence.Schema(sdkevidence.TypeFindings)
	return collector.Capabilities{
		Roles:    []collector.Role{collector.RoleHub},
		Produces: []collector.EvidenceType{{Type: sdkevidence.TypeFindings, Scope: collector.ScopeHub, Schema: schema}},
		Consumes: []string{imagecontents.Type},
		Watches:  true,
		Operations: []collector.Operation{{
			Name: "match", Description: "Matches the SBOM of a manifest.", Role: collector.RoleHub,
			Consumes: []string{imagecontents.Type}, Produces: []string{sdkevidence.TypeFindings},
		}},
	}
}

// Watch sends an empty snapshot, and then says SourceChanged whenever the database changes.
func (m *matcherStandIn) Watch(ctx context.Context, _ collector.WatchRequest, sink collector.Sink) error {
	if err := sink.SnapshotStart(); err != nil {
		return err
	}
	if err := sink.SnapshotEnd(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.changes:
			if err := sink.SourceChanged(); err != nil {
				return err
			}
		}
	}
}

func (m *matcherStandIn) Invoke(_ context.Context, req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure,
	error) {
	call := matchCall{Subject: req.Subject, Role: req.Role}
	var platform string
	for _, input := range req.Inputs {
		call.Inputs = append(call.Inputs, input.Type())
		platform, _ = sdkevidence.Platform(input)
	}
	call.Platform = platform
	m.mu.Lock()
	m.calls = append(m.calls, call)
	found := sdkevidence.Findings{Version: m.version, Matches: slices.Clone(m.matches)}
	m.mu.Unlock()
	e, err := sdkevidence.New(sdkevidence.TypeFindings, req.Subject, found, sdkevidence.WithPlatform(platform),
		sdkevidence.WithSource("/hub/collectors/matcher"))
	if err != nil {
		return nil, nil, err
	}
	return []cloudevents.Event{e}, nil, nil
}

// setDatabase changes the database to one of the version that gives the matches, and says so on the stream.
func (m *matcherStandIn) setDatabase(version string, matches ...sdkevidence.Match) {
	m.mu.Lock()
	m.version, m.matches = version, slices.Clone(matches)
	m.mu.Unlock()
	m.changes <- struct{}{}
}

// matched returns what the findings collector asked of the matcher so far.
func (m *matcherStandIn) matched() []matchCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.calls)
}
