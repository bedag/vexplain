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
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/bedag/vexplain/internal/collector"
	"github.com/bedag/vexplain/internal/controller/scan"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/testenv"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.
//
// The specs are in the external package scan_test, because internal/setup, which the suite runs,
// imports this package.

const (
	// operatorNamespace is the namespace the manager under test runs in, where the scan Jobs run.
	operatorNamespace = "vexplain-system"
	// scannerImage is the image that the manager's scan Jobs run.
	scannerImage = "scanner.example/vexplain-scanner:1.0"
	// registryMirror is the one registry mirror that the scan Jobs are given.
	registryMirror = "artifacts.example=http://mirror.example:5000"
	// suitePassword is the password in the credentials of every scan of the suite. It must never
	// appear in a log.
	suitePassword = "suite-secret-password"

	// scanTask is the value of the task label on the scan Jobs and their pods.
	scanTask = "scan"
	// scannerContainer is the name of the container of a scan pod, and scannerCollector the name of
	// the Collector that holds the settings of the scans.
	scannerContainer = "scanner"
	scannerCollector = "scanner"
	// appPod is the name of the pod whose image a test scans, and appContainer the name of its
	// container.
	appPod       = "app-0"
	appContainer = "app"
	// amd64Node and arm64Node are the nodes of each architecture.
	amd64Node = "node-amd64"
	arm64Node = "node-arm64"
)

var (
	ctx = context.Background()
	// k8sClient reads and writes through the API server, without a cache.
	k8sClient client.Client
	// k8sManager runs the controllers, wired by setup.Register as in production.
	k8sManager ctrl.Manager
	// registry is the health registry that the runner reports into.
	registry *collector.Registry
	// queue is how the specs ask for scans, as the hub does.
	queue *scan.Queue
	// scanLogs holds the logs that the scan pods of the specs print. envtest runs no kubelet, so
	// there are no real ones.
	scanLogs *podLogs
	// pullCredentials is the source of the credentials of the scans. It records what it is asked.
	pullCredentials *recordingCredentials
	// suiteLog holds every line that the suite logs, the manager's included.
	suiteLog *logRecorder

	// proxyEnv holds the proxy variables of the manager, which every scan Job gets.
	proxyEnv = []corev1.EnvVar{
		{Name: "HTTPS_PROXY", Value: "http://proxy.example:3128"},
		{Name: "NO_PROXY", Value: "10.0.0.0/8,.cluster.local"},
	}
	// dockerConfig is the config.json of every scan of the suite.
	dockerConfig = []byte(`{"auths":{"artifacts.example":{"username":"team-a-puller","password":"` + suitePassword + `"}}}`)
)

func TestScan(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Scan Suite")
}

var _ = BeforeSuite(func() {
	suiteLog = &logRecorder{}
	logf.SetLogger(zap.New(zap.WriteTo(io.MultiWriter(GinkgoWriter, suiteLog)), zap.UseDevMode(true)))

	registry = collector.NewRegistry()
	queue = scan.NewQueue()
	scanLogs = &podLogs{logs: map[string]string{}}
	pullCredentials = &recordingCredentials{config: dockerConfig}
	env := testenv.Start(setup.Options{
		OperatorNamespace:   operatorNamespace,
		CollectorRegistry:   registry,
		ScannerImage:        scannerImage,
		ScanQueue:           queue,
		ScanLogs:            scanLogs,
		ScanCredentials:     pullCredentials,
		ProxyEnv:            proxyEnv,
		ScanRegistryMirrors: []string{registryMirror},
		// A request that waits for a free slot asks again after this, so that a spec sees the next
		// Job start within seconds.
		ScanSlotWait: time.Second,
	})
	k8sClient, k8sManager = env.Client, env.Manager

	By("creating the operator namespace, and a node of each architecture")
	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}})).To(Succeed())
	for _, arch := range []string{"amd64", "arm64"} {
		Expect(k8sClient.Create(ctx, &corev1.Node{ObjectMeta: metav1.ObjectMeta{
			Name:   "node-" + arch,
			Labels: map[string]string{corev1.LabelOSStable: "linux", corev1.LabelArchStable: arch},
		}})).To(Succeed())
	}
})

// The credentials of a scan go into the Job's Secret, and nowhere else: whatever the specs did, no
// line that the manager logged holds them.
var _ = AfterSuite(func() {
	logged := suiteLog.String()
	Expect(logged).NotTo(BeEmpty())
	for _, form := range []string{suitePassword, base64.StdEncoding.EncodeToString(dockerConfig), string(dockerConfig)} {
		Expect(logged).NotTo(ContainSubstring(form))
	}
})

// podLogs is the LogReader of the suite: the log of each scan pod, by name, as a spec sets it.
type podLogs struct {
	mu   sync.Mutex
	logs map[string]string
}

func (l *podLogs) set(pod, log string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs[pod] = log
}

// ScanLog returns the log of the pod, or an empty log, as a pod that printed nothing has. Scan pods
// run in the operator's namespace, and a pod anywhere else has no log here.
func (l *podLogs) ScanLog(_ context.Context, namespace, pod string) (string, error) {
	if namespace != operatorNamespace {
		return "", fmt.Errorf("no scan pod runs in namespace %q", namespace)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.logs[pod], nil
}

// credentialsCall is what the runner asked a CredentialSource for.
type credentialsCall struct {
	namespace, pod, repository string
}

// recordingCredentials gives every scan the same config.json, and records what it is asked.
type recordingCredentials struct {
	mu     sync.Mutex
	config []byte
	calls  []credentialsCall
}

func (c *recordingCredentials) DockerConfig(_ context.Context, pod *corev1.Pod, repository string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, credentialsCall{namespace: pod.Namespace, pod: pod.Name, repository: repository})
	return c.config, nil
}

// callsFor returns the calls that asked for the credentials of the pods in namespace.
func (c *recordingCredentials) callsFor(namespace string) []credentialsCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	var calls []credentialsCall
	for _, call := range c.calls {
		if call.namespace == namespace {
			calls = append(calls, call)
		}
	}
	return calls
}

// logRecorder keeps what a logger writes. The manager logs from many goroutines, so it is safe
// for concurrent use.
type logRecorder struct {
	mu    sync.Mutex
	lines strings.Builder
}

func (l *logRecorder) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lines.Write(p)
}

// String returns everything written so far.
func (l *logRecorder) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lines.String()
}
