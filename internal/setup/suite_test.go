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

package setup_test

import (
	"context"
	"fmt"
	"io"
	"slices"
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

	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/testenv"
)

// These specs use Ginkgo (BDD-style Go testing framework). Refer to http://onsi.github.io/ginkgo/
// to learn more about Ginkgo.
//
// They run a manager that setup.Register wires without a scanner image and without a matcher, as
// cmd/main.go wires one whose environment names neither, and check what it leaves out. The suite
// is a test binary of its own, so its log holds the lines of that one manager only.

const (
	// operatorNamespace is the namespace the manager runs in.
	operatorNamespace = "vexplain-system"

	startup = 30 * time.Second
	poll    = 100 * time.Millisecond
	// quiet is how long a spec watches for something that must not happen.
	quiet = 3 * time.Second
)

var (
	ctx = context.Background()
	// k8sClient reads and writes through the API server, without a cache.
	k8sClient client.Client
	// k8sManager is the manager under test.
	k8sManager ctrl.Manager
	// requests records the scans that the hub asks for.
	requests *recordingExecutor
	// suiteLog holds every line that the suite logs, the manager's included.
	suiteLog *logRecorder
)

func TestSetup(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Setup Suite")
}

var _ = BeforeSuite(func() {
	suiteLog = &logRecorder{}
	logf.SetLogger(zap.New(zap.WriteTo(io.MultiWriter(GinkgoWriter, suiteLog)), zap.UseDevMode(true)))

	requests = &recordingExecutor{}
	env := testenv.Start(setup.Options{
		OperatorNamespace: operatorNamespace,
		// The Collector controller reads the registry once per resync, so a short one lets a spec see
		// a reported health within seconds.
		CollectorResync: time.Second,
		// The hub would ask for scans here, where a spec sees each request.
		ScanExecutor: requests,
	})
	k8sClient, k8sManager = env.Client, env.Manager

	By("creating the operator namespace")
	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}})).To(Succeed())
})

// recordingExecutor records the scans that the hub asks for.
type recordingExecutor struct {
	mu       sync.Mutex
	requests []tasks.ScanRequest
}

func (e *recordingExecutor) RequestScan(_ context.Context, req tasks.ScanRequest) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requests = append(e.requests, req)
	return nil
}

// taken returns the requests that the executor took.
func (e *recordingExecutor) taken() []tasks.ScanRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.requests)
}

// logRecorder keeps everything that is written to it.
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

// newNamespace creates a namespace for the workloads of a spec, and returns its name once the
// manager's cache holds it, so that the pod inventory reads its labels at the first reconcile of a
// pod in it.
func newNamespace(name string) string {
	GinkgoHelper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	Expect(k8sClient.Create(ctx, ns)).To(Succeed())
	Eventually(func() error {
		return k8sManager.GetClient().Get(ctx, client.ObjectKeyFromObject(ns), &corev1.Namespace{})
	}, startup, poll).Should(Succeed())
	return ns.Name
}

// runPod creates a pod named name whose container runs the image that the runtime reports as
// imageID, and writes its status as a kubelet would.
func runPod(namespace, name, imageID string) {
	GinkgoHelper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "artifacts.example/team-a/app:1.0"}}},
	}
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "app", Image: "artifacts.example/team-a/app:1.0", ImageID: imageID,
	}}}
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
}

// digestOf returns the n-th digest of the specs.
func digestOf(n int) string {
	return fmt.Sprintf("sha256:%064x", n)
}
