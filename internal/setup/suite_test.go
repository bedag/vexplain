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

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/testenv"
)

// These specs use Ginkgo (BDD-style Go testing framework). Refer to http://onsi.github.io/ginkgo/
// to learn more about Ginkgo.
//
// They run a manager that setup.Register wires with no Playbook installed, and check what it leaves
// out, and how it runs the collectors that the specs serve. The chain from presence to a sheet,
// through the production wiring, is in the package chain. The suite is a test binary of its own, so its log holds the lines of that one manager
// only.

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
	// requests records the evidence that the hub asks for.
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
		// The Collector controller checks each collector once per resync, so a short one lets a spec
		// see a change within seconds.
		CollectorResync: time.Second,
		// The hub would ask for evidence here, where a spec sees each request.
		Executor: requests,
		// The pool reaches the collectors that the specs serve in this process.
		CollectorDialer: collectors.dial,
	})
	k8sClient, k8sManager = env.Client, env.Manager

	By("creating the operator namespace")
	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}})).To(Succeed())
})

// recordingExecutor records the evidence that the hub asks for.
type recordingExecutor struct {
	mu       sync.Mutex
	requests []tasks.Request
}

func (e *recordingExecutor) Request(_ context.Context, req tasks.Request) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requests = append(e.requests, req)
	return nil
}

// taken returns the requests that the executor took.
func (e *recordingExecutor) taken() []tasks.Request {
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

// otherCluster is a cluster whose spoke writes presence to the manager's inventory, as the hub of
// several clusters gets it. Its entries are its own: the manager's presence, which keeps the
// entries of the manager's cluster, never forgets them.
const otherCluster = "cluster-b"

// observeElsewhere writes the entry of otherCluster for digest, as its spoke does once a pod runs
// the image, pulled from the repositories, or an image ID without one. It forgets the entry, and
// with it the object, after the spec.
func observeElsewhere(digest string, repositories ...string) {
	GinkgoHelper()
	store := inventory.NewCRDStore(k8sClient, nil, func() string { return otherCluster })
	kind := inventoryv1alpha1.DigestKindImageID
	if len(repositories) > 0 {
		kind = inventoryv1alpha1.DigestKindRepoDigest
	}
	Expect(store.Observe(ctx, digest, inventory.Observation{
		Cluster: otherCluster, ClusterID: otherCluster + "-id", DigestKind: kind, Repositories: repositories,
		NamespaceCount: 1,
	})).To(Succeed())
	DeferCleanup(func() { Expect(store.Forget(ctx, digest, otherCluster, otherCluster+"-id")).To(Succeed()) })
}

// digestOf returns the n-th digest of the specs.
func digestOf(n int) string {
	return fmt.Sprintf("sha256:%064x", n)
}
