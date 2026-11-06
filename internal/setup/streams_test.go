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
	"net"
	"os"
	"path/filepath"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/sdk/collector"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

// A collector that the specs serve in the suite's process, as its Deployment would serve it: over mutual TLS with
// the certificates that the manager's authority issued for it. The manager's collector pool reaches it through
// collectorRoutes. envtest runs no Deployment controller and no kubelet, so a spec writes the status of the
// collector's Deployment, and of the pod that reports the digest it runs.

// collectorRoutes is where the specs serve each collector, by the address of its Service, which the manager's pool
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

// collectors routes the manager's collector pool to the collectors that the specs serve.
var collectors = &collectorRoutes{routes: map[string]string{}}

// presencePackage is the package of the presence collector of the specs.
const presencePackage = "artifacts.example/collectors/presence:0.1.0"

// presenceCollector is a collector of the presence type, as the workloads collector is: it watches in the spoke role,
// and its snapshot says that a Deployment runs its image on an arm64 node. It records the context of its Watch.
type presenceCollector struct {
	digest string

	mu      sync.Mutex
	context *collector.Context
}

func (p *presenceCollector) Info() collector.Info {
	return collector.Info{Name: "presence", Version: "0.1.0"}
}

func (p *presenceCollector) Capabilities() collector.Capabilities {
	schema, _ := sdkevidence.Schema(sdkevidence.TypePresence)
	return collector.Capabilities{
		Roles: []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{
			{Type: sdkevidence.TypePresence, Scope: collector.ScopeSpoke, Schema: schema},
		},
		Watches: true,
	}
}

func (p *presenceCollector) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	p.mu.Lock()
	p.context = &req.Context
	p.mu.Unlock()
	e, err := sdkevidence.New(sdkevidence.TypePresence, subjects.Image(p.digest), sdkevidence.Presence{
		DigestKind:   "RepoDigest",
		Repositories: []string{"artifacts.example/team-a/web"},
		Workloads: []sdkevidence.PresenceWorkload{{
			APIGroup: "apps", Kind: "Deployment", Namespace: "team-a", Name: "web", UID: "uid-web",
			Pods: []sdkevidence.PresencePod{{Name: "web-5d8f9-x2k4p", Node: "node-arm64", Platform: "linux/arm64"}},
		}},
	}, sdkevidence.WithSource("/clusters/"+req.Context.Cluster+"/collectors/presence"))
	if err != nil {
		return err
	}
	for _, step := range []func() error{sink.SnapshotStart, func() error { return sink.Event(e) }, sink.SnapshotEnd} {
		if err := step(); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

// watchedWith returns the context of the collector's last Watch, or nil before its first.
func (p *presenceCollector) watchedWith() *collector.Context {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.context
}

var _ = Describe("A collector of the presence type", func() {
	It("has the presence that it streams written as this cluster's entries, until its Collector goes", func() {
		const name = "presence-a"
		digest := digestOf(301)
		presence := &presenceCollector{digest: digest}
		Expect(k8sClient.Create(ctx, &configv1alpha1.Collector{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       configv1alpha1.CollectorSpec{Package: presencePackage},
		})).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, &configv1alpha1.Collector{
				ObjectMeta: metav1.ObjectMeta{Name: name},
			}))).To(Succeed())
		})

		By("deploying it, and serving it with the certificates of its Deployment")
		serveCollector(name, presence)
		makeAvailable(name)

		By("watching it in the spoke role, with the cluster's context")
		Eventually(presence.watchedWith, startup, poll).ShouldNot(BeNil())
		watched := presence.watchedWith()
		Expect(watched.Cluster).To(Equal(settings.DefaultClusterName))
		Expect(watched.OperatorNamespace).To(Equal(operatorNamespace))
		Expect(watched.OwnPodLabel).To(Equal(workloads.TaskLabel))

		By("writing the entry of the image that its snapshot names, with the platforms of its pods")
		Eventually(func(g Gomega) {
			var obj inventoryv1alpha1.ImageInventory
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj)).To(Succeed())
			g.Expect(obj.Status.Clusters).To(HaveExactElements(And(
				HaveField("Cluster", settings.DefaultClusterName),
				HaveField("Platforms", []string{"linux/arm64"}),
				HaveField("Workloads", []inventoryv1alpha1.WorkloadReference{
					{APIGroup: ptr.To("apps"), Kind: "Deployment", Namespace: "team-a", Name: "web"},
				}),
			)))
		}, startup, poll).Should(Succeed())

		By("forgetting what it delivered once its Collector goes")
		Expect(k8sClient.Delete(ctx, &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: name}})).To(Succeed())
		Eventually(lookup(digest), startup, poll).Should(Satisfy(apierrors.IsNotFound))
	})
})

// serveCollector serves c with the SDK's server under the name of its Collector, once the manager has issued the
// certificates of its Deployment, until the spec ends, and routes the manager's pool to it.
func serveCollector(name string, c collector.Collector) {
	GinkgoHelper()
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
}

// makeAvailable creates the pod of the Collector's Deployment, which reports the digest of the image it runs, and
// writes the status of the Deployment as the Deployment controller would once that pod is available and the rollout
// has completed. The pod is deleted when the spec ends.
func makeAvailable(name string) {
	GinkgoHelper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: operatorNamespace, Name: certs.ServiceName(name) + "-5d8f9-x2k4p",
			Labels: map[string]string{"vexplain.bedag.ch/collector": name},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "collector", Image: presencePackage}}},
	}
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, pod, client.GracePeriodSeconds(0)))).To(Succeed())
	})
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "collector", Image: presencePackage, Ready: true,
		ImageID: "artifacts.example/collectors/presence@" + digestOf(399),
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
