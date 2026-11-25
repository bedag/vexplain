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

package modes_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/testenv"
	"github.com/bedag/vexplain/sdk/collector"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// These specs start a manager in each mode, one after the other, and check which parts of the production wiring run:
// what a mode leaves out does nothing, even where the objects that it works on exist.

const (
	operatorNamespace = "vexplain-system"
	presencePackage   = "artifacts.example/collectors/presence:0.1.0"
	startup           = 60 * time.Second
	poll              = 100 * time.Millisecond
	// quiet is how long a spec watches for something that must not happen.
	quiet = 3 * time.Second
	// vmType is the type of the subjects of the spec's playbook.
	vmType       = "com.example.vm.v1alpha1"
	playbookName = "vm-cves"
)

func TestModes(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Setup modes suite")
}

// routes is where the specs serve each collector, by the address of its Service, which the manager's pool dials.
var routes = struct {
	sync.Mutex
	m map[string]string
}{m: map[string]string{}}

func dial(ctx context.Context, address string) (net.Conn, error) {
	routes.Lock()
	listen, ok := routes.m[address]
	routes.Unlock()
	if !ok {
		return nil, fmt.Errorf("no collector is served at %s", address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", listen)
}

// start starts a manager in the mode, on an API server of its own, and returns a client of that server.
func start(mode setup.Mode) client.Client {
	GinkgoHelper()
	env := testenv.Start(setup.Options{OperatorNamespace: operatorNamespace, Mode: mode, CollectorResync: time.Second,
		CollectorDialer: dial})
	Expect(env.Client.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}})).To(Succeed())
	return env.Client
}

// presenceCollector watches, and its snapshot says that a Deployment runs its image. It takes the spoke role, and the
// hub role too when hubToo is set.
type presenceCollector struct {
	digest string
	hubToo bool

	mu      sync.Mutex
	watched map[collector.Role]bool
}

// watchedIn says whether the manager opened a Watch of the role.
func (p *presenceCollector) watchedIn(role collector.Role) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.watched[role]
}

func (p *presenceCollector) Info() collector.Info {
	return collector.Info{Name: "presence", Version: "0.1.0"}
}

func (p *presenceCollector) Capabilities() collector.Capabilities {
	schema, _ := sdkevidence.Schema(sdkevidence.TypePresence)
	roles := []collector.Role{collector.RoleSpoke}
	if p.hubToo {
		roles = append(roles, collector.RoleHub)
	}
	return collector.Capabilities{
		Roles: roles,
		Produces: []collector.EvidenceType{
			{Type: sdkevidence.TypePresence, Scope: collector.ScopeSpoke, Schema: schema},
		},
		Watches: true,
	}
}

func (p *presenceCollector) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	p.mu.Lock()
	if p.watched == nil {
		p.watched = map[collector.Role]bool{}
	}
	p.watched[req.Role] = true
	p.mu.Unlock()
	if req.Role != collector.RoleSpoke {
		<-ctx.Done()
		return ctx.Err()
	}
	e, err := sdkevidence.New(sdkevidence.TypePresence, subjects.Image(p.digest), sdkevidence.Presence{
		DigestKind:   "RepoDigest",
		Repositories: []string{"artifacts.example/team-a/web"},
		Workloads: []sdkevidence.PresenceWorkload{{
			Subject:  "workload/cluster-a/team-a/Deployment.apps/web",
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

// deploy creates the Collector of the presence collector, serves it with the certificates that the manager issued for
// its Deployment, and makes the Deployment available, as the Deployment controller would.
func deploy(k8s client.Client, name string, c collector.Collector) {
	GinkgoHelper()
	ctx := context.Background()
	Expect(k8s.Create(ctx, &configv1alpha1.Collector{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       configv1alpha1.CollectorSpec{Package: ptr.To(presencePackage)},
	})).To(Succeed())

	var secret corev1.Secret
	Eventually(func() error {
		return k8s.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: certs.SecretName(name)}, &secret)
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
	routes.Lock()
	routes.m[net.JoinHostPort(certs.ServerName(name, operatorNamespace), "9443")] = grpcListener.Addr().String()
	routes.Unlock()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: operatorNamespace, Name: certs.ServiceName(name) + "-5d8f9-x2k4p",
			Labels: map[string]string{"vexplain.bedag.ch/collector": name},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "collector", Image: presencePackage}}},
	}
	Expect(k8s.Create(ctx, pod)).To(Succeed())
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "collector", Image: presencePackage, Ready: true,
		ImageID: "artifacts.example/collectors/presence@" + digestOf(399),
	}}}
	Expect(k8s.Status().Update(ctx, pod)).To(Succeed())
	Eventually(func(g Gomega) {
		var d appsv1.Deployment
		g.Expect(k8s.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: certs.ServiceName(name)}, &d)).To(Succeed())
		d.Status = appsv1.DeploymentStatus{
			ObservedGeneration: d.Generation, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue, Reason: "MinimumReplicasAvailable"},
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
			},
		}
		g.Expect(k8s.Status().Update(ctx, &d)).To(Succeed())
	}, startup, poll).Should(Succeed())
}

func digestOf(n int) string { return fmt.Sprintf("sha256:%064x", n) }

// entry returns a lookup of the ImageInventory of the digest.
func entry(k8s client.Client, digest string) func() error {
	return func() error {
		var obj inventoryv1alpha1.ImageInventory
		return k8s.Get(context.Background(), client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj)
	}
}

var _ = Describe("The modes", func() {
	ctx := context.Background()

	It("has Spoke write presence, and judge nothing", func() {
		k8s := start(setup.ModeSpoke)
		digest := digestOf(301)
		deploy(k8s, "presence-a", &presenceCollector{digest: digest})

		Eventually(entry(k8s, digest), startup, poll).Should(Succeed())

		// A playbook and a Spoke are the hub's: nothing reconciles them in a spoke.
		holdRule(k8s)
		playbook := &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: playbookName}, Spec: vmPlaybook("hold")}
		Expect(k8s.Create(ctx, playbook)).To(Succeed())
		Expect(k8s.Create(ctx, newSpoke())).To(Succeed())
		Consistently(func(g Gomega) {
			var got configv1alpha1.Playbook
			g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(playbook), &got)).To(Succeed())
			g.Expect(got.Status.Conditions).To(BeEmpty())
			var spoke configv1alpha1.Spoke
			g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(newSpoke()), &spoke)).To(Succeed())
			g.Expect(spoke.Status.Conditions).To(BeEmpty())
			var verdicts inventoryv1alpha1.ImageVerdictsList
			g.Expect(k8s.List(ctx, &verdicts)).To(Succeed())
			g.Expect(verdicts.Items).To(BeEmpty())
		}, quiet, poll).Should(Succeed())
	})

	It("has Hub reconcile playbooks, and write no presence", func() {
		k8s := start(setup.ModeHub)
		digest := digestOf(302)
		// A collector of both roles is usable here, so only the missing spoke sink keeps its presence out.
		presence := &presenceCollector{digest: digest, hubToo: true}
		deploy(k8s, "presence-b", presence)

		holdRule(k8s)
		// The hub's controller judges a playbook, which turns Ready False here, for it has no producers.
		Expect(k8s.Create(ctx, &configv1alpha1.Playbook{ObjectMeta: metav1.ObjectMeta{Name: playbookName},
			Spec: vmPlaybook("hold")})).To(Succeed())
		Eventually(func(g Gomega) {
			var got configv1alpha1.Playbook
			g.Expect(k8s.Get(ctx, client.ObjectKey{Name: playbookName}, &got)).To(Succeed())
			g.Expect(got.Status.Conditions).To(ContainElement(And(
				HaveField("Type", configv1alpha1.ConditionReady), HaveField("Reason", configv1alpha1.ReasonTypeNotProduced))))
		}, startup, poll).Should(Succeed())
		// The hub connects to its spokes: this Spoke's Secret is missing.
		Expect(k8s.Create(ctx, newSpoke())).To(Succeed())
		Eventually(func(g Gomega) {
			var got configv1alpha1.Spoke
			g.Expect(k8s.Get(ctx, client.ObjectKeyFromObject(newSpoke()), &got)).To(Succeed())
			g.Expect(got.Status.Conditions).To(ContainElement(And(HaveField("Type", configv1alpha1.ConditionConnected),
				HaveField("Reason", configv1alpha1.ReasonCredentialsInvalid))))
		}, startup, poll).Should(Succeed())

		Eventually(func(g Gomega) {
			var got configv1alpha1.Collector
			g.Expect(k8s.Get(ctx, client.ObjectKey{Name: "presence-b"}, &got)).To(Succeed())
			g.Expect(got.Status.Conditions).To(ContainElement(And(
				HaveField("Type", configv1alpha1.ConditionReady), HaveField("Reason", configv1alpha1.ReasonHealthy))))
		}, startup, poll).Should(Succeed())
		// Its streams run, in the hub role, and none opens in the spoke role.
		Eventually(func() bool { return presence.watchedIn(collector.RoleHub) }, startup, poll).Should(BeTrue())
		Consistently(func() bool { return presence.watchedIn(collector.RoleSpoke) }, quiet, poll).Should(BeFalse())
		Expect(entry(k8s, digest)()).To(Satisfy(apierrors.IsNotFound))
	})
})

// holdRule creates a rule that holds every finding open, which a playbook's pipeline names.
func holdRule(k8s client.Client) {
	GinkgoHelper()
	Expect(k8s.Create(context.Background(), &configv1alpha1.Rule{
		ObjectMeta: metav1.ObjectMeta{Name: "hold"},
		Spec: configv1alpha1.RuleSpec{Condition: "true",
			Outcome: &configv1alpha1.RuleOutcome{Status: ptr.To(configv1alpha1.VEXStatusUnderInvestigation)}},
	})).To(Succeed())
}

// newSpoke returns the Spoke of the specs, whose Secret doesn't exist.
func newSpoke() *configv1alpha1.Spoke {
	return &configv1alpha1.Spoke{ObjectMeta: metav1.ObjectMeta{Name: "cluster-b"},
		Spec: configv1alpha1.SpokeSpec{CredentialsSecretRef: configv1alpha1.SecretReference{Name: "cluster-b-credentials"}}}
}

// vmPlaybook is a playbook whose pipeline is the rules.
func vmPlaybook(rules ...string) configv1alpha1.PlaybookSpec {
	spec := configv1alpha1.PlaybookSpec{
		Subjects: configv1alpha1.PlaybookSource{Type: vmType},
		Findings: configv1alpha1.PlaybookFindings{Type: ptr.To(sdkevidence.TypeFindings)},
		Evidence: []configv1alpha1.PlaybookEvidence{{Name: "machineSbom", Type: sdkevidence.TypeSBOM}},
	}
	for _, rule := range rules {
		spec.Pipeline = append(spec.Pipeline, configv1alpha1.PlaybookStep{Rule: rule})
	}
	return spec
}
