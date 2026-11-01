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

package config_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/collectorclient"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/setup"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// maxMessageBytes is the longest condition message and event note that the deployer writes: the events API takes a
// note of 1 kB at most.
const maxMessageBytes = 1024

// These specs run against the manager that the suite starts through setup.Register, so the deployer under test is
// the production one, wired as cmd/main.go wires it. Each spec serves the collector of its Collector in the suite's
// process, and writes what envtest's missing controllers would: the status of the Deployment, and its pod.
var _ = Describe("Checking a collector", func() {
	It("records the capabilities, the version and the digest of a collector that the SDK serves, and is Healthy", func() {
		name := newCollector(helloSpec(`{"greeting": "hello"}`))
		serveSDK(name, &helloCollector{})

		By("waiting for its Deployment, without asking the collector anything")
		expectReady(name, metav1.ConditionUnknown, configv1alpha1.ReasonProgressing)

		makeAvailable(name, runningDigest)
		got, _ := expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
		Expect(got.Status.Version).To(HaveValue(Equal("1.2.3")))
		// The deployer reads the pod through the manager's cache, which may see it after the Deployment.
		Eventually(func(g Gomega) *string {
			got, _ := readyOf(name)(g)
			return got.Status.PackageDigest
		}, deployTimeout, deployPoll).Should(HaveValue(Equal(runningDigest)), "the digest that the pod reports")
		Expect(got.Status.Capabilities).To(Equal(&configv1alpha1.CollectorCapabilities{
			Roles: []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleHub, configv1alpha1.CollectorRoleSpoke},
			Produces: []configv1alpha1.ProducedType{
				{Type: greetingType, Scope: configv1alpha1.EvidenceScopeHub},
				{Type: helloType, Scope: configv1alpha1.EvidenceScopeSpoke},
			},
			Consumes: []string{helloType},
			Watch:    configv1alpha1.CollectorWatchSupported,
			Operations: []configv1alpha1.CollectorOperation{
				{Name: greet, Produces: []string{greetingType}, Consumes: []string{helloType}},
			},
		}))
		Expect(got.Status.LastSuccessTime).NotTo(BeNil(), "the health check succeeded")
		Expect(unhealthyEvents(name)(Default)).To(BeEmpty())
	})

	It("is IncompatibleAPI for a collector that speaks only v9, records none of its answer, and says so once", func() {
		f := newFakeCollector()
		f.answer(func(info *collectorv1alpha1.GetInfoResponse, _ *collectorv1alpha1.GetCapabilitiesResponse) {
			info.ApiVersions = []string{"v9"}
		})
		name := newCollector(helloSpec(""))
		serveFake(name, f)
		makeAvailable(name, runningDigest)

		got, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonIncompatibleAPI)
		Expect(ready.Message).To(And(ContainSubstring(`"v9"`), ContainSubstring("v1alpha1")))
		Expect(got.Status.Capabilities).To(BeNil())
		Expect(got.Status.Version).To(BeNil())
		Eventually(unhealthyEvents(name), deployTimeout, deployPoll).Should(HaveLen(1))
		Consistently(unhealthyEvents(name), 3*time.Second, 500*time.Millisecond).Should(HaveLen(1))
	})

	It("is PackageInvalid for a collector that declares a type outside the pattern of types, and records none of its capabilities", func() {
		f := newFakeCollector()
		f.answer(func(_ *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
			caps.Produces[0].Type = "Hello Type"
		})
		name := newCollector(helloSpec(""))
		serveFake(name, f)
		makeAvailable(name, runningDigest)

		got, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonPackageInvalid)
		Expect(ready.Message).To(ContainSubstring(`"Hello Type"`))
		Expect(got.Status.Capabilities).To(BeNil(), "nothing partial is written")

		By("recording the capabilities once the package declares types that it may")
		f.answer(func(_ *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
			caps.Produces[0].Type = helloType
		})
		got, _ = expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
		Expect(got.Status.Capabilities).NotTo(BeNil())
		Expect(got.Status.Capabilities.Produces).To(Equal([]configv1alpha1.ProducedType{
			{Type: helloType, Scope: configv1alpha1.EvidenceScopeSpoke},
		}))
	})

	It("is SettingsInvalid for settings that break the collector's schema, says where, and is Healthy once they are fixed", func() {
		name := newCollector(helloSpec(`{"greeting": 42}`))
		serveSDK(name, &helloCollector{})
		makeAvailable(name, runningDigest)

		got, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonSettingsInvalid)
		Expect(ready.Message).To(ContainSubstring("/greeting"))
		Expect(got.Status.Capabilities).NotTo(BeNil(), "the package itself is fine, so what it declares is recorded")

		Eventually(func() error {
			var obj configv1alpha1.Collector
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
				return err
			}
			obj.Spec.Settings = &runtime.RawExtension{Raw: []byte(`{"greeting": "hello"}`)}
			return k8sClient.Update(ctx, &obj)
		}, deployTimeout, deployPoll).Should(Succeed())
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
	})

	It("is SettingsInvalid when the collector's own check refuses the settings, and gives its problems", func() {
		name := newCollector(helloSpec(`{"greeting": "bonjour"}`))
		serveSDK(name, &helloCollector{refuse: func(json.RawMessage) []string {
			return []string{"the greeting must be in English"}
		}})
		makeAvailable(name, runningDigest)

		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonSettingsInvalid)
		Expect(ready.Message).To(ContainSubstring("the greeting must be in English"))
	})

	// A collector refuses the operator until it has loaded the certificate that the operator's authority issued
	// for it, so a check that fails within a grace after the certificate was issued says nothing yet. The suite's
	// clock moves past the grace.
	It("is NoData while its health checks fail within the grace, CollectorFailing after it with one event, and Healthy again once it serves", func() {
		f := newFakeCollector()
		f.serve(false)
		name := newCollector(helloSpec(""))
		serveFake(name, f)
		makeAvailable(name, runningDigest)

		got, _ := expectReady(name, metav1.ConditionUnknown, configv1alpha1.ReasonNoData)
		Expect(got.Status.Capabilities).NotTo(BeNil(), "the collector answered everything but its health")
		Consistently(func(g Gomega) string {
			_, ready := readyOf(name)(g)
			return ready.Reason
		}, 3*time.Second, 500*time.Millisecond).Should(Equal(configv1alpha1.ReasonNoData))
		Expect(unhealthyEvents(name)(Default)).To(BeEmpty())

		By("failing once the grace is over")
		clock.advance(3 * time.Minute)
		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonCollectorFailing)
		Expect(ready.Message).To(ContainSubstring("NOT_SERVING"))
		Eventually(unhealthyEvents(name), deployTimeout, deployPoll).Should(HaveLen(1))
		event := unhealthyEvents(name)(Default)[0]
		Expect(event.Type).To(Equal(corev1.EventTypeWarning))
		Expect(event.Regarding).To(And(HaveField("Kind", "Collector"), HaveField("Name", name)))
		Expect(event.Note).To(Equal(ready.Message))
		By("recording no further event, however often the deployer checks it again")
		Consistently(unhealthyEvents(name), 3*time.Second, 500*time.Millisecond).Should(HaveLen(1))

		By("being Healthy once it answers SERVING again")
		f.serve(true)
		got, _ = expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
		Expect(got.Status.LastSuccessTime).NotTo(BeNil())
		Expect(unhealthyEvents(name)(Default)).To(HaveLen(1), "recovering records no event")
	})

	// What a collector answers is its own text, and kubectl prints a condition as it is.
	It("makes the collector's text printable, and bounds it, in the condition and in the event", func() {
		f := newFakeCollector()
		f.refuseSettings("\x1b[31mred\u202e" + strings.Repeat("é", 1000))
		name := newCollector(helloSpec(""))
		serveFake(name, f)
		makeAvailable(name, runningDigest)

		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonSettingsInvalid)
		Expect(len(ready.Message)).To(BeNumerically("<=", maxMessageBytes))
		Expect(utf8.ValidString(ready.Message)).To(BeTrue())
		Expect(strings.ContainsFunc(ready.Message, func(r rune) bool { return !unicode.IsPrint(r) })).To(BeFalse(), ready.Message)
		Expect(ready.Message).To(And(ContainSubstring("[31mred"), HaveSuffix("...")))
		Eventually(unhealthyEvents(name), deployTimeout, deployPoll).Should(HaveLen(1))
		Expect(unhealthyEvents(name)(Default)[0].Note).To(Equal(ready.Message))
	})

	// Review Focus 3: a Collector is deleted while a playbook names it. Its evidence goes, and so do its entries in
	// the facts, so the findings that it covered are held open. What the deployer made for it carries it as the
	// controller owner, which the garbage collector of a real cluster follows; envtest runs none (e2e spec 19).
	It("deletes the evidence of a deleted Collector and its entries in the facts, and lets it go", func() {
		name := newCollector(helloSpec(""))
		other := apiName("other")
		Eventually(func(g Gomega) []string {
			var obj configv1alpha1.Collector
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &obj)).To(Succeed())
			return obj.Finalizers
		}, deployTimeout, deployPoll).Should(ContainElement(evidenceFinalizer))

		By("storing evidence of the collector and of another source about an image that runs")
		digest := fmt.Sprintf("sha256:%064x", nameCounter.Add(1))
		runImage(digest)
		e, err := sdkevidence.New(helloType, subject.Image(digest), map[string]string{"greeting": "hello"},
			sdkevidence.WithSource("/clusters/local/collectors/"+name))
		Expect(err).NotTo(HaveOccurred())
		noCluster := func() string { return "" }
		store := evidence.NewCRDStore(k8sClient, nil, noCluster)
		facts := evidence.NewFactsWriter(inventory.NewCRDStore(k8sClient, nil, noCluster))
		for _, source := range []string{name, other} {
			Expect(store.Put(ctx, source, "1.0.0", e)).To(Succeed())
			Expect(facts.Succeeded(ctx, digest, source, "1.0.0", []cloudevents.Event{e})).To(Succeed())
		}
		DeferCleanup(func() { Expect(store.DeleteBySource(ctx, other)).To(Succeed()) })
		Expect(facts.Failed(ctx, digest, name, "NotFound", "the image is gone from the registry")).To(Succeed())
		// The deployer reads the facts through the manager's cache.
		Eventually(cachedFactsOf(digest), deployTimeout, deployPoll).Should(HaveField("Failures", HaveLen(1)))

		By("deleting the Collector")
		Expect(k8sClient.Delete(ctx, &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: name}})).To(Succeed())
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: name}, &configv1alpha1.Collector{})
		}, deployTimeout, deployPoll).Should(Satisfy(apierrors.IsNotFound), "the finalizer lets it go")

		key := evidence.Key{Subject: subject.Image(digest), Type: helloType, Source: name}
		Expect(store.Get(ctx, key)).To(BeNil(), "its evidence is gone")
		key.Source = other
		Expect(store.Get(ctx, key)).NotTo(BeNil(), "the other source's evidence stays")
		var obj inventoryv1alpha1.ImageInventory
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj)).To(Succeed())
		Expect(obj.Status.Facts.Evidence).To(ConsistOf(HaveField("Source", other)))
		Expect(obj.Status.Facts.Failures).To(BeEmpty())
	})
})

// runImage runs a pod in a namespace of its own whose container runs the image of digest, so that the image has an
// ImageInventory, which only the presence of its digest creates. The pod is deleted when the spec ends.
func runImage(digest string) {
	GinkgoHelper()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: apiName("team")}}
	createObject(ns)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "app-0"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "artifacts.example/team-a/app:1.0"}}},
	}
	createObject(pod)
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: "app", Image: "artifacts.example/team-a/app:1.0", ImageID: "artifacts.example/team-a/app@" + digest,
	}}}
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
	Eventually(func() error {
		return k8sClient.Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &inventoryv1alpha1.ImageInventory{})
	}, deployTimeout, deployPoll).Should(Succeed())
}

// cachedFactsOf returns a function that reads the facts of the image of digest through the manager's cache.
func cachedFactsOf(digest string) func(g Gomega) *inventoryv1alpha1.ImageFacts {
	return func(g Gomega) *inventoryv1alpha1.ImageFacts {
		var obj inventoryv1alpha1.ImageInventory
		g.Expect(k8sManager.GetClient().Get(ctx, client.ObjectKey{Name: inventory.NameForDigest(digest)}, &obj)).To(Succeed())
		g.Expect(obj.Status.Facts).NotTo(BeNil())
		return obj.Status.Facts
	}
}

// --- what a collector answers to GetInfo and GetCapabilities ---

// The tests below run without the suite's API server: they check what the deployer makes of an answer, and how its
// grace works on a clock of their own.

func TestAnAnswerToGetInfoWithoutANameOrAVersionIsPackageInvalid(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*collectorv1alpha1.GetInfoResponse)
		reason string
		says   string
	}{
		"no name":                        {func(i *collectorv1alpha1.GetInfoResponse) { i.Name = "" }, configv1alpha1.ReasonPackageInvalid, "no name"},
		"no version":                     {func(i *collectorv1alpha1.GetInfoResponse) { i.Version = "" }, configv1alpha1.ReasonPackageInvalid, "no version"},
		"a version of 129 characters":    {func(i *collectorv1alpha1.GetInfoResponse) { i.Version = strings.Repeat("1", 129) }, configv1alpha1.ReasonPackageInvalid, "128"},
		"a version that isn't printable": {func(i *collectorv1alpha1.GetInfoResponse) { i.Version = "1.0\n" }, configv1alpha1.ReasonPackageInvalid, "printable"},
		"no version of the API":          {func(i *collectorv1alpha1.GetInfoResponse) { i.ApiVersions = nil }, configv1alpha1.ReasonIncompatibleAPI, "v1alpha1"},
		"only another version of the API": {func(i *collectorv1alpha1.GetInfoResponse) { i.ApiVersions = []string{"v9", "v1beta1"} },
			configv1alpha1.ReasonIncompatibleAPI, `"v9", "v1beta1"`},
	} {
		t.Run(name, func(t *testing.T) {
			info := newFakeCollector().info
			tc.change(info)

			version, reason, message := configcontroller.CheckInfo(info)

			require.Empty(t, version)
			require.Equal(t, tc.reason, reason)
			require.Contains(t, message, tc.says)
		})
	}

	version, reason, message := configcontroller.CheckInfo(&collectorv1alpha1.GetInfoResponse{
		Name: helloName, Version: "1.2.3", ApiVersions: []string{"v9", speaks},
	})
	require.Equal(t, "1.2.3", version, "a collector that also speaks another version is fine")
	require.Empty(t, reason)
	require.Empty(t, message)
}

// The schema of the Collector requires what status.capabilities holds, and bounds it. An answer that the API would
// refuse, and one that vexplain can't use, is PackageInvalid, and nothing of it is recorded: a partial answer would
// read as a collector that produces less than it does.
func TestAMalformedAnswerToGetCapabilitiesIsPackageInvalidAndNothingOfItIsRecorded(t *testing.T) {
	// What the error of each case says, at least.
	const (
		saysRole          = "role"
		saysTwice         = "twice"
		saysScope         = "scope"
		saysNoCompile     = "doesn't compile"
		saysTooMany       = "32"
		outsideThePattern = "hello"
		saysNamedHello    = `"` + outsideThePattern + `"`
	)
	typeNamed := func(n int) string { return fmt.Sprintf("com.example.type%d.v1alpha1", n) }
	for name, tc := range map[string]struct {
		change func(*collectorv1alpha1.GetCapabilitiesResponse)
		says   string
	}{
		"no role": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Roles = []collectorv1alpha1.Role{collectorv1alpha1.Role_ROLE_UNSPECIFIED}
		}, saysRole},
		"a role that no version knows": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Roles = []collectorv1alpha1.Role{7}
		}, saysRole},
		"a role listed twice": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Roles = []collectorv1alpha1.Role{collectorv1alpha1.Role_ROLE_SPOKE, collectorv1alpha1.Role_ROLE_SPOKE}
		}, saysTwice},
		"a produced type without a name": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces[0].Type = ""
		}, "without a name"},
		"a produced type outside the pattern of types": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces[0].Type = outsideThePattern
		}, saysNamedHello},
		"a produced type of 254 characters": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces[0].Type = "com." + strings.Repeat("a", 241) + ".v1alpha1"
		}, "253"},
		"a produced type without a scope": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces[0].Scope = collectorv1alpha1.Scope_SCOPE_UNSPECIFIED
		}, saysScope},
		"a scope that no version knows": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces[0].Scope = 7
		}, saysScope},
		"a produced type without a schema": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces[0].Schema = nil
		}, "no schema"},
		"a schema that isn't JSON": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces[0].Schema = []byte(`{"type":`)
		}, "schema"},
		"a schema that doesn't compile": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces[0].Schema = []byte(`{"type": 5}`)
		}, saysNoCompile},
		"a schema that refers outside itself": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces[0].Schema = []byte(`{"$ref": "https://schemas.example/hello.json"}`)
		}, saysNoCompile},
		"a produced type listed twice": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces = append(c.Produces, c.Produces[0])
		}, saysTwice},
		"33 produced types": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Produces = nil
			for i := range 33 {
				c.Produces = append(c.Produces, &collectorv1alpha1.EvidenceType{
					Type: typeNamed(i), Scope: collectorv1alpha1.Scope_SCOPE_HUB, Schema: []byte(`{}`),
				})
			}
		}, saysTooMany},
		"a consumed type outside the pattern of types": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Consumes = []string{"Findings"}
		}, `"Findings"`},
		"a consumed type listed twice": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Consumes = []string{helloType, helloType}
		}, saysTwice},
		"33 consumed types": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			for i := range 33 {
				c.Consumes = append(c.Consumes, typeNamed(i))
			}
		}, saysTooMany},
		"an operation without a name": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].Name = ""
		}, "without a name"},
		"an operation of a name of 64 characters": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].Name = strings.Repeat("o", 64)
		}, "63"},
		"an operation whose name isn't printable": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].Name = "greet\n"
		}, "printable"},
		"an operation listed twice": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations = append(c.Operations, c.Operations[0])
		}, saysTwice},
		"17 operations": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations = nil
			for i := range 17 {
				c.Operations = append(c.Operations, &collectorv1alpha1.Operation{
					Name: fmt.Sprintf("op-%d", i), Role: collectorv1alpha1.Role_ROLE_SPOKE,
				})
			}
		}, "16"},
		"an operation in a role that no version knows": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].Role = 7
		}, saysRole},
		"an operation that produces a type outside the pattern of types": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].Produces = []string{outsideThePattern}
		}, saysNamedHello},
		"an operation that consumes a type listed twice": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].Consumes = []string{helloType, helloType}
		}, saysTwice},
		"an operation that produces 33 types": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].Produces = nil
			for i := range 33 {
				c.Operations[0].Produces = append(c.Operations[0].Produces, typeNamed(i))
			}
		}, saysTooMany},
		"a parameter schema that doesn't compile": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].ParameterSchema = []byte(`{"minimum": "one"}`)
		}, saysNoCompile},
		"a settings schema that doesn't compile": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.SettingsSchema = []byte(`{"properties": []}`)
		}, saysNoCompile},
		"more permissions than the deployer checks": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			verbs := make([]string, 0, 129)
			for i := range 129 {
				verbs = append(verbs, fmt.Sprintf("verb-%d", i))
			}
			c.Permissions = []*collectorv1alpha1.PolicyRule{{ApiGroups: []string{""}, Resources: []string{"secrets"}, Verbs: verbs}}
		}, "128"},
	} {
		t.Run(name, func(t *testing.T) {
			answer := helloCapabilities()
			tc.change(answer)

			recorded, err := configcontroller.CapabilitiesOf(answer)

			require.ErrorContains(t, err, tc.says)
			require.Nil(t, recorded)
		})
	}
}

// What status.capabilities records doesn't depend on the order in which a collector lists what it declares, so a
// collector that answers in another order each time doesn't change the status each time.
func TestTheCapabilitiesAreRecordedInOrder(t *testing.T) {
	answer := &collectorv1alpha1.GetCapabilitiesResponse{
		Roles: []collectorv1alpha1.Role{collectorv1alpha1.Role_ROLE_SPOKE, collectorv1alpha1.Role_ROLE_HUB},
		Produces: []*collectorv1alpha1.EvidenceType{
			{Type: helloType, Scope: collectorv1alpha1.Scope_SCOPE_SPOKE, Schema: []byte(`{}`)},
			{Type: greetingType, Scope: collectorv1alpha1.Scope_SCOPE_HUB, Schema: []byte(`{}`)},
		},
		Consumes: []string{helloType, greetingType},
		Operations: []*collectorv1alpha1.Operation{
			{Name: "wave", Role: collectorv1alpha1.Role_ROLE_HUB, Produces: []string{helloType, greetingType}},
			{Name: greet, Role: collectorv1alpha1.Role_ROLE_SPOKE, Consumes: []string{helloType, greetingType}},
		},
	}

	recorded, err := configcontroller.CapabilitiesOf(answer)

	require.NoError(t, err)
	require.Equal(t, &configv1alpha1.CollectorCapabilities{
		Roles: []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleHub, configv1alpha1.CollectorRoleSpoke},
		Produces: []configv1alpha1.ProducedType{
			{Type: greetingType, Scope: configv1alpha1.EvidenceScopeHub},
			{Type: helloType, Scope: configv1alpha1.EvidenceScopeSpoke},
		},
		Consumes: []string{greetingType, helloType},
		Watch:    configv1alpha1.CollectorWatchNotSupported,
		Operations: []configv1alpha1.CollectorOperation{
			{Name: greet, Consumes: []string{greetingType, helloType}},
			{Name: "wave", Produces: []string{greetingType, helloType}},
		},
	}, recorded)
}

// --- the grace of the health check ---

// graceCollector is the name of the Collector of the tests of the grace.
const graceCollector = "hello"

// graceEnv is a deployer that a test reconciles itself, over a fake client, on a clock of its own, with a collector
// that the test serves.
type graceEnv struct {
	t        *testing.T
	client   client.Client
	routes   *collectorRoutes
	recorder *events.FakeRecorder
	now      time.Time
	request  ctrl.Request
	// collector is what the test serves as the collector.
	collector *fakeCollector
}

// newGraceEnv returns the environment of a test, whose Collector is named graceCollector.
func newGraceEnv(t *testing.T) *graceEnv {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, setup.AddToScheme(scheme))
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&configv1alpha1.Collector{
			ObjectMeta: metav1.ObjectMeta{Name: graceCollector, Generation: 1},
			Spec:       configv1alpha1.CollectorSpec{Package: examplePackage},
		}).
		WithStatusSubresource(&configv1alpha1.Collector{}).
		Build()
	return &graceEnv{
		t:         t,
		client:    c,
		routes:    newCollectorRoutes(),
		recorder:  events.NewFakeRecorder(16),
		now:       time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC),
		request:   ctrl.Request{NamespacedName: client.ObjectKey{Name: graceCollector}},
		collector: newFakeCollector(),
	}
}

// start returns the deployer of a new process of the operator: with an authority and a pool of its own.
func (e *graceEnv) start() *configcontroller.CollectorReconciler {
	authority := certs.NewAuthority(e.client, e.client, operatorNamespace, time.Now)
	pool := collectorclient.NewPool(authority.ClientTLS, operatorNamespace)
	pool.Dialer = e.routes.dial
	noCluster := func() string { return "" }
	return &configcontroller.CollectorReconciler{
		Client:            e.client,
		Scheme:            e.client.Scheme(),
		APIReader:         e.client,
		Recorder:          e.recorder,
		Authority:         authority,
		Pool:              pool,
		Evidence:          evidence.NewCRDStore(e.client, nil, noCluster),
		Facts:             evidence.NewFactsWriter(inventory.NewCRDStore(e.client, nil, noCluster)),
		OperatorNamespace: operatorNamespace,
		Resync:            30 * time.Second,
		Now:               func() time.Time { return e.now },
	}
}

// reconcile runs one reconcile of the Collector, and returns its Ready condition after it.
func (e *graceEnv) reconcile(r *configcontroller.CollectorReconciler) *metav1.Condition {
	e.t.Helper()
	result, err := r.Reconcile(e.t.Context(), e.request)
	require.NoError(e.t, err)
	require.Equal(e.t, 30*time.Second, result.RequeueAfter)
	var obj configv1alpha1.Collector
	require.NoError(e.t, e.client.Get(e.t.Context(), e.request.NamespacedName, &obj))
	ready := meta.FindStatusCondition(obj.Status.Conditions, configv1alpha1.ConditionReady)
	require.NotNil(e.t, ready)
	return ready
}

// makeAvailable writes the status of an available Deployment, and the pod that runs the collector.
func (e *graceEnv) makeAvailable() {
	e.t.Helper()
	var d appsv1.Deployment
	require.NoError(e.t, e.client.Get(e.t.Context(), client.ObjectKey{Namespace: operatorNamespace, Name: "vexplain-collector-hello"}, &d))
	d.Status = appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}
	require.NoError(e.t, e.client.Status().Update(e.t.Context(), &d))
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: "vexplain-collector-hello-x2k4p",
		Labels: map[string]string{collectorLabel: graceCollector}}}
	require.NoError(e.t, e.client.Create(e.t.Context(), pod))
	pod.Status = corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
		Name: collectorContainer, ImageID: "artifacts.example/vexplain/hello@" + runningDigest,
	}}}
	require.NoError(e.t, e.client.Status().Update(e.t.Context(), pod))
}

// serve serves the test's collector with the certificate that its Secret holds now, as a collector does once it
// has loaded its mounted Secret.
func (e *graceEnv) serve() {
	e.t.Helper()
	var secret corev1.Secret
	require.NoError(e.t, e.client.Get(e.t.Context(), client.ObjectKey{Namespace: operatorNamespace, Name: certs.SecretName(graceCollector)}, &secret))
	e.routes.route(graceCollector, e.collector.start(e.t, writeTLSFiles(e.t, &secret)))
}

// events returns the events recorded since the last call.
func (e *graceEnv) events() []string {
	var got []string
	for {
		select {
		case event := <-e.recorder.Events:
			got = append(got, event)
		default:
			return got
		}
	}
}

// A collector refuses the operator until it has loaded the certificate that the operator's authority issued for it,
// after a start of the operator, which issues every certificate again, or after its own certificate was issued
// again. A health check that fails within 2 minutes of either says nothing yet: Ready stays Unknown, with NoData, and
// no event is recorded. Only a check that fails after the grace makes it CollectorFailing.
func TestAFailingHealthCheckWithinTheGraceIsNoDataAndAfterItCollectorFailing(t *testing.T) {
	e := newGraceEnv(t)
	first := e.start()
	start := e.now
	require.Equal(t, configv1alpha1.ReasonProgressing, e.reconcile(first).Reason)
	e.makeAvailable()
	e.serve()
	e.collector.serve(false)

	// The checks fail within the grace after the start.
	e.now = start.Add(configcontroller.HealthGrace - time.Second)
	require.Equal(t, configv1alpha1.ReasonNoData, e.reconcile(first).Reason)
	require.Empty(t, e.events())

	// They fail after the grace.
	e.now = start.Add(configcontroller.HealthGrace)
	ready := e.reconcile(first)
	require.Equal(t, metav1.ConditionFalse, ready.Status)
	require.Equal(t, configv1alpha1.ReasonCollectorFailing, ready.Reason)
	require.Equal(t, []string{"Warning " + unhealthyReason + " " + ready.Message}, e.events())
	require.Equal(t, configv1alpha1.ReasonCollectorFailing, e.reconcile(first).Reason)
	require.Empty(t, e.events(), "the event comes with the change only")

	// The collector's certificate is issued again, which starts a grace of its own.
	require.NoError(t, e.client.Delete(t.Context(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: operatorNamespace, Name: certs.SecretName(graceCollector)}}))
	reissued := e.now
	require.Equal(t, configv1alpha1.ReasonNoData, e.reconcile(first).Reason)
	e.now = reissued.Add(configcontroller.HealthGrace - time.Second)
	require.Equal(t, configv1alpha1.ReasonNoData, e.reconcile(first).Reason)
	require.Empty(t, e.events(), "leaving False is no failure")
	e.now = reissued.Add(configcontroller.HealthGrace)
	require.Equal(t, configv1alpha1.ReasonCollectorFailing, e.reconcile(first).Reason)
	require.Len(t, e.events(), 1)

	// The collector serves.
	e.collector.serve(true)
	require.Equal(t, configv1alpha1.ReasonHealthy, e.reconcile(first).Reason)

	// A new process has a new authority, which issues the collector's certificate again, and the collector refuses
	// the new process's client until it has loaded it.
	// The operator starts again.
	second := e.start()
	restarted := e.now
	ready = e.reconcile(second)
	require.Equal(t, configv1alpha1.ReasonNoData, ready.Reason, ready.Message)
	require.Empty(t, e.events())
	e.now = restarted.Add(configcontroller.HealthGrace)
	require.Equal(t, configv1alpha1.ReasonCollectorFailing, e.reconcile(second).Reason)
	require.Len(t, e.events(), 1)

	// The collector loads the certificate that the new authority issued. The pool's connection waits a moment
	// before it connects again, as after any failure.
	e.serve()
	require.Eventually(t, func() bool { return e.reconcile(second).Reason == configv1alpha1.ReasonHealthy }, 20*time.Second,
		100*time.Millisecond)
}

// The finalizer deletes what the collector delivered, closes the pool's connection to it, and lets it go.
func TestADeletedCollectorsConnectionIsClosed(t *testing.T) {
	e := newGraceEnv(t)
	r := e.start()
	e.reconcile(r)
	e.makeAvailable()
	e.serve()
	require.Equal(t, configv1alpha1.ReasonHealthy, e.reconcile(r).Reason)
	dialed := e.routes.dials(graceCollector)

	require.NoError(t, e.client.Delete(t.Context(), &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: graceCollector}}))
	result, err := r.Reconcile(t.Context(), e.request)

	require.NoError(t, err)
	require.Zero(t, result.RequeueAfter)
	require.True(t, apierrors.IsNotFound(e.client.Get(t.Context(), e.request.NamespacedName, &configv1alpha1.Collector{})),
		"the finalizer let it go")
	require.NoError(t, r.Pool.Health(t.Context(), graceCollector))
	require.Equal(t, dialed+1, e.routes.dials(graceCollector), "a later call dials again: the connection was closed")
}
