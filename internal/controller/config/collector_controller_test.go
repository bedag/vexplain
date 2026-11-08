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
	"context"
	"encoding/json"
	"errors"
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
	"google.golang.org/protobuf/types/known/timestamppb"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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

// The names and values of the schedules and sources of the tests.
const (
	cronEverySixHours = "0 */6 * * *"
	cronHourly        = "0 * * * *"
	cronWeekly        = "30 2 * * 0"
	scheduleCompact   = "compact"
	scheduleRefresh   = "refresh"
	databaseSource    = "vulnerability-db"
	aboutAMissingName = "without a name"
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

	It("records the schedules and the sources of a collector, and writes the sources only when they change", func() {
		built := time.Date(2026, 11, 8, 3, 0, 0, 0, time.UTC)
		f := newFakeCollector()
		f.answer(func(info *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
			caps.Schedules = []*collectorv1alpha1.Schedule{
				{Name: scheduleRefresh, Cron: cronEverySixHours}, {Name: scheduleCompact, Cron: cronWeekly},
			}
			info.Sources = []*collectorv1alpha1.Source{
				{Name: databaseSource, Version: "v7", BuiltTime: timestamppb.New(built)},
			}
		})
		name := newCollector(helloSpec(""))
		serveFake(name, f)
		makeAvailable(name, runningDigest)

		got, _ := expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
		Expect(got.Status.Capabilities.Schedules).To(Equal([]configv1alpha1.CollectorSchedule{
			{Name: scheduleCompact, Cron: cronWeekly}, {Name: scheduleRefresh, Cron: cronEverySixHours},
		}))
		Expect(got.Status.Sources).To(ConsistOf(And(
			HaveField("Name", databaseSource),
			HaveField("Version", "v7"),
			HaveField("BuiltTime.Time", BeTemporally("==", built)))))

		By("writing nothing while the sources stay the same")
		Consistently(func(g Gomega) string {
			got, _ := readyOf(name)(g)
			return got.ResourceVersion
		}, 3*time.Second, 500*time.Millisecond).Should(Equal(got.ResourceVersion))

		By("writing the new version of a source")
		f.answer(func(info *collectorv1alpha1.GetInfoResponse, _ *collectorv1alpha1.GetCapabilitiesResponse) {
			info.Sources[0].Version = "v8"
		})
		Eventually(func(g Gomega) []configv1alpha1.CollectorSource {
			got, _ := readyOf(name)(g)
			return got.Status.Sources
		}, deployTimeout, deployPoll).Should(ConsistOf(HaveField("Version", "v8")))
	})

	It("is PackageInvalid for a collector whose sources are malformed, and records none of them", func() {
		f := newFakeCollector()
		f.answer(func(info *collectorv1alpha1.GetInfoResponse, _ *collectorv1alpha1.GetCapabilitiesResponse) {
			info.Sources = []*collectorv1alpha1.Source{{Name: databaseSource}}
		})
		name := newCollector(helloSpec(""))
		serveFake(name, f)
		makeAvailable(name, runningDigest)

		got, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonPackageInvalid)
		Expect(ready.Message).To(ContainSubstring(databaseSource))
		Expect(got.Status.Sources).To(BeEmpty())
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

	// The SDK's server answers SERVING until it stops, so a collector that crash-loops, or is killed for its memory,
	// shows as a Deployment without an available replica: it can't be reached, and after the grace it is failing.
	It("is NoData, and CollectorFailing with one event after the grace, once its Deployment has no available replica", func() {
		name := newCollector(helloSpec(""))
		serveFake(name, newFakeCollector())
		makeAvailable(name, runningDigest)
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)

		Eventually(func(g Gomega) {
			var d appsv1.Deployment
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: certs.ServiceName(name)}, &d)).To(Succeed())
			d.Status.AvailableReplicas, d.Status.ReadyReplicas = 0, 0
			g.Expect(k8sClient.Status().Update(ctx, &d)).To(Succeed())
		}, deployTimeout, deployPoll).Should(Succeed())
		expectReady(name, metav1.ConditionUnknown, configv1alpha1.ReasonNoData)
		Expect(unhealthyEvents(name)(Default)).To(BeEmpty(), "within the grace")

		clock.advance(3 * time.Minute)
		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonCollectorFailing)
		Expect(ready.Message).To(ContainSubstring("0 of 1"))
		Eventually(unhealthyEvents(name), deployTimeout, deployPoll).Should(HaveLen(1))
		Consistently(unhealthyEvents(name), 3*time.Second, 500*time.Millisecond).Should(HaveLen(1))
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
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: certs.SecretName(name)}, &corev1.Secret{})).
			To(Satisfy(apierrors.IsNotFound), "the finalizer deletes the TLS Secret, and its key, itself")
	})
})

// runImage writes an entry of this cluster for the image of digest, as the spoke's presence does once a pod runs it,
// so that the image has an ImageInventory, which only the presence of its digest creates. No presence collector
// streams to the manager of the suite, so its presence never writes one itself. The ImageInventory is deleted when
// the spec ends.
func runImage(digest string) {
	GinkgoHelper()
	store := inventory.NewCRDStore(k8sClient, nil, func() string { return "local" })
	Expect(store.Observe(ctx, digest, inventory.Observation{
		Cluster: "local", ClusterID: "local-id", DigestKind: inventoryv1alpha1.DigestKindRepoDigest,
		Repositories: []string{"artifacts.example/team-a/app"}, NamespaceCount: 1,
	})).To(Succeed())
	DeferCleanup(func() { Expect(store.Forget(ctx, digest, "local", "local-id")).To(Succeed()) })
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
		saysPrintable     = "printable"
		saysLabelLength   = "63"
	)
	// rule returns a permission rule of the groups, resources and verbs.
	rule := func(groups, resources, verbs []string) []*collectorv1alpha1.PolicyRule {
		return []*collectorv1alpha1.PolicyRule{{ApiGroups: groups, Resources: resources, Verbs: verbs}}
	}
	core, secrets, get := []string{""}, []string{"secrets"}, []string{verbGet}
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
		}, aboutAMissingName},
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
		}, aboutAMissingName},
		"an operation of a name of 64 characters": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].Name = strings.Repeat("o", 64)
		}, saysLabelLength},
		"an operation whose name isn't printable": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Operations[0].Name = "greet\n"
		}, saysPrintable},
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
		"a permission rule without an API group": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Permissions = rule(nil, secrets, get)
		}, "API group"},
		"a permission rule without a resource": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Permissions = rule(core, nil, get)
		}, "resource"},
		"a permission rule without a verb": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Permissions = rule(core, secrets, nil)
		}, "verb"},
		"a permission rule with an empty resource": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Permissions = rule(core, []string{""}, get)
		}, "resource"},
		"a permission rule with an empty verb": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Permissions = rule(core, secrets, []string{""})
		}, "verb"},
		"an API group of 254 characters": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Permissions = rule([]string{strings.Repeat("g", 254)}, secrets, get)
		}, "253"},
		"a resource of 64 characters": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Permissions = rule(core, []string{strings.Repeat("r", 64)}, get)
		}, saysLabelLength},
		"a subresource of 64 characters": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Permissions = rule(core, []string{"pods/" + strings.Repeat("s", 64)}, get)
		}, saysLabelLength},
		"a verb of 64 characters": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Permissions = rule(core, secrets, []string{strings.Repeat("v", 64)})
		}, saysLabelLength},
		"a verb that isn't printable": {func(c *collectorv1alpha1.GetCapabilitiesResponse) {
			c.Permissions = rule(core, secrets, []string{"get\x1b[31m"})
		}, saysPrintable},
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

func TestTheSchedulesAreRecordedInOrder(t *testing.T) {
	answer := helloCapabilities()
	answer.Schedules = []*collectorv1alpha1.Schedule{
		{Name: scheduleRefresh, Cron: cronEverySixHours}, {Name: scheduleCompact, Cron: cronWeekly},
	}

	recorded, err := configcontroller.CapabilitiesOf(answer)

	require.NoError(t, err)
	require.Equal(t, []configv1alpha1.CollectorSchedule{
		{Name: scheduleCompact, Cron: cronWeekly}, {Name: scheduleRefresh, Cron: cronEverySixHours},
	}, recorded.Schedules)
}

func TestMalformedSchedulesAreRefused(t *testing.T) {
	many := make([]*collectorv1alpha1.Schedule, 9)
	for i := range many {
		many[i] = &collectorv1alpha1.Schedule{Name: fmt.Sprintf("schedule-%d", i), Cron: cronHourly}
	}
	tests := map[string]struct {
		schedules []*collectorv1alpha1.Schedule
		says      string
	}{
		"a schedule without a name": {[]*collectorv1alpha1.Schedule{{Cron: cronHourly}}, aboutAMissingName},
		"a schedule without a cron": {[]*collectorv1alpha1.Schedule{{Name: scheduleRefresh}}, `"refresh"`},
		"a name that isn't printable": {
			[]*collectorv1alpha1.Schedule{{Name: "re\x07fresh", Cron: cronHourly}}, "printable"},
		"a name that is too long": {
			[]*collectorv1alpha1.Schedule{{Name: strings.Repeat("a", 64), Cron: cronHourly}}, "63"},
		"a cron that is too long": {
			[]*collectorv1alpha1.Schedule{{Name: scheduleRefresh, Cron: strings.Repeat("*", 129)}}, "128"},
		"a name twice": {
			[]*collectorv1alpha1.Schedule{{Name: scheduleRefresh, Cron: cronHourly}, {Name: scheduleRefresh, Cron: "1 * * * *"}}, "twice"},
		"more schedules than the status holds": {many, "more than the 8"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			answer := helloCapabilities()
			answer.Schedules = tc.schedules

			recorded, err := configcontroller.CapabilitiesOf(answer)

			require.ErrorContains(t, err, tc.says)
			require.Nil(t, recorded)
		})
	}
}

func TestTheSourcesAreRecordedInOrderInWholeSeconds(t *testing.T) {
	built := time.Date(2026, 11, 8, 3, 0, 0, 500, time.UTC)
	info := newFakeCollector().info
	info.Sources = []*collectorv1alpha1.Source{
		{Name: databaseSource, Version: "v7", BuiltTime: timestamppb.New(built)},
		{Name: "advisories", Version: "2026-11-01"},
	}

	sources, reason, message := configcontroller.SourcesOf(info)

	require.Empty(t, reason, message)
	require.Equal(t, []configv1alpha1.CollectorSource{
		{Name: "advisories", Version: "2026-11-01"},
		{Name: databaseSource, Version: "v7", BuiltTime: ptr.To(metav1.NewTime(built.Truncate(time.Second)))},
	}, sources)
}

func TestMalformedSourcesArePackageInvalid(t *testing.T) {
	many := make([]*collectorv1alpha1.Source, 9)
	for i := range many {
		many[i] = &collectorv1alpha1.Source{Name: fmt.Sprintf("source-%d", i), Version: "v1"}
	}
	tests := map[string]struct {
		sources []*collectorv1alpha1.Source
		says    string
	}{
		"a source without a name":    {[]*collectorv1alpha1.Source{{Version: "v1"}}, aboutAMissingName},
		"a source without a version": {[]*collectorv1alpha1.Source{{Name: databaseSource}}, "\"" + databaseSource + "\""},
		"a version that is too long": {
			[]*collectorv1alpha1.Source{{Name: databaseSource, Version: strings.Repeat("v", 129)}}, "128"},
		"a name twice": {
			[]*collectorv1alpha1.Source{{Name: "a", Version: "1"}, {Name: "a", Version: "2"}}, "twice"},
		"more sources than the status holds": {many, "more than the 8"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			info := newFakeCollector().info
			info.Sources = tc.sources

			sources, reason, message := configcontroller.SourcesOf(info)

			require.Equal(t, configv1alpha1.ReasonPackageInvalid, reason)
			require.Contains(t, message, tc.says)
			require.Nil(t, sources)
		})
	}
}

// --- the grace of the health check ---

// graceCollector is the name of the Collector of the tests of the grace.
const graceCollector = "hello"

// The verbs of the fake client's calls that a test of the grace can refuse.
const (
	verbGetObject = "get"
	verbUpdate    = "update"
	verbCreate    = "create"
)

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
	// refuse, when a test sets it, answers each get, create and update of the fake client first: an error that it
	// returns is the API server's answer.
	refuse func(verb string, obj client.Object) error
	// secretReads counts the reads of the collector's TLS Secret.
	secretReads int
	// scheduleClock is the clock of the deployer's scheduler, which a test moves, and whose rounds it runs itself.
	scheduleClock *clocktesting.FakeClock
}

// newGraceEnv returns the environment of a test, whose Collector is named graceCollector.
func newGraceEnv(t *testing.T) *graceEnv {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, setup.AddToScheme(scheme))
	e := &graceEnv{
		t:             t,
		routes:        newCollectorRoutes(),
		recorder:      events.NewFakeRecorder(16),
		now:           time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC),
		request:       ctrl.Request{NamespacedName: client.ObjectKey{Name: graceCollector}},
		collector:     newFakeCollector(),
		scheduleClock: clocktesting.NewFakeClock(time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)),
	}
	answer := func(verb string, obj client.Object) error {
		if _, ok := obj.(*corev1.Secret); ok && verb == verbGetObject {
			e.secretReads++
		}
		if e.refuse == nil {
			return nil
		}
		return e.refuse(verb, obj)
	}
	e.client = fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&configv1alpha1.Collector{
			ObjectMeta: metav1.ObjectMeta{Name: graceCollector, Generation: 1},
			Spec:       configv1alpha1.CollectorSpec{Package: examplePackage},
		}).
		WithStatusSubresource(&configv1alpha1.Collector{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if err := answer(verbGetObject, obj); err != nil {
					return err
				}
				return c.Get(ctx, key, obj, opts...)
			},
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if err := answer(verbCreate, obj); err != nil {
					return err
				}
				// The fake client would keep a review as an object, and answer nothing: here each review allows what it
				// asks, as RBAC does once the operator has granted it.
				if review, ok := obj.(*authorizationv1.SubjectAccessReview); ok {
					review.Status.Allowed = true
					return nil
				}
				return c.Create(ctx, obj, opts...)
			},
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if err := answer(verbUpdate, obj); err != nil {
					return err
				}
				return c.Update(ctx, obj, opts...)
			},
		}).
		Build()
	return e
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
		Scheduler: configcontroller.NewScheduler(pool, collectorclient.ClusterContext(e.client, operatorNamespace),
			30*time.Second, e.scheduleClock),
	}
}

// reconcile runs one reconcile of the Collector, and returns its Ready condition after it.
func (e *graceEnv) reconcile(r *configcontroller.CollectorReconciler) *metav1.Condition {
	e.t.Helper()
	result, err := r.Reconcile(e.t.Context(), e.request)
	require.NoError(e.t, err)
	require.Equal(e.t, 30*time.Second, result.RequeueAfter)
	return e.collectorReady()
}

// reconcileFailing runs one reconcile of the Collector, which must fail, and returns the Ready condition after it,
// and the error.
func (e *graceEnv) reconcileFailing(r *configcontroller.CollectorReconciler) (*metav1.Condition, error) {
	e.t.Helper()
	_, err := r.Reconcile(e.t.Context(), e.request)
	require.Error(e.t, err)
	return e.collectorReady(), err
}

// collectorReady returns the Collector's Ready condition.
func (e *graceEnv) collectorReady() *metav1.Condition {
	e.t.Helper()
	ready := meta.FindStatusCondition(e.collectorObject().Status.Conditions, configv1alpha1.ConditionReady)
	require.NotNil(e.t, ready)
	return ready
}

// collectorObject reads the Collector, past the test's refusals.
func (e *graceEnv) collectorObject() *configv1alpha1.Collector {
	e.t.Helper()
	refuse := e.refuse
	e.refuse = nil
	defer func() { e.refuse = refuse }()
	var obj configv1alpha1.Collector
	require.NoError(e.t, e.client.Get(e.t.Context(), e.request.NamespacedName, &obj))
	return &obj
}

// makeAvailable writes the status of an available Deployment, and the pod that runs the collector, whose container
// reports that it runs the package of the Collector at runningDigest.
func (e *graceEnv) makeAvailable() {
	e.t.Helper()
	e.makeAvailableReporting("artifacts.example/vexplain/hello@" + runningDigest)
}

// rolledOut are the conditions of a Deployment whose rollout completed, as the Deployment controller sets them: its
// Progressing condition keeps that reason until the next rollout.
var rolledOut = []appsv1.DeploymentCondition{{
	Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable",
	Message: `ReplicaSet "vexplain-collector-hello-5d8f9" has successfully progressed.`,
}}

// makeAvailableReporting is makeAvailable, with the pod's container reporting imageID.
func (e *graceEnv) makeAvailableReporting(imageID string) {
	e.t.Helper()
	e.setDeploymentStatus(func(d *appsv1.Deployment) appsv1.DeploymentStatus {
		return appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1,
			Conditions: rolledOut}
	})
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: "vexplain-collector-hello-x2k4p",
		Labels: map[string]string{collectorLabel: graceCollector}}}
	require.NoError(e.t, e.client.Create(e.t.Context(), pod))
	pod.Status = corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: collectorContainer, ImageID: imageID}}}
	require.NoError(e.t, e.client.Status().Update(e.t.Context(), pod))
}

// setDeploymentStatus writes the status that status returns for the collector's Deployment, as the Deployment
// controller would.
func (e *graceEnv) setDeploymentStatus(status func(*appsv1.Deployment) appsv1.DeploymentStatus) {
	e.t.Helper()
	var d appsv1.Deployment
	require.NoError(e.t, e.client.Get(e.t.Context(), client.ObjectKey{Namespace: operatorNamespace, Name: "vexplain-collector-hello"}, &d))
	d.Status = status(&d)
	require.NoError(e.t, e.client.Status().Update(e.t.Context(), &d))
}

// healthy brings the Collector to Ready True: it reconciles once to deploy it, makes its Deployment available, serves
// the collector, and reconciles again.
func (e *graceEnv) healthy(r *configcontroller.CollectorReconciler) {
	e.t.Helper()
	e.reconcile(r)
	e.makeAvailable()
	e.serve()
	require.Equal(e.t, configv1alpha1.ReasonHealthy, e.reconcile(r).Reason)
}

// changePackage changes the Collector's package, as an upgrade does, so that the deployer writes its Deployment again.
func (e *graceEnv) changePackage(pkg string) {
	e.t.Helper()
	obj := e.collectorObject()
	obj.Spec.Package = pkg
	require.NoError(e.t, e.client.Update(e.t.Context(), obj))
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

// The finalizer deletes what the collector delivered, and its TLS Secret, whose key nothing else then deletes when the
// Secret never got its owner. It closes the pool's connection to the collector, and lets the Collector go.
func TestADeletedCollectorsSecretGoesAndItsConnectionIsClosed(t *testing.T) {
	e := newGraceEnv(t)
	r := e.start()
	e.healthy(r)
	dialed := e.routes.dials(graceCollector)
	// The Secret lost its owner, as when the write of its owner failed and the Collector was deleted before a retry.
	var secret corev1.Secret
	require.NoError(t, e.client.Get(t.Context(), client.ObjectKey{Namespace: operatorNamespace, Name: certs.SecretName(graceCollector)}, &secret))
	secret.OwnerReferences = nil
	require.NoError(t, e.client.Update(t.Context(), &secret))

	require.NoError(t, e.client.Delete(t.Context(), &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: graceCollector}}))
	result, err := r.Reconcile(t.Context(), e.request)

	require.NoError(t, err)
	require.Zero(t, result.RequeueAfter)
	require.True(t, apierrors.IsNotFound(e.client.Get(t.Context(), e.request.NamespacedName, &configv1alpha1.Collector{})),
		"the finalizer let it go")
	require.True(t, apierrors.IsNotFound(e.client.Get(t.Context(),
		client.ObjectKey{Namespace: operatorNamespace, Name: certs.SecretName(graceCollector)}, &corev1.Secret{})),
		"the finalizer deleted the TLS Secret")
	require.NoError(t, r.Pool.Health(t.Context(), graceCollector))
	require.Equal(t, dialed+1, e.routes.dials(graceCollector), "a later call dials again: the connection was closed")
}

// A collector whose Deployment has rolled out, and whose pod is no longer available, as when it crash-loops or is
// killed for its memory, can't be reached: the grace, then CollectorFailing and the event. So is one whose rollout has
// exceeded its progress deadline.
func TestACollectorWhoseDeploymentIsNoLongerAvailableIsFailingAfterTheGrace(t *testing.T) {
	for name, status := range map[string]func(*appsv1.Deployment) appsv1.DeploymentStatus{
		"no replica available after the rollout completed": func(d *appsv1.Deployment) appsv1.DeploymentStatus {
			return appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 1, UpdatedReplicas: 1, Conditions: rolledOut}
		},
		"a progress deadline exceeded": func(d *appsv1.Deployment) appsv1.DeploymentStatus {
			return appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 2, UpdatedReplicas: 1, AvailableReplicas: 1,
				Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse,
					Reason: "ProgressDeadlineExceeded", Message: `ReplicaSet "vexplain-collector-hello-5d8f9" has timed out progressing.`}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newGraceEnv(t)
			r := e.start()
			start := e.now
			e.healthy(r)

			e.setDeploymentStatus(status)
			ready := e.reconcile(r)
			require.Equal(t, configv1alpha1.ReasonNoData, ready.Reason, "within the grace")
			require.Contains(t, ready.Message, configcontroller.HealthGrace.String(), "the message gives the grace")
			require.Contains(t, ready.Message, "Deployment", "and what the check found")
			require.NotContains(t, ready.Message, "may not have loaded", "a Deployment's failure is none of the certificate's")
			require.Empty(t, e.events())
			e.now = start.Add(configcontroller.HealthGrace)
			ready = e.reconcile(r)

			require.Equal(t, metav1.ConditionFalse, ready.Status)
			require.Equal(t, configv1alpha1.ReasonCollectorFailing, ready.Reason, ready.Message)
			require.Contains(t, ready.Message, "Deployment")
			require.Equal(t, []string{"Warning " + unhealthyReason + " " + ready.Message}, e.events())
			require.False(t, collectorclient.Usable(e.collectorObject()))
		})
	}
}

// A pod that is still starting is no failure, as kubectl's rollout status waits for it, however long it takes past
// the grace: a start that never finishes shows as the rollout's progress deadline, which is one.
func TestAPodThatIsStillStartingIsProgressingPastTheGrace(t *testing.T) {
	e := newGraceEnv(t)
	r := e.start()
	start := e.now
	require.Equal(t, configv1alpha1.ReasonProgressing, e.reconcile(r).Reason)
	e.setDeploymentStatus(func(d *appsv1.Deployment) appsv1.DeploymentStatus {
		return appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 1, UpdatedReplicas: 1,
			Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "ReplicaSetUpdated"}}}
	})

	e.now = start.Add(configcontroller.HealthGrace + time.Minute)
	ready := e.reconcile(r)

	require.Equal(t, metav1.ConditionUnknown, ready.Status)
	require.Equal(t, configv1alpha1.ReasonProgressing, ready.Reason)
	require.Empty(t, e.events())
}

// An error that may pass when the deployer tries again leaves Ready as it was, but not for ever: once such errors have
// gone on for longer than the grace, as from a webhook that can't be called, the deployer can't say that the
// collector works, and it is failing. A reconcile that succeeds ends the run of errors.
func TestATransientErrorThatLastsPastTheGraceIsAFailure(t *testing.T) {
	e := newGraceEnv(t)
	r := e.start()
	e.healthy(r)
	e.now = e.now.Add(configcontroller.HealthGrace)
	unavailable := apierrors.NewInternalError(errors.New(`failed calling webhook "policy.example": context deadline exceeded`))
	refuseUpdates := func(verb string, obj client.Object) error {
		if _, ok := obj.(*appsv1.Deployment); ok && verb == verbUpdate {
			return unavailable
		}
		return nil
	}
	e.changePackage("artifacts.example/vexplain/hello:0.2.0")
	e.refuse = refuseUpdates
	failingSince := e.now

	ready, err := e.reconcileFailing(r)
	require.True(t, apierrors.IsInternalError(err), err)
	require.Equal(t, configv1alpha1.ReasonHealthy, ready.Reason, "an error that may pass leaves Ready as it was")
	e.now = failingSince.Add(configcontroller.HealthGrace - time.Second)
	ready, _ = e.reconcileFailing(r)
	require.Equal(t, configv1alpha1.ReasonHealthy, ready.Reason, "within the grace")
	require.Empty(t, e.events())

	e.now = failingSince.Add(configcontroller.HealthGrace)
	ready, err = e.reconcileFailing(r)
	require.True(t, apierrors.IsInternalError(err), "the error is still returned, for the retry")
	require.Equal(t, metav1.ConditionFalse, ready.Status)
	require.Equal(t, configv1alpha1.ReasonCollectorFailing, ready.Reason)
	require.Contains(t, ready.Message, "failed calling webhook")
	require.Len(t, e.events(), 1)
	e.now = e.now.Add(time.Minute)
	ready, _ = e.reconcileFailing(r)
	require.Equal(t, configv1alpha1.ReasonCollectorFailing, ready.Reason)
	require.Empty(t, e.events(), "the event comes with the change only")

	// The webhook answers again: the reconcile succeeds, and a later run of errors starts a grace of its own.
	e.refuse = nil
	e.reconcile(r)
	e.setDeploymentStatus(func(d *appsv1.Deployment) appsv1.DeploymentStatus {
		return appsv1.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1,
			Conditions: rolledOut}
	})
	require.Equal(t, configv1alpha1.ReasonHealthy, e.reconcile(r).Reason)
	e.changePackage("artifacts.example/vexplain/hello:0.3.0")
	e.refuse = refuseUpdates
	ready, _ = e.reconcileFailing(r)
	require.Equal(t, configv1alpha1.ReasonHealthy, ready.Reason)
}

// A reconcile that fails isn't tried again later than the resync, whatever controller-runtime's back-off would wait,
// up to 16 minutes: a run of errors that turns a collector failing shows within the grace and a resync, and so does
// its end.
func TestAnErrorIsTriedAgainAtLeastAsOftenAsTheDeployerResyncs(t *testing.T) {
	limiter := configcontroller.RetryLimiter(30 * time.Second)
	request := ctrl.Request{NamespacedName: client.ObjectKey{Name: graceCollector}}

	require.Equal(t, 5*time.Millisecond, limiter.When(request), "a conflict is tried again at once")
	var last time.Duration
	for range 30 {
		last = limiter.When(request)
	}

	require.Equal(t, 30*time.Second, last)
}

// A write of what the runtime config shapes that the API server refuses, as invalid, as a bad request, or as
// forbidden by admission or a quota, is RuntimeConfigInvalid with the API server's message: no retry changes it.
func TestAWriteThatTheAPIServerRefusesIsRuntimeConfigInvalid(t *testing.T) {
	deployments := appsv1.SchemeGroupVersion.WithResource("deployments").GroupResource()
	for name, refusal := range map[string]error{
		"forbidden by a quota": apierrors.NewForbidden(deployments, "vexplain-collector-hello",
			errors.New("exceeded quota: collectors, requested: count/deployments.apps=1, used: count/deployments.apps=1, limited: count/deployments.apps=1")),
		"refused by an admission webhook": apierrors.NewBadRequest(
			`admission webhook "policy.example" denied the request: images must come from artifacts.example`),
	} {
		t.Run(name, func(t *testing.T) {
			e := newGraceEnv(t)
			r := e.start()
			e.healthy(r)
			e.changePackage("artifacts.example/vexplain/hello:0.2.0")
			e.refuse = func(verb string, obj client.Object) error {
				if _, ok := obj.(*appsv1.Deployment); ok && verb == verbUpdate {
					return refusal
				}
				return nil
			}

			ready := e.reconcile(r)

			require.Equal(t, metav1.ConditionFalse, ready.Status)
			require.Equal(t, configv1alpha1.ReasonRuntimeConfigInvalid, ready.Reason)
			require.Contains(t, ready.Message, refusal.Error())
			require.Len(t, e.events(), 1)
		})
	}
}

// An error that keeps the deployer from checking the collector, and that trying again won't fix, leaves Ready no
// longer True: the deployer can't say that the collector works. One that trying again may fix, such as a conflict with
// another write, leaves Ready as it was.
func TestAnErrorBeforeTheChecksLeavesReadyNotTrueUnlessItMayPass(t *testing.T) {
	configs := configv1alpha1.GroupVersion.WithResource("collectorruntimeconfigs").GroupResource()
	e := newGraceEnv(t)
	r := e.start()
	e.healthy(r)
	e.now = e.now.Add(configcontroller.HealthGrace)

	e.changePackage("artifacts.example/vexplain/hello:0.2.0")
	e.refuse = func(verb string, obj client.Object) error {
		if _, ok := obj.(*appsv1.Deployment); ok && verb == verbUpdate {
			return apierrors.NewConflict(appsv1.SchemeGroupVersion.WithResource("deployments").GroupResource(),
				"vexplain-collector-hello", errors.New("the object has been modified"))
		}
		return nil
	}
	ready, err := e.reconcileFailing(r)
	require.True(t, apierrors.IsConflict(err), err)
	require.Equal(t, configv1alpha1.ReasonHealthy, ready.Reason, "a conflict may pass when the deployer tries again")
	require.Empty(t, e.events())

	e.refuse = func(verb string, obj client.Object) error {
		if _, ok := obj.(*configv1alpha1.CollectorRuntimeConfig); ok && verb == verbGetObject {
			return apierrors.NewForbidden(configs, "default", errors.New(`User "system:serviceaccount:vexplain-system:controller-manager" cannot get resource "collectorruntimeconfigs"`))
		}
		return nil
	}
	ready, err = e.reconcileFailing(r)
	require.True(t, apierrors.IsForbidden(err), err)
	require.NotEqual(t, metav1.ConditionTrue, ready.Status, "the deployer can't say that the collector works")
	require.Equal(t, configv1alpha1.ReasonCollectorFailing, ready.Reason)
	require.Len(t, e.events(), 1)
}

// The status of a healthy collector isn't written at every resync: its last success time is written when it turns
// healthy, and when the time that the status holds is more than 5 minutes old.
func TestTheLastSuccessTimeIsWrittenOnAChangeAndWhenItIsFiveMinutesOld(t *testing.T) {
	e := newGraceEnv(t)
	r := e.start()
	healthyAt := e.now
	e.healthy(r)
	lastSuccess := func() time.Time {
		t.Helper()
		obj := e.collectorObject()
		require.NotNil(t, obj.Status.LastSuccessTime)
		return obj.Status.LastSuccessTime.Time
	}
	require.True(t, lastSuccess().Equal(healthyAt))
	written := e.collectorObject().ResourceVersion

	e.now = healthyAt.Add(time.Minute)
	e.reconcile(r)
	require.Equal(t, written, e.collectorObject().ResourceVersion, "nothing changed but the time of the success")
	require.True(t, lastSuccess().Equal(healthyAt))

	e.now = healthyAt.Add(5*time.Minute + time.Second)
	e.reconcile(r)
	require.True(t, lastSuccess().Equal(e.now), "the time is more than 5 minutes old")

	// After a failure, the next success is written at once.
	refreshed := e.now
	e.now = refreshed.Add(configcontroller.HealthGrace)
	e.collector.serve(false)
	require.Equal(t, configv1alpha1.ReasonCollectorFailing, e.reconcile(r).Reason)
	e.now = e.now.Add(10 * time.Second)
	e.collector.serve(true)
	require.Equal(t, configv1alpha1.ReasonHealthy, e.reconcile(r).Reason)
	require.True(t, lastSuccess().Equal(e.now))
}

// The deployer reads the TLS Secret for its labels and owner until it has them, and not at every resync after.
func TestTheTLSSecretIsReadForItsOwnerOnlyUntilItHasIt(t *testing.T) {
	e := newGraceEnv(t)
	r := e.start()
	e.healthy(r)
	e.secretReads = 0

	for range 3 {
		e.reconcile(r)
	}

	require.Equal(t, 3, e.secretReads, "the authority reads it at each check, and nothing else does")
}

// A bare image ID is the digest of the image's configuration, which no registry serves, and not the package's
// digest, so the status records none.
func TestAPodThatReportsABareImageIDGivesNoPackageDigest(t *testing.T) {
	e := newGraceEnv(t)
	r := e.start()
	e.reconcile(r)
	e.makeAvailableReporting(runningDigest)
	e.serve()

	require.Equal(t, configv1alpha1.ReasonHealthy, e.reconcile(r).Reason)
	require.Nil(t, e.collectorObject().Status.PackageDigest)
}

// How far the rollout of a collector's Deployment has got: still in progress, failed, or done. A rollout that is still
// in progress says nothing about the collector, and a failed one is a collector that can't be reached.
func TestTheRolloutOfADeployment(t *testing.T) {
	deployment := func(status appsv1.DeploymentStatus) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Generation: 2},
			Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](1)},
			Status:     status,
		}
	}
	deadline := []appsv1.DeploymentCondition{{
		Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded",
		Message: `ReplicaSet "vexplain-collector-hello-5d8f9" has timed out progressing.`,
	}}
	starting := []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "ReplicaSetUpdated"}}
	for name, tc := range map[string]struct {
		status     appsv1.DeploymentStatus
		inProgress bool
		failure    string
	}{
		"available": {status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}},
		"a spec that the Deployment controller hasn't seen": {inProgress: true,
			status: appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1, Conditions: deadline}},
		"no updated replica yet": {inProgress: true, status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 1, AvailableReplicas: 1}},
		"an older replica left": {inProgress: true,
			status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 2, UpdatedReplicas: 1, AvailableReplicas: 1}},
		"the progress deadline exceeded": {failure: "timed out progressing",
			status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 2, UpdatedReplicas: 1, AvailableReplicas: 1, Conditions: deadline}},
		"no replica available after the rollout completed": {failure: "0 of 1",
			status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 1, UpdatedReplicas: 1, Conditions: rolledOut}},
		"a replica that is still starting": {inProgress: true,
			status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 1, UpdatedReplicas: 1, Conditions: starting}},
		"a replica that is still starting, and no Progressing condition": {inProgress: true,
			status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 1, UpdatedReplicas: 1}},
	} {
		t.Run(name, func(t *testing.T) {
			inProgress, failure := configcontroller.RolloutOf(deployment(tc.status))

			require.Equal(t, tc.inProgress, inProgress)
			if tc.failure == "" {
				require.NoError(t, failure)
			} else {
				require.ErrorContains(t, failure, tc.failure)
			}
		})
	}
}
