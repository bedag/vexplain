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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collectorclient/mcptest"
)

// An MCP collector names a server that runs elsewhere (design of the agent on image cases, 5.9). The deployer deploys
// nothing for it: it connects with the headers of the Collector's labelled Secrets, lists the server's tools, and is
// Ready while the server serves every tool on the Collector's list. The specs' server runs in the suite's process, over
// TLS with the certificate of every test server, which the client of the suite's manager trusts.
var _ = Describe("An MCP collector", func() {
	// token is what the specs' server takes, and refusedToken one that it refuses, echoing it.
	const (
		token        = "token-of-the-wiki-mcp-server"
		refusedToken = "token-that-the-wiki-mcp-server-refuses"
		// labelled is the value of the label that lets the operator read a Secret of headers.
		labelled = "true"
	)
	var server *mcptest.Server
	BeforeEach(func() {
		server = mcptest.NewServer(token)
		DeferCleanup(server.Close)
	})

	// headers creates a Secret of headers that sends the token, with the label vexplain.bedag.ch/mcp-headers: "true"
	// when labelled, and returns its name.
	headers := func(value string, usable bool) string {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: apiName("wiki-mcp"), Namespace: operatorNamespace},
			StringData: map[string]string{"Authorization": "Bearer " + value}}
		if usable {
			secret.Labels = map[string]string{configv1alpha1.MCPHeadersLabel: labelled}
		}
		createObject(secret)
		return secret.Name
	}
	// collector creates a Collector of the specs' server with the Secret of headers and the list of tools, and returns
	// its name.
	collector := func(secret string, tools ...string) string {
		obj := &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: apiName("wiki")},
			Spec: configv1alpha1.CollectorSpec{MCP: &configv1alpha1.CollectorMCP{URL: server.Endpoint(), Tools: tools,
				HeadersFrom: []configv1alpha1.MCPHeaders{{SecretRef: configv1alpha1.SecretReference{Name: secret}}}}}}
		createObject(obj)
		return obj.Name
	}

	It("is Ready while its server serves every tool on its list, and gets nothing deployed", func() {
		name := collector(headers(token, true), mcptest.Search, mcptest.GetPage)

		got, ready := expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
		Expect(ready.Message).To(ContainSubstring("serves every tool"))
		Expect(got.Status.Capabilities).To(BeNil(), "an MCP collector streams nothing and runs no operation")
		Expect(got.Status.LastSuccessTime).NotTo(BeNil())
		Expect(server.Calls(mcptest.Search)+server.Calls(mcptest.GetPage)).To(BeZero(), "the check calls no tool")

		By("finding no Deployment, Service or TLS Secret of it")
		objects := "vexplain-collector-" + name
		for _, obj := range []client.Object{&appsv1.Deployment{}, &corev1.Service{}, &corev1.ServiceAccount{}} {
			err := k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: objects}, obj)
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), "%T: %v", obj, err)
		}
		err := k8sClient.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: objects + "-tls"}, &corev1.Secret{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "the TLS Secret: %v", err)
	})

	It("is Ready=False with ToolsMissing, naming the tool, while its server lacks a tool on its list", func() {
		name := collector(headers(token, true), mcptest.Search, "rename_page")

		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonToolsMissing)
		Expect(ready.Message).To(ContainSubstring("rename_page"))
		Expect(ready.Message).NotTo(ContainSubstring(mcptest.Search))
		Eventually(unhealthyEvents(name), deployTimeout, deployPoll).Should(HaveLen(1))
	})

	It("doesn't read a Secret of headers without the label, and sends the server nothing", func() {
		name := collector(headers(token, false), mcptest.Search)

		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonCollectorFailing)
		Expect(ready.Message).To(And(ContainSubstring(configv1alpha1.MCPHeadersLabel), ContainSubstring("doesn't exist")))
		Expect(server.Requests()).To(BeZero())
	})

	It("never shows its headers in its status, an event or the log, even when its server echoes them", func() {
		name := collector(headers(refusedToken, true), mcptest.Search)

		got, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonCollectorFailing)
		Expect(ready.Message).To(ContainSubstring("unauthorized: [withheld]"), "the server's error echoed the token")
		Expect(server.Requests()).To(BeNumerically(">=", 1), "the server got the token, and echoed it")
		Eventually(unhealthyEvents(name), deployTimeout, deployPoll).Should(HaveLen(1))

		object, err := json.Marshal(got)
		Expect(err).NotTo(HaveOccurred())
		var all eventsv1.EventList
		Expect(k8sClient.List(ctx, &all)).To(Succeed())
		everyEvent, err := json.Marshal(all)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(object)).NotTo(ContainSubstring(refusedToken))
		Expect(string(everyEvent)).NotTo(ContainSubstring(refusedToken))
		Expect(suiteLog.String()).NotTo(ContainSubstring(refusedToken))
	})
})
