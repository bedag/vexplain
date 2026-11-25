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
	"fmt"
	"net"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/remote"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/testenv"
)

// The suite's manager runs the hub's Spoke controller, and these specs connect it to a spoke: a second API server,
// where the hub's ServiceAccount may read the namespaces and renew its own token, as the spoke's install grants it. The
// hub's own API server has that account too, so a Secret can point the hub at another cluster that accepts its token.
var _ = Describe("Spoke controller", Ordered, func() {
	var (
		spokeCfg *rest.Config
		spokeK8s client.Client
		spokeID  string
	)

	BeforeAll(func() {
		spokeCfg = testenv.StartAPIServer()
		var err error
		spokeK8s, err = client.New(spokeCfg, client.Options{Scheme: k8sClient.Scheme()})
		Expect(err).NotTo(HaveOccurred())
		Expect(spokeK8s.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}})).To(Succeed())
		for _, c := range []client.Client{spokeK8s, k8sClient} {
			Expect(testenv.GrantHub(ctx, c, operatorNamespace)).To(Succeed())
		}
		spokeID, err = settings.ClusterID(ctx, spokeK8s)
		Expect(err).NotTo(HaveOccurred())
	})

	// tokenOf returns a token of the hub's ServiceAccount in the cluster of c that lives 10 minutes, as an admin creates
	// the first one.
	tokenOf := func(c client.Client) string {
		GinkgoHelper()
		token, err := testenv.Token(ctx, c, operatorNamespace, testenv.HubAccount, 600)
		Expect(err).NotTo(HaveOccurred())
		return token
	}

	// credentials is what an admin puts into the admin's Secret of a spoke.
	credentials := func(server string, ca []byte, token string) map[string][]byte {
		return map[string][]byte{remote.ServerKey: []byte(server), remote.CAKey: ca, remote.TokenKey: []byte(token)}
	}

	// newSpoke creates the admin's Secret with data, and a Spoke of the name that names it, and returns the Secret.
	// Both go when the spec ends.
	newSpoke := func(name string, data map[string][]byte) *corev1.Secret {
		GinkgoHelper()
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: name + "-credentials"},
			Data: data}
		createObject(secret)
		createObject(&configv1alpha1.Spoke{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: configv1alpha1.SpokeSpec{CredentialsSecretRef: configv1alpha1.SecretReference{Name: secret.Name}}})
		return secret
	}

	// rewrite writes data into the admin's Secret, and changes the Spoke's labels. The controller reads the Secret at
	// each check, every minute, since the manager's cache holds no Secret, and a change of the Spoke brings a check at
	// once.
	rewrite := func(name string, secret *corev1.Secret, data map[string][]byte) {
		GinkgoHelper()
		secret.Data = data
		Expect(k8sClient.Update(ctx, secret)).To(Succeed())
		Eventually(func() error {
			var obj configv1alpha1.Spoke
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &obj); err != nil {
				return err
			}
			obj.Spec.Labels = map[string]configv1alpha1.LabelValue{
				"example.com/rewrite": configv1alpha1.LabelValue(fmt.Sprint(nameCounter.Add(1))),
			}
			return k8sClient.Update(ctx, &obj)
		}, deployTimeout, deployPoll).Should(Succeed())
	}

	// expectConnected waits until the controller has acted on the Spoke's generation with the Connected condition of
	// the status and reason, and returns the Spoke. Ready says what Connected says, as kstatus expects it.
	expectConnected := func(name string, want metav1.ConditionStatus, reason string) *configv1alpha1.Spoke {
		GinkgoHelper()
		got := &configv1alpha1.Spoke{}
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, got)).To(Succeed())
			g.Expect(ptr.Deref(got.Status.ObservedGeneration, 0)).To(Equal(got.Generation))
			connected := meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionConnected)
			g.Expect(connected).NotTo(BeNil())
			g.Expect(connected.Reason).To(Equal(reason), connected.Message)
			g.Expect(connected.Status).To(Equal(want))
		}, deployTimeout, deployPoll).Should(Succeed())
		ready := meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionReady)
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(want))
		Expect(ready.Reason).To(Equal(reason))
		expectConsistentConditions(got.Generation, ptr.Deref(got.Status.ObservedGeneration, 0), got.Status.Conditions)
		return got
	}

	It("records the spoke's identity at the first contact, and stops at a Secret that points at another cluster", func() {
		name := apiName("cluster-a")
		secret := newSpoke(name, credentials(spokeCfg.Host, spokeCfg.CAData, tokenOf(spokeK8s)))

		got := expectConnected(name, metav1.ConditionTrue, configv1alpha1.ReasonConnected)
		Expect(got.Status.ClusterID).To(HaveValue(Equal(spokeID)))
		Expect(got.Status.TokenExpirationTime).NotTo(BeNil())
		Expect(got.Status.TokenExpirationTime.Time).To(BeTemporally("~", time.Now().Add(10*time.Minute), time.Minute),
			"the bootstrap token, which isn't due for renewal yet")
		Expect(got.Finalizers).To(ContainElement("vexplain.bedag.ch/spoke"))
		Expect(kstatusOf(got)).To(Equal(status.CurrentStatus))

		// The Secret now points at the hub's own API server, with a token that works there.
		hubCfg := k8sManager.GetConfig()
		rewrite(name, secret, credentials(hubCfg.Host, hubCfg.CAData, tokenOf(k8sClient)))

		got = expectConnected(name, metav1.ConditionFalse, configv1alpha1.ReasonIdentityChanged)
		Expect(got.Status.ClusterID).To(HaveValue(Equal(spokeID)), "the identity of the first contact stays")
		Expect(kstatusOf(got)).To(Equal(status.FailedStatus))
	})

	It("marks a Spoke whose token expired before the hub could renew it TokenExpired, until an admin puts a new one", func() {
		name := apiName("cluster-b")
		expired := testenv.UnsignedToken(operatorNamespace, testenv.HubAccount,
			time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
		secret := newSpoke(name, credentials(spokeCfg.Host, spokeCfg.CAData, expired))

		got := expectConnected(name, metav1.ConditionFalse, configv1alpha1.ReasonTokenExpired)
		Expect(kstatusOf(got)).To(Equal(status.FailedStatus))
		for _, c := range got.Status.Conditions {
			for part := range strings.SplitSeq(expired, ".") {
				Expect(c.Message).NotTo(ContainSubstring(part), "a condition holds the token")
			}
		}

		rewrite(name, secret, credentials(spokeCfg.Host, spokeCfg.CAData, tokenOf(spokeK8s)))
		expectConnected(name, metav1.ConditionTrue, configv1alpha1.ReasonConnected)
	})

	It("marks a Spoke that can't be reached Unreachable: Reconciling within the grace, and Stalled after it", func() {
		// A port that nothing listens on.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		address := listener.Addr().String()
		Expect(listener.Close()).To(Succeed())
		name := apiName("cluster-c")
		token := testenv.UnsignedToken(operatorNamespace, testenv.HubAccount, time.Now(), time.Now().Add(time.Hour))
		secret := newSpoke(name, credentials("https://"+address, spokeCfg.CAData, token))

		got := expectConnected(name, metav1.ConditionFalse, configv1alpha1.ReasonUnreachable)
		Expect(meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionReconciling)).To(BeTrue())
		Expect(kstatusOf(got)).To(Equal(status.InProgressStatus))

		// The hub lost the spoke longer ago than the grace.
		Eventually(func() error {
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, got); err != nil {
				return err
			}
			connected := meta.FindStatusCondition(got.Status.Conditions, configv1alpha1.ConditionConnected)
			connected.LastTransitionTime = metav1.NewTime(connected.LastTransitionTime.Add(-3 * time.Minute))
			return k8sClient.Status().Update(ctx, got)
		}, deployTimeout, deployPoll).Should(Succeed())
		rewrite(name, secret, secret.Data)

		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, got)).To(Succeed())
			g.Expect(ptr.Deref(got.Status.ObservedGeneration, 0)).To(Equal(got.Generation))
			g.Expect(meta.IsStatusConditionTrue(got.Status.Conditions, configv1alpha1.ConditionStalled)).To(BeTrue())
		}, deployTimeout, deployPoll).Should(Succeed())
		Expect(kstatusOf(got)).To(Equal(status.FailedStatus))
	})

	It("marks a Spoke whose Secret is missing CredentialsInvalid, and lets it go once deleted", func() {
		name := apiName("cluster-d")
		obj := &configv1alpha1.Spoke{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: configv1alpha1.SpokeSpec{CredentialsSecretRef: configv1alpha1.SecretReference{Name: name + "-missing"}}}
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())

		got := expectConnected(name, metav1.ConditionFalse, configv1alpha1.ReasonCredentialsInvalid)
		Expect(kstatusOf(got)).To(Equal(status.FailedStatus))
		Expect(got.Finalizers).To(ContainElement("vexplain.bedag.ch/spoke"))

		Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Name: name}, &configv1alpha1.Spoke{})
		}, deployTimeout, deployPoll).Should(Satisfy(apierrors.IsNotFound))
	})
})
