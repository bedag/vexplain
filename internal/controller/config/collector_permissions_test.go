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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// The permissions of the specs: a verb on resources of the core group.
const (
	verbGet = "get"
	pods    = "pods"
	podLogs = "pods/log"
	nodes   = "nodes"
)

// These specs check the permissions that a collector declares against the RBAC of envtest's API server, which
// authorizes with RBAC, through SubjectAccessReviews for the collector's service account. They run in the Check mode,
// where the operator grants none: a spec binds them, as an admin would.
var _ = Describe("Checking a collector's permissions", func() {
	BeforeEach(func() {
		setPolicy(configv1alpha1.CollectorPolicy{Permissions: ptr.To(configv1alpha1.PermissionsModeCheck)})
	})

	It("is MissingPermissions while its service account lacks what the collector declares, lists what it lacks, and is Healthy once it holds it all", func() {
		f := newFakeCollector()
		f.answer(func(_ *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
			caps.Permissions = []*collectorv1alpha1.PolicyRule{
				{ApiGroups: []string{""}, Resources: []string{pods, podLogs}, Verbs: []string{verbGet}, Namespaced: true},
				{ApiGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"list", "watch"}},
			}
		})
		name := newCollector(helloSpec(""))
		serveFake(name, f)
		makeAvailable(name, runningDigest)
		account := certs.ServiceName(name)

		got, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonMissingPermissions)
		Expect(ready.Message).To(And(
			ContainSubstring(account),
			ContainSubstring("get pods in "+operatorNamespace),
			ContainSubstring("get pods/log in "+operatorNamespace),
			ContainSubstring("list deployments.apps across the cluster"),
			ContainSubstring("watch deployments.apps across the cluster"),
		))
		Expect(got.Status.Capabilities).NotTo(BeNil(), "the package itself is fine, so what it declares is recorded")
		Eventually(unhealthyEvents(name), deployTimeout, deployPoll).Should(HaveLen(1))

		By("binding a Role in the operator's namespace, which grants what the collector needs there")
		bind(account, &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: apiName("collector")},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{pods, podLogs}, Verbs: []string{verbGet}}},
		})
		Eventually(func(g Gomega) string {
			_, ready := readyOf(name)(g)
			return ready.Message
		}, deployTimeout, deployPoll).ShouldNot(ContainSubstring(pods))
		_, ready = readyOf(name)(Default)
		Expect(ready.Reason).To(Equal(configv1alpha1.ReasonMissingPermissions))
		Expect(ready.Message).To(ContainSubstring("watch deployments.apps across the cluster"))

		By("binding a ClusterRole, which grants what it needs across the cluster")
		bind(account, &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: apiName("collector")},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"list", "watch"}}},
		})
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
		Expect(unhealthyEvents(name)(Default)).To(HaveLen(1), "recovering records no event")
	})

	It("doesn't take a permission in the operator's namespace for one across the cluster", func() {
		f := newFakeCollector()
		f.answer(func(_ *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
			caps.Permissions = []*collectorv1alpha1.PolicyRule{{ApiGroups: []string{""}, Resources: []string{nodes}, Verbs: []string{verbGet}}}
		})
		name := newCollector(helloSpec(""))
		serveFake(name, f)
		makeAvailable(name, runningDigest)
		bind(certs.ServiceName(name), &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: apiName("collector")},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{nodes}, Verbs: []string{verbGet}}},
		})

		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonMissingPermissions)
		Expect(ready.Message).To(ContainSubstring("get nodes across the cluster"))
	})
})

// bind creates role, a Role or a ClusterRole, and binds it to the service account of the name in the operator's
// namespace, as an admin would. Both go when the spec ends.
func bind[R *rbacv1.Role | *rbacv1.ClusterRole](account string, role R) {
	GinkgoHelper()
	subjects := []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: operatorNamespace, Name: account}}
	switch r := any(role).(type) {
	case *rbacv1.Role:
		createObject(r)
		createObject(&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: r.Namespace, Name: r.Name},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: r.Name},
			Subjects:   subjects,
		})
	case *rbacv1.ClusterRole:
		createObject(r)
		createObject(&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: r.Name},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: r.Name},
			Subjects:   subjects,
		})
	}
}
