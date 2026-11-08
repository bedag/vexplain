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
	"errors"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
	"github.com/bedag/vexplain/internal/settings"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// The ceilings, as the install names them: what the operator may grant a collector across the cluster, and what it
// may grant one in its own namespace.
const (
	ceilingName           = "vexplain-collector"
	namespacedCeilingName = "vexplain-collector-namespaced"
)

// The API groups, resources, verbs and kinds that the specs of the ceilings and the grants name.
const (
	groupApps           = "apps"
	groupBatch          = "batch"
	resourceDeployments = "deployments"
	resourceJobs        = "jobs"
	resourceSecrets     = "secrets"
	resourceConfigMaps  = "configmaps"
	verbList            = "list"
	verbWatch           = "watch"
	verbDelete          = "delete"
	kindClusterRole     = "ClusterRole"
	kindClusterBinding  = "ClusterRoleBinding"
	kindRole            = "Role"
	kindBinding         = "RoleBinding"
)

// The rules that the specs' collectors declare.
func listDeployments() *collectorv1alpha1.PolicyRule {
	return &collectorv1alpha1.PolicyRule{
		ApiGroups: []string{groupApps}, Resources: []string{resourceDeployments}, Verbs: []string{verbList, verbWatch},
	}
}

func getPodLogs() *collectorv1alpha1.PolicyRule {
	return &collectorv1alpha1.PolicyRule{
		ApiGroups: []string{""}, Resources: []string{podLogs}, Verbs: []string{verbGet}, Namespaced: true,
	}
}

// rbacRule is the RBAC rule of a declared rule.
func rbacRule(rule *collectorv1alpha1.PolicyRule) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{APIGroups: rule.GetApiGroups(), Resources: rule.GetResources(), Verbs: rule.GetVerbs()}
}

// The rules of the specs' ceilings. envtest runs no aggregation controller, so a spec writes the rules of a ceiling
// itself, where the API server would gather them from the ClusterRoles that carry the ceiling's label.
var (
	clusterCeiling = []rbacv1.PolicyRule{
		rbacRule(listDeployments()),
		{APIGroups: []string{""}, Resources: []string{resourceSecrets}, Verbs: []string{verbGet, verbList}},
		// Kinds that envtest's API server doesn't serve.
		{
			APIGroups: []string{"gateway.networking.k8s.io"}, Resources: []string{"gateways", "httproutes"},
			Verbs: []string{verbList, verbWatch},
		},
		{APIGroups: []string{"cilium.io"}, Resources: []string{"ciliumnetworkpolicies"}, Verbs: []string{verbList, verbWatch}},
	}
	namespacedCeiling = []rbacv1.PolicyRule{
		rbacRule(getPodLogs()),
		{APIGroups: []string{groupBatch}, Resources: []string{resourceJobs}, Verbs: []string{verbCreate, verbDelete}},
	}
)

// declaring returns a collector that declares the rules.
func declaring(rules ...*collectorv1alpha1.PolicyRule) *fakeCollector {
	f := newFakeCollector()
	f.answer(func(_ *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
		caps.Permissions = rules
	})
	return f
}

// running creates a Collector of spec, serves f as its collector and makes its Deployment available. It returns the
// Collector's name.
func running(spec configv1alpha1.CollectorSpec, f *fakeCollector) string {
	GinkgoHelper()
	name := newCollector(spec)
	serveFake(name, f)
	makeAvailable(name, runningDigest)
	return name
}

// grant is what the operator granted the collector of a Collector: a ClusterRole and its ClusterRoleBinding, and a
// Role and its RoleBinding in the operator's namespace, all named vexplain-collector-<name>.
type grant struct {
	clusterRole    rbacv1.ClusterRole
	clusterBinding rbacv1.ClusterRoleBinding
	role           rbacv1.Role
	binding        rbacv1.RoleBinding
}

// objects returns the objects of the grant.
func (g *grant) objects() []client.Object {
	return []client.Object{&g.clusterRole, &g.clusterBinding, &g.role, &g.binding}
}

// grantKeys returns the empty objects of the grant of the Collector of the name, with their keys.
func grantKeys(name string) *grant {
	g := &grant{}
	for _, obj := range g.objects() {
		obj.SetName(certs.ServiceName(name))
	}
	g.role.Namespace, g.binding.Namespace = operatorNamespace, operatorNamespace
	return g
}

// grantOf waits until the operator has granted the collector of the Collector of the name all four objects, and
// returns them.
func grantOf(name string) *grant {
	GinkgoHelper()
	got := grantKeys(name)
	Eventually(func(g Gomega) {
		for _, obj := range got.objects() {
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		}
	}, deployTimeout, deployPoll).Should(Succeed())
	return got
}

// versions returns a function that reads the resource version of each object of the grant of the Collector of the
// name, which changes with each write of it.
func versions(name string) func(g Gomega) []string {
	return func(g Gomega) []string {
		objects := grantKeys(name).objects()
		written := make([]string, 0, len(objects))
		for _, obj := range objects {
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
			written = append(written, obj.GetResourceVersion())
		}
		return written
	}
}

// granted returns a function that says which objects of the grant of the Collector of the name exist, by kind.
func granted(name string) func(g Gomega) []string {
	return func(g Gomega) []string {
		var kinds []string
		for _, obj := range grantKeys(name).objects() {
			err := k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)
			if apierrors.IsNotFound(err) {
				continue
			}
			g.Expect(err).NotTo(HaveOccurred())
			kinds = append(kinds, kindOf(obj))
		}
		return kinds
	}
}

// kindOf names the kind of an object of a grant.
func kindOf(obj client.Object) string {
	switch obj.(type) {
	case *rbacv1.ClusterRole:
		return kindClusterRole
	case *rbacv1.ClusterRoleBinding:
		return kindClusterBinding
	case *rbacv1.Role:
		return kindRole
	default:
		return kindBinding
	}
}

// setRules gives the ClusterRole of the name the rules.
func setRules(name string, rules []rbacv1.PolicyRule) {
	GinkgoHelper()
	Eventually(func() error {
		var role rbacv1.ClusterRole
		if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &role); err != nil {
			return err
		}
		role.Rules = rules
		return k8sClient.Update(ctx, &role)
	}, deployTimeout, deployPoll).Should(Succeed())
}

// setPolicy creates the OperatorConfig with the policy of the collectors' permissions, and deletes it when the spec
// ends.
func setPolicy(policy configv1alpha1.CollectorPolicy) {
	GinkgoHelper()
	createObject(&configv1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: settings.ConfigName},
		Spec:       configv1alpha1.OperatorConfigSpec{Collectors: &policy},
	})
}

// These specs run the deployer in the Grant mode, the default, against the ceilings that each spec creates. envtest
// runs the manager as an admin, whom the API server's escalation check lets grant anything, so what refuses a rule
// here is the operator's own check against the ceilings and the deny list.
var _ = Describe("Granting a collector's permissions", func() {
	BeforeEach(func() {
		createObject(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: ceilingName}, Rules: clusterCeiling})
		createObject(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: namespacedCeilingName}, Rules: namespacedCeiling})
	})

	It("grants what a collector declares through a ClusterRole, a Role and their bindings, labelled and owned by the Collector", func() {
		name := running(helloSpec(""), declaring(listDeployments(), getPodLogs()))

		g := grantOf(name)
		Expect(g.clusterRole.Rules).To(Equal([]rbacv1.PolicyRule{rbacRule(listDeployments())}))
		Expect(g.role.Rules).To(Equal([]rbacv1.PolicyRule{rbacRule(getPodLogs())}))
		account := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: certs.ServiceName(name), Namespace: operatorNamespace}
		Expect(g.clusterBinding.RoleRef).To(Equal(rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: kindClusterRole, Name: g.clusterRole.Name}))
		Expect(g.clusterBinding.Subjects).To(ConsistOf(account))
		Expect(g.binding.RoleRef).To(Equal(rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: kindRole, Name: g.role.Name}))
		Expect(g.binding.Subjects).To(ConsistOf(account))

		// envtest has no garbage collector, so the owner reference is what deletes the grant with its Collector.
		var owner configv1alpha1.Collector
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: name}, &owner)).To(Succeed())
		for _, obj := range g.objects() {
			Expect(obj.GetLabels()).To(HaveKeyWithValue(collectorLabel, name), kindOf(obj))
			Expect(metav1.IsControlledBy(obj, &owner)).To(BeTrue(), kindOf(obj))
		}
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)

		By("leaving the grant as it is while nothing changes, so that each check reviews it")
		written := versions(name)(Default)
		Consistently(versions(name), "3s", deployPoll).Should(Equal(written))
	})

	It("drops a rule that the collector no longer declares, and deletes the role and the binding that hold no rule", func() {
		f := declaring(listDeployments(), getPodLogs())
		name := running(helloSpec(""), f)
		grantOf(name)

		f.answer(func(_ *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
			caps.Permissions = []*collectorv1alpha1.PolicyRule{
				{ApiGroups: []string{groupApps}, Resources: []string{resourceDeployments}, Verbs: []string{verbList}},
			}
		})

		Eventually(granted(name), deployTimeout, deployPoll).Should(ConsistOf(kindClusterRole, kindClusterBinding))
		var role rbacv1.ClusterRole
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: certs.ServiceName(name)}, &role)).To(Succeed())
		Expect(role.Rules).To(Equal([]rbacv1.PolicyRule{{APIGroups: []string{groupApps}, Resources: []string{resourceDeployments}, Verbs: []string{verbList}}}))
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
	})

	It("binds the service account that a runtime config gives the collector's Deployment", func() {
		const account = "collector-identity"
		config := &configv1alpha1.CollectorRuntimeConfig{ObjectMeta: metav1.ObjectMeta{Name: apiName("runtime")}}
		config.Spec.DeploymentTemplate = &runtime.RawExtension{Raw: []byte(
			`{"spec": {"template": {"spec": {"serviceAccountName": "` + account + `"}}}}`)}
		createObject(config)
		spec := helloSpec("")
		spec.RuntimeConfigRef = &configv1alpha1.RuntimeConfigReference{Name: config.Name}

		name := running(spec, declaring(listDeployments(), getPodLogs()))

		g := grantOf(name)
		bound := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: account, Namespace: operatorNamespace}
		Expect(g.clusterBinding.Subjects).To(ConsistOf(bound))
		Expect(g.binding.Subjects).To(ConsistOf(bound))
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
	})

	It("grants a rule of the collector's own namespace that the ceiling of the whole cluster covers", func() {
		inItsNamespace := listDeployments()
		inItsNamespace.Namespaced = true

		name := running(helloSpec(""), declaring(inItsNamespace))

		Eventually(granted(name), deployTimeout, deployPoll).Should(ConsistOf(kindRole, kindBinding))
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
	})

	It("grants rules on kinds that the cluster doesn't serve, such as the Gateway API's and Cilium's", func() {
		gateways := &collectorv1alpha1.PolicyRule{ApiGroups: []string{"gateway.networking.k8s.io"},
			Resources: []string{"gateways", "httproutes"}, Verbs: []string{verbList, verbWatch}}
		cilium := &collectorv1alpha1.PolicyRule{ApiGroups: []string{"cilium.io"},
			Resources: []string{"ciliumnetworkpolicies"}, Verbs: []string{verbList, verbWatch}}

		name := running(helloSpec(""), declaring(gateways, cilium))

		Eventually(granted(name), deployTimeout, deployPoll).Should(ConsistOf(kindClusterRole, kindClusterBinding))
		var role rbacv1.ClusterRole
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: certs.ServiceName(name)}, &role)).To(Succeed())
		Expect(role.Rules).To(Equal([]rbacv1.PolicyRule{rbacRule(gateways), rbacRule(cilium)}))
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
	})

	It("refuses a rule outside the ceiling, naming the rule and the ceiling, and grants none of the collector's rules", func() {
		getConfigMaps := &collectorv1alpha1.PolicyRule{ApiGroups: []string{""}, Resources: []string{resourceConfigMaps}, Verbs: []string{verbGet}}

		name := running(helloSpec(""), declaring(listDeployments(), getConfigMaps))

		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonPermissionsNotAllowed)
		Expect(ready.Message).To(And(ContainSubstring("get configmaps across the cluster"), ContainSubstring("ceiling")))
		Expect(ready.Message).NotTo(ContainSubstring(resourceDeployments), "the rules that the ceiling allows aren't named")
		Consistently(granted(name), "2s", deployPoll).Should(BeEmpty())
	})

	It("refuses a rule of the collector's own namespace outside both ceilings, naming the namespaced ceiling", func() {
		createConfigMaps := &collectorv1alpha1.PolicyRule{ApiGroups: []string{""}, Resources: []string{resourceConfigMaps},
			Verbs: []string{verbCreate}, Namespaced: true}

		name := running(helloSpec(""), declaring(createConfigMaps))

		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonPermissionsNotAllowed)
		Expect(ready.Message).To(And(ContainSubstring("create configmaps in "+operatorNamespace), ContainSubstring("namespaced ceiling")))
		Expect(granted(name)(Default)).To(BeEmpty())
	})

	It("refuses a rule that the deny list refuses, naming the deny list, though the ceiling covers it", func() {
		listSecrets := &collectorv1alpha1.PolicyRule{ApiGroups: []string{""}, Resources: []string{resourceSecrets}, Verbs: []string{verbList}}

		name := running(helloSpec(""), declaring(listDeployments(), listSecrets))

		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonPermissionsNotAllowed)
		Expect(ready.Message).To(And(ContainSubstring("list secrets across the cluster"), ContainSubstring("deny list")))
		Expect(granted(name)(Default)).To(BeEmpty())
	})

	It("takes back a grant that the ceiling no longer covers, and grants it again once the ceiling does", func() {
		name := running(helloSpec(""), declaring(listDeployments(), getPodLogs()))
		grantOf(name)

		By("narrowing the ceiling of the whole cluster")
		setRules(ceilingName, clusterCeiling[1:])
		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonPermissionsNotAllowed)
		Expect(ready.Message).To(And(ContainSubstring("list, watch deployments.apps across the cluster"), ContainSubstring("ceiling")))
		Eventually(granted(name), deployTimeout, deployPoll).Should(BeEmpty())

		By("widening it again")
		setRules(ceilingName, clusterCeiling)
		expectReady(name, metav1.ConditionTrue, configv1alpha1.ReasonHealthy)
		Eventually(granted(name), deployTimeout, deployPoll).Should(ConsistOf(kindClusterRole, kindClusterBinding, kindRole, kindBinding))
	})

	It("takes back a grant that the deny list refuses, though the collector no longer answers what it declares", func() {
		f := declaring(listDeployments(), getPodLogs())
		name := running(helloSpec(""), f)
		grantOf(name)

		By("making the collector answer GetInfo with no version of the collector API that the operator speaks")
		f.answer(func(info *collectorv1alpha1.GetInfoResponse, _ *collectorv1alpha1.GetCapabilitiesResponse) {
			info.ApiVersions = []string{"v0"}
		})
		expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonIncompatibleAPI)

		By("denying what the collector was granted")
		setPolicy(configv1alpha1.CollectorPolicy{DeniedPermissions: []configv1alpha1.PermissionRule{
			{APIGroups: []string{groupApps}, Resources: []string{resourceDeployments}, Verbs: []string{verbWatch}},
		}})
		Eventually(granted(name), deployTimeout, deployPoll).Should(BeEmpty())
	})

	It("in the Check mode, grants nothing, takes back what it granted, and reports what the service account lacks", func() {
		name := running(helloSpec(""), declaring(listDeployments(), getPodLogs()))
		grantOf(name)

		setPolicy(configv1alpha1.CollectorPolicy{Permissions: ptr.To(configv1alpha1.PermissionsModeCheck)})

		Eventually(granted(name), deployTimeout, deployPoll).Should(BeEmpty())
		_, ready := expectReady(name, metav1.ConditionFalse, configv1alpha1.ReasonMissingPermissions)
		Expect(ready.Message).To(And(
			ContainSubstring("list deployments.apps across the cluster"),
			ContainSubstring("get pods/log in "+operatorNamespace),
		))

		By("installing another collector, which gets nothing")
		other := running(helloSpec(""), declaring(listDeployments()))
		expectReady(other, metav1.ConditionFalse, configv1alpha1.ReasonMissingPermissions)
		Expect(granted(other)(Default)).To(BeEmpty())
	})
})

// A write of a grant that the API server refuses as forbidden, as its escalation check refuses a role beyond what the
// operator holds, is PermissionsNotAllowed with the API server's message, and the operator takes back what it
// granted: the grant holds only while every rule is allowed.
func TestAGrantThatTheAPIServerRefusesIsPermissionsNotAllowed(t *testing.T) {
	clusterRoles := rbacv1.SchemeGroupVersion.WithResource("clusterroles").GroupResource()
	escalation := apierrors.NewForbidden(clusterRoles, "vexplain-collector-hello", errors.New(
		`user "system:serviceaccount:vexplain-system:vexplain-controller-manager" is attempting to grant RBAC permissions not currently held`))
	refused := func(write string) func(verb string, obj client.Object) error {
		return func(verb string, obj client.Object) error {
			if _, ok := obj.(*rbacv1.ClusterRole); ok && verb == write {
				return escalation
			}
			return nil
		}
	}
	for name, tc := range map[string]struct {
		// granted says whether the operator granted the collector its rules before the API server refuses a write.
		granted bool
		write   string
	}{
		"the create of a grant": {write: verbCreate},
		"the update of a grant": {granted: true, write: verbUpdate},
	} {
		t.Run(name, func(t *testing.T) {
			e := newGraceEnv(t)
			declareUnderACeiling(e)
			r := e.start()
			e.reconcile(r)
			e.makeAvailable()
			e.serve()
			if tc.granted {
				grantAndReview(e, r)
				e.collector.answer(func(_ *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
					caps.Permissions[0].Verbs = append(caps.Permissions[0].Verbs, verbGet)
				})
			}
			e.refuse = refused(tc.write)

			ready := e.reconcile(r)

			require.Equal(t, metav1.ConditionFalse, ready.Status)
			require.Equal(t, configv1alpha1.ReasonPermissionsNotAllowed, ready.Reason)
			require.Contains(t, ready.Message, "is attempting to grant RBAC permissions not currently held")
			e.refuse = nil
			for _, obj := range grantKeys(graceCollector).objects() {
				err := e.client.Get(t.Context(), client.ObjectKeyFromObject(obj), obj)
				require.True(t, apierrors.IsNotFound(err), "%s: %v", kindOf(obj), err)
			}
		})
	}
}

// declareUnderACeiling makes the test's collector declare listDeployments, and gives the cluster a ceiling that covers
// it, and get on Deployments too.
func declareUnderACeiling(e *graceEnv) {
	e.t.Helper()
	require.NoError(e.t, e.client.Create(e.t.Context(), &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: ceilingName},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{groupApps}, Resources: []string{resourceDeployments}, Verbs: []string{verbGet, verbList, verbWatch},
		}},
	}))
	e.collector.answer(func(_ *collectorv1alpha1.GetInfoResponse, caps *collectorv1alpha1.GetCapabilitiesResponse) {
		caps.Permissions = []*collectorv1alpha1.PolicyRule{listDeployments()}
	})
}

// grantAndReview runs the reconcile that grants the test's collector what it declares, which writes nothing and asks
// to be called again in a moment, and then the one that reviews the grant, which finds the collector Healthy.
func grantAndReview(e *graceEnv, r *configcontroller.CollectorReconciler) {
	e.t.Helper()
	result, err := r.Reconcile(e.t.Context(), e.request)
	require.NoError(e.t, err)
	require.Equal(e.t, configcontroller.GrantReview, result.RequeueAfter)
	require.Equal(e.t, configv1alpha1.ReasonHealthy, e.reconcile(r).Reason)
}

// The reconcile that changes a grant sets no Ready on the strength of the change: it writes nothing of what it found,
// and asks to be called again in a moment. The API server's authorizer learns of a grant a moment after the write, and
// the next reconcile's SubjectAccessReviews decide.
func TestTheReconcileThatChangesAGrantSetsNoReadyAndChecksAgainSoon(t *testing.T) {
	e := newGraceEnv(t)
	declareUnderACeiling(e)
	r := e.start()
	require.Equal(t, configv1alpha1.ReasonProgressing, e.reconcile(r).Reason)
	e.makeAvailable()
	e.serve()
	written := e.collectorObject().ResourceVersion

	result, err := r.Reconcile(t.Context(), e.request)

	require.NoError(t, err)
	require.Equal(t, configcontroller.GrantReview, result.RequeueAfter, "it checks again in a moment")
	require.Less(t, configcontroller.GrantReview, 30*time.Second, "sooner than the resync")
	require.Equal(t, written, e.collectorObject().ResourceVersion, "nothing of the check is written")
	require.Equal(t, configv1alpha1.ReasonProgressing, e.collectorReady().Reason)
	var role rbacv1.ClusterRole
	require.NoError(t, e.client.Get(t.Context(), client.ObjectKey{Name: certs.ServiceName(graceCollector)}, &role),
		"the grant was written")

	require.Equal(t, configv1alpha1.ReasonHealthy, e.reconcile(r).Reason, "the next reconcile reviews the grant")
}
