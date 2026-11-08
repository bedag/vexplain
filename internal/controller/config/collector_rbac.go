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

package config

import (
	"context"
	"fmt"
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/evidence"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// The deployer grants each collector the permissions that it declares, within the ceilings and outside the deny list
// (decision 0041): ClusterRoles and their bindings in the whole cluster, and Roles and their bindings in the operator's
// namespace alone. It reads the ceilings, ClusterRoles too, through the API reader. It never holds the escalate or the
// bind verb, so the API server's escalation check refuses it any role beyond what it holds: the ceilings, and its own
// rights. Markers generate no bindings: config/rbac/manager_secrets_rolebinding.yaml binds the Role.
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete,namespace=vexplain-system

// grantObjects are the objects through which the operator grants a collector what it declares, each named
// vexplain-collector-<name>, as the collector's service account is: a ClusterRole and its ClusterRoleBinding for
// what it needs in the whole cluster, and a Role and its RoleBinding, in the operator's namespace, for what it needs
// there.
type grantObjects struct {
	clusterRole    *rbacv1.ClusterRole
	clusterBinding *rbacv1.ClusterRoleBinding
	role           *rbacv1.Role
	binding        *rbacv1.RoleBinding
}

// grantObjectsOf returns the objects of the grant of a collector, empty but for their names.
func (r *CollectorReconciler) grantObjectsOf(collector string) grantObjects {
	name := certs.ServiceName(collector)
	return grantObjects{
		clusterRole:    &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}},
		clusterBinding: &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}},
		role:           &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Namespace: r.OperatorNamespace, Name: name}},
		binding:        &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: r.OperatorNamespace, Name: name}},
	}
}

// permit grants the collector of obj the rules that it declares, in the Grant mode, and returns whether the grant
// changed. A rule outside the ceilings, or one that the deny list refuses, is PermissionsNotAllowed, which names each
// such rule and the guard that refuses it, and so is a write of the grant that the API server refuses as forbidden,
// with its message: the operator then takes back what it granted the collector, since a grant holds only while every
// rule is allowed. In any other mode, it grants nothing.
func (r *CollectorReconciler) permit(ctx context.Context, obj *configv1alpha1.Collector, account string,
	rules []*collectorv1alpha1.PolicyRule, policy permissionPolicy) (changed bool, refused *refusal, err error) {
	if !policy.grants() {
		return false, nil, nil
	}
	if notAllowed := policy.notAllowed(rules, r.OperatorNamespace); len(notAllowed) > 0 {
		if _, err := r.revoke(ctx, obj); err != nil {
			return false, nil, err
		}
		return false, refuse(configv1alpha1.ReasonPermissionsNotAllowed,
			"The operator may not grant permissions that the collector declares: %s.", firstOf(notAllowed)), nil
	}
	changed, err = r.grant(ctx, obj, account, rules)
	if apierrors.IsForbidden(err) {
		if _, revokeErr := r.revoke(ctx, obj); revokeErr != nil {
			return false, nil, revokeErr
		}
		return false, refuse(configv1alpha1.ReasonPermissionsNotAllowed,
			"The API server refuses to grant the permissions that the collector declares: %v", err), nil
	}
	return changed, nil, err
}

// grant gives account, a service account in the operator's namespace, the rules that the collector of obj declares:
// those for the whole cluster through the ClusterRole and the ClusterRoleBinding of its grant, and those for its own
// namespace through the Role and the RoleBinding. Each object carries the collector label and is owned by the
// Collector, so that it goes with it. A role holds exactly the rules of its scope, so a rule that the collector no
// longer declares goes, and a role that would hold none goes with its binding. A binding names account, the service
// account that the collector's Deployment runs as, which a runtime config may change. grant returns whether it changed
// anything.
func (r *CollectorReconciler) grant(ctx context.Context, obj *configv1alpha1.Collector, account string,
	rules []*collectorv1alpha1.PolicyRule) (bool, error) {
	var clusterRules, namespacedRules []rbacv1.PolicyRule
	for _, rule := range rules {
		if rule.GetNamespaced() {
			namespacedRules = append(namespacedRules, rbacRuleOf(rule))
		} else {
			clusterRules = append(clusterRules, rbacRuleOf(rule))
		}
	}
	clusterRules, namespacedRules = canonical(clusterRules), canonical(namespacedRules)
	g := r.grantObjectsOf(obj.Name)
	subjects := []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: account, Namespace: r.OperatorNamespace}}
	// Each role comes before its binding: the API server checks a binding against the rules of its role, which must
	// exist.
	parts := []struct {
		object client.Object
		wanted bool
		set    func()
	}{
		{g.clusterRole, len(clusterRules) > 0, func() { g.clusterRole.Rules = clusterRules }},
		{g.clusterBinding, len(clusterRules) > 0, func() {
			g.clusterBinding.RoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: g.clusterRole.Name}
			g.clusterBinding.Subjects = subjects
		}},
		{g.role, len(namespacedRules) > 0, func() { g.role.Rules = namespacedRules }},
		{g.binding, len(namespacedRules) > 0, func() {
			g.binding.RoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: g.role.Name}
			g.binding.Subjects = subjects
		}},
	}
	changed := false
	for _, part := range parts {
		if !part.wanted {
			continue
		}
		result, err := controllerutil.CreateOrUpdate(ctx, r.Client, part.object, func() error {
			part.object.SetLabels(withEntries(part.object.GetLabels(), collectorLabels(obj.Name)))
			part.set()
			return controllerutil.SetControllerReference(obj, part.object, r.Scheme)
		})
		if err != nil {
			return changed, fmt.Errorf("grant collector %s what it declares: %w", obj.Name, err)
		}
		changed = changed || result != controllerutil.OperationResultNone
	}
	// A binding goes before its role.
	for _, part := range slices.Backward(parts) {
		if part.wanted {
			continue
		}
		deleted, err := r.deleteGranted(ctx, obj, part.object)
		if err != nil {
			return changed, err
		}
		changed = changed || deleted
	}
	return changed, nil
}

// canonical returns rules in one order, whatever the order that a collector answered them in: the API groups, the
// resources and the verbs of each rule sorted and without repeats, and the rules sorted and without repeats. A role
// is compared with what it held in order, so the same rules in another order would write it again at every check, and
// that check would end without a review.
func canonical(rules []rbacv1.PolicyRule) []rbacv1.PolicyRule {
	for i := range rules {
		for _, names := range []*[]string{&rules[i].APIGroups, &rules[i].Resources, &rules[i].Verbs} {
			slices.Sort(*names)
			*names = slices.Compact(*names)
		}
	}
	slices.SortFunc(rules, func(a, b rbacv1.PolicyRule) int {
		if c := slices.Compare(a.APIGroups, b.APIGroups); c != 0 {
			return c
		}
		if c := slices.Compare(a.Resources, b.Resources); c != 0 {
			return c
		}
		return slices.Compare(a.Verbs, b.Verbs)
	})
	return slices.CompactFunc(rules, func(a, b rbacv1.PolicyRule) bool {
		return slices.Equal(a.APIGroups, b.APIGroups) && slices.Equal(a.Resources, b.Resources) &&
			slices.Equal(a.Verbs, b.Verbs)
	})
}

// takeBack takes back what the operator granted the collector of obj that policy no longer allows: all of it in a mode
// other than Grant, and in the Grant mode all of it once a rule that it holds is outside the ceilings or denied. It
// judges the rules that the grant holds, and asks the collector nothing, so that a collector that doesn't answer, or
// answers what keeps it from being used, keeps no grant that the admin has since narrowed. It returns whether it took
// anything back.
func (r *CollectorReconciler) takeBack(ctx context.Context, obj *configv1alpha1.Collector, policy permissionPolicy) (
	bool, error) {
	if policy.grants() {
		held, err := r.grantedRules(ctx, obj)
		if err != nil || len(policy.notAllowed(held, r.OperatorNamespace)) == 0 {
			return false, err
		}
	}
	revoked, err := r.revoke(ctx, obj)
	if revoked {
		logf.FromContext(ctx).Info("Took back what the operator had granted the collector, which the permissions policy no longer allows")
	}
	return revoked, err
}

// grantedRules returns the rules that the grant of the collector of obj holds, as rules that a collector declares:
// those of its ClusterRole across the cluster, and those of its Role in the collector's own namespace.
func (r *CollectorReconciler) grantedRules(ctx context.Context, obj *configv1alpha1.Collector) (
	[]*collectorv1alpha1.PolicyRule, error) {
	g := r.grantObjectsOf(obj.Name)
	for _, role := range []client.Object{g.clusterRole, g.role} {
		if err := r.Get(ctx, client.ObjectKeyFromObject(role), role); client.IgnoreNotFound(err) != nil {
			return nil, fmt.Errorf("read what the operator granted collector %s: %w", obj.Name, err)
		}
	}
	return slices.Concat(declaredOf(g.clusterRole.Rules, false), declaredOf(g.role.Rules, true)), nil
}

// declaredOf returns the rules of a role as rules that a collector declares, for its own namespace when namespaced.
func declaredOf(rules []rbacv1.PolicyRule, namespaced bool) []*collectorv1alpha1.PolicyRule {
	declared := make([]*collectorv1alpha1.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		declared = append(declared, &collectorv1alpha1.PolicyRule{
			ApiGroups: rule.APIGroups, Resources: rule.Resources, Verbs: rule.Verbs, Namespaced: namespaced,
		})
	}
	return declared
}

// revoke takes back all that the operator granted the collector of obj, each binding before its role, and returns
// whether it deleted anything.
func (r *CollectorReconciler) revoke(ctx context.Context, obj *configv1alpha1.Collector) (bool, error) {
	g := r.grantObjectsOf(obj.Name)
	revoked := false
	for _, object := range []client.Object{g.clusterBinding, g.clusterRole, g.binding, g.role} {
		deleted, err := r.deleteGranted(ctx, obj, object)
		if err != nil {
			return revoked, err
		}
		revoked = revoked || deleted
	}
	return revoked, nil
}

// deleteGranted deletes object, an object of the grant of the collector of obj, when the cache holds it with the
// collector label of obj. The cache holds no such object without the label, so one that someone else made under the
// name stays. It returns whether it deleted the object.
func (r *CollectorReconciler) deleteGranted(ctx context.Context, obj *configv1alpha1.Collector, object client.Object) (bool, error) {
	if err := r.Get(ctx, client.ObjectKeyFromObject(object), object); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("read what the operator granted collector %s: %w", obj.Name, err)
	}
	if object.GetLabels()[evidence.CollectorLabel] != obj.Name {
		return false, nil
	}
	if err := r.Delete(ctx, object); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("take back what the operator granted collector %s: %w", obj.Name, err)
	}
	return true, nil
}
