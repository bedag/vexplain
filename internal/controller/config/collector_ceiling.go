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
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/component-helpers/auth/rbac/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/settings"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// The ceilings bound what the operator grants a collector of the permissions that it declares (decision 0041). Each is
// an aggregated ClusterRole of the install, whose rules the API server gathers from the ClusterRoles that carry its
// label: ceilingName covers what a collector may get in the whole cluster, and the manager holds it there, and
// namespacedCeilingName covers what a collector declares for its own namespace, and the manager holds it there alone.
const (
	ceilingName           = "vexplain-collector"
	namespacedCeilingName = "vexplain-collector-namespaced"
)

// The guards that may refuse a rule that a collector declares, as the Ready condition names them.
const (
	guardCeiling           = "ceiling"
	guardNamespacedCeiling = "namespaced ceiling"
	guardDenyList          = "deny list"
)

// star stands for every API group, resource or verb in a rule of RBAC, and of the deny list.
const star = "*"

// ceilings are the rules of the two ceilings: cluster those of ceilingName, and namespaced those of
// namespacedCeilingName.
type ceilings struct {
	cluster, namespaced []rbacv1.PolicyRule
}

// of returns the rules that may cover rule: those of the ceiling of the whole cluster for a rule across the cluster,
// and those of both ceilings for a rule of the collector's own namespace, where the manager holds both, and where the
// API server's escalation check sums them for a Role that the manager creates.
func (c ceilings) of(rule *collectorv1alpha1.PolicyRule) []rbacv1.PolicyRule {
	if !rule.GetNamespaced() {
		return c.cluster
	}
	return slices.Concat(c.cluster, c.namespaced)
}

// permissionPolicy decides what the operator grants a collector: the mode and the deny list of the OperatorConfig,
// and, in the Grant mode, the ceilings.
type permissionPolicy struct {
	mode     configv1alpha1.PermissionsMode
	denied   []configv1alpha1.PermissionRule
	ceilings ceilings
}

// grants says whether the operator grants the collectors what they declare, as it does in the Grant mode. In any
// other mode it grants nothing, and the SubjectAccessReviews check what an admin bound.
func (p permissionPolicy) grants() bool {
	return p.mode == configv1alpha1.PermissionsModeGrant
}

// notAllowed returns each of the rules that a collector declares that the policy doesn't let the operator grant, as
// a description that names the rule and the guard that refuses it.
func (p permissionPolicy) notAllowed(rules []*collectorv1alpha1.PolicyRule, namespace string) []string {
	var refused []string
	for _, rule := range rules {
		if ok, guard := covered(p.ceilings.of(rule), p.denied, rule); !ok {
			refused = append(refused, describeRefusal(rule, guard, namespace))
		}
	}
	return refused
}

// permissionPolicy reads the policy of the collectors' permissions: the OperatorConfig through the cache, and, in the
// Grant mode, the ceilings through the API reader, since the cache holds only what the operator grants. A ceiling
// that doesn't exist covers nothing. The ceilings are read at each check, so that a change that an admin makes to the
// ClusterRoles that extend them counts within a resync.
func (r *CollectorReconciler) permissionPolicy(ctx context.Context) (permissionPolicy, error) {
	effective, err := settings.Load(ctx, r.Client)
	if err != nil {
		return permissionPolicy{}, err
	}
	policy := permissionPolicy{mode: effective.PermissionsMode, denied: effective.DeniedPermissions}
	if !policy.grants() {
		return policy, nil
	}
	if policy.ceilings.cluster, err = r.ceilingRules(ctx, ceilingName); err != nil {
		return permissionPolicy{}, err
	}
	if policy.ceilings.namespaced, err = r.ceilingRules(ctx, namespacedCeilingName); err != nil {
		return permissionPolicy{}, err
	}
	return policy, nil
}

// ceilingRules returns the rules of the ceiling of the name, or none when it doesn't exist.
func (r *CollectorReconciler) ceilingRules(ctx context.Context, name string) ([]rbacv1.PolicyRule, error) {
	var ceiling rbacv1.ClusterRole
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: name}, &ceiling); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read the ceiling %s: %w", name, err)
	}
	return ceiling.Rules, nil
}

// covered says whether the operator may grant rule, a rule that a collector declares: no rule of the deny list
// overlaps it, and ceiling, the rules of the ceilings that may cover it, covers it, which Kubernetes' own comparison
// judges as the API server's escalation check judges a role that the operator creates, wildcards, subresources and
// resource names included. When the operator may not grant the rule, guard names what refuses it: the deny list,
// which wins over the ceilings, or else the ceiling, which for a rule of the collector's own namespace is the
// namespaced ceiling, the one meant for it.
func covered(ceiling []rbacv1.PolicyRule, denied []configv1alpha1.PermissionRule, rule *collectorv1alpha1.PolicyRule) (
	ok bool, guard string) {
	for i := range denied {
		if overlaps(&denied[i], rule) {
			return false, guardDenyList
		}
	}
	if allowed, _ := validation.Covers(ceiling, []rbacv1.PolicyRule{rbacRuleOf(rule)}); !allowed {
		if rule.GetNamespaced() {
			return false, guardNamespacedCeiling
		}
		return false, guardCeiling
	}
	return true, ""
}

// overlaps says whether a rule of the deny list and a declared rule share an API group, a resource and a verb, a star
// in either standing for any.
func overlaps(denied *configv1alpha1.PermissionRule, rule *collectorv1alpha1.PolicyRule) bool {
	return shareOne(denied.APIGroups, rule.GetApiGroups(), namesMatch) &&
		shareOne(denied.Resources, rule.GetResources(), resourcesMatch) &&
		shareOne(denied.Verbs, rule.GetVerbs(), namesMatch)
}

// shareOne says whether a name of a and a name of b match.
func shareOne(a, b []string, match func(x, y string) bool) bool {
	return slices.ContainsFunc(a, func(x string) bool {
		return slices.ContainsFunc(b, func(y string) bool { return match(x, y) })
	})
}

// namesMatch says whether two names of a rule may stand for the same: they are equal, or one is a star.
func namesMatch(x, y string) bool {
	return x == y || x == star || y == star
}

// resourcesMatch says whether two resources of a rule may stand for the same. A star stands for every resource and
// every subresource. Otherwise both name a subresource or neither does, and the resources and the subresources
// match, so that a star for the resource, as RBAC writes */log for the logs of everything, matches pods/log.
func resourcesMatch(x, y string) bool {
	if x == star || y == star {
		return true
	}
	xResource, xSubresource, xHasSub := strings.Cut(x, "/")
	yResource, ySubresource, yHasSub := strings.Cut(y, "/")
	return xHasSub == yHasSub && namesMatch(xResource, yResource) && namesMatch(xSubresource, ySubresource)
}

// rbacRuleOf returns the RBAC rule that grants what a declared rule names.
func rbacRuleOf(rule *collectorv1alpha1.PolicyRule) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{
		APIGroups: slices.Clone(rule.GetApiGroups()),
		Resources: slices.Clone(rule.GetResources()),
		Verbs:     slices.Clone(rule.GetVerbs()),
	}
}

// describeRefusal says which guard refuses a declared rule: "the deny list refuses list secrets across the cluster",
// or "the namespaced ceiling doesn't allow create configmaps in vexplain-system".
func describeRefusal(rule *collectorv1alpha1.PolicyRule, guard, namespace string) string {
	if guard == guardDenyList {
		return fmt.Sprintf("the %s refuses %s", guard, describeRule(rule, namespace))
	}
	return fmt.Sprintf("the %s doesn't allow %s", guard, describeRule(rule, namespace))
}

// describeRule says what a declared rule names, as describePermission says one permission: its verbs, its resources,
// each named by its API group as kubectl does, and where: "list, watch deployments.apps across the cluster", or "get
// pods/log in vexplain-system".
func describeRule(rule *collectorv1alpha1.PolicyRule, namespace string) string {
	resources := make([]string, 0, len(rule.GetApiGroups())*len(rule.GetResources()))
	for _, group := range rule.GetApiGroups() {
		for _, named := range rule.GetResources() {
			resource, subresource, _ := strings.Cut(named, "/")
			resources = append(resources, qualified(group, resource, subresource))
		}
	}
	if !rule.GetNamespaced() {
		namespace = ""
	}
	return fmt.Sprintf("%s %s %s", strings.Join(rule.GetVerbs(), ", "), strings.Join(resources, ", "), placeOf(namespace))
}
