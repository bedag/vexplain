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
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// The deployer asks the API server whether a collector's service account holds each permission that the collector
// declares. It grants none: granting would need the escalate and bind verbs, which the operator shouldn't hold, so an
// admin binds the roles (design 5.9).
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

// maxPermissionChecks is the most permissions that the deployer checks for one collector, each a verb on a resource
// of an API group: a SubjectAccessReview each, at every resync. A collector that declares more is PackageInvalid, so
// that no collector makes the operator ask the API server without bound.
const maxPermissionChecks = 128

// permissionChecks returns what the deployer asks the API server about the permissions that a collector declares: one
// review for each API group, resource and verb of each rule, in the operator's namespace for a namespaced rule and
// across the cluster for the others. It refuses more than maxPermissionChecks, before it asks anything.
func permissionChecks(rules []*collectorv1alpha1.PolicyRule, namespace string) ([]authorizationv1.ResourceAttributes, error) {
	var checks []authorizationv1.ResourceAttributes
	for _, rule := range rules {
		scope := ""
		if rule.GetNamespaced() {
			scope = namespace
		}
		// Each factor is bounded before they are multiplied, so that the product can't overflow.
		groups, resources, verbs := len(rule.GetApiGroups()), len(rule.GetResources()), len(rule.GetVerbs())
		if max(groups, resources, verbs) > maxPermissionChecks || groups*resources*verbs > maxPermissionChecks-len(checks) {
			return nil, fmt.Errorf("GetCapabilities declares more than the %d permissions that the operator checks", maxPermissionChecks)
		}
		for _, group := range rule.GetApiGroups() {
			for _, resource := range rule.GetResources() {
				// A rule names a subresource after its resource, such as pods/log, as RBAC does.
				resource, subresource, _ := strings.Cut(resource, "/")
				for _, verb := range rule.GetVerbs() {
					checks = append(checks, authorizationv1.ResourceAttributes{
						Namespace: scope, Verb: verb, Group: group, Resource: resource, Subresource: subresource,
					})
				}
			}
		}
	}
	return checks, nil
}

// missingPermissions asks the API server, for each check, whether the service account of the name in the operator's
// namespace holds it, and returns those that it lacks, each as described. The review names the groups of every
// service account too, so that a binding to them counts, as it does when the collector calls the API server.
func (r *CollectorReconciler) missingPermissions(ctx context.Context, account string,
	checks []authorizationv1.ResourceAttributes) ([]string, error) {
	var missing []string
	for _, check := range checks {
		review := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "system:serviceaccount:" + r.OperatorNamespace + ":" + account,
			Groups: []string{
				"system:serviceaccounts", "system:serviceaccounts:" + r.OperatorNamespace, "system:authenticated",
			},
			ResourceAttributes: &check,
		}}
		if err := r.Create(ctx, review); err != nil {
			return nil, fmt.Errorf("ask whether the service account %s may %s: %w", account, describePermission(check), err)
		}
		if !review.Status.Allowed {
			missing = append(missing, describePermission(check))
		}
	}
	return missing, nil
}

// describePermission says what a check asks for, naming a resource by its group as kubectl does: "get pods/log in
// vexplain-system", or "watch deployments.apps across the cluster".
func describePermission(check authorizationv1.ResourceAttributes) string {
	resource := check.Resource
	if check.Group != "" {
		resource += "." + check.Group
	}
	if check.Subresource != "" {
		resource += "/" + check.Subresource
	}
	where := "across the cluster"
	if check.Namespace != "" {
		where = "in " + check.Namespace
	}
	return fmt.Sprintf("%s %s %s", check.Verb, resource, where)
}
