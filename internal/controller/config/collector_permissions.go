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
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	authorizationv1 "k8s.io/api/authorization/v1"

	"github.com/bedag/vexplain/internal/text"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// The deployer asks the API server whether a collector's service account holds each permission that the collector
// declares. It grants none: granting would need the escalate and bind verbs, which the operator shouldn't hold, so an
// admin binds the roles (design 5.9).
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

const (
	// maxPermissionChecks is the most permissions that the deployer checks for one collector, each a verb on a
	// resource of an API group: a SubjectAccessReview each, at every resync. A collector that declares more is
	// PackageInvalid, so that no collector makes the operator ask the API server without bound.
	maxPermissionChecks = 128
	// maxGroupLength bounds an API group, which Kubernetes names with a DNS subdomain, and maxNameLength a resource, a
	// subresource and a verb, which it names as it names a label.
	maxGroupLength = 253
	maxNameLength  = 63
)

// permissionChecks returns what the deployer asks the API server about the permissions that a collector declares: one
// review for each API group, resource and verb of each rule, in the operator's namespace for a namespaced rule and
// across the cluster for the others. It refuses, before it asks anything, a rule that RBAC would refuse in a role,
// since it names no API group, no resource or no verb, a name that isn't printable or that is longer than Kubernetes
// names are, and more than maxPermissionChecks: what the reviews and their errors repeat of a rule is then safe to
// show.
func permissionChecks(rules []*collectorv1alpha1.PolicyRule, namespace string) ([]authorizationv1.ResourceAttributes, error) {
	var checks []authorizationv1.ResourceAttributes
	for i, rule := range rules {
		// Each factor is bounded before they are multiplied, so that the product can't overflow, and before the names
		// are read, so that a rule of millions of names costs nothing.
		groups, resources, verbs := len(rule.GetApiGroups()), len(rule.GetResources()), len(rule.GetVerbs())
		if max(groups, resources, verbs) > maxPermissionChecks || groups*resources*verbs > maxPermissionChecks-len(checks) {
			return nil, fmt.Errorf("GetCapabilities declares more than the %d permissions that the operator checks", maxPermissionChecks)
		}
		if err := checkRule(rule); err != nil {
			return nil, fmt.Errorf("the permission rule %d of GetCapabilities %w", i+1, err)
		}
		scope := ""
		if rule.GetNamespaced() {
			scope = namespace
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

// checkRule says why a declared rule can't be checked, as the end of a sentence about it, or nil when it can.
func checkRule(rule *collectorv1alpha1.PolicyRule) error {
	switch {
	case len(rule.GetApiGroups()) == 0:
		return errors.New("names no API group")
	case len(rule.GetResources()) == 0:
		return errors.New("names no resource")
	case len(rule.GetVerbs()) == 0:
		return errors.New("names no verb")
	}
	for _, group := range rule.GetApiGroups() {
		// The empty group is the core group.
		if err := checkRuleName("API group", group, maxGroupLength); group != "" && err != nil {
			return err
		}
	}
	for _, named := range rule.GetResources() {
		resource, subresource, sub := strings.Cut(named, "/")
		if err := checkRuleName("resource", resource, maxNameLength); err != nil {
			return err
		}
		if err := checkRuleName("subresource", subresource, maxNameLength); sub && err != nil {
			return err
		}
	}
	for _, verb := range rule.GetVerbs() {
		if err := checkRuleName("verb", verb, maxNameLength); err != nil {
			return err
		}
	}
	return nil
}

// checkRuleName says why name, a name of what a rule names, can't be checked: it is empty, isn't printable, or is
// longer than limit.
func checkRuleName(what, name string, limit int) error {
	switch {
	case name == "":
		return fmt.Errorf("names an empty %s", what)
	case text.Printable(name) != name:
		return fmt.Errorf("names the %s %s, which isn't printable", what, quote(name))
	case utf8.RuneCountInString(name) > limit:
		return fmt.Errorf("names the %s %s, of more than %d characters", what, quote(name), limit)
	}
	return nil
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
			return nil, fmt.Errorf("ask the API server whether the service account %s holds the permissions that the collector declares: %w",
				account, err)
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
