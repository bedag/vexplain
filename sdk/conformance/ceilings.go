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

package conformance

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/bedag/vexplain/sdk/collector"
)

// The labels by which a ClusterRole extends one of vexplain's ceilings, with the value "true". The ceilings bound what
// vexplain grants a collector of the permissions that it declares: CeilingLabel extends vexplain-collector, which
// covers what a collector may get in the whole cluster, and NamespacedCeilingLabel extends
// vexplain-collector-namespaced, which covers what a collector declares for its own namespace. Each ceiling is an
// aggregated ClusterRole, whose rules the API server gathers from the ClusterRoles that carry its label.
const (
	CeilingLabel           = "rbac.vexplain.bedag.ch/aggregate-to-collector"
	NamespacedCeilingLabel = "rbac.vexplain.bedag.ch/aggregate-to-collector-namespaced"
)

// star stands for every API group, resource or verb in a rule of RBAC.
const star = "*"

// CeilingRules returns the rules that the ClusterRoles of manifests give vexplain's ceilings: cluster, those of the
// ClusterRoles that carry CeilingLabel, and namespaced, those of the ones that carry NamespacedCeilingLabel, each with
// the value "true" and in the order of manifests, as the API server would gather them. manifests is YAML, documents
// separated by ---, such as vexplain's install file config/rbac/collector.yaml. A document of another kind adds
// nothing.
func CeilingRules(manifests []byte) (cluster, namespaced []rbacv1.PolicyRule, err error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(manifests), 4096)
	for {
		var role rbacv1.ClusterRole
		if err := decoder.Decode(&role); errors.Is(err, io.EOF) {
			return cluster, namespaced, nil
		} else if err != nil {
			return nil, nil, fmt.Errorf("read the ClusterRoles of the manifests: %w", err)
		}
		if role.Kind != "ClusterRole" {
			continue
		}
		if role.Labels[CeilingLabel] == "true" {
			cluster = append(cluster, role.Rules...)
		}
		if role.Labels[NamespacedCeilingLabel] == "true" {
			namespaced = append(namespaced, role.Rules...)
		}
	}
}

// Uncovered returns each of the permissions that the ceiling of its scope, as the ClusterRoles of manifests extend it,
// doesn't cover: a permission across the cluster needs the rules that CeilingRules returns for the cluster, and one in
// the collector's own namespace those that it returns for the namespace. Each API group, resource and verb of a
// permission needs a rule that holds it, or a star in its place, and that names no objects of the resource; a
// subresource needs its own name, or */<subresource>. These are the rules of the API server's escalation check, by
// which vexplain may grant only what the ceilings hold. A permission is named by its verb, its resource, with its API
// group as kubectl writes it, and its scope: "list deployments.apps across the cluster", or "get pods/log in the
// collector's namespace". vexplain's own collectors check against the defaults of its install that they declare
// nothing beyond them.
func Uncovered(manifests []byte, permissions []collector.Permission) ([]string, error) {
	cluster, namespaced, err := CeilingRules(manifests)
	if err != nil {
		return nil, err
	}
	var uncovered []string
	for _, p := range permissions {
		ceiling, where := cluster, "across the cluster"
		if p.Namespaced {
			ceiling, where = namespaced, "in the collector's namespace"
		}
		for _, group := range p.APIGroups {
			for _, resource := range p.Resources {
				for _, verb := range p.Verbs {
					if !slices.ContainsFunc(ceiling, func(rule rbacv1.PolicyRule) bool { return holds(rule, group, resource, verb) }) {
						uncovered = append(uncovered, fmt.Sprintf("%s %s %s", verb, qualified(group, resource), where))
					}
				}
			}
		}
	}
	return uncovered, nil
}

// holds says whether rule holds verb on resource of group, for every object of the resource.
func holds(rule rbacv1.PolicyRule, group, resource, verb string) bool {
	if len(rule.ResourceNames) > 0 {
		return false
	}
	resourceHeld := slices.Contains(rule.Resources, star) || slices.Contains(rule.Resources, resource)
	if _, subresource, ok := strings.Cut(resource, "/"); ok && !resourceHeld {
		resourceHeld = slices.Contains(rule.Resources, star+"/"+subresource)
	}
	return resourceHeld &&
		(slices.Contains(rule.APIGroups, star) || slices.Contains(rule.APIGroups, group)) &&
		(slices.Contains(rule.Verbs, star) || slices.Contains(rule.Verbs, verb))
}

// qualified names a resource by its API group, as kubectl does: pods/log, or deployments.apps.
func qualified(group, resource string) string {
	if group == "" {
		return resource
	}
	resource, subresource, ok := strings.Cut(resource, "/")
	if !ok {
		return resource + "." + group
	}
	return resource + "." + group + "/" + subresource
}
