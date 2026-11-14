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

package spoke

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/sdk/evidence"
)

// playbookMatching returns a playbook of the images in presence with the match.
func playbookMatching(name string, match *configv1alpha1.PlaybookMatch) configv1alpha1.Playbook {
	return configv1alpha1.Playbook{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: configv1alpha1.PlaybookSpec{
			Match:    match,
			Subjects: configv1alpha1.PlaybookSource{Type: evidence.TypePresence},
		},
	}
}

// stageKey is the label of the namespaces and clusters that the playbooks of the tests select.
const stageKey = "stage"

// stage selects the labels whose stage is the value.
func stage(value string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{stageKey: value}}
}

// A report holds the results of the playbooks of the images in presence whose cluster selector selects the cluster's
// labels and whose namespace selector selects its namespace's labels. An absent match or selector selects everything,
// and one that doesn't parse selects nothing, as the hub has it.
func TestPlaybooksForMatchesTheClusterAndTheNamespaceByTheirLabels(t *testing.T) {
	other := playbookMatching("other-subjects", nil)
	other.Spec.Subjects.Type = "ch.example.certificates.v1alpha1"
	playbooks := []configv1alpha1.Playbook{
		playbookMatching("everywhere", nil),
		playbookMatching("prod-namespaces", &configv1alpha1.PlaybookMatch{Namespaces: stage("prod")}),
		playbookMatching("dev-namespaces", &configv1alpha1.PlaybookMatch{Namespaces: stage("dev")}),
		playbookMatching("prod-clusters", &configv1alpha1.PlaybookMatch{Clusters: stage("prod")}),
		playbookMatching("dev-clusters", &configv1alpha1.PlaybookMatch{Clusters: stage("dev")}),
		playbookMatching("prod-both", &configv1alpha1.PlaybookMatch{Clusters: stage("prod"), Namespaces: stage("prod")}),
		playbookMatching("empty-selectors", &configv1alpha1.PlaybookMatch{
			Clusters: &metav1.LabelSelector{}, Namespaces: &metav1.LabelSelector{}}),
		playbookMatching("unparsable", &configv1alpha1.PlaybookMatch{Namespaces: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: stageKey, Operator: "Near"}}}}),
		other,
	}
	prod := map[string]string{stageKey: "prod"}

	matching := playbooksFor(prod, prod, playbooks)

	names := make([]string, 0, len(matching))
	for _, p := range matching {
		names = append(names, p.Name)
	}

	require.Equal(t, []string{"everywhere", "prod-namespaces", "prod-clusters", "prod-both", "empty-selectors"}, names,
		"in their order, and none whose selectors leave out the cluster or the namespace, or that judges no image")
	require.Empty(t, playbooksFor(map[string]string{stageKey: "dev"}, prod, playbooks[1:2]),
		"a namespace that the selector leaves out")
}
