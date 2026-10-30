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

package scope_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/scope"
)

// The label keys of the fixtures, and the two values that most rows repeat.
const (
	team     = "team"
	tier     = "tier"
	app      = "app"
	vexplain = "vexplain"

	web   = "web"
	debug = "debug"
)

// labelSet is shorthand for a label map, so that the rows of a table stay short.
type labelSet = map[string]string

// equals selects the objects that carry the label key=value.
func equals(key, value string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: labelSet{key: value}}
}

// expression selects the objects that satisfy one match expression.
func expression(key string, operator metav1.LabelSelectorOperator, values ...string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{Key: key, Operator: operator, Values: values},
	}}
}

// Each row is one pod: the scope, the labels of the pod's namespace (ns) and the labels of the pod.
// A nil map is a namespace or a pod without labels.
func TestMatches(t *testing.T) {
	tests := []struct {
		name string
		cfg  *configv1alpha1.Scope
		ns   labelSet
		pod  labelSet
		want bool
	}{
		// Without limits, every pod is in scope.
		{
			name: "a nil scope matches everything",
			cfg:  nil,
			ns:   labelSet{team: "b"},
			pod:  labelSet{app: debug},
			want: true,
		},
		{
			name: "an empty scope matches everything",
			cfg:  &configv1alpha1.Scope{},
			want: true,
		},

		// includeNamespaces and excludeNamespaces read the labels of the namespace.
		{
			name: "includeNamespaces: a namespace with the label is in",
			cfg:  &configv1alpha1.Scope{IncludeNamespaces: equals(team, "a")},
			ns:   labelSet{team: "a"},
			want: true,
		},
		{
			name: "includeNamespaces: a namespace with another value is out",
			cfg:  &configv1alpha1.Scope{IncludeNamespaces: equals(team, "a")},
			ns:   labelSet{team: "b"},
			want: false,
		},
		{
			name: "includeNamespaces: a namespace without labels is out",
			cfg:  &configv1alpha1.Scope{IncludeNamespaces: equals(team, "a")},
			want: false,
		},
		{
			name: "includeNamespaces: an empty selector matches every namespace",
			cfg:  &configv1alpha1.Scope{IncludeNamespaces: &metav1.LabelSelector{}},
			ns:   labelSet{team: "b"},
			want: true,
		},
		{
			name: "includeNamespaces: a match expression that holds is in",
			cfg:  &configv1alpha1.Scope{IncludeNamespaces: expression(team, metav1.LabelSelectorOpIn, "a", "b")},
			ns:   labelSet{team: "b"},
			want: true,
		},
		{
			name: "includeNamespaces: a match expression that fails is out",
			cfg:  &configv1alpha1.Scope{IncludeNamespaces: expression(team, metav1.LabelSelectorOpIn, "a", "b")},
			ns:   labelSet{team: "c"},
			want: false,
		},
		{
			name: "excludeNamespaces: a namespace with the label is out",
			cfg:  &configv1alpha1.Scope{ExcludeNamespaces: equals(vexplain, "off")},
			ns:   labelSet{vexplain: "off"},
			want: false,
		},
		{
			name: "excludeNamespaces: a namespace without the label is in",
			cfg:  &configv1alpha1.Scope{ExcludeNamespaces: equals(vexplain, "off")},
			ns:   labelSet{team: "a"},
			want: true,
		},
		{
			name: "excludeNamespaces: a match expression that holds is out",
			cfg:  &configv1alpha1.Scope{ExcludeNamespaces: expression(vexplain, metav1.LabelSelectorOpExists)},
			ns:   labelSet{vexplain: "on"},
			want: false,
		},
		{
			name: "excludeNamespaces wins over includeNamespaces",
			cfg: &configv1alpha1.Scope{
				IncludeNamespaces: equals(team, "a"),
				ExcludeNamespaces: equals(vexplain, "off"),
			},
			ns:   labelSet{team: "a", vexplain: "off"},
			want: false,
		},
		{
			name: "a namespace that includeNamespaces selects and excludeNamespaces doesn't is in",
			cfg: &configv1alpha1.Scope{
				IncludeNamespaces: equals(team, "a"),
				ExcludeNamespaces: equals(vexplain, "off"),
			},
			ns:   labelSet{team: "a"},
			want: true,
		},

		// includePods and excludePods read the labels of the pod.
		{
			name: "includePods: a pod with the label is in",
			cfg:  &configv1alpha1.Scope{IncludePods: equals(tier, web)},
			pod:  labelSet{tier: web},
			want: true,
		},
		{
			name: "includePods: a pod with another value is out",
			cfg:  &configv1alpha1.Scope{IncludePods: equals(tier, web)},
			pod:  labelSet{tier: "api"},
			want: false,
		},
		{
			name: "excludePods: a pod with the label is out",
			cfg:  &configv1alpha1.Scope{ExcludePods: equals(app, debug)},
			pod:  labelSet{app: debug},
			want: false,
		},
		{
			name: "excludePods: a pod with another value is in",
			cfg:  &configv1alpha1.Scope{ExcludePods: equals(app, debug)},
			pod:  labelSet{app: web},
			want: true,
		},
		{
			name: "excludePods wins over includePods",
			cfg: &configv1alpha1.Scope{
				IncludePods: equals(tier, web),
				ExcludePods: equals(app, debug),
			},
			pod:  labelSet{tier: web, app: debug},
			want: false,
		},

		// A pod is in scope only when its namespace and the pod both pass.
		{
			name: "a pod is in when its namespace and the pod both pass",
			cfg: &configv1alpha1.Scope{
				IncludeNamespaces: equals(team, "a"),
				IncludePods:       equals(tier, web),
			},
			ns:   labelSet{team: "a"},
			pod:  labelSet{tier: web},
			want: true,
		},
		{
			name: "a pod is out when its namespace passes and the pod fails",
			cfg: &configv1alpha1.Scope{
				IncludeNamespaces: equals(team, "a"),
				IncludePods:       equals(tier, web),
			},
			ns:   labelSet{team: "a"},
			pod:  labelSet{tier: "api"},
			want: false,
		},
		{
			name: "a pod is out when its namespace fails and the pod passes",
			cfg: &configv1alpha1.Scope{
				IncludeNamespaces: equals(team, "a"),
				IncludePods:       equals(tier, web),
			},
			ns:   labelSet{team: "b"},
			pod:  labelSet{tier: web},
			want: false,
		},

		// The API server rejects an empty exclude selector, because it would exclude the whole
		// cluster. A client that skips the CRD schema can still deliver one. It then keeps its
		// Kubernetes meaning, which is to match everything, so that nothing is analysed and
		// nothing is guessed.
		{
			name: "an empty excludeNamespaces matches every namespace",
			cfg:  &configv1alpha1.Scope{ExcludeNamespaces: &metav1.LabelSelector{}},
			ns:   labelSet{team: "a"},
			want: false,
		},
		{
			name: "an empty excludePods matches every pod",
			cfg:  &configv1alpha1.Scope{ExcludePods: &metav1.LabelSelector{}},
			pod:  labelSet{app: web},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := scope.New(tc.cfg)
			require.NoError(t, err)

			require.Equal(t, tc.want, m.Matches(tc.ns, tc.pod))
		})
	}
}

// The CRD schema can't tell whether the operator of a match expression is valid, so a selector
// that does not parse reaches New. It must fail whichever of the four selectors it is, name that
// one by its JSON name and keep the parse error as the cause.
func TestNewRejectsInvalidSelector(t *testing.T) {
	bad := expression(team, "Bogus", "a")
	_, parseErr := metav1.LabelSelectorAsSelector(bad)
	require.Error(t, parseErr, "the fixture must not parse")

	tests := []struct {
		field string // the JSON name of the field that holds the bad selector
		cfg   *configv1alpha1.Scope
	}{
		{"includeNamespaces", &configv1alpha1.Scope{IncludeNamespaces: bad}},
		{"excludeNamespaces", &configv1alpha1.Scope{ExcludeNamespaces: bad}},
		{"includePods", &configv1alpha1.Scope{IncludePods: bad}},
		{"excludePods", &configv1alpha1.Scope{ExcludePods: bad}},
	}

	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			m, err := scope.New(tc.cfg)

			require.Nil(t, m)
			require.EqualError(t, err, tc.field+": "+parseErr.Error())
			require.EqualError(t, errors.Unwrap(err), parseErr.Error())
		})
	}

	// New stops at the first bad selector, in the order of the fields of Scope.
	t.Run("several", func(t *testing.T) {
		m, err := scope.New(&configv1alpha1.Scope{ExcludeNamespaces: bad, IncludePods: bad})

		require.Nil(t, m)
		require.EqualError(t, err, "excludeNamespaces: "+parseErr.Error())
	})
}
