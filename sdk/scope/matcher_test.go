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

	"github.com/bedag/vexplain/sdk/scope"
)

// The label keys of the fixtures, and the two values that most rows repeat.
const (
	team     = "team"
	tier     = "tier"
	app      = "app"
	vexplain = "vexplain"

	web   = "web"
	debug = "debug"
	api   = "api"
	off   = "off"
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
		cfg  *scope.Scope
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
			cfg:  &scope.Scope{},
			want: true,
		},

		// includeNamespaces and excludeNamespaces read the labels of the namespace.
		{
			name: "includeNamespaces: a namespace with the label is in",
			cfg:  &scope.Scope{IncludeNamespaces: equals(team, "a")},
			ns:   labelSet{team: "a"},
			want: true,
		},
		{
			name: "includeNamespaces: a namespace with another value is out",
			cfg:  &scope.Scope{IncludeNamespaces: equals(team, "a")},
			ns:   labelSet{team: "b"},
			want: false,
		},
		{
			name: "includeNamespaces: a namespace without labels is out",
			cfg:  &scope.Scope{IncludeNamespaces: equals(team, "a")},
			want: false,
		},
		{
			name: "includeNamespaces: an empty selector matches every namespace",
			cfg:  &scope.Scope{IncludeNamespaces: &metav1.LabelSelector{}},
			ns:   labelSet{team: "b"},
			want: true,
		},
		{
			name: "includeNamespaces: a match expression that holds is in",
			cfg:  &scope.Scope{IncludeNamespaces: expression(team, metav1.LabelSelectorOpIn, "a", "b")},
			ns:   labelSet{team: "b"},
			want: true,
		},
		{
			name: "includeNamespaces: a match expression that fails is out",
			cfg:  &scope.Scope{IncludeNamespaces: expression(team, metav1.LabelSelectorOpIn, "a", "b")},
			ns:   labelSet{team: "c"},
			want: false,
		},
		{
			name: "excludeNamespaces: a namespace with the label is out",
			cfg:  &scope.Scope{ExcludeNamespaces: equals(vexplain, off)},
			ns:   labelSet{vexplain: off},
			want: false,
		},
		{
			name: "excludeNamespaces: a namespace without the label is in",
			cfg:  &scope.Scope{ExcludeNamespaces: equals(vexplain, off)},
			ns:   labelSet{team: "a"},
			want: true,
		},
		{
			name: "excludeNamespaces: a match expression that holds is out",
			cfg:  &scope.Scope{ExcludeNamespaces: expression(vexplain, metav1.LabelSelectorOpExists)},
			ns:   labelSet{vexplain: "on"},
			want: false,
		},
		{
			name: "excludeNamespaces wins over includeNamespaces",
			cfg: &scope.Scope{
				IncludeNamespaces: equals(team, "a"),
				ExcludeNamespaces: equals(vexplain, off),
			},
			ns:   labelSet{team: "a", vexplain: off},
			want: false,
		},
		{
			name: "a namespace that includeNamespaces selects and excludeNamespaces doesn't is in",
			cfg: &scope.Scope{
				IncludeNamespaces: equals(team, "a"),
				ExcludeNamespaces: equals(vexplain, off),
			},
			ns:   labelSet{team: "a"},
			want: true,
		},

		// includePods and excludePods read the labels of the pod.
		{
			name: "includePods: a pod with the label is in",
			cfg:  &scope.Scope{IncludePods: equals(tier, web)},
			pod:  labelSet{tier: web},
			want: true,
		},
		{
			name: "includePods: a pod with another value is out",
			cfg:  &scope.Scope{IncludePods: equals(tier, web)},
			pod:  labelSet{tier: api},
			want: false,
		},
		{
			name: "excludePods: a pod with the label is out",
			cfg:  &scope.Scope{ExcludePods: equals(app, debug)},
			pod:  labelSet{app: debug},
			want: false,
		},
		{
			name: "excludePods: a pod with another value is in",
			cfg:  &scope.Scope{ExcludePods: equals(app, debug)},
			pod:  labelSet{app: web},
			want: true,
		},
		{
			name: "excludePods wins over includePods",
			cfg: &scope.Scope{
				IncludePods: equals(tier, web),
				ExcludePods: equals(app, debug),
			},
			pod:  labelSet{tier: web, app: debug},
			want: false,
		},

		// A pod is in scope only when its namespace and the pod both pass.
		{
			name: "a pod is in when its namespace and the pod both pass",
			cfg: &scope.Scope{
				IncludeNamespaces: equals(team, "a"),
				IncludePods:       equals(tier, web),
			},
			ns:   labelSet{team: "a"},
			pod:  labelSet{tier: web},
			want: true,
		},
		{
			name: "a pod is out when its namespace passes and the pod fails",
			cfg: &scope.Scope{
				IncludeNamespaces: equals(team, "a"),
				IncludePods:       equals(tier, web),
			},
			ns:   labelSet{team: "a"},
			pod:  labelSet{tier: api},
			want: false,
		},
		{
			name: "a pod is out when its namespace fails and the pod passes",
			cfg: &scope.Scope{
				IncludeNamespaces: equals(team, "a"),
				IncludePods:       equals(tier, web),
			},
			ns:   labelSet{team: "b"},
			pod:  labelSet{tier: web},
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

// An empty exclude selector matches every object, so it would take the whole cluster out of the
// analysis. The CRD schema rejects it, but a client that skips the schema can still deliver one,
// and New must refuse it: nothing is analysed on a guess about what the admin meant. An exclude
// that is absent is another matter, and removes nothing, as the rows of TestMatches show.
func TestNewRejectsAnEmptyExclude(t *testing.T) {
	// The ways to write a selector without terms. The CRD schema calls each of them empty.
	noTerms := &metav1.LabelSelector{}
	noMatchLabels := &metav1.LabelSelector{MatchLabels: labelSet{}}
	noMatchExpressions := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{}}

	const (
		excludeNamespaces = "excludeNamespaces"
		excludePods       = "excludePods"
	)
	tests := []struct {
		name  string
		field string // the JSON name of the field that holds the empty selector
		cfg   *scope.Scope
	}{
		{"excludeNamespaces without terms", excludeNamespaces,
			&scope.Scope{ExcludeNamespaces: noTerms}},
		{"excludeNamespaces with an empty matchLabels", excludeNamespaces,
			&scope.Scope{ExcludeNamespaces: noMatchLabels}},
		{"excludeNamespaces with an empty matchExpressions", excludeNamespaces,
			&scope.Scope{ExcludeNamespaces: noMatchExpressions}},
		{"excludePods without terms", excludePods,
			&scope.Scope{ExcludePods: noTerms}},
		{"excludePods with an empty matchLabels", excludePods,
			&scope.Scope{ExcludePods: noMatchLabels}},
		{"excludePods with an empty matchExpressions", excludePods,
			&scope.Scope{ExcludePods: noMatchExpressions}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := scope.New(tc.cfg)

			require.Nil(t, m)
			require.ErrorContains(t, err, tc.field)
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
		cfg   *scope.Scope
	}{
		{"includeNamespaces", &scope.Scope{IncludeNamespaces: bad}},
		{"excludeNamespaces", &scope.Scope{ExcludeNamespaces: bad}},
		{"includePods", &scope.Scope{IncludePods: bad}},
		{"excludePods", &scope.Scope{ExcludePods: bad}},
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
		m, err := scope.New(&scope.Scope{ExcludeNamespaces: bad, IncludePods: bad})

		require.Nil(t, m)
		require.EqualError(t, err, "excludeNamespaces: "+parseErr.Error())
	})
}

// An admin reads a refusal in the Ready condition of the OperatorConfig, whose controller shows what
// New returns, so a change to its text is a change that they see. These are the texts.
func TestNewRefusesWithTheseTexts(t *testing.T) {
	// emptyExclude is the refusal of an empty exclude selector in the named field.
	emptyExclude := func(field string) string {
		return field + ": must not be empty, because an empty selector matches every object; " +
			"leave the field out to exclude nothing"
	}
	// unparsable is the refusal of bad in the named field, as the label selector parser words it.
	bad := expression(team, "Bogus", "a")
	unparsable := func(field string) string {
		return field + `: "Bogus" is not a valid label selector operator`
	}

	tests := []struct {
		name string
		cfg  *scope.Scope
		want string
	}{
		{"an empty excludeNamespaces", &scope.Scope{ExcludeNamespaces: &metav1.LabelSelector{}},
			emptyExclude("excludeNamespaces")},
		{"an empty excludePods", &scope.Scope{ExcludePods: &metav1.LabelSelector{}}, emptyExclude("excludePods")},
		{"an unparsable selector", &scope.Scope{IncludeNamespaces: bad}, unparsable("includeNamespaces")},

		// New stops at the first selector that it refuses, in the order of the fields of Scope:
		// includeNamespaces, excludeNamespaces, includePods, excludePods. Each row puts two neighbours
		// of that order at fault, and the three pairs fix the whole order.
		{"includeNamespaces comes before excludeNamespaces",
			&scope.Scope{ExcludeNamespaces: &metav1.LabelSelector{}, IncludeNamespaces: bad},
			unparsable("includeNamespaces")},
		{"excludeNamespaces comes before includePods",
			&scope.Scope{IncludePods: bad, ExcludeNamespaces: &metav1.LabelSelector{}},
			emptyExclude("excludeNamespaces")},
		{"includePods comes before excludePods",
			&scope.Scope{ExcludePods: &metav1.LabelSelector{}, IncludePods: bad},
			unparsable("includePods")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := scope.New(tc.cfg)

			require.Nil(t, m)
			require.EqualError(t, err, tc.want)
		})
	}
}

// vexplain passes the scope to its collectors as JSON, in the context of every Watch and Invoke: the
// JSON of OperatorConfig's spec.scope. Parse reads it into the Matcher that New builds from the same
// scope.
func TestParseReadsTheScopeOfTheContext(t *testing.T) {
	m, err := scope.Parse([]byte(`{
  "includeNamespaces": {"matchLabels": {"team": "a"}},
  "excludeNamespaces": {"matchExpressions": [{"key": "vexplain", "operator": "In", "values": ["off"]}]},
  "includePods": {"matchLabels": {"tier": "web"}},
  "excludePods": {"matchExpressions": [{"key": "app", "operator": "Exists"}]}
}`))
	require.NoError(t, err)

	require.True(t, m.Matches(labelSet{team: "a"}, labelSet{tier: web}))
	require.False(t, m.Matches(labelSet{team: "b"}, labelSet{tier: web}), "includeNamespaces")
	require.False(t, m.Matches(labelSet{team: "a", vexplain: off}, labelSet{tier: web}), "excludeNamespaces")
	require.False(t, m.Matches(labelSet{team: "a"}, labelSet{tier: api}), "includePods")
	require.False(t, m.Matches(labelSet{team: "a"}, labelSet{tier: web, app: debug}), "excludePods")
}

// A context without a scope limits nothing, as an OperatorConfig without one does.
func TestParseOfNoScopeMatchesEverything(t *testing.T) {
	for _, raw := range []string{"", "  ", "null", "{}"} {
		t.Run(raw, func(t *testing.T) {
			m, err := scope.Parse([]byte(raw))
			require.NoError(t, err)

			require.True(t, m.Matches(labelSet{team: "b"}, labelSet{app: debug}))
		})
	}
}

// A scope that Parse can't read fully is refused, never applied in part: a field that it doesn't know
// could be one that leaves pods out, and a collector that ignored it would report them. New's refusals
// hold too.
func TestParseRefusesAScopeThatItCantReadFully(t *testing.T) {
	for name, raw := range map[string]string{
		"not JSON":                    `{"includeNamespaces":`,
		"not an object":               `["team"]`,
		"a field that Scope lacks":    `{"excludeNodes": {"matchLabels": {"pool": "gpu"}}}`,
		"a field that selectors lack": `{"includePods": {"matchLabel": {"tier": "web"}}}`,
		"an empty exclude":            `{"excludePods": {}}`,
		"an unparsable selector":      `{"includePods": {"matchExpressions": [{"key": "tier", "operator": "Bogus"}]}}`,
		"more after the scope":        `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			m, err := scope.Parse([]byte(raw))

			require.Nil(t, m)
			require.Error(t, err)
		})
	}
}
