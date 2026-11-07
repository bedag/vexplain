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

package attribution_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/sdk/attribution"
)

// vexplain passes the allowlists of owner attribution to its collectors as JSON, in the context of every Watch and
// Invoke: the JSON of OperatorConfig's spec.ownerAttribution.
func TestParseReadsTheAllowlistsOfTheContext(t *testing.T) {
	got, err := attribution.Parse([]byte(`{
  "namespaceLabels": ["team"],
  "namespaceAnnotations": ["contact"],
  "workloadLabels": ["app.kubernetes.io/part-of", "example.com/cost-center"]
}`))

	require.NoError(t, err)
	require.Equal(t, attribution.Allowlists{
		NamespaceLabels:      []string{"team"},
		NamespaceAnnotations: []string{"contact"},
		WorkloadLabels:       []string{"app.kubernetes.io/part-of", "example.com/cost-center"},
	}, got)
}

// A context without allowlists copies nothing, as an OperatorConfig without them does.
func TestParseOfNoAllowlistsAllowsNothing(t *testing.T) {
	for _, raw := range []string{"", "  ", "null", "{}"} {
		t.Run(raw, func(t *testing.T) {
			got, err := attribution.Parse([]byte(raw))

			require.NoError(t, err)
			require.Zero(t, got)
		})
	}
}

// Allowlists that Parse can't read fully are refused, never applied in part: a field that it doesn't know, such as one
// whose name the API changed, would copy nothing that an admin allowlisted there, and nobody would notice.
func TestParseRefusesAllowlistsThatItCantReadFully(t *testing.T) {
	for name, raw := range map[string]string{
		"not JSON":                       `{"namespaceLabels":`,
		"not an object":                  `["team"]`,
		"a field that Allowlists lacks":  `{"podAnnotations": ["contact"]}`,
		"a list that holds no strings":   `{"workloadLabels": [1]}`,
		"more after the allowlists":      `{} {}`,
		"a field whose name is misspelt": `{"namespaceLabel": ["team"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := attribution.Parse([]byte(raw))

			require.Error(t, err)
			require.Zero(t, got)
		})
	}
}
