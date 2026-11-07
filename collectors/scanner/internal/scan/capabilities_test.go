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

package scan_test

import (
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/sdk/collector"
)

// These tests hold what the collector declares in GetCapabilities to the golden file testdata/capabilities.json. The
// operator's chain test (internal/setup/chain) builds its stand-in for this collector from the same file, read from its
// path in the repository, since the operator imports no collector: a change to the capabilities fails here until the
// file follows it, and then the stand-in follows too. Run the tests with -update to write the file.

var update = flag.Bool("update", false, "write the golden file of the capabilities")

const capabilitiesPath = "testdata/capabilities.json"

// The names of roles and scopes in the golden file.
var (
	roleNames  = map[collector.Role]string{collector.RoleSpoke: "Spoke", collector.RoleHub: "Hub"}
	scopeNames = map[collector.Scope]string{collector.ScopeSpoke: "Spoke", collector.ScopeHub: "Hub"}
)

type goldenType struct {
	Type   string          `json:"type"`
	Scope  string          `json:"scope"`
	Schema json.RawMessage `json:"schema,omitempty"`
}

type goldenOperation struct {
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Role            string          `json:"role"`
	Produces        []string        `json:"produces,omitempty"`
	Consumes        []string        `json:"consumes,omitempty"`
	ParameterSchema json.RawMessage `json:"parameterSchema,omitempty"`
}

type goldenPermission struct {
	APIGroups  []string `json:"apiGroups"`
	Resources  []string `json:"resources"`
	Verbs      []string `json:"verbs"`
	Namespaced bool     `json:"namespaced,omitempty"`
}

type goldenCapabilities struct {
	Roles          []string           `json:"roles"`
	Produces       []goldenType       `json:"produces,omitempty"`
	Consumes       []string           `json:"consumes,omitempty"`
	Watches        bool               `json:"watches"`
	Operations     []goldenOperation  `json:"operations,omitempty"`
	SettingsSchema json.RawMessage    `json:"settingsSchema,omitempty"`
	Permissions    []goldenPermission `json:"permissions,omitempty"`
}

// goldenOf returns the JSON of the capabilities, as the golden file has it.
func goldenOf(t *testing.T, caps collector.Capabilities) []byte {
	t.Helper()
	g := goldenCapabilities{Consumes: caps.Consumes, Watches: caps.Watches, SettingsSchema: caps.SettingsSchema}
	for _, role := range caps.Roles {
		g.Roles = append(g.Roles, roleNames[role])
	}
	for _, p := range caps.Produces {
		g.Produces = append(g.Produces, goldenType{Type: p.Type, Scope: scopeNames[p.Scope], Schema: p.Schema})
	}
	for _, op := range caps.Operations {
		g.Operations = append(g.Operations, goldenOperation{Name: op.Name, Description: op.Description,
			Role: roleNames[op.Role], Produces: op.Produces, Consumes: op.Consumes, ParameterSchema: op.ParameterSchema})
	}
	for _, p := range caps.Permissions {
		g.Permissions = append(g.Permissions, goldenPermission{APIGroups: p.APIGroups, Resources: p.Resources,
			Verbs: p.Verbs, Namespaced: p.Namespaced})
	}
	raw, err := json.MarshalIndent(g, "", "  ")
	require.NoError(t, err)
	return append(raw, '\n')
}

func TestTheCapabilitiesAreTheGoldenFile(t *testing.T) {
	got := goldenOf(t, newFixture(t, newRunner(scanned)).scanner.Capabilities())
	if *update {
		require.NoError(t, os.WriteFile(capabilitiesPath, got, 0o644))
	}

	want, err := os.ReadFile(capabilitiesPath)
	require.NoError(t, err)
	require.JSONEq(t, string(want), string(got), "run the tests with -update, and the chain test's stand-in follows")
}
