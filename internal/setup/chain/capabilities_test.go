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

package chain_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/sdk/collector"
)

// The stand-ins for the scanner, the vulnerabilities collector and the network-reach collector take their capabilities from the golden files
// that the collectors' own tests hold their GetCapabilities to, read from their paths in the repository: the operator's module imports no
// collector. A change to a collector's capabilities fails its own golden test until its file follows, and the file
// changes the stand-in, so this suite can't stay green on capabilities that drifted.
const (
	scannerCapabilitiesPath         = "collectors/scanner/internal/scan/testdata/capabilities.json"
	vulnerabilitiesCapabilitiesPath = "collectors/vulnerabilities/internal/match/testdata/capabilities.json"
	networkReachCapabilitiesPath    = "collectors/network-reach/internal/exposure/testdata/capabilities.json"
)

type goldenType struct {
	Type   string          `json:"type"`
	Scope  string          `json:"scope"`
	Schema json.RawMessage `json:"schema"`
}

type goldenOperation struct {
	Name            string          `json:"name"`
	Description     string          `json:"description"`
	Role            string          `json:"role"`
	Produces        []string        `json:"produces"`
	Consumes        []string        `json:"consumes"`
	ParameterSchema json.RawMessage `json:"parameterSchema"`
}

type goldenPermission struct {
	APIGroups  []string `json:"apiGroups"`
	Resources  []string `json:"resources"`
	Verbs      []string `json:"verbs"`
	Namespaced bool     `json:"namespaced"`
}

type goldenCapabilities struct {
	Roles          []string           `json:"roles"`
	Produces       []goldenType       `json:"produces"`
	Consumes       []string           `json:"consumes"`
	Watches        bool               `json:"watches"`
	Operations     []goldenOperation  `json:"operations"`
	SettingsSchema json.RawMessage    `json:"settingsSchema"`
	Permissions    []goldenPermission `json:"permissions"`
}

var (
	roles  = map[string]collector.Role{"Spoke": collector.RoleSpoke, "Hub": collector.RoleHub}
	scopes = map[string]collector.Scope{"Spoke": collector.ScopeSpoke, "Hub": collector.ScopeHub}
)

// testingT is what the helpers need of a test: *testing.T and Ginkgo's GinkgoT() both are one.
type testingT interface {
	require.TestingT
	Helper()
}

// capabilitiesOf reads a golden file of the repository as the capabilities that it holds.
func capabilitiesOf(t testingT, path string) collector.Capabilities {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repositoryRoot, path))
	require.NoError(t, err)
	var g goldenCapabilities
	require.NoError(t, json.Unmarshal(raw, &g))
	caps := collector.Capabilities{Consumes: g.Consumes, Watches: g.Watches, SettingsSchema: g.SettingsSchema}
	for _, name := range g.Roles {
		role, ok := roles[name]
		require.True(t, ok, "role %q", name)
		caps.Roles = append(caps.Roles, role)
	}
	for _, p := range g.Produces {
		scope, ok := scopes[p.Scope]
		require.True(t, ok, "scope %q", p.Scope)
		caps.Produces = append(caps.Produces, collector.EvidenceType{Type: p.Type, Scope: scope, Schema: p.Schema})
	}
	for _, op := range g.Operations {
		role, ok := roles[op.Role]
		require.True(t, ok, "role %q", op.Role)
		caps.Operations = append(caps.Operations, collector.Operation{Name: op.Name, Description: op.Description,
			Role: role, Produces: op.Produces, Consumes: op.Consumes, ParameterSchema: op.ParameterSchema})
	}
	for _, p := range g.Permissions {
		caps.Permissions = append(caps.Permissions, collector.Permission{
			APIGroups: p.APIGroups, Resources: p.Resources, Verbs: p.Verbs, Namespaced: p.Namespaced})
	}
	return caps
}

func TestTheStandInsTakeTheCapabilitiesOfTheGoldenFiles(t *testing.T) {
	require.Equal(t, capabilitiesOf(t, scannerCapabilitiesPath), newScannerStandIn(t, nil).Capabilities())
	require.Equal(t, capabilitiesOf(t, vulnerabilitiesCapabilitiesPath), newVulnerabilitiesStandIn(t, "v1").Capabilities())
	require.Equal(t, capabilitiesOf(t, networkReachCapabilitiesPath), newNetworkReachStandIn(t, nil).Capabilities())
}
