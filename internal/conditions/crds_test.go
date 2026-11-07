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

package conditions_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

// crdDirectory holds the CRDs of the install, as make manifests generates them.
var crdDirectory = filepath.Join("..", "..", "config", "crd", "bases")

// held lists the CRDs whose kind a controller of vexplain reconciles, and so carries a status that kstatus
// can read: status.observedGeneration, and the conditions Ready, Reconciling and Stalled (decision 0036).
var held = []string{
	"collectors.config.vexplain.bedag.ch",
	"modelconfigs.config.vexplain.bedag.ch",
	"operatorconfigs.config.vexplain.bedag.ch",
	"playbooks.config.vexplain.bedag.ch",
	"rules.config.vexplain.bedag.ch",
}

// leftOut lists the CRDs whose kind no controller reconciles, each with the reason. kstatus reads them as
// current.
var leftOut = map[string]string{
	"collectorruntimeconfigs.config.vexplain.bedag.ch": "the deployer only reads it, and a Collector reports a bad one",
	"evidences.inventory.vexplain.bedag.ch":            "its status is evidence that vexplain writes",
	"imageinventories.inventory.vexplain.bedag.ch":     "its status is the inventory that vexplain writes",
	"imageverdicts.inventory.vexplain.bedag.ch":        "its status is the sheet of verdicts that vexplain writes",
	"workloadreports.triage.vexplain.bedag.ch":         "its status is the report that vexplain writes",
}

// readCRDs reads every CRD of crdDirectory, by name.
func readCRDs(t *testing.T) map[string]*apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(crdDirectory, "*.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, files, "no CRD in %s", crdDirectory)
	crds := map[string]*apiextensionsv1.CustomResourceDefinition{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		var crd apiextensionsv1.CustomResourceDefinition
		require.NoError(t, yaml.UnmarshalStrict(data, &crd), file)
		crds[crd.Name] = &crd
	}
	return crds
}

// TestEveryCRDIsHeldToKstatusOrLeftOutWithAReason is how a new kind gets a status that kstatus can read: a
// CRD in neither list fails, until it is added to one of them.
func TestEveryCRDIsHeldToKstatusOrLeftOutWithAReason(t *testing.T) {
	crds := readCRDs(t)
	for _, name := range held {
		_, also := leftOut[name]
		require.False(t, also, "%s is both held and left out", name)
		require.Contains(t, crds, name, "%s is held, and no CRD of that name exists", name)
	}
	for name, reason := range leftOut {
		require.NotEmpty(t, reason, "%s is left out without a reason", name)
		require.Contains(t, crds, name, "%s is left out, and no CRD of that name exists", name)
	}
	for name := range crds {
		_, out := leftOut[name]
		require.True(t, out || slices.Contains(held, name),
			"the CRD %s is neither held to a status that kstatus can read nor left out with a reason: add it to one of the lists", name)
	}
}

func TestEveryHeldCRDHasAnObservedGenerationAndConditions(t *testing.T) {
	crds := readCRDs(t)
	for _, name := range held {
		crd, ok := crds[name]
		require.True(t, ok, name)
		for _, version := range crd.Spec.Versions {
			require.NotNil(t, version.Subresources, "%s %s", name, version.Name)
			require.NotNil(t, version.Subresources.Status, "%s %s has no status subresource", name, version.Name)
			status, ok := version.Schema.OpenAPIV3Schema.Properties["status"]
			require.True(t, ok, "%s %s has no status", name, version.Name)

			observed, ok := status.Properties["observedGeneration"]
			require.True(t, ok, "%s %s has no status.observedGeneration", name, version.Name)
			require.Equal(t, "integer", observed.Type, "%s %s: status.observedGeneration", name, version.Name)
			require.Equal(t, "int64", observed.Format, "%s %s: status.observedGeneration", name, version.Name)

			conditions, ok := status.Properties["conditions"]
			require.True(t, ok, "%s %s has no status.conditions", name, version.Name)
			require.Equal(t, "array", conditions.Type, "%s %s: status.conditions", name, version.Name)
			require.NotNil(t, conditions.Items, "%s %s: status.conditions", name, version.Name)
			for _, field := range []string{"type", "status", "reason", "message", "observedGeneration", "lastTransitionTime"} {
				require.Contains(t, conditions.Items.Schema.Properties, field,
					"%s %s: status.conditions are no metav1.Condition", name, version.Name)
			}
		}
	}
}
