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

package config_test

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"

	"github.com/bedag/vexplain/sdk/evidence"
)

// typeMaxLength is the longest name of a type of evidence that a CRD accepts.
const typeMaxLength = 253

// statusField and capabilitiesField are the properties of a Collector that lead to what the collector
// answered, and items stands, in a place, for the items of a list.
const (
	statusField       = "status"
	capabilitiesField = "capabilities"
	items             = "[]"
)

// typePlaces lists where the schemas of the config kinds hold the name of a type of evidence, by the
// file of the CRD. A place is the names of the properties on the way down from the top of the schema,
// and items stands for the items of a list.
var typePlaces = map[string][][]string{
	"config.vexplain.bedag.ch_collectors.yaml": {
		{statusField, capabilitiesField, "produces", items, typeField},
		{statusField, capabilitiesField, "consumes", items},
		{statusField, capabilitiesField, "operations", items, "produces", items},
		{statusField, capabilitiesField, "operations", items, "consumes", items},
	},
	"config.vexplain.bedag.ch_playbooks.yaml": {
		{specField, subjectsField, typeField},
		{specField, "evidence", items, typeField},
	},
	"config.vexplain.bedag.ch_rules.yaml": {
		{specField, "inputs", items, typeField},
	},
}

// A kubebuilder marker can't name a Go constant, so each place in a CRD repeats the pattern of the
// SDK's types as text. The SDK is what collectors are written against, so its pattern decides what a
// type may look like, and this test fails when a marker drifts from it, or when a place is left
// without one.
func TestTypesOfEvidenceInTheCRDsFollowTheSDKsPattern(t *testing.T) {
	for file, places := range typePlaces {
		crd := readCRD(t, file)
		require.Len(t, crd.Spec.Versions, 1, file)
		root := crd.Spec.Versions[0].Schema.OpenAPIV3Schema

		for _, place := range places {
			schema := root
			for _, step := range place {
				schema = descend(t, schema, step)
			}

			require.Equal(t, evidence.TypePattern, schema.Pattern, "%s: %v", file, place)
			require.NotNil(t, schema.MaxLength, "%s: %v has no maximum length", file, place)
			require.Equal(t, int64(typeMaxLength), *schema.MaxLength, "%s: %v", file, place)
		}
	}
}

// readCRD reads a generated CRD of the config group.
func readCRD(t *testing.T, file string) *apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "bases", file))
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.UnmarshalStrict(data, &crd))
	return &crd
}

// descend returns the schema below schema at step: the property of that name, or for "[]" the items.
func descend(t *testing.T, schema *apiextensionsv1.JSONSchemaProps, step string) *apiextensionsv1.JSONSchemaProps {
	t.Helper()
	if step == items {
		require.NotNil(t, schema.Items, "no items below the schema")
		require.NotNil(t, schema.Items.Schema, "the items have no schema")
		return schema.Items.Schema
	}
	property, ok := schema.Properties[step]
	require.True(t, ok, "no property %q; the schema has %v", step, slices.Sorted(maps.Keys(schema.Properties)))
	return &property
}
