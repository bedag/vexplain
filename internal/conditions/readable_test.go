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
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// The kinds that people can read (decision 0039): every CRD takes a category, so that one kubectl get lists them,
// and the list columns of the data kinds and the reports read the summaries of their status, since a column can't
// add up a list.

const (
	// categoryEveryKind is the category of every kind of vexplain, and categoryData the one of the kinds that only
	// vexplain writes, its data.
	categoryEveryKind = "vexplain"
	categoryData      = "vexplain-data"

	imageInventories = "imageinventories.inventory.vexplain.bedag.ch"
	imageVerdicts    = "imageverdicts.inventory.vexplain.bedag.ch"
	workloadReports  = "workloadreports.triage.vexplain.bedag.ch"
)

// dataKinds lists the CRDs of the data kinds: what vexplain writes, and nobody else.
var dataKinds = []string{
	"evidences.inventory.vexplain.bedag.ch",
	imageInventories,
	imageVerdicts,
}

// column is what a test checks of a list column: its name, the JSONPath that it reads, and its priority, 1 for a
// column that kubectl shows only with -o wide.
type column struct {
	name, path string
	priority   int32
}

// columnsOf returns the list columns of a version of a CRD, in order.
func columnsOf(version apiextensionsv1.CustomResourceDefinitionVersion) []column {
	columns := make([]column, 0, len(version.AdditionalPrinterColumns))
	for _, c := range version.AdditionalPrinterColumns {
		columns = append(columns, column{name: c.Name, path: c.JSONPath, priority: c.Priority})
	}
	return columns
}

func TestEveryCRDTakesTheCategoryVexplainAndOnlyTheDataKindsVexplainData(t *testing.T) {
	crds := readCRDs(t)
	for _, name := range dataKinds {
		require.Contains(t, crds, name, "a data kind that no CRD has")
	}
	for name, crd := range crds {
		categories := crd.Spec.Names.Categories
		require.Contains(t, categories, categoryEveryKind, "%s: kubectl get vexplain lists every kind", name)
		require.Equal(t, slices.Contains(dataKinds, name), slices.Contains(categories, categoryData),
			"%s: kubectl get vexplain-data lists the data kinds, and only them", name)
		require.NotContains(t, categories, "all", "%s: kubectl get all stays as it is", name)
	}
}

// The columns of the kinds that 0039 names, in the order that kubectl shows them.
func TestTheColumnsOfTheSheetsTheImagesAndTheReportsReadTheirSummaries(t *testing.T) {
	age := column{"Age", ".metadata.creationTimestamp", 0}
	want := map[string][]column{
		imageVerdicts: {
			{"Open", ".status.summary.open", 0},
			{"Fixable", ".status.summary.fixable", 0},
			{"Held", ".status.summary.held", 0},
			{"Settled", ".status.summary.settled", 0},
			{"Omitted", ".status.summary.omitted", 0},
			age,
		},
		imageInventories: {
			{"Image", ".status.summary.image", 0},
			{"Workloads", ".status.summary.workloads", 0},
			{"Namespaces", ".status.summary.namespaces", 0},
			{"Scan State", ".status.summary.scanState", 0},
			{"Open", ".status.summary.open", 0},
			{"Fixable", ".status.summary.fixable", 0},
			age,
			{"Platforms", ".status.facts.manifests[*].platform", 1},
		},
		workloadReports: {
			// A report's name is hashed when the workload's is too long for it, so -o wide says which workload it is for.
			{"Kind", ".spec.workload.kind", 1},
			{"Workload", ".spec.workload.name", 1},
			{"Exposure", ".status.exposure", 0},
			{"Highest Urgency", ".status.summary.highestUrgency", 0},
			{"Updates", ".status.summary.updates", 0},
			{"Mitigations", ".status.summary.mitigations", 1},
			{"To Investigate", ".status.summary.investigations", 0},
			{"Critical", ".status.summary.critical", 0},
			{"Known Exploited", ".status.summary.knownExploited", 0},
			// An image without a verdict adds nothing to the other columns, so this one says that they aren't the whole
			// answer yet (decision 0038).
			{"Pending Images", ".status.summary.pending", 0},
			age,
		},
	}
	crds := readCRDs(t)
	for name, columns := range want {
		crd, ok := crds[name]
		require.True(t, ok, name)
		for _, version := range crd.Spec.Versions {
			require.Equal(t, columns, columnsOf(version), "%s %s", name, version.Name)
		}
	}
}

// An image's record is named after its digest, so a column of the digest says it twice.
func TestNoColumnOfAnImageShowsItsDigest(t *testing.T) {
	crd, ok := readCRDs(t)[imageInventories]
	require.True(t, ok)
	for _, version := range crd.Spec.Versions {
		for _, c := range columnsOf(version) {
			require.NotEqual(t, ".spec.digest", c.path, "%s: the column %s", version.Name, c.name)
		}
	}
}

// Most clusters run one platform, so a column of platforms says little, and shows only with -o wide.
func TestEveryPlatformColumnShowsOnlyWithWide(t *testing.T) {
	for name, crd := range readCRDs(t) {
		for _, version := range crd.Spec.Versions {
			for _, c := range columnsOf(version) {
				if strings.Contains(strings.ToLower(c.name+c.path), "platform") {
					require.Equal(t, int32(1), c.priority, "%s %s: the column %s", name, version.Name, c.name)
				}
			}
		}
	}
}

// A column whose path names no field of the schema shows nothing, whatever the object holds.
func TestEveryColumnReadsAFieldOfItsSchema(t *testing.T) {
	for name, crd := range readCRDs(t) {
		for _, version := range crd.Spec.Versions {
			for _, c := range columnsOf(version) {
				require.True(t, readsAField(version.Schema.OpenAPIV3Schema, c.path),
					"%s %s: the column %s reads %s, which the schema lacks", name, version.Name, c.name, c.path)
			}
		}
	}
}

// selector matches what a JSONPath selects of a list, such as [*] or [?(@.type=="Ready")].
var selector = regexp.MustCompile(`\[[^\]]*\]`)

// readsAField reports whether a column's JSONPath names a field of the schema: each of its steps a property, and
// each step that selects from a list a list. The schema of a CRD says nothing of metadata but that it is an object,
// so a path into metadata names a field of the standard object metadata.
func readsAField(schema *apiextensionsv1.JSONSchemaProps, path string) bool {
	if strings.HasPrefix(path, ".metadata.") {
		return true
	}
	steps := strings.Split(strings.TrimPrefix(selector.ReplaceAllString(path, "[]"), "."), ".")
	at := schema
	for _, step := range steps {
		field, list := strings.CutSuffix(step, "[]")
		next, ok := at.Properties[field]
		if !ok {
			return false
		}
		at = &next
		if list {
			if at.Type != "array" || at.Items == nil || at.Items.Schema == nil {
				return false
			}
			at = at.Items.Schema
		}
	}
	return true
}
