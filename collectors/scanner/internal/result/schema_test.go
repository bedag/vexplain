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

package result_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/collectors/scanner/internal/result"
)

// These tests hold the JSON of a Manifest, the data of the scanner's evidence, to the golden files in testdata, and
// to the schema that the collector declares for its type. The operator's default rules read that JSON, and their
// tests read the same golden files, since the operator imports no type of the scanner: a change of the JSON fails
// here until the golden files follow it, and then there until the rules' fixtures do.

// everyField sets every field of a Manifest, nested ones included: the JSON of manifest-every-field.json.
func everyField() result.Manifest {
	return result.Manifest{
		Platform: "linux/arm64/v8",
		Digest:   "sha256:" + strings.Repeat("cd", 32),
		SBOM:     json.RawMessage(`{"artifacts":[{"id":"a","name":"n","version":"v","type":"t"}]}`),
		Packages: []result.PackageFacts{{ID: "a", FilesListed: 1, FilesPresent: 2, SharedLibraries: 3, OtherELFFiles: 4}},
		ELF:      result.ELFSummary{Total: 6, Owned: 5, Unowned: []string{"/x"}},
		Libraries: []result.Library{
			{Path: "/p", Soname: "s", PackageID: "a", ReachedBy: []string{"/r"}, ReachedCount: 7, NameHits: []string{"/h"},
				NameHitCount: 8},
			{Path: "/usr/lib/libz.so.1", Soname: "libz.so.1"},
		},
		Preload: result.Preload{LDPreload: true, LDAudit: true, EtcLdSoPreload: true},
	}
}

// golden reads a golden file of testdata.
func golden(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return raw
}

func TestAManifestIsWrittenAsTheGoldenJSON(t *testing.T) {
	for file, m := range map[string]result.Manifest{
		"manifest-every-field.json": everyField(),
		"manifest-no-field.json":    {},
	} {
		t.Run(file, func(t *testing.T) {
			raw, err := json.Marshal(m)
			require.NoError(t, err)

			require.JSONEq(t, string(golden(t, file)), string(raw))
		})
	}
}

// The golden file with every field names each field of Manifest, and of the types in it, so that a field that is
// added to them fails this test until the golden file has it.
func TestTheGoldenJSONNamesEveryFieldOfAManifest(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal(golden(t, "manifest-every-field.json"), &doc))

	requireEveryField(t, reflect.TypeFor[result.Manifest](), doc, "manifest")
}

// requireEveryField requires that the JSON object doc holds every field of the struct type, by its JSON name, and so
// do the objects of the fields that are structs, or lists of them: the first object of such a list.
func requireEveryField(t *testing.T, typ reflect.Type, doc map[string]any, at string) {
	t.Helper()
	for field := range typ.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		value, ok := doc[name]
		require.True(t, ok, "%s has no %q", at, name)
		inner := field.Type
		if inner.Kind() == reflect.Slice {
			inner = inner.Elem()
			if list, isList := value.([]any); isList && len(list) > 0 {
				value = list[0]
			}
		}
		if inner.Kind() != reflect.Struct {
			continue
		}
		object, isObject := value.(map[string]any)
		require.True(t, isObject, "%s.%s is an object", at, name)
		requireEveryField(t, inner, object, at+"."+name)
	}
}

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(result.Schema()))
	require.NoError(t, err, "the schema is JSON")
	compiler := jsonschema.NewCompiler()
	// A schema stands alone: vexplain compiles it from the capabilities, without the collector's files.
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	const url = "urn:vexplain:schema:" + result.EvidenceType
	require.NoError(t, compiler.AddResource(url, doc))
	schema, err := compiler.Compile(url)
	require.NoError(t, err)
	return schema
}

// The schema's $id is the dataschema of the type's events, as the SDK gives it to every event.
func TestTheSchemaIsTheTypes(t *testing.T) {
	var schema struct {
		ID string `json:"$id"`
	}
	require.NoError(t, json.Unmarshal(result.Schema(), &schema))

	require.Equal(t, "urn:vexplain:schema:"+result.EvidenceType, schema.ID)
}

func TestTheSchemaAcceptsAManifestWithEveryField(t *testing.T) {
	schema := compileSchema(t)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(golden(t, "manifest-every-field.json")))
	require.NoError(t, err)

	require.NoError(t, schema.Validate(doc))
}

// What a scan finds in an image without packages or libraries leaves both lists null, which the schema takes.
func TestTheSchemaAcceptsAManifestWithoutPackagesOrLibraries(t *testing.T) {
	schema := compileSchema(t)
	m := everyField()
	m.Packages, m.Libraries, m.ELF = nil, nil, result.ELFSummary{}
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	require.NoError(t, err)

	require.NoError(t, schema.Validate(doc))
}

func TestTheSchemaRefusesWhatNoManifestHolds(t *testing.T) {
	schema := compileSchema(t)
	for name, change := range map[string]func(m map[string]any){
		"an unknown field":            func(m map[string]any) { m["files"] = []any{} },
		"no SBOM":                     func(m map[string]any) { delete(m, "sbom") },
		"an empty SBOM":               func(m map[string]any) { m["sbom"] = map[string]any{} },
		"a platform of capitals":      func(m map[string]any) { m["platform"] = "Linux/AMD64" },
		"a digest that isn't sha256":  func(m map[string]any) { m["digest"] = "sha256:1111" },
		"a negative count":            func(m map[string]any) { m["elf"].(map[string]any)["total"] = -1 },
		"an unknown field of the ELF": func(m map[string]any) { m["elf"].(map[string]any)["x"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			require.NoError(t, json.Unmarshal(golden(t, "manifest-every-field.json"), &m))
			change(m)
			raw, err := json.Marshal(m)
			require.NoError(t, err)
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			require.NoError(t, err)

			require.Error(t, schema.Validate(doc))
		})
	}
}
