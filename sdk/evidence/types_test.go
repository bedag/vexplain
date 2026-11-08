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

package evidence_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/sdk/evidence"
)

const (
	teamA          = "team-a"
	web            = "web"
	webPod         = "web-0"
	kindContainer  = "Container"
	digestKindID   = "ImageID"
	reachNamespace = "Namespace"

	// The package and the producer of the samples.
	pkg1    = "pkg-1"
	libfoo  = "libfoo"
	typeDeb = "deb"
	typeRPM = "rpm"
	syft    = "syft"

	// The names of fields that several objects have, which TestSchemasFieldByField lists again and
	// again.
	fieldAPIGroup  = "apiGroup"
	fieldKind      = "kind"
	fieldName      = "name"
	fieldNamespace = "namespace"
	fieldPlatform  = "platform"
	fieldVersion   = "version"
	// fieldModularityLabel is the field of a package that names an RPM's module stream.
	fieldModularityLabel = "modularityLabel"
)

// samplePresence has every field set.
func samplePresence() evidence.Presence {
	return evidence.Presence{
		DigestKind:   "RepoDigest",
		Repositories: []string{"registry.example/team-a/app"},
		Workloads: []evidence.PresenceWorkload{{
			APIGroup:  "apps",
			Kind:      "Deployment",
			Namespace: teamA,
			Name:      web,
			UID:       "6f9619ff-8b86-4011-b42d-00c04fc964ff",
			Pods: []evidence.PresencePod{
				{Name: "web-6d4cf56db6-x2x9p", Node: "node-1", Platform: "linux/amd64", Containers: []evidence.PresenceContainer{
					{Name: "setup", Kind: "InitContainer"}, {Name: "proxy", Kind: "Sidecar"}, {Name: "web", Kind: kindContainer},
				}},
				{Name: "web-6d4cf56db6-q7t4m", Node: "node-2", Platform: "linux/arm64/v8"},
			},
			Labels:               []evidence.KeyValue{{Key: "app.kubernetes.io/name", Value: "web"}},
			NamespaceLabels:      []evidence.KeyValue{{Key: "team", Value: "a"}},
			NamespaceAnnotations: []evidence.KeyValue{{Key: "owner", Value: "team-a"}},
		}},
	}
}

const presenceJSON = `{
  "digestKind": "RepoDigest",
  "repositories": ["registry.example/team-a/app"],
  "workloads": [{
    "apiGroup": "apps",
    "kind": "Deployment",
    "namespace": "team-a",
    "name": "web",
    "uid": "6f9619ff-8b86-4011-b42d-00c04fc964ff",
    "pods": [
      {"name": "web-6d4cf56db6-x2x9p", "node": "node-1", "platform": "linux/amd64", "containers": [
        {"name": "setup", "kind": "InitContainer"},
        {"name": "proxy", "kind": "Sidecar"},
        {"name": "web", "kind": "Container"}
      ]},
      {"name": "web-6d4cf56db6-q7t4m", "node": "node-2", "platform": "linux/arm64/v8"}
    ],
    "labels": [{"key": "app.kubernetes.io/name", "value": "web"}],
    "namespaceLabels": [{"key": "team", "value": "a"}],
    "namespaceAnnotations": [{"key": "owner", "value": "team-a"}]
  }]
}`

// minimalPresence has only what the type requires: a bare Pod, so that the core group's empty
// apiGroup is written out, and no pods, labels or repositories.
func minimalPresence() evidence.Presence {
	return evidence.Presence{
		DigestKind: digestKindID,
		Workloads: []evidence.PresenceWorkload{
			{Kind: "Pod", Namespace: teamA, Name: webPod, UID: "0e5f4b1c-2a6d-4c43-9d51-7f3f1d9a1e42"},
		},
	}
}

const minimalPresenceJSON = `{
  "digestKind": "ImageID",
  "workloads": [{
    "apiGroup": "",
    "kind": "Pod",
    "namespace": "team-a",
    "name": "web-0",
    "uid": "0e5f4b1c-2a6d-4c43-9d51-7f3f1d9a1e42"
  }]
}`

// sampleFindings has every field set.
func sampleFindings() evidence.Findings {
	return evidence.Findings{
		Version: "v6.1.0+2026-10-30T00:00:00Z",
		Matches: []evidence.Match{{
			VulnerabilityID: "CVE-2026-111497",
			PackageID:       pkg1,
			PackageName:     libfoo,
			PackageVersion:  "1.2.3-1",
			PackageType:     typeDeb,
			Severity:        "High",
			FixState:        "fixed",
			FixedVersions:   []string{"1.2.3-2"},
			KnownExploited:  true,
			CVSS:            []evidence.CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		}},
	}
}

const findingsJSON = `{
  "version": "v6.1.0+2026-10-30T00:00:00Z",
  "matches": [{
    "vulnerabilityID": "CVE-2026-111497",
    "packageID": "pkg-1",
    "packageName": "libfoo",
    "packageVersion": "1.2.3-1",
    "packageType": "deb",
    "severity": "High",
    "fixState": "fixed",
    "fixedVersions": ["1.2.3-2"],
    "knownExploited": true,
    "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
  }]
}`

// minimalFindings is a match with only what the type requires. A package can lack a version, and
// the source can say nothing about a fix, which is an empty fixState that is still written out.
func minimalFindings() evidence.Findings {
	return evidence.Findings{
		Version: "v6.1.0+2026-10-30T00:00:00Z",
		Matches: []evidence.Match{{
			VulnerabilityID: "CVE-2026-111497",
			PackageID:       pkg1,
			PackageName:     libfoo,
			PackageType:     typeDeb,
			Severity:        "Unknown",
		}},
	}
}

const minimalFindingsJSON = `{
  "version": "v6.1.0+2026-10-30T00:00:00Z",
  "matches": [{
    "vulnerabilityID": "CVE-2026-111497",
    "packageID": "pkg-1",
    "packageName": "libfoo",
    "packageType": "deb",
    "severity": "Unknown",
    "fixState": "",
    "knownExploited": false
  }]
}`

// sampleExposure has every field set.
func sampleExposure() evidence.Exposure {
	return evidence.Exposure{
		External: evidence.ExternalExposure{
			Exposed: true,
			Via:     []evidence.ObjectRef{{APIGroup: "networking.k8s.io", Kind: "Ingress", Namespace: teamA, Name: web}},
		},
		InternalReach: "Namespaces",
		Indirect:      true,
	}
}

const exposureJSON = `{
  "external": {
    "exposed": true,
    "via": [{"apiGroup": "networking.k8s.io", "kind": "Ingress", "namespace": "team-a", "name": "web"}]
  },
  "internalReach": "Namespaces",
  "indirect": true
}`

// minimalExposure has only what the type requires: nothing reaches the workload from outside.
func minimalExposure() evidence.Exposure {
	return evidence.Exposure{InternalReach: reachNamespace}
}

const minimalExposureJSON = `{
  "external": {"exposed": false},
  "internalReach": "Namespace",
  "indirect": false
}`

// sampleSBOM has every field set: a package of Ubuntu whose source package, openssl, its purl names, as Syft writes
// it.
func sampleSBOM() evidence.SBOM {
	return evidence.SBOM{
		Distro: &evidence.Distro{ID: "ubuntu", Version: "24.04", Codename: "noble", IDLike: []string{"debian"}},
		Packages: []evidence.SBOMPackage{{
			ID:      "6f5b2e7a9c1d3e4f",
			Name:    "libssl3t64",
			Version: "3.0.13-0ubuntu3.5",
			Type:    typeDeb,
			PURL:    "pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.5?arch=amd64&distro=ubuntu-24.04&upstream=openssl",
			CPEs:    []string{"cpe:2.3:a:libssl3t64:libssl3t64:3.0.13-0ubuntu3.5:*:*:*:*:*:*:*"},
		}},
		Producer:         evidence.Producer{Name: syft, Version: "1.55.0"},
		FailedCatalogers: []string{"rpm-db-cataloger"},
	}
}

const sbomJSON = `{
  "distro": {"id": "ubuntu", "version": "24.04", "codename": "noble", "idLike": ["debian"]},
  "packages": [{
    "id": "6f5b2e7a9c1d3e4f",
    "name": "libssl3t64",
    "version": "3.0.13-0ubuntu3.5",
    "type": "deb",
    "purl": "pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.5?arch=amd64&distro=ubuntu-24.04&upstream=openssl",
    "cpes": ["cpe:2.3:a:libssl3t64:libssl3t64:3.0.13-0ubuntu3.5:*:*:*:*:*:*:*"]
  }],
  "producer": {"name": "syft", "version": "1.55.0"},
  "failedCatalogers": ["rpm-db-cataloger"]
}`

// minimalSBOM has only what the type requires: no distribution, and a package that has neither a version, a purl
// nor a CPE.
func minimalSBOM() evidence.SBOM {
	return evidence.SBOM{
		Packages: []evidence.SBOMPackage{{ID: pkg1, Name: libfoo, Type: typeDeb}},
		Producer: evidence.Producer{Name: syft},
	}
}

const minimalSBOMJSON = `{
  "packages": [{"id": "pkg-1", "name": "libfoo", "type": "deb"}],
  "producer": {"name": "syft"}
}`

// modularSBOM holds RPMs of AlmaLinux in each state of a modularity label: one of the module stream nodejs:20, one of
// no module stream, and one whose stream the producer doesn't know. Syft reads the label of an RPM of the rpm
// database, and knows none for an rpm file.
func modularSBOM() evidence.SBOM {
	return evidence.SBOM{
		Distro: &evidence.Distro{ID: "almalinux", Version: "8.9", IDLike: []string{"rhel", "centos", "fedora"}},
		Packages: []evidence.SBOMPackage{
			{
				ID: pkg1, Name: "nodejs", Version: "1:20.10.0-1.module_el8.9.0", Type: typeRPM,
				ModularityLabel: new("nodejs:20:8090020240101000000:a1b2c3d4"),
			},
			{ID: "pkg-2", Name: "openssl-libs", Version: "1:1.1.1k-12.el8_9", Type: typeRPM, ModularityLabel: new("")},
			{ID: "pkg-3", Name: "app", Version: "1.0-1", Type: typeRPM},
		},
		Producer: evidence.Producer{Name: syft, Version: "1.55.0"},
	}
}

const modularSBOMJSON = `{
  "distro": {"id": "almalinux", "version": "8.9", "idLike": ["rhel", "centos", "fedora"]},
  "packages": [
    {
      "id": "pkg-1",
      "name": "nodejs",
      "version": "1:20.10.0-1.module_el8.9.0",
      "type": "rpm",
      "modularityLabel": "nodejs:20:8090020240101000000:a1b2c3d4"
    },
    {"id": "pkg-2", "name": "openssl-libs", "version": "1:1.1.1k-12.el8_9", "type": "rpm", "modularityLabel": ""},
    {"id": "pkg-3", "name": "app", "version": "1.0-1", "type": "rpm"}
  ],
  "producer": {"name": "syft", "version": "1.55.0"}
}`

// jsonOf marshals v, and fails the test when that fails.
func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// TestCoreTypesJSON pins the names and the shape of the three types' data, which every collector
// has to write, in whatever language it is written. Reading the JSON back into the type refuses a
// name that the type doesn't have.
func TestCoreTypesJSON(t *testing.T) {
	t.Run("presence", func(t *testing.T) {
		requireJSON(t, samplePresence(), presenceJSON)
		requireJSON(t, minimalPresence(), minimalPresenceJSON)
	})
	t.Run("findings", func(t *testing.T) {
		requireJSON(t, sampleFindings(), findingsJSON)
		requireJSON(t, minimalFindings(), minimalFindingsJSON)
	})
	t.Run("exposure", func(t *testing.T) {
		requireJSON(t, sampleExposure(), exposureJSON)
		requireJSON(t, minimalExposure(), minimalExposureJSON)
	})
	t.Run("sbom", func(t *testing.T) {
		requireJSON(t, sampleSBOM(), sbomJSON)
		requireJSON(t, minimalSBOM(), minimalSBOMJSON)
		// An RPM's modularity label keeps its three states: a stream, no stream (""), and unknown (absent).
		requireJSON(t, modularSBOM(), modularSBOMJSON)
	})
}

func requireJSON[T any](t *testing.T, sample T, wantJSON string) {
	t.Helper()
	require.JSONEq(t, wantJSON, jsonOf(t, sample))

	var decoded T
	dec := json.NewDecoder(strings.NewReader(wantJSON))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&decoded))
	require.Equal(t, sample, decoded)
}

// A list that the schema requires is written as [], and never as null, also when nothing fills it:
// an image with no matches is the usual case for a findings event.
func TestRequiredListsAreNeverNull(t *testing.T) {
	require.JSONEq(t, `{"version": "v1", "matches": []}`, jsonOf(t, evidence.Findings{Version: "v1"}))
	require.JSONEq(t, `{"version": "v1", "matches": []}`, jsonOf(t, &evidence.Findings{Version: "v1"}))
	require.JSONEq(t, `{"digestKind": "ImageID", "workloads": []}`,
		jsonOf(t, evidence.Presence{DigestKind: digestKindID}))
	require.JSONEq(t, `{"digestKind": "ImageID", "workloads": []}`,
		jsonOf(t, &evidence.Presence{DigestKind: digestKindID}))
	// A filesystem without packages, such as that of an image of one static binary, is an SBOM too.
	require.JSONEq(t, `{"packages": [], "producer": {"name": "syft"}}`,
		jsonOf(t, evidence.SBOM{Producer: evidence.Producer{Name: syft}}))
	require.JSONEq(t, `{"packages": [], "producer": {"name": "syft"}}`,
		jsonOf(t, &evidence.SBOM{Producer: evidence.Producer{Name: syft}}))
}

// compile returns the schema of an event type, compiled by a standard JSON Schema validator.
func compile(t *testing.T, eventType string) *jsonschema.Schema {
	t.Helper()
	raw, ok := evidence.Schema(eventType)
	require.True(t, ok, "no schema for %s", eventType)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	require.NoError(t, err)
	compiler := jsonschema.NewCompiler()
	url := "urn:vexplain:schema:" + eventType
	require.NoError(t, compiler.AddResource(url, doc))
	schema, err := compiler.Compile(url)
	require.NoError(t, err)
	return schema
}

// validate checks the JSON text of an instance against the schema.
func validate(t *testing.T, schema *jsonschema.Schema, instance string) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(instance))
	require.NoError(t, err)
	return schema.Validate(inst)
}

func TestSchemasAcceptTheSamples(t *testing.T) {
	samples := map[string][]string{
		evidence.TypePresence: {
			jsonOf(t, samplePresence()),
			jsonOf(t, minimalPresence()),
		},
		evidence.TypeFindings: {
			jsonOf(t, sampleFindings()),
			jsonOf(t, minimalFindings()),
			jsonOf(t, evidence.Findings{Version: "v1"}),
		},
		evidence.TypeExposure: {
			jsonOf(t, sampleExposure()),
			jsonOf(t, minimalExposure()),
		},
		evidence.TypeSBOM: {
			jsonOf(t, sampleSBOM()),
			jsonOf(t, minimalSBOM()),
			jsonOf(t, modularSBOM()),
			jsonOf(t, evidence.SBOM{Producer: evidence.Producer{Name: syft}}),
		},
	}
	for eventType, instances := range samples {
		t.Run(eventType, func(t *testing.T) {
			schema := compile(t, eventType)
			for _, instance := range instances {
				require.NoError(t, validate(t, schema, instance), instance)
			}
		})
	}
}

// at returns the object that is the first element of the list at key.
func at(doc map[string]any, key string) map[string]any {
	return doc[key].([]any)[0].(map[string]any)
}

// viaOf returns a list of n references, as the via of an exposure.
func viaOf(t *testing.T, n int) []any {
	t.Helper()
	refs := make([]evidence.ObjectRef, n)
	for i := range refs {
		refs[i] = evidence.ObjectRef{Kind: "Service", Namespace: teamA, Name: web}
	}
	var via []any
	require.NoError(t, json.Unmarshal([]byte(jsonOf(t, refs)), &via))
	return via
}

// requireRefused checks that the schema of eventType accepts valid, and that it refuses valid after
// each of the changes, which make one thing wrong.
func requireRefused(t *testing.T, eventType, valid string, changes map[string]func(doc map[string]any)) {
	t.Helper()
	schema := compile(t, eventType)
	require.NoError(t, validate(t, schema, valid), "the unchanged sample must be valid")
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			var doc map[string]any
			require.NoError(t, json.Unmarshal([]byte(valid), &doc))
			change(doc)
			require.Error(t, validate(t, schema, jsonOf(t, doc)))
		})
	}
}

func TestPresenceSchemaRefuses(t *testing.T) {
	requireRefused(t, evidence.TypePresence, presenceJSON, map[string]func(doc map[string]any){
		"digestKind is a number":                  func(d map[string]any) { d["digestKind"] = 7 },
		"digestKind is not RepoDigest or ImageID": func(d map[string]any) { d["digestKind"] = "Tag" },
		"workloads is an object":                  func(d map[string]any) { d["workloads"] = map[string]any{} },
		"workloads is missing":                    func(d map[string]any) { delete(d, "workloads") },
		"repositories is a string":                func(d map[string]any) { d["repositories"] = "registry.example/app" },
		"a field that the type doesn't have":      func(d map[string]any) { d["extra"] = true },
		"a workload has no uid":                   func(d map[string]any) { delete(at(d, "workloads"), "uid") },
		"a workload's pods is a string":           func(d map[string]any) { at(d, "workloads")["pods"] = webPod },
		"a container's kind is unknown": func(d map[string]any) {
			at(at(d, "workloads"), "pods")["containers"].([]any)[0].(map[string]any)["kind"] = "Ephemeral"
		},
		"a container has no name": func(d map[string]any) {
			delete(at(at(d, "workloads"), "pods")["containers"].([]any)[0].(map[string]any), "name")
		},
		"a pod names more than 32 containers": func(d map[string]any) {
			containers := make([]any, 33)
			for i := range containers {
				containers[i] = map[string]any{"name": fmt.Sprintf("c%d", i), "kind": "Container"}
			}
			at(at(d, "workloads"), "pods")["containers"] = containers
		},
		"a pod's platform is only an os": func(d map[string]any) {
			at(at(d, "workloads"), "pods")["platform"] = "linux"
		},
		"a label's value is a number": func(d map[string]any) {
			at(at(d, "workloads"), "labels")["value"] = 5
		},
	})
}

// A digest of a reference is a kind of its own, and a pod names its containers, at most 32.
func TestPresenceSchemaAcceptsContainersAndReferences(t *testing.T) {
	schema := compile(t, evidence.TypePresence)
	reference := minimalPresence()
	reference.DigestKind = evidence.DigestKindReference
	reference.Repositories = []string{"registry.example/team-a/app:1.0"}
	require.NoError(t, validate(t, schema, jsonOf(t, reference)))

	full := minimalPresence()
	full.Workloads[0].Pods = []evidence.PresencePod{{Name: webPod}}
	for i := range 32 {
		full.Workloads[0].Pods[0].Containers = append(full.Workloads[0].Pods[0].Containers,
			evidence.PresenceContainer{Name: fmt.Sprintf("c%d", i), Kind: kindContainer})
	}
	require.NoError(t, validate(t, schema, jsonOf(t, full)))
}

func TestFindingsSchemaRefuses(t *testing.T) {
	requireRefused(t, evidence.TypeFindings, findingsJSON, map[string]func(doc map[string]any){
		"knownExploited is a string":     func(d map[string]any) { at(d, "matches")["knownExploited"] = "yes" },
		"fixedVersions is a string":      func(d map[string]any) { at(d, "matches")["fixedVersions"] = "1.2.3-2" },
		"matches is missing":             func(d map[string]any) { delete(d, "matches") },
		"matches is null":                func(d map[string]any) { d["matches"] = nil },
		"version is a number":            func(d map[string]any) { d["version"] = 6 },
		"a match has no vulnerabilityID": func(d map[string]any) { delete(at(d, "matches"), "vulnerabilityID") },
		"a match has an empty packageID": func(d map[string]any) { at(d, "matches")["packageID"] = "" },
		"a cvss entry has no vector": func(d map[string]any) {
			delete(at(at(d, "matches"), "cvss"), "vector")
		},
	})
}

func TestExposureSchemaRefuses(t *testing.T) {
	requireRefused(t, evidence.TypeExposure, exposureJSON, map[string]func(doc map[string]any){
		"indirect is a string":                 func(d map[string]any) { d["indirect"] = "true" },
		"internalReach is not one of the four": func(d map[string]any) { d["internalReach"] = "Galaxy" },
		"external is missing":                  func(d map[string]any) { delete(d, "external") },
		"exposed is a string": func(d map[string]any) {
			d["external"].(map[string]any)["exposed"] = "yes"
		},
		"via has more than eight references": func(d map[string]any) {
			d["external"].(map[string]any)["via"] = viaOf(t, 9)
		},
	})
}

func TestSBOMSchemaRefuses(t *testing.T) {
	pkg := func(d map[string]any) map[string]any { return at(d, "packages") }
	distro := func(d map[string]any) map[string]any { return d["distro"].(map[string]any) }
	requireRefused(t, evidence.TypeSBOM, sbomJSON, map[string]func(doc map[string]any){
		"a field that the type doesn't have":         func(d map[string]any) { d["artifacts"] = []any{} },
		"a field that a package doesn't have":        func(d map[string]any) { pkg(d)["metadata"] = map[string]any{} },
		"a field that the distribution doesn't have": func(d map[string]any) { distro(d)["prettyName"] = "Ubuntu" },
		"a field that the producer doesn't have":     func(d map[string]any) { d["producer"].(map[string]any)["url"] = "x" },
		"packages is null":                           func(d map[string]any) { d["packages"] = nil },
		"packages is an object":                      func(d map[string]any) { d["packages"] = map[string]any{} },
		"a CPE is empty":                             func(d map[string]any) { pkg(d)["cpes"] = []any{""} },
		"cpes is a string":                           func(d map[string]any) { pkg(d)["cpes"] = "cpe:2.3:a:x:y:1" },
		"idLike is a string":                         func(d map[string]any) { distro(d)["idLike"] = "debian" },
		"idLike names an empty distribution":         func(d map[string]any) { distro(d)["idLike"] = []any{""} },
		"a failed cataloger is empty":                func(d map[string]any) { d["failedCatalogers"] = []any{""} },
		"failedCatalogers is a string":               func(d map[string]any) { d["failedCatalogers"] = "rpm-db-cataloger" },
		"the distribution is a string":               func(d map[string]any) { d["distro"] = "ubuntu-24.04" },
		// An unknown modularity label is left out, never null.
		"a modularity label is null":     func(d map[string]any) { pkg(d)[fieldModularityLabel] = nil },
		"a modularity label is a number": func(d map[string]any) { pkg(d)[fieldModularityLabel] = 20 },
	})
}

func TestExposureSchemaAcceptsEightReferencesInVia(t *testing.T) {
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(exposureJSON), &doc))
	doc["external"].(map[string]any)["via"] = viaOf(t, 8)
	require.NoError(t, validate(t, compile(t, evidence.TypeExposure), jsonOf(t, doc)))
}

// TestSchemasFieldByField changes each field of a sample in turn. A schema refuses the sample
// without a field that it requires, and accepts it without one that it makes optional. It refuses
// an empty string for the fields that name something, and accepts one where Kubernetes itself uses
// the empty string: the core API group, and the namespace of an object that has none.
func TestSchemasFieldByField(t *testing.T) {
	root := func(doc map[string]any) map[string]any { return doc }
	workload := func(doc map[string]any) map[string]any { return at(doc, "workloads") }
	external := func(doc map[string]any) map[string]any { return doc["external"].(map[string]any) }
	match := func(doc map[string]any) map[string]any { return at(doc, "matches") }
	// Workloads and object references are both named by these four fields.
	identity := []string{fieldAPIGroup, fieldKind, fieldNamespace, fieldName}

	tests := []struct {
		name       string
		eventType  string
		sample     string
		object     func(doc map[string]any) map[string]any
		required   []string
		optional   []string
		nonEmpty   []string
		mayBeEmpty []string
	}{
		{
			name: "a presence event", eventType: evidence.TypePresence, sample: presenceJSON, object: root,
			required: []string{"digestKind", "workloads"},
			optional: []string{"repositories"},
		},
		{
			name: "a workload", eventType: evidence.TypePresence, sample: presenceJSON, object: workload,
			required:   append(slices.Clone(identity), "uid"),
			optional:   []string{"pods", "labels", "namespaceLabels", "namespaceAnnotations"},
			nonEmpty:   []string{fieldKind, fieldNamespace, fieldName, "uid"},
			mayBeEmpty: []string{fieldAPIGroup},
		},
		{
			name: "a pod", eventType: evidence.TypePresence, sample: presenceJSON,
			object:   func(doc map[string]any) map[string]any { return at(workload(doc), "pods") },
			required: []string{fieldName},
			optional: []string{"node", fieldPlatform},
			nonEmpty: []string{fieldName, "node", "platform"},
		},
		{
			name: "a label", eventType: evidence.TypePresence, sample: presenceJSON,
			object:     func(doc map[string]any) map[string]any { return at(workload(doc), "labels") },
			required:   []string{"key", "value"},
			nonEmpty:   []string{"key"},
			mayBeEmpty: []string{"value"},
		},
		{
			name: "a findings event", eventType: evidence.TypeFindings, sample: findingsJSON, object: root,
			required: []string{fieldVersion, "matches"},
			nonEmpty: []string{fieldVersion},
		},
		{
			name: "a match", eventType: evidence.TypeFindings, sample: findingsJSON, object: match,
			required: []string{
				"vulnerabilityID", "packageID", "packageName", "packageType", "severity", "fixState", "knownExploited",
			},
			optional:   []string{"packageVersion", "fixedVersions", "cvss"},
			nonEmpty:   []string{"vulnerabilityID", "packageID", "packageName", "packageVersion"},
			mayBeEmpty: []string{"packageType", "severity", "fixState"},
		},
		{
			name: "a cvss score", eventType: evidence.TypeFindings, sample: findingsJSON,
			object:   func(doc map[string]any) map[string]any { return at(match(doc), "cvss") },
			required: []string{fieldVersion, "vector"},
			nonEmpty: []string{fieldVersion, "vector"},
		},
		{
			name: "an exposure event", eventType: evidence.TypeExposure, sample: exposureJSON, object: root,
			required: []string{"external", "internalReach", "indirect"},
		},
		{
			name: "an external exposure", eventType: evidence.TypeExposure, sample: exposureJSON, object: external,
			required: []string{"exposed"},
			optional: []string{"via"},
		},
		{
			name: "an object reference", eventType: evidence.TypeExposure, sample: exposureJSON,
			object:     func(doc map[string]any) map[string]any { return at(external(doc), "via") },
			required:   identity,
			nonEmpty:   []string{fieldKind, fieldName},
			mayBeEmpty: []string{fieldAPIGroup, fieldNamespace},
		},
		{
			name: "an sbom event", eventType: evidence.TypeSBOM, sample: sbomJSON, object: root,
			required: []string{"packages", "producer"},
			optional: []string{"distro", "failedCatalogers"},
		},
		{
			name: "a package", eventType: evidence.TypeSBOM, sample: sbomJSON,
			object:     func(doc map[string]any) map[string]any { return at(doc, "packages") },
			required:   []string{"id", fieldName, "type"},
			optional:   []string{fieldVersion, "purl", "cpes"},
			nonEmpty:   []string{"id", fieldName, fieldVersion, "purl"},
			mayBeEmpty: []string{"type"},
		},
		{
			// The empty string says that an RPM comes from no module stream.
			name: "an RPM of a module stream", eventType: evidence.TypeSBOM, sample: modularSBOMJSON,
			object:     func(doc map[string]any) map[string]any { return at(doc, "packages") },
			optional:   []string{fieldModularityLabel},
			mayBeEmpty: []string{fieldModularityLabel},
		},
		{
			name: "a distribution", eventType: evidence.TypeSBOM, sample: sbomJSON,
			object:   func(doc map[string]any) map[string]any { return doc["distro"].(map[string]any) },
			required: []string{"id"},
			optional: []string{fieldVersion, "codename", "idLike"},
			nonEmpty: []string{"id", fieldVersion, "codename"},
		},
		{
			name: "a producer", eventType: evidence.TypeSBOM, sample: sbomJSON,
			object:   func(doc map[string]any) map[string]any { return doc["producer"].(map[string]any) },
			required: []string{fieldName},
			optional: []string{fieldVersion},
			nonEmpty: []string{fieldName, fieldVersion},
		},
	}

	// try changes the sample of test i, and returns what the schema says about the result.
	try := func(t *testing.T, i int, change func(object map[string]any)) error {
		var doc map[string]any
		require.NoError(t, json.Unmarshal([]byte(tests[i].sample), &doc))
		change(tests[i].object(doc))
		return validate(t, compile(t, tests[i].eventType), jsonOf(t, doc))
	}
	for i, tc := range tests {
		for _, field := range tc.required {
			t.Run(tc.name+" requires "+field, func(t *testing.T) {
				require.Error(t, try(t, i, func(o map[string]any) { delete(o, field) }))
			})
		}
		for _, field := range tc.optional {
			t.Run(tc.name+" doesn't require "+field, func(t *testing.T) {
				require.NoError(t, try(t, i, func(o map[string]any) { delete(o, field) }))
			})
		}
		for _, field := range tc.nonEmpty {
			t.Run(tc.name+" refuses an empty "+field, func(t *testing.T) {
				require.Error(t, try(t, i, func(o map[string]any) { o[field] = "" }))
			})
		}
		for _, field := range tc.mayBeEmpty {
			t.Run(tc.name+" accepts an empty "+field, func(t *testing.T) {
				require.NoError(t, try(t, i, func(o map[string]any) { o[field] = "" }))
			})
		}
	}
}

func TestExposureSchemaAcceptsEachReach(t *testing.T) {
	for _, reach := range []string{"Namespace", "Peers", "Namespaces", "Cluster"} {
		t.Run(reach, func(t *testing.T) {
			require.NoError(t, validate(t, compile(t, evidence.TypeExposure),
				jsonOf(t, evidence.Exposure{InternalReach: reach})))
		})
	}
}

func TestPresenceSchemaAcceptsEachDigestKind(t *testing.T) {
	for _, kind := range []string{"RepoDigest", "ImageID"} {
		t.Run(kind, func(t *testing.T) {
			presence := minimalPresence()
			presence.DigestKind = kind
			require.NoError(t, validate(t, compile(t, evidence.TypePresence), jsonOf(t, presence)))
		})
	}
}
