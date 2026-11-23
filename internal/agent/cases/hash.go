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

package cases

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"

	"k8s.io/utils/ptr"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/evidence"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// imageContentsType is the type of the scanner's evidence of what the filesystem of a platform manifest holds.
const imageContentsType = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"

// InputHash returns the SHA-256 of what a verdict on a case rests on, as sha256:<hex>: the case's findings, each by its
// vulnerability ID and package (name, version and type), and for each name of the case file's evidence, the SHA-256 of
// the facts of each of its producers, as EvidenceHashes gives them. It hashes canonical JSON, sorted, so the order of
// the findings and of the hashes changes nothing. What changes urgency, order or the next step but never whether the
// subject is affected doesn't count: EPSS, CVSS, the known-exploited flag, a fix that appears, the database's version,
// and the status that rules concluded (decision 0052). Nor does what a scan numbers anew each time, such as a package's
// ID. A name without data counts as one with none.
func InputHash(findings []inventoryv1alpha1.Finding, evidenceHashes map[string][]string) string {
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	}
	type finding struct {
		VulnerabilityID string `json:"vulnerabilityID"`
		Package         pkg    `json:"package"`
	}
	type data struct {
		Name   string   `json:"name"`
		SHA256 []string `json:"sha256"`
	}
	in := struct {
		Findings []finding `json:"findings"`
		Evidence []data    `json:"evidence"`
	}{Findings: []finding{}, Evidence: []data{}}
	for _, f := range findings {
		in.Findings = append(in.Findings, finding{VulnerabilityID: f.VulnerabilityID, Package: pkg{
			Name: f.Package.Name, Version: ptr.Deref(f.Package.Version, ""), Type: f.Package.Type,
		}})
	}
	slices.SortFunc(in.Findings, func(a, b finding) int {
		return cmp.Or(cmp.Compare(a.VulnerabilityID, b.VulnerabilityID), cmp.Compare(a.Package.Name, b.Package.Name),
			cmp.Compare(a.Package.Version, b.Package.Version), cmp.Compare(a.Package.Type, b.Package.Type))
	})
	for _, name := range slices.Sorted(maps.Keys(evidenceHashes)) {
		in.Evidence = append(in.Evidence, data{Name: name, SHA256: append([]string{}, slices.Sorted(slices.Values(evidenceHashes[name]))...)})
	}
	// Strings, lists and structs always marshal.
	raw, _ := json.Marshal(in)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EvidenceHashes returns, for each of the names of the case file's evidence, the SHA-256 of the facts of each of its
// producers that the sheet rests on, as factsOf gives them, in hex, sorted. A name whose evidence is missing has none.
// It reads the data through the evidence store, so a producer of another version that finds the same facts gives the
// same hash.
func EvidenceHashes(ctx context.Context, store evidence.Store, sheet *inventoryv1alpha1.ImageVerdicts,
	names []string) (map[string][]string, error) {
	data, err := EvidenceData(ctx, store, sheet, names)
	if err != nil {
		return nil, err
	}
	return HashesOf(sheet, data), nil
}

// HashesOf returns the hashes of the case file's evidence, as EvidenceHashes gives them, of data that EvidenceData read
// for the sheet, which names the type of each name.
func HashesOf(sheet *inventoryv1alpha1.ImageVerdicts, data map[string][]json.RawMessage) map[string][]string {
	types := map[string]string{}
	for _, e := range sheet.Status.Evidence {
		types[e.Name] = e.Type
	}
	hashes := make(map[string][]string, len(data))
	for name, docs := range data {
		hashes[name] = nil
		for _, doc := range docs {
			sum := sha256.Sum256(factsOf(types[name], doc))
			hashes[name] = append(hashes[name], hex.EncodeToString(sum[:]))
		}
		slices.Sort(hashes[name])
	}
	return hashes
}

// factsOf returns what a verdict rests on of the data of a piece of evidence of the type, and leaves out what says how
// the scan ran, which changes with each scan and each release of the scanner: for an SBOM, its distribution, its
// packages by name, version, type and purl, sorted, and the catalogers that failed, sorted; for the scanner's image
// contents, its data without a producer, descriptor or source; and for any other type, or data that doesn't read as
// its type, the whole data, so that any change makes the verdict stale.
func factsOf(eventType string, data json.RawMessage) []byte {
	switch eventType {
	case sdkevidence.TypeSBOM:
		var s sdkevidence.SBOM
		if json.Unmarshal(data, &s) != nil {
			return data
		}
		type pkg struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
			PURL    string `json:"purl"`
		}
		facts := struct {
			Distro            *sdkevidence.Distro            `json:"distro"`
			Packages          []pkg                          `json:"packages"`
			FailedCatalogers  []string                       `json:"failedCatalogers"`
			CatalogerFailures []sdkevidence.CatalogerFailure `json:"catalogerFailures"`
		}{Distro: s.Distro, Packages: []pkg{}, FailedCatalogers: slices.Sorted(slices.Values(s.FailedCatalogers))}
		for _, p := range s.Packages {
			facts.Packages = append(facts.Packages, pkg{Name: p.Name, Version: p.Version, Type: p.Type, PURL: p.PURL})
		}
		slices.SortFunc(facts.Packages, func(a, b pkg) int {
			return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Version, b.Version), cmp.Compare(a.Type, b.Type),
				cmp.Compare(a.PURL, b.PURL))
		})
		for _, f := range s.CatalogerFailures {
			facts.CatalogerFailures = append(facts.CatalogerFailures, sdkevidence.CatalogerFailure{
				Cataloger: f.Cataloger, PackageTypes: slices.Sorted(slices.Values(f.PackageTypes))})
		}
		slices.SortFunc(facts.CatalogerFailures, func(a, b sdkevidence.CatalogerFailure) int {
			return cmp.Or(cmp.Compare(a.Cataloger, b.Cataloger), slices.Compare(a.PackageTypes, b.PackageTypes))
		})
		// Strings, lists and structs of them always marshal.
		raw, _ := json.Marshal(facts)
		return raw
	case imageContentsType:
		var fields map[string]json.RawMessage
		if json.Unmarshal(data, &fields) != nil {
			return data
		}
		delete(fields, "producer")
		delete(fields, "descriptor")
		delete(fields, "source")
		// The fields hold valid JSON, which marshals with the keys sorted.
		raw, _ := json.Marshal(fields)
		return raw
	}
	return data
}

// EvidenceData returns, for each of the names of the case file's evidence, the data of each of its producers that the
// sheet rests on, as the evidence store holds it. A name whose evidence is missing has none. The case file holds only
// this evidence, of the types that the playbook names.
func EvidenceData(ctx context.Context, store evidence.Store, sheet *inventoryv1alpha1.ImageVerdicts,
	names []string) (map[string][]json.RawMessage, error) {
	data := make(map[string][]json.RawMessage, len(names))
	for _, name := range names {
		data[name] = nil
	}
	subject := subjects.Manifest(sheet.Spec.ManifestDigest)
	for _, e := range sheet.Status.Evidence {
		if _, wanted := data[e.Name]; !wanted || e.Version == nil {
			continue
		}
		record, err := store.Get(ctx, evidence.Key{Subject: subject, Type: e.Type, Source: e.Source})
		if err != nil {
			return nil, err
		}
		if record == nil {
			continue
		}
		data[e.Name] = append(data[e.Name], record.Event.Data())
	}
	return data, nil
}
