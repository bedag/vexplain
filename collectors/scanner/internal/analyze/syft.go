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

package analyze

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/bedag/vexplain/sdk/evidence"
)

// supportedSchema is the major version of Syft's JSON schema that the analysis reads: that of Syft
// v1.55.0, which the scanner image pins and testdata/gen.sh runs. Another major version may name the
// metadata of the package databases differently, so it is refused rather than read wrongly.
const supportedSchema = "16"

// osMetadataTypes are the metadata types, in schema 16, of the packages that an OS package database
// lists. Their file lists say which files a package owns, and which of them must be present.
var osMetadataTypes = map[string]bool{
	"apk-db-entry":  true,
	"dpkg-db-entry": true,
	"rpm-db-entry":  true,
}

// rpmMetadataTypes are the metadata types, in schema 16, of an RPM: one of the rpm database, and one of an rpm file.
// Both carry the RPM's modularity label, which the manifest's SBOM keeps.
var rpmMetadataTypes = map[string]bool{
	"rpm-db-entry": true,
	"rpm-archive":  true,
}

// sbomPackage is what the analysis reads of one package of the SBOM. Its paths are cleaned and
// absolute, as paths inside the image.
type sbomPackage struct {
	id string
	// os is true for a package of an OS package database.
	os bool
	// files is the file list of an OS package. Syft lists what the database lists, and for rpm only
	// the files that exist.
	files []string
	// locations are where Syft found the package: its database, or the package's own file, such as
	// a Go binary or a JAR.
	locations []string
}

// syftDocument is what the analysis reads of Syft's JSON: the identities, file lists and locations
// of the packages, the distribution, the version of Syft, and the unknowns of its files.
type syftDocument struct {
	Schema *struct {
		Version string `json:"version"`
	} `json:"schema"`
	Artifacts []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
		PURL    string `json:"purl"`
		CPEs    []struct {
			CPE string `json:"cpe"`
		} `json:"cpes"`
		MetadataType string          `json:"metadataType"`
		Metadata     json.RawMessage `json:"metadata"`
		Locations    []syftPath      `json:"locations"`
	} `json:"artifacts"`
	Distro *struct {
		ID              string   `json:"id"`
		VersionID       string   `json:"versionID"`
		VersionCodename string   `json:"versionCodename"`
		IDLike          []string `json:"idLike"`
	} `json:"distro"`
	Descriptor struct {
		Version string `json:"version"`
	} `json:"descriptor"`
	Files []struct {
		Unknowns []string `json:"unknowns"`
	} `json:"files"`
}

// failedCatalogerPattern matches an unknown of a file that a package cataloger of Syft failed on: the cataloger's
// name, a colon and the error, as Syft writes it. Syft names every cataloger "...-cataloger", and its file catalogers
// "file-...", which find no packages.
var failedCatalogerPattern = regexp.MustCompile(`^([a-z0-9]+(?:-[a-z0-9]+)*-cataloger): `)

// nothingFound holds the notes that a cataloger of Syft v1.55.0 writes after its name for a file that it found nothing
// to identify in, which is no failure: a file that holds no package, such as an empty dpkg status file or a lock file
// without entries, and a Java archive that names none.
var nothingFound = map[string]bool{
	"unable to determine packages":     true,
	"no package identified in archive": true,
}

// syftName is the name of the producer of the SBOM: the scan runs Syft, which says its version in its JSON.
const syftName = "syft"

// syftPath is an element of a list of locations or of files, which both name their path "path".
type syftPath struct {
	Path string `json:"path"`
}

// parseSBOM reads Syft's JSON: the packages that the analysis reads, and the manifest's SBOM. It
// refuses JSON of another shape, a schema of another major version, and packages without an ID or
// with the ID of another, because the facts of the manifest are kept by package ID, and a match names
// its package by it.
//
// The SBOM keeps each package as Syft wrote it, in Syft's order: its ID, name, version, type, purl
// with every qualifier, and CPEs, and an RPM's modularity label. A vulnerability matcher reads an OS
// package's source package and distribution from the qualifiers upstream and distro of its purl
// (decision 0044), so the purl is never rewritten. The distribution is Syft's, when it found one with
// an ID.
//
// The SBOM's document is Syft's JSON without its file lists (reduceSBOM), which the vulnerabilities
// collector hands Grype as it is, as phase 2b did: Grype then matches all that the document holds. The
// packages are the document's artifacts, under the document's IDs, by which a match names its package.
//
// The SBOM names the catalogers that failed (failedCatalogers), whose packages it may lack.
func parseSBOM(raw []byte) ([]sbomPackage, evidence.SBOM, error) {
	var doc syftDocument
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Schema == nil || doc.Schema.Version == "" {
		return nil, evidence.SBOM{}, ErrSBOM
	}
	if major, _, _ := strings.Cut(doc.Schema.Version, "."); major != supportedSchema {
		return nil, evidence.SBOM{}, ErrUnsupportedSBOM
	}

	pkgs := make([]sbomPackage, 0, len(doc.Artifacts))
	sbom := evidence.SBOM{
		Packages: make([]evidence.SBOMPackage, 0, len(doc.Artifacts)),
		Producer: evidence.Producer{Name: syftName, Version: doc.Descriptor.Version},
	}
	if d := doc.Distro; d != nil && d.ID != "" {
		sbom.Distro = &evidence.Distro{ID: d.ID, Version: d.VersionID, Codename: d.VersionCodename, IDLike: d.IDLike}
	}
	seen := make(map[string]bool, len(doc.Artifacts))
	for _, a := range doc.Artifacts {
		if a.ID == "" || seen[a.ID] {
			return nil, evidence.SBOM{}, ErrSBOM
		}
		seen[a.ID] = true
		pkg := sbomPackage{id: a.ID, os: osMetadataTypes[a.MetadataType], locations: cleanPaths(a.Locations)}
		if pkg.os {
			var metadata struct {
				Files []syftPath `json:"files"`
			}
			if err := json.Unmarshal(a.Metadata, &metadata); err != nil {
				return nil, evidence.SBOM{}, ErrSBOM
			}
			pkg.files = cleanPaths(metadata.Files)
		}
		pkgs = append(pkgs, pkg)

		identity := evidence.SBOMPackage{ID: a.ID, Name: a.Name, Version: a.Version, Type: a.Type, PURL: a.PURL}
		for _, c := range a.CPEs {
			identity.CPEs = append(identity.CPEs, c.CPE)
		}
		if rpmMetadataTypes[a.MetadataType] {
			// Syft's purl of an RPM names no module stream, so the label comes from the metadata, in its three
			// states: a stream, "" for none, and none at all where Syft doesn't know.
			var metadata struct {
				ModularityLabel *string `json:"modularityLabel"`
			}
			if err := json.Unmarshal(a.Metadata, &metadata); err != nil {
				return nil, evidence.SBOM{}, ErrSBOM
			}
			identity.ModularityLabel = metadata.ModularityLabel
		}
		sbom.Packages = append(sbom.Packages, identity)
	}
	document, err := reduceSBOM(raw)
	if err != nil {
		return nil, evidence.SBOM{}, err
	}
	sbom.Document = &evidence.SBOMDocument{Format: evidence.SBOMFormatSyftJSON, Content: document}
	sbom.FailedCatalogers = failedCatalogers(doc)
	return pkgs, sbom, nil
}

// failedCatalogers returns the package catalogers that failed on a file of the root, each once, sorted. Syft records
// such a failure among the unknowns of the file, and keeps it only for a file where it found no package, so the
// cataloger's packages may be missing from the SBOM, and no count of the analysis shows it. The other unknowns name no
// cataloger that failed: a cataloger's note that it found nothing to identify in a file (nothingFound), the notes of
// Syft's unknowns-labeler, of an executable without a package, which the completeness counts, and of an archive that
// it didn't catalog, and the failures of its file catalogers. The error after the name is text from the image, and is
// never kept.
func failedCatalogers(doc syftDocument) []string {
	var failed []string
	for _, f := range doc.Files {
		for _, unknown := range f.Unknowns {
			match := failedCatalogerPattern.FindStringSubmatch(unknown)
			if match != nil && !strings.HasPrefix(match[1], "file-") && !nothingFound[unknown[len(match[0]):]] {
				failed = append(failed, match[1])
			}
		}
	}
	slices.Sort(failed)
	return slices.Compact(failed)
}

// catalogComplete checks that Syft catalogued every package database of the root: that each file of
// a package database that isn't empty is where Syft found a package. An empty file lists no package.
//
// Paths compare as the entries that they name inside the root, so a database that a link to its
// directory reaches matches whichever path Syft reports, such as Fedora's /var/lib/rpm, which links to
// /usr/lib/sysimage/rpm.
func (t *tree) catalogComplete(pkgs []sbomPackage) error {
	found := map[string]bool{}
	for _, pkg := range pkgs {
		for _, p := range pkg.locations {
			if entry, status := t.resolve(p, true); status == resolved {
				found[entry] = true
			}
		}
	}
	for _, p := range t.databaseFiles() {
		if found[p] {
			continue
		}
		info, err := os.Lstat(t.host(p))
		if err != nil {
			return ErrRootUnreadable
		}
		if info.Size() > 0 {
			return ErrCatalogIncomplete
		}
	}
	return nil
}

// databaseFiles returns the regular files that the paths of the package databases name in the root,
// each once.
func (t *tree) databaseFiles() []string {
	var paths []string
	for _, db := range packageDatabases {
		for _, name := range db.files {
			paths = append(paths, db.dir+name)
		}
		for _, name := range db.fileDirs {
			dir, status := t.resolve(db.dir+name, true)
			if status != resolved || t.kinds[dir] != kindDir {
				continue
			}
			for p := range t.kinds {
				if p != dir && path.Dir(p) == dir {
					paths = append(paths, p)
				}
			}
		}
	}
	var files []string
	seen := map[string]bool{}
	for _, p := range paths {
		entry, status := t.resolve(p, true)
		if status == resolved && t.kinds[entry] == kindFile && !seen[entry] {
			seen[entry] = true
			files = append(files, entry)
		}
	}
	return files
}

func cleanPaths(list []syftPath) []string {
	paths := make([]string, 0, len(list))
	for _, p := range list {
		paths = append(paths, cleanPath(p.Path))
	}
	return paths
}

// cleanPath returns p as a clean, absolute path inside the image.
func cleanPath(p string) string {
	return path.Clean("/" + p)
}

// reduceSBOM returns Syft's JSON without its file lists: without artifactRelationships and the
// top-level files, and without the files in the metadata of each package. Every other field stays,
// among them source, sourceVersion, originPackage, sourceRpm and modularityLabel, which Grype matches
// on. The document keeps Syft's shape; its fields come out in sorted order, and its strings without
// HTML escaping.
func reduceSBOM(raw []byte) (json.RawMessage, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil || doc == nil {
		return nil, ErrSBOM
	}
	delete(doc, "artifactRelationships")
	delete(doc, "files")
	if artifacts, ok := doc["artifacts"]; ok {
		var list []map[string]json.RawMessage
		if err := json.Unmarshal(artifacts, &list); err != nil {
			return nil, ErrSBOM
		}
		for _, artifact := range list {
			if err := dropFileList(artifact); err != nil {
				return nil, err
			}
		}
		reduced, err := marshal(list)
		if err != nil {
			return nil, ErrSBOM
		}
		doc["artifacts"] = reduced
	}
	reduced, err := marshal(doc)
	if err != nil {
		return nil, ErrSBOM
	}
	return reduced, nil
}

// dropFileList removes the files from a package's metadata. Metadata that isn't an object has none.
func dropFileList(artifact map[string]json.RawMessage) error {
	raw, ok := artifact["metadata"]
	if !ok {
		return nil
	}
	var metadata map[string]json.RawMessage
	if json.Unmarshal(raw, &metadata) != nil {
		return nil
	}
	if _, ok := metadata["files"]; !ok {
		return nil
	}
	delete(metadata, "files")
	reduced, err := marshal(metadata)
	if err != nil {
		return ErrSBOM
	}
	artifact["metadata"] = reduced
	return nil
}

// marshal returns the JSON of v without HTML escaping, so that strings stay as Syft wrote them.
func marshal(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
