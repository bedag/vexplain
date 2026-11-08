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

package match

import (
	"encoding/json"
	"strings"

	"github.com/anchore/packageurl-go"

	"github.com/bedag/vexplain/sdk/evidence"
)

// The document of Syft's JSON that Grype matches an SBOM from.
//
// Grype reads a package's name, version, type, purl and CPEs from Syft's JSON, and the source package of an OS package
// from the package's metadata only: a Debian package's source, an RPM's source RPM, and an Alpine package's origin.
// Debian, RPM-based and Alpine distributions track many vulnerabilities by the source package, such as openssl for
// libssl3, so a document without it would leave their findings out. The sbom type names the source package in the
// purl's qualifier upstream, as Syft writes it, and Grype's own purl input reads it from there (decision 0044).
// documentOf writes it into the metadata that Grype reads it from in a Syft document, as Syft writes it there, so that
// Grype gets the packages that it got from Syft's own JSON, and their matches. The distribution is the SBOM's.
//
// Syft's decoder takes the rest of what Grype reads of a package from its purl: its language, its architecture, and
// the epoch of an RPM whose version lacks one.

const (
	// syftSchemaVersion is the version of the schema of Syft's JSON that the document follows: that of Syft v1.55.0,
	// which Grype v0.121.0 reads. Grype takes a document for Syft's JSON when its schema's URL names Syft's repository.
	syftSchemaVersion = "16.1.11"
	syftSchemaURL     = "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-" + syftSchemaVersion + ".json"
	// upstreamQualifier is the qualifier of a purl that names the package's source package.
	upstreamQualifier = "upstream"
)

// The types of packages whose source package Grype reads from their metadata, as the sbom type names them, which are
// Syft's names.
const (
	typeDeb = "deb"
	typeRPM = "rpm"
	typeAPK = "apk"
)

// document is what Grype reads of an SBOM in Syft's JSON.
type document struct {
	Artifacts []artifact `json:"artifacts"`
	// ArtifactRelationships is empty: an SBOM has none, and Syft's JSON always has the list.
	ArtifactRelationships []struct{} `json:"artifactRelationships"`
	Distro                *release   `json:"distro,omitempty"`
	Descriptor            descriptor `json:"descriptor"`
	// Schema comes last, where Syft writes it and its decoder looks for it first.
	Schema schema `json:"schema"`
}

// artifact is a package of Syft's JSON.
type artifact struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Type         string   `json:"type"`
	CPEs         []string `json:"cpes,omitempty"`
	PURL         string   `json:"purl,omitempty"`
	MetadataType string   `json:"metadataType,omitempty"`
	Metadata     any      `json:"metadata,omitempty"`
}

// release is a distribution, in the words of os-release, as Syft's JSON names them.
type release struct {
	ID              string   `json:"id"`
	IDLike          []string `json:"idLike,omitempty"`
	VersionID       string   `json:"versionID,omitempty"`
	VersionCodename string   `json:"versionCodename,omitempty"`
}

// descriptor names what made the document's packages.
type descriptor struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type schema struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

// The metadata of a Debian package, an RPM and an Alpine package that name its source package, as Syft's JSON names
// them, under their metadata types.
const (
	dpkgMetadataType = "dpkg-db-entry"
	rpmMetadataType  = "rpm-db-entry"
	apkMetadataType  = "apk-db-entry"
)

type dpkgMetadata struct {
	Source        string `json:"source"`
	SourceVersion string `json:"sourceVersion,omitempty"`
}

type rpmMetadata struct {
	SourceRpm string `json:"sourceRpm"`
}

type apkMetadata struct {
	OriginPackage string `json:"originPackage"`
}

// documentOf returns the document of Syft's JSON that Grype matches the SBOM from: each package under its ID, with its
// name, version, type, purl and CPEs, and the metadata that metadataOf gives it; the distribution of the SBOM; and the
// producer of the SBOM as the document's.
func documentOf(sbom evidence.SBOM) ([]byte, error) {
	doc := document{
		Artifacts:             make([]artifact, 0, len(sbom.Packages)),
		ArtifactRelationships: []struct{}{},
		Descriptor:            descriptor{Name: sbom.Producer.Name, Version: sbom.Producer.Version},
		Schema:                schema{Version: syftSchemaVersion, URL: syftSchemaURL},
	}
	if d := sbom.Distro; d != nil {
		doc.Distro = &release{ID: d.ID, IDLike: d.IDLike, VersionID: d.Version, VersionCodename: d.Codename}
	}
	for _, p := range sbom.Packages {
		a := artifact{ID: p.ID, Name: p.Name, Version: p.Version, Type: p.Type, CPEs: p.CPEs, PURL: p.PURL}
		a.MetadataType, a.Metadata = metadataOf(p)
		doc.Artifacts = append(doc.Artifacts, a)
	}
	return json.Marshal(doc)
}

// metadataOf returns the metadata, and its type, from which Grype reads the source package of an OS package in a Syft
// document: the qualifier upstream of the package's purl, as Syft writes it. For a Debian package it is the source
// package and its version, source@version; for an RPM, the source RPM; for an Alpine package, the origin. Syft writes
// no qualifier for an Alpine package that is its own origin, though its JSON names the origin, which Grype reads as a
// source package of the package's own name: so does the document. A package of another type, or a Debian package or
// an RPM whose purl names no source package, has no metadata.
func metadataOf(p evidence.SBOMPackage) (string, any) {
	upstream := upstreamOf(p.PURL)
	switch {
	case p.Type == typeDeb && upstream != "":
		source, version, _ := strings.Cut(upstream, "@")
		return dpkgMetadataType, dpkgMetadata{Source: source, SourceVersion: version}
	case p.Type == typeRPM && upstream != "":
		return rpmMetadataType, rpmMetadata{SourceRpm: upstream}
	case p.Type == typeAPK && upstream != "":
		return apkMetadataType, apkMetadata{OriginPackage: upstream}
	case p.Type == typeAPK:
		return apkMetadataType, apkMetadata{OriginPackage: p.Name}
	}
	return "", nil
}

// upstreamOf returns the qualifier upstream of the purl, as Grype's purl input reads it, or "" for a purl without it
// or one that doesn't parse.
func upstreamOf(purl string) string {
	parsed, err := packageurl.FromString(purl)
	if err != nil {
		return ""
	}
	for _, q := range parsed.Qualifiers {
		if q.Key == upstreamQualifier {
			return q.Value
		}
	}
	return ""
}
