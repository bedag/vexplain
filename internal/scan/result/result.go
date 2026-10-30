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

// Package result is the format in which a scan reports to the operator. A scan runs in a throwaway
// Job: the scanner binary analyses one image and prints one line to its log, and the operator
// reads that line back. This package holds the types of what a scan found, and the codecs for the
// log line and for the evidence that the operator stores.
//
// The scanner and the operator both import it, so it uses only the standard library: it must not
// pull Kubernetes or the API types into the scanner. The JSON field names are the wire contract
// between the two binaries.
package result

import (
	"encoding/json"
	"math"
)

// SchemaVersion is the version of the JSON of a Result. The prefixes of the log lines name it too.
const SchemaVersion = 1

const (
	// ResultPrefix starts the line that a scan prints when it succeeds. The rest of the line is the
	// base64 of the gzip of the JSON of a Result. No other line of a scan's log may start with the
	// name in it, "vexplain-scan-result", and a space.
	ResultPrefix = "vexplain-scan-result v1 "
	// ErrorPrefix starts the line that a scan prints when it fails. The rest of the line is an
	// ErrorReason. No other line of a scan's log may start with the name in it,
	// "vexplain-scan-error", and a space.
	ErrorPrefix = "vexplain-scan-error v1 "
)

// Result is what a scan found in one image: a Manifest for each platform that it scanned.
type Result struct {
	// SchemaVersion is the version of this format. Encode sets it, and Parse accepts no other value
	// than the current SchemaVersion.
	SchemaVersion int `json:"schemaVersion"`
	// Image is the image that was scanned, as repository@digest.
	Image string `json:"image"`
	// Manifests holds what the scan found in each platform manifest of the image.
	Manifests []Manifest `json:"manifests"`
}

// Manifest is what a scan found in the filesystem of one platform manifest of an image. The
// operator stores it as the evidence of that manifest, and the rules read it.
type Manifest struct {
	// Platform is the platform of the manifest, as os/architecture[/variant].
	Platform string `json:"platform"`
	// Digest is the digest of the platform manifest.
	Digest string `json:"digest"`
	// SBOM is Syft's JSON for the filesystem, without file lists.
	SBOM json.RawMessage `json:"sbom"`
	// Packages holds the file facts of the SBOM's packages, each under its ID in the SBOM.
	Packages []PackageFacts `json:"packages"`
	// ELF counts the ELF files of the filesystem, and those that a package owns.
	ELF ELFSummary `json:"elf"`
	// Libraries lists the shared libraries of the filesystem: the ELF files that have a soname.
	Libraries []Library `json:"libraries"`
	// Preload says whether the image loads libraries that no ELF file asks for.
	Preload Preload `json:"preload"`
}

// PackageFacts says how much of one package is in the filesystem.
type PackageFacts struct {
	// ID is the package's ID in the SBOM.
	ID string `json:"id"`
	// FilesListed is the number of files that the package's database lists.
	FilesListed int `json:"filesListed"`
	// FilesPresent is the number of those files that are in the final filesystem.
	FilesPresent int `json:"filesPresent"`
	// SharedLibraries is the number of ELF files that the package owns and that have a soname.
	SharedLibraries int `json:"sharedLibraries"`
	// OtherELFFiles is the number of ELF files that the package owns and that have no soname, such
	// as executables and plugins.
	OtherELFFiles int `json:"otherElfFiles"`
}

// ELFSummary counts the ELF files of a filesystem.
type ELFSummary struct {
	// Total is the number of ELF files.
	Total int `json:"total"`
	// Owned is the number of ELF files that a package owns.
	Owned int `json:"owned"`
	// Unowned holds the paths of the ELF files that no package owns: the first 100, sorted.
	Unowned []string `json:"unowned,omitempty"`
}

// Library is a shared library of a filesystem, and what leads to it.
type Library struct {
	// Path is the path of the library's file.
	Path string `json:"path"`
	// Soname is the library's soname.
	Soname string `json:"soname"`
	// PackageID is the ID of the package that owns the library. It is empty when none does.
	PackageID string `json:"packageId,omitempty"`
	// ReachedBy holds the paths of the ELF files, outside the package that owns the library, that
	// reach it through their dependencies: the first 20, sorted.
	ReachedBy []string `json:"reachedBy,omitempty"`
	// ReachedCount is the number of those ELF files, and so can be more than ReachedBy holds.
	ReachedCount int `json:"reachedCount"`
	// NameHits holds the paths of the files that name the library, as the analysis counts a name:
	// the first 20, sorted.
	NameHits []string `json:"nameHits,omitempty"`
	// NameHitCount is the number of those files, and so can be more than NameHits holds.
	NameHitCount int `json:"nameHitCount"`
}

// Preload says whether an image loads libraries that no ELF file asks for. It holds only whether
// a setting exists, never the setting's value.
type Preload struct {
	// LDPreload is true when the image configuration sets LD_PRELOAD.
	LDPreload bool `json:"ldPreload"`
	// LDAudit is true when the image configuration sets LD_AUDIT.
	LDAudit bool `json:"ldAudit"`
	// EtcLdSoPreload is true when /etc/ld.so.preload exists and isn't empty.
	EtcLdSoPreload bool `json:"etcLdSoPreload"`
}

// ErrorReason says why a scan failed. Its values are those of the API's ScanFailureReason that a
// scanner can report: NotPullable and TimedOut are set by the operator and never by a scanner, so
// they are not here. This package can't import the API types, so a test keeps the spelling equal.
type ErrorReason string

const (
	// ErrorReasonPullFailed means the image could not be pulled, for a reason that Unauthorized and
	// NotFound don't cover.
	ErrorReasonPullFailed ErrorReason = "PullFailed"
	// ErrorReasonUnauthorized means the registry refused the credentials, or wanted some.
	ErrorReasonUnauthorized ErrorReason = "Unauthorized"
	// ErrorReasonNotFound means the registry has no image with the digest.
	ErrorReasonNotFound ErrorReason = "NotFound"
	// ErrorReasonNoMatchingPlatform means the image has no manifest for any of the platforms to scan.
	ErrorReasonNoMatchingPlatform ErrorReason = "NoMatchingPlatform"
	// ErrorReasonTooLarge means the image unpacks to more than the scratch volume holds.
	ErrorReasonTooLarge ErrorReason = "TooLarge"
	// ErrorReasonCatalogFailed means the scan could not list the packages of the unpacked image.
	ErrorReasonCatalogFailed ErrorReason = "CatalogFailed"
	// ErrorReasonInternal means the scan failed for a reason of its own that no other value names.
	ErrorReasonInternal ErrorReason = "Internal"
)

// valid reports whether r is one of the seven reasons above.
func (r ErrorReason) valid() bool {
	switch r {
	case ErrorReasonPullFailed, ErrorReasonUnauthorized, ErrorReasonNotFound,
		ErrorReasonNoMatchingPlatform, ErrorReasonTooLarge, ErrorReasonCatalogFailed,
		ErrorReasonInternal:
		return true
	}
	return false
}

// Completeness returns the share of the manifest's ELF files that packages own, as a percentage
// rounded down: floor(100·Owned/Total). It is 100 when the filesystem has no ELF files, because
// there is nothing to account for.
//
// Counts that can't be true give 0, so that a guard on completeness holds a verdict back instead of
// passing it. They are a negative count, more files owned than found, and more files than an int32
// holds, which is how the API counts them. The last also keeps the multiplication from overflowing.
func (m Manifest) Completeness() int32 {
	owned, total := int64(m.ELF.Owned), int64(m.ELF.Total)
	if owned < 0 || owned > total || total > math.MaxInt32 {
		return 0
	}
	if total == 0 {
		return 100
	}
	return int32(100 * owned / total)
}
