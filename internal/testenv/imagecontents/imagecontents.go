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

// Package imagecontents writes the scanner collector's evidence for the tests of the operator: the data of the type
// ch.bedag.vexplain.scanner.image-contents.v1alpha1, which the default rules read, and which the specs of the hub
// store as the spoke would. The operator imports no type of a collector, so this package has types of its own, with
// the JSON of the scanner's Manifest. Its test holds them to the golden files that the scanner's own tests hold the
// scanner to, so that the two can't drift apart.
//
// Only test files import it, so it never enters the manager binary.
package imagecontents

import (
	"encoding/json"
	"math"
)

// Type is the type of the scanner's evidence about a platform manifest.
const Type = "ch.bedag.vexplain.scanner.image-contents.v1alpha1"

// Manifest is what the scanner found in the filesystem of one platform manifest.
type Manifest struct {
	Platform  string          `json:"platform"`
	Digest    string          `json:"digest"`
	SBOM      json.RawMessage `json:"sbom"`
	Packages  []PackageFacts  `json:"packages"`
	ELF       ELFSummary      `json:"elf"`
	Libraries []Library       `json:"libraries"`
	Preload   Preload         `json:"preload"`
}

// PackageFacts says how much of one package of the SBOM is in the filesystem.
type PackageFacts struct {
	ID              string `json:"id"`
	FilesListed     int    `json:"filesListed"`
	FilesPresent    int    `json:"filesPresent"`
	SharedLibraries int    `json:"sharedLibraries"`
	OtherELFFiles   int    `json:"otherElfFiles"`
}

// ELFSummary counts the ELF files of the filesystem, and those that a package owns.
type ELFSummary struct {
	Total   int      `json:"total"`
	Owned   int      `json:"owned"`
	Unowned []string `json:"unowned,omitempty"`
}

// Library is a shared library of the filesystem, and what leads to it.
type Library struct {
	Path         string   `json:"path"`
	Soname       string   `json:"soname"`
	PackageID    string   `json:"packageId,omitempty"`
	ReachedBy    []string `json:"reachedBy,omitempty"`
	ReachedCount int      `json:"reachedCount"`
	NameHits     []string `json:"nameHits,omitempty"`
	NameHitCount int      `json:"nameHitCount"`
}

// Preload says whether the image loads libraries that no ELF file asks for.
type Preload struct {
	LDPreload      bool `json:"ldPreload"`
	LDAudit        bool `json:"ldAudit"`
	EtcLdSoPreload bool `json:"etcLdSoPreload"`
}

// Completeness is the coverage of the evidence of m, as the scanner gives it: the share of the ELF files that
// packages own, as a percentage rounded down, 100 for a filesystem without ELF files, and 0 for counts that can't be
// true.
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
