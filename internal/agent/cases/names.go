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
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"k8s.io/utils/ptr"

	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
)

// The labels of an Assessment, so that one label query lists every case of a vulnerability, or of a manifest.
const (
	// VulnerabilityLabel holds the vulnerability's ID, with what a label value can't hold replaced.
	VulnerabilityLabel = "vexplain.bedag.ch/vulnerability"
	// DigestLabel holds the first 63 hex digits of the manifest's digest, which a label value can hold.
	DigestLabel = "vexplain.bedag.ch/digest"
)

var (
	notInName  = regexp.MustCompile(`[^a-z0-9-]`)
	notInLabel = regexp.MustCompile(`[^A-Za-z0-9._-]`)
)

// Name returns the name of a case's Assessment: the vulnerability's ID in lower case, with every character outside
// [a-z0-9-] turned into '-', cut to 200 and without leading dashes, a dash, and the first 16 hex digits of the SHA-256
// of the ID, '@' and the manifest's digest. The hash tells apart two IDs that differ only in a replaced character.
func Name(vulnerabilityID, manifestDigest string) string {
	id := notInName.ReplaceAllString(strings.ToLower(vulnerabilityID), "-")
	id = strings.TrimLeft(id[:min(len(id), 200)], "-")
	sum := sha256.Sum256([]byte(vulnerabilityID + "@" + manifestDigest))
	hash := hex.EncodeToString(sum[:])[:16]
	if id == "" {
		return hash
	}
	return id + "-" + hash
}

// StatementName returns the name of the VexStatement of a verdict on a case: the name of the case's Assessment, a
// dash, and the first 10 hex digits of the SHA-256 of the verdict's inputHash, status and justification. Each verdict
// has a statement of its own, so a new verdict never takes the place, or the review, of an earlier one.
func StatementName(assessment, inputHash, status, justification string) string {
	sum := sha256.Sum256([]byte(inputHash + status + justification))
	return assessment + "-" + hex.EncodeToString(sum[:])[:10]
}

// Silences reports whether the Assessment holds a verdict that would silence its case, NotAffected with its
// justification or Fixed, on inputs that it names: one that a person reviews.
func Silences(as *triagev1alpha1.Assessment) bool {
	v := as.Status.Verdict
	return v != nil && as.Status.InputHash != nil && (v.Status == triagev1alpha1.VEXStatusFixed ||
		v.Status == triagev1alpha1.VEXStatusNotAffected && v.Justification != nil)
}

// StatementNameOf returns the name of the statement of the Assessment's verdict, which silences its case.
func StatementNameOf(as *triagev1alpha1.Assessment) string {
	v := as.Status.Verdict
	return StatementName(as.Name, *as.Status.InputHash, string(v.Status), string(ptr.Deref(v.Justification, "")))
}

// Labels returns the labels of a case's Assessment: the vulnerability's ID, with every character outside
// [A-Za-z0-9._-] turned into '_', cut to 63 and trimmed of what a label value can't start or end with, and the first
// 63 hex digits of the manifest's digest.
func Labels(vulnerabilityID, manifestDigest string) map[string]string {
	id := notInLabel.ReplaceAllString(vulnerabilityID, "_")
	id = strings.Trim(id[:min(len(id), 63)], "._-")
	digest := strings.TrimPrefix(manifestDigest, "sha256:")
	return map[string]string{VulnerabilityLabel: id, DigestLabel: digest[:min(len(digest), 63)]}
}
