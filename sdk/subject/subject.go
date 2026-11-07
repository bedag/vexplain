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

// Package subject builds and reads the subjects of evidence: the subject attribute of a
// CloudEvent, which says what the evidence is about.
//
// A subject is a path with a prefix, and the prefix is its kind. vexplain defines three:
//
//	image/sha256:<64 hex>                                      a reported image digest
//	manifest/sha256:<64 hex>                                   a platform manifest
//	workload/<cluster>/<namespace>/<Kind>[.<group>]/<name>     a workload
//
// A collector may add prefixes of its own, such as vm/<cluster>/<name>. The core passes such a
// subject on and never reads it.
package subject

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Kind is the prefix of a subject.
type Kind string

// The kinds that vexplain defines.
const (
	// KindImage is a digest as the container runtime reports it, which can be an index.
	KindImage Kind = "image"
	// KindManifest is the manifest of one platform of an image.
	KindManifest Kind = "manifest"
	// KindWorkload is a workload of a cluster, such as a Deployment or a bare Pod.
	KindWorkload Kind = "workload"
)

const (
	digestPrefix = "sha256:"
	hashLength   = 64
	// workloadFields are the cluster, the namespace, the kind with its group, and the name.
	workloadFields = 4
)

// Workload names a workload in a cluster. Group is empty for the core API group, such as for a Pod.
type Workload struct{ Cluster, Namespace, Group, Kind, Name string }

// Subject is a parsed subject. Kind says which of the other fields it sets: Digest for an image or
// a manifest, Workload for a workload, and Raw for a kind that a collector defines.
type Subject struct {
	Kind     Kind
	Digest   string
	Workload Workload
	// Raw is the whole subject, as it was given, for a kind that a collector defines. It is empty
	// for the kinds above, which Parse reads into the other fields.
	Raw string
}

// Image returns the subject of a reported image digest, such as image/sha256:<64 hex>. It does not
// check the digest: Parse does.
func Image(digest string) string { return string(KindImage) + "/" + digest }

// Manifest returns the subject of a platform manifest, such as manifest/sha256:<64 hex>. It does
// not check the digest: Parse does.
func Manifest(digest string) string { return string(KindManifest) + "/" + digest }

// ForWorkload returns the subject of a workload, such as
// workload/cluster-a/team-a/Deployment.apps/web. A workload of the core group has no group suffix:
// workload/cluster-a/team-a/Pod/web-0. It does not check the fields: Parse does.
func ForWorkload(w Workload) string {
	kind := w.Kind
	if w.Group != "" {
		kind += "." + w.Group
	}
	return strings.Join([]string{string(KindWorkload), w.Cluster, w.Namespace, kind, w.Name}, "/")
}

// Parse reads a subject. A collector's own prefix parses as that Kind, with Raw set. The errors
// don't repeat the subject: a collector chooses it, and an error can reach logs and events.
func Parse(s string) (Subject, error) {
	prefix, rest, ok := strings.Cut(s, "/")
	if !ok || prefix == "" || rest == "" {
		return Subject{}, errors.New("a subject is a prefix and a path, such as image/sha256:<64 hex>")
	}
	switch kind := Kind(prefix); kind {
	case KindImage, KindManifest:
		if !isSHA256(rest) {
			article := "a"
			if kind == KindImage {
				article = "an"
			}
			return Subject{}, fmt.Errorf("the digest of %s %s subject is sha256: and 64 lowercase hex digits", article, kind)
		}
		return Subject{Kind: kind, Digest: rest}, nil
	case KindWorkload:
		w, err := parseWorkload(rest)
		if err != nil {
			return Subject{}, err
		}
		return Subject{Kind: kind, Workload: w}, nil
	default:
		return Subject{Kind: kind, Raw: s}, nil
	}
}

// isSHA256 reports whether d is sha256: and 64 lowercase hex digits, the one digest form that
// evidence uses.
func isSHA256(d string) bool {
	hash, ok := strings.CutPrefix(d, digestPrefix)
	if !ok || len(hash) != hashLength {
		return false
	}
	for i := range len(hash) {
		c := hash[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// parseWorkload reads what follows workload/ in a subject. The kind and its group are one field,
// split at the first dot: a kind has no dot, and a group can have several, as networking.k8s.io does.
func parseWorkload(rest string) (Workload, error) {
	fields := strings.Split(rest, "/")
	if len(fields) != workloadFields || slices.Contains(fields, "") {
		return Workload{}, errors.New(
			"a workload subject is workload/<cluster>/<namespace>/<Kind>[.<group>]/<name>, and no field is empty")
	}
	kind, group, hasGroup := strings.Cut(fields[2], ".")
	if kind == "" || (hasGroup && group == "") {
		return Workload{}, errors.New("the kind of a workload subject is <Kind> or <Kind>.<group>, with no empty part")
	}
	return Workload{Cluster: fields[0], Namespace: fields[1], Group: group, Kind: kind, Name: fields[3]}, nil
}
