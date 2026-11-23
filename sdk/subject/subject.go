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
// A subject is a path with a prefix, and the prefix is its kind. vexplain defines five:
//
//	image/sha256:<64 hex>                                      a reported image digest
//	manifest/sha256:<64 hex>                                   a platform manifest
//	workload/<cluster>/<namespace>/<Kind>[.<group>]/<name>     a workload
//	host/<name>                                                a host name, in lowercase
//	address/<ip>[:<port>]                                      an IP address, IPv6 in brackets with a port
//
// A collector may add prefixes of its own, such as vm/<cluster>/<name>. The core passes such a
// subject on and never reads it.
package subject

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
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
	// KindHost is a host name through which something outside a cluster reaches a workload.
	KindHost Kind = "host"
	// KindAddress is an IP address, with a port or without, through which the same happens.
	KindAddress Kind = "address"
)

const (
	digestPrefix = "sha256:"
	hashLength   = 64
	// workloadFields are the cluster, the namespace, the kind with its group, and the name.
	workloadFields = 4
	// maxHostLength and maxLabelLength are the limits of a DNS name and of one of its labels.
	maxHostLength  = 253
	maxLabelLength = 63
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
	// Host is the name of a host subject. Addr and Port are those of an address subject, where Port
	// is 0 when the subject has none.
	Host string
	Addr netip.Addr
	Port uint16
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
	case KindHost:
		// Only the normal form parses, so that subjects compare by their text.
		if normal, err := Host(rest); err != nil || normal != s {
			return Subject{}, errors.New("a host subject is host/<name> in normal form: lowercase, with no trailing dot")
		}
		return Subject{Kind: kind, Host: rest}, nil
	case KindAddress:
		addr, port, err := parseAddress(rest)
		if normal, nerr := Address(addr.String(), port); err != nil || nerr != nil || normal != s {
			return Subject{}, errors.New("an address subject is address/<ip> or address/<ip>:<port> in normal form, " +
				"with an IPv6 address in brackets only before a port")
		}
		return Subject{Kind: kind, Addr: addr, Port: port}, nil
	default:
		return Subject{Kind: kind, Raw: s}, nil
	}
}

// parseAddress reads <ip> or <ip>:<port>, with an IPv6 address in brackets when a port follows.
func parseAddress(rest string) (netip.Addr, uint16, error) {
	if ap, err := netip.ParseAddrPort(rest); err == nil {
		return ap.Addr(), ap.Port(), nil
	}
	addr, err := netip.ParseAddr(rest)
	return addr, 0, err
}

// Host returns the subject of a host name, such as host/shop.app.example, in normal form: lowercase,
// with no trailing dot. A leading *.label stands for any host below it. Entry points repeat across
// clusters, so a host carries no cluster.
func Host(name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	labels := strings.Split(strings.TrimPrefix(name, "*."), ".")
	// Two labels after a wildcard, so that *.example never covers a whole top-level domain.
	if len(name) > maxHostLength || len(labels) < 2 {
		return "", errors.New("a host is at least two labels of at most 253 characters in all, such as shop.app.example")
	}
	for _, l := range labels {
		if !isLabel(l) {
			return "", errors.New("a host label is 1 to 63 letters, digits and hyphens, with no hyphen at either end")
		}
	}
	return string(KindHost) + "/" + name, nil
}

// isLabel reports whether l is a DNS label: 1 to 63 letters, digits and hyphens, none at either end.
func isLabel(l string) bool {
	if l == "" || len(l) > maxLabelLength || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := range len(l) {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// Address returns the subject of an IP address, and of a port when it is not 0, such as
// address/192.0.2.10:30443. The address is unmapped and has no zone. An IPv6 address is in brackets
// only when a port follows, so that the port can't be taken for part of it.
func Address(addr string, port uint16) (string, error) {
	a, err := netip.ParseAddr(addr)
	if err != nil || a.Zone() != "" {
		return "", errors.New("an address is an IPv4 or IPv6 address with no zone")
	}
	a = a.Unmap()
	text := a.String()
	if port != 0 {
		if a.Is6() {
			text = "[" + text + "]"
		}
		text += ":" + strconv.Itoa(int(port))
	}
	return string(KindAddress) + "/" + text, nil
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
