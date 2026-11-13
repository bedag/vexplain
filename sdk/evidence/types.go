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

package evidence

import "encoding/json"

// The data of the core types, as Go types. Their JSON is the contract with
// every collector, whatever language it is written in: the names are lower camel case, and the
// schemas in schemas/ describe the same shape. A field is required, and so always written, when a
// rule needs it to make sense of the data. Some required strings can be empty where Kubernetes
// uses the empty string itself: the core API group, and the namespace of an object that has none.
// The other fields are optional, and left out when empty.

// KeyValue is one label or one annotation.
type KeyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// The values of Presence.DigestKind.
const (
	// DigestKindRepoDigest is a digest that a registry can serve.
	DigestKindRepoDigest = "RepoDigest"
	// DigestKindImageID is the digest of an image's configuration, which no registry can serve.
	DigestKindImageID = "ImageID"
	// DigestKindReference is the DigestKind of an image that has no digest, which no registry can serve.
	DigestKindReference = "Reference"
)

// Presence is the data of a presence event (TypePresence): one reported image digest, and every
// workload that runs it.
type Presence struct {
	// DigestKind is RepoDigest, a digest that a registry can serve, ImageID, which none can, or Reference, for an
	// image that has no digest: its subject is the SHA-256 of the image reference, and Repositories holds the
	// reference.
	DigestKind   string   `json:"digestKind"`
	Repositories []string `json:"repositories,omitempty"`
	// Workloads is written as [] when it is empty, never as null.
	Workloads []PresenceWorkload `json:"workloads"`
}

// MarshalJSON writes an empty Workloads as [], where a nil slice would be written as null, which
// the schema refuses.
func (p Presence) MarshalJSON() ([]byte, error) {
	type plain Presence
	if p.Workloads == nil {
		p.Workloads = []PresenceWorkload{}
	}
	return json.Marshal(plain(p))
}

// PresenceWorkload is a workload that runs the digest.
type PresenceWorkload struct {
	// APIGroup is empty for the core group, such as for a bare Pod.
	APIGroup  string `json:"apiGroup"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	// Pods are the pods of the workload that run the digest.
	Pods []PresencePod `json:"pods,omitempty"`
	// Labels are the workload's labels that the owner attribution allows, and no others: those of its
	// own object for a Deployment, a StatefulSet, a DaemonSet or a CronJob, and those of its pods for
	// any other workload, such as a bare pod or one of a custom controller.
	Labels []KeyValue `json:"labels,omitempty"`
	// NamespaceLabels are the namespace's labels that the owner attribution allows, and no others.
	NamespaceLabels []KeyValue `json:"namespaceLabels,omitempty"`
	// NamespaceAnnotations are the namespace's annotations that the owner attribution allows, and
	// no others.
	NamespaceAnnotations []KeyValue `json:"namespaceAnnotations,omitempty"`
}

// PresencePod is a pod that runs the digest.
type PresencePod struct {
	Name string `json:"name"`
	// Node is the node that the pod runs on.
	Node string `json:"node,omitempty"`
	// Platform is the platform of the node, as os/arch[/variant].
	Platform string `json:"platform,omitempty"`
	// Containers are the containers of the pod that run the digest, at most 32.
	Containers []PresenceContainer `json:"containers,omitempty"`
}

// PresenceContainer is a container of a pod that runs the digest.
type PresenceContainer struct {
	Name string `json:"name"`
	// Kind is Container, InitContainer, or Sidecar: an init container with restartPolicy Always.
	Kind string `json:"kind"`
}

// Findings is the data of a findings event (TypeFindings): what a source, such as a vulnerability
// matcher, found in a manifest.
type Findings struct {
	// Version is the version of the source's database. A finding is only as current as it.
	Version string `json:"version"`
	// Matches is written as [] when the source found nothing, never as null.
	Matches []Match `json:"matches"`
}

// MarshalJSON writes empty Matches as [], where a nil slice would be written as null, which the
// schema refuses. A manifest without a match is the usual case.
func (f Findings) MarshalJSON() ([]byte, error) {
	type plain Findings
	if f.Matches == nil {
		f.Matches = []Match{}
	}
	return json.Marshal(plain(f))
}

// Match is one vulnerability in one package. The strings are the source's own.
type Match struct {
	// ID identifies the match: <vulnerabilityID>/<packageID>. It is left out where it would be too long.
	ID string `json:"id,omitempty"`
	// Title is what the match is, in a line: <vulnerabilityID> in <packageName> <packageVersion>.
	Title string `json:"title,omitempty"`
	// VulnerabilityID is the CVE where one exists, and else the ID of the advisory.
	VulnerabilityID string `json:"vulnerabilityID"`
	// PackageID is the ID of the package in the SBOM that the match was made from, which is how a
	// rule finds what the scan knows about the package.
	PackageID   string `json:"packageID"`
	PackageName string `json:"packageName"`
	// PackageVersion is left out for a package that has none.
	PackageVersion string `json:"packageVersion,omitempty"`
	PackageType    string `json:"packageType"`
	// Severity is the source's, such as Critical, High, Medium, Low, Negligible or Unknown.
	Severity string `json:"severity"`
	// FixState is the source's, such as fixed, not-fixed, wont-fix or unknown. It is empty when the
	// source says nothing.
	FixState      string   `json:"fixState"`
	FixedVersions []string `json:"fixedVersions,omitempty"`
	// FixTarget is the lowest of the fixed versions that is above the installed one, compared as the package's own
	// version scheme orders them. It is left out where no scheme or no such version is known, and is at most 128
	// characters: a version is never cut.
	FixTarget string `json:"fixTarget,omitempty"`
	// UpdateTarget is the highest FixTarget of the package's matches in the manifest: the version that an update of
	// the package goes to, which fixes all of them that have a fix.
	UpdateTarget string `json:"updateTarget,omitempty"`
	// Aliases are the IDs of the related vulnerabilities, such as the GHSA ID of a CVE: at most 8, sorted, and never
	// the match's own ID.
	Aliases []string `json:"aliases,omitempty"`
	// KnownExploited is true when the source lists the vulnerability as known to be exploited.
	KnownExploited bool   `json:"knownExploited"`
	CVSS           []CVSS `json:"cvss,omitempty"`
}

// CVSS is one score of a vulnerability, as the vector that it is calculated from.
type CVSS struct {
	// Version is the version of CVSS, such as 3.1.
	Version string `json:"version"`
	Vector  string `json:"vector"`
}

// Exposure is the data of an exposure event (TypeExposure): how far a workload can be reached.
type Exposure struct {
	External ExternalExposure `json:"external"`
	// InternalReach is how far the network policies let the rest of the cluster reach the workload:
	// Namespace for its own namespace only, Peers for specific peers, Namespaces for several
	// namespaces, and Cluster for all of it, which is also the reach where no policy applies.
	InternalReach string `json:"internalReach"`
	// Indirect is true when the workload is reachable, one hop away, from a workload that is exposed
	// from outside.
	Indirect bool `json:"indirect"`
	// WidenedBy names what set the internal reach when it goes beyond the workload's namespace: a rule
	// of a policy, or a reason without one, such as no policy in the namespace. At most 8.
	WidenedBy []Widening `json:"widenedBy,omitempty"`
	// Unseen names what the collector couldn't evaluate, sorted: one of the Unseen values each, at most
	// 8. What it names narrows no reach, and where it names any, the workload may be reached further
	// than the evidence says.
	Unseen []string `json:"unseen,omitempty"`
}

// The values of Exposure.Unseen.
const (
	// UnseenAdminNetworkPolicy says that the cluster serves AdminNetworkPolicy, whose rules can let in
	// what the network policies deny.
	UnseenAdminNetworkPolicy = "AdminNetworkPolicy"
	// UnseenCalicoNetworkPolicy says that the cluster serves Calico's policies, whose rules can let in
	// what the network policies deny.
	UnseenCalicoNetworkPolicy = "CalicoNetworkPolicy"
	// UnseenIPBlock says that a policy lets in an ipBlock, which can hold the address of any pod or
	// node, and of anything outside the cluster.
	UnseenIPBlock = "ipBlock"
	// UnseenUnknownParentRef says that a route that sends traffic to the workload attaches to a parent
	// of a kind that the collector doesn't read, which may face outside.
	UnseenUnknownParentRef = "unknownParentRef"
)

// Widening is what set a workload's internal reach: a rule of a policy, or a reason without one.
type Widening struct {
	// Kind, Namespace and Name name the object, such as a NetworkPolicy, or the Namespace that has
	// no policy. Namespace is empty for an object that has none.
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Rule is the index of the object's ingress rule that set the reach, from 0, and nil where no
	// one rule did.
	Rule *int32 `json:"rule,omitempty"`
	// Reason says how the object set the reach.
	Reason string `json:"reason"`
}

// ExternalExposure says whether something outside the cluster reaches the workload.
type ExternalExposure struct {
	Exposed bool `json:"exposed"`
	// Via are the objects that expose the workload, such as an Ingress or a Service. At most 8.
	Via []ObjectRef `json:"via,omitempty"`
}

// ObjectRef names an object. APIGroup is empty for the core group, and Namespace for an object that
// has none.
type ObjectRef struct {
	APIGroup  string `json:"apiGroup"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// SBOM is the data of an sbom event (TypeSBOM): a subject's package inventory, such as what a scanner
// found in the filesystem of a platform manifest. A vulnerability matcher reads it, and so do the
// rules that join a finding to its package by the package's ID.
type SBOM struct {
	// Distro is the distribution of the subject. It is left out when the producer found none.
	Distro *Distro `json:"distro,omitempty"`
	// Packages is written as [] when the subject has none, never as null. Each package has an ID of
	// its own.
	Packages []SBOMPackage `json:"packages"`
	// Producer is what made the inventory.
	Producer Producer `json:"producer"`
	// FailedCatalogers names the producer's catalogers that failed, whose packages the inventory may
	// lack.
	FailedCatalogers []string `json:"failedCatalogers,omitempty"`
	// Document is the producer's SBOM document, which a vulnerability matcher reads as it is, so that it
	// matches all that the document holds (decision 0044). Packages stay: rules join a finding to its
	// package by the package's ID, which is the one that the document gives it. It is nil when the
	// producer has none, and a matcher then reads the packages.
	Document *SBOMDocument `json:"document,omitempty"`
}

// The formats of an SBOM document, in Syft's names. Grype reads all three.
const (
	SBOMFormatSyftJSON      = "syft-json"
	SBOMFormatCycloneDXJSON = "cyclonedx-json"
	SBOMFormatSPDXJSON      = "spdx-json"
)

// SBOMDocument is an SBOM document in a standard format, as its producer wrote it.
type SBOMDocument struct {
	// Format is the document's format: SBOMFormatSyftJSON, SBOMFormatCycloneDXJSON or
	// SBOMFormatSPDXJSON.
	Format string `json:"format"`
	// Content is the document itself, a JSON object.
	Content json.RawMessage `json:"content"`
}

// MarshalJSON writes empty Packages as [], where a nil slice would be written as null, which the
// schema refuses.
func (s SBOM) MarshalJSON() ([]byte, error) {
	type plain SBOM
	if s.Packages == nil {
		s.Packages = []SBOMPackage{}
	}
	return json.Marshal(plain(s))
}

// Distro is a distribution, as its os-release file names it. A vulnerability matcher picks the
// distribution's advisories by it.
type Distro struct {
	// ID is os-release's ID, such as debian or alpine.
	ID string `json:"id"`
	// Version is os-release's VERSION_ID, such as 12 or 3.22.2. A rolling distribution has none.
	Version string `json:"version,omitempty"`
	// Codename is os-release's VERSION_CODENAME, such as bookworm, which names a release that has no
	// version, such as Debian's testing.
	Codename string `json:"codename,omitempty"`
	// IDLike is os-release's ID_LIKE: the distributions that this one derives from, such as debian
	// for an ID that a matcher doesn't know.
	IDLike []string `json:"idLike,omitempty"`
}

// SBOMPackage is one package of an SBOM.
type SBOMPackage struct {
	// ID is the package's ID, unique within the SBOM. A match names its package by it.
	ID   string `json:"id"`
	Name string `json:"name"`
	// Version is left out for a package that has none.
	Version string `json:"version,omitempty"`
	// Type is the producer's type of the package, such as deb, rpm, apk, go-module or java-archive.
	Type string `json:"type"`
	// PURL is the package URL, with the qualifiers that the producer wrote. An OS package's purl names
	// its source package in the qualifier upstream and its distribution in distro, as Syft writes
	// them: a distribution tracks many vulnerabilities by the source package.
	PURL string `json:"purl,omitempty"`
	// CPEs are the package's CPEs, in the producer's order.
	CPEs []string `json:"cpes,omitempty"`
	// ModularityLabel is an RPM's modularity label, name:stream:version:context, such as
	// nodejs:20:8090020240101000000:a1b2c3d4: the module stream that the RPM comes from. It is "" for an RPM of no
	// module stream, and nil when the producer doesn't know. An RPM-based distribution publishes advisories per
	// module stream, and a matcher that doesn't know a package's stream applies those of every stream to it: then an
	// advisory that another stream is fixed, as AlmaLinux publishes them, hides the vulnerability of the package's own.
	ModularityLabel *string `json:"modularityLabel,omitempty"`
}

// Producer is what made an SBOM, such as Syft at its version.
type Producer struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}
