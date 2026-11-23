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

import (
	"encoding/json"
	"math"
	"net/netip"

	"github.com/bedag/vexplain/sdk/subject"
)

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
	// Subject is the workload's subject, with its cluster, such as
	// workload/cluster-a/team-a/Deployment.apps/web. Exposure is about the same subject.
	Subject string `json:"subject"`
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
	KnownExploited bool `json:"knownExploited"`
	// EPSSPermille is the source's EPSS score of the vulnerability, the probability that it is exploited in the
	// next 30 days, in per mille: floor(score x 1000), 0 to 1000. It is left out where the source has none.
	EPSSPermille *int32 `json:"epssPermille,omitempty"`
	// EPSSDate is the date of the score, as the source writes it. It is left out with the score.
	EPSSDate string `json:"epssDate,omitempty"`
	CVSS     []CVSS `json:"cvss,omitempty"`
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
	// UnseenAdminNetworkPolicy says that the cluster serves SIG Network's AdminNetworkPolicy, or its
	// ClusterNetworkPolicy, which replaces it, whose rules can let in what the network policies deny.
	UnseenAdminNetworkPolicy = "AdminNetworkPolicy"
	// UnseenCalicoNetworkPolicy says that the cluster serves Calico's policies, in crd.projectcalico.org
	// or projectcalico.org, whose rules can let in what the network policies deny.
	UnseenCalicoNetworkPolicy = "CalicoNetworkPolicy"
	// UnseenIPBlock says that a policy lets in an IP block, which can hold the address of any pod or
	// node, and of anything outside the cluster.
	UnseenIPBlock = "IPBlock"
	// UnseenUnknownParentRef says that a route that sends traffic to the workload attaches to a parent
	// of a kind that the collector doesn't read, which may face outside.
	UnseenUnknownParentRef = "UnknownParentRef"
)

// Widening is what set a workload's internal reach: a rule of a policy, or a reason without one.
type Widening struct {
	// Kind, Namespace and Name name the object, such as a NetworkPolicy, or the Namespace that has
	// no policy. Namespace is empty for an object that has none.
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Rule is the index of the object's ingress rule that set the reach, from 0, and nil where no
	// one rule did. For a Cilium policy, the index runs across the ingress rules of its spec and
	// then of each of its specs.
	Rule *int32 `json:"rule,omitempty"`
	// Reason says how the object set the reach.
	Reason string `json:"reason"`
}

// ExternalExposure says whether something outside the cluster reaches the workload.
type ExternalExposure struct {
	Exposed bool `json:"exposed"`
	// EntryPoints are the ways in from outside the cluster, at most MaxEntryPoints. It is written as []
	// when it is empty, never as null.
	EntryPoints []EntryPoint `json:"entryPoints"`
	// Unchecked lists why a way in can't be asked about: one of the Unchecked values each, at most
	// MaxUnchecked. It is written as [] when it is empty, never as null.
	Unchecked []string `json:"unchecked"`
}

// MarshalJSON writes an empty EntryPoints or Unchecked as [], where a nil slice would be written as
// null, which the schema refuses. An exposure rule reads both lists, and fails on one that is missing.
func (e ExternalExposure) MarshalJSON() ([]byte, error) {
	type plain ExternalExposure
	if e.EntryPoints == nil {
		e.EntryPoints = []EntryPoint{}
	}
	if e.Unchecked == nil {
		e.Unchecked = []string{}
	}
	return json.Marshal(plain(e))
}

// The values of ExternalExposure.Unchecked.
const (
	// UncheckedHostNetwork says that a pod runs on its node's network, which has no entry point of its own.
	UncheckedHostNetwork = "HostNetwork"
	// UncheckedNoAddress says that a way in has no address that the collector can name yet, as when its status is
	// empty.
	UncheckedNoAddress = "NoAddress"
	// UncheckedNotASubject says that an address was left out because it makes no subject.
	UncheckedNotASubject = "NotASubject"
	// UncheckedTooManyAddresses says that an entry point had more than MaxEntryPointAddresses addresses,
	// and keeps the first ones.
	UncheckedTooManyAddresses = "TooManyAddresses"
	// UncheckedTooManyEntryPoints says that the workload had more than MaxEntryPoints entry points, and
	// keeps the first ones, sorted.
	UncheckedTooManyEntryPoints = "TooManyEntryPoints"
)

// The limits of an exposure's entry points.
const (
	MaxEntryPoints         = 32
	MaxEntryPointAddresses = 256
	MaxUnchecked           = 8
)

// EntryPoint is one way in from outside the cluster: host names or IP addresses, as an EndpointSlice
// holds them, that reach the workload through one object.
type EntryPoint struct {
	Addresses []string `json:"addresses"`
	// Port is nil where the way in has none, so that a source answers for every port.
	Port *int32 `json:"port,omitempty"`
	// Protocol is TCP, UDP or SCTP, where the way in has a port.
	Protocol string `json:"protocol,omitempty"`
	// ObjectRef is the object that opens the way in, such as an Ingress or a Service.
	ObjectRef ObjectRef `json:"objectRef"`
	// ParentRef is a route's Gateway.
	ParentRef *ObjectRef `json:"parentRef,omitempty"`
	// Subjects are what the sources are asked about, one for each address: see EntryPointSubjects.
	Subjects []string `json:"subjects"`
}

// EntryPointSubjects gives the subjects of an entry point's addresses. An IP address gets the port,
// where port isn't 0, and any other address is a host name, which gets none, since sources look hosts
// up by name. A port outside 0..65535 refuses every IP address. An address that is neither is
// refused: it is counted, and left out. kept holds the accepted addresses as given, and subjects
// their subjects, in the same order.
func EntryPointSubjects(addresses []string, port int32) (kept, subjects []string, refused int) {
	for _, a := range addresses {
		var s string
		var err error
		if ip, perr := netip.ParseAddr(a); perr == nil {
			if port < 0 || port > math.MaxUint16 {
				refused++
				continue
			}
			s, err = subject.Address(ip.String(), uint16(port))
		} else {
			s, err = subject.Host(a)
		}
		if err != nil {
			refused++
			continue
		}
		kept, subjects = append(kept, a), append(subjects, s)
	}
	return kept, subjects, refused
}

// ObjectRef names an object. APIGroup is empty for the core group, and Namespace for an object that
// has none.
type ObjectRef struct {
	APIGroup  string `json:"apiGroup"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// Description is the data of a description event (TypeDescription): what a vulnerability database holds for one
// vulnerability, from each of its providers, and whether each package that it was asked about has the fix of a
// provider. The strings are the database's own.
type Description struct {
	// VulnerabilityID is the ID that the database was asked about.
	VulnerabilityID string `json:"vulnerabilityID"`
	// Aliases are the IDs of the same vulnerability that the records name, such as the CVE of a GitHub advisory, each
	// once, sorted. The providers list what they say under these IDs too, each answer under the one ID that its
	// records are of.
	Aliases     []string `json:"aliases,omitempty"`
	Description string   `json:"description,omitempty"`
	// CVSS are the vectors of the records' scores, each once.
	CVSS []CVSS `json:"cvss,omitempty"`
	// KnownExploited is true when a record lists the vulnerability as known to be exploited.
	KnownExploited bool `json:"knownExploited"`
	// EPSSPermille is the EPSS score of the vulnerability's CVE, in per mille: floor(score x 1000), 0 to 1000. It is
	// left out where the database has none. EPSSDate is the date of the score.
	EPSSPermille *int32 `json:"epssPermille,omitempty"`
	EPSSDate     string `json:"epssDate,omitempty"`
	// References are the URLs that the records name, each once.
	References []string `json:"references,omitempty"`
	// Packages are the packages that the database was asked about, as they were given, at most 16.
	Packages []DescribedPackage `json:"packages,omitempty"`
	// Providers are what each provider says of a fix: the entries that answer for a package of Packages, and for a
	// package that none answers for, some that name it. It is written as [] when there are none, never as null.
	Providers []ProviderFix `json:"providers"`
	// OtherProviders count the entries that Providers leaves out, per provider, sorted by provider. Each says Unknown
	// for every package of Packages.
	OtherProviders []ProviderCount `json:"otherProviders,omitempty"`
}

// ProviderCount is how many entries of a provider a Description leaves out.
type ProviderCount struct {
	Provider string `json:"provider"`
	Entries  int32  `json:"entries"`
}

// MarshalJSON writes empty Providers as [], where a nil slice would be written as null, which the schema refuses.
func (d Description) MarshalJSON() ([]byte, error) {
	type plain Description
	if d.Providers == nil {
		d.Providers = []ProviderFix{}
	}
	return json.Marshal(plain(d))
}

// DescribedPackage is a package that the database was asked about: its name, version and type, which are the SBOM's,
// and its purl and distribution, which name its source package and its release, as Grype reads them.
type DescribedPackage struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type"`
	PURL    string `json:"purl,omitempty"`
	Distro  string `json:"distro,omitempty"`
}

// ProviderFix is what one provider says of one package, in one namespace, such as a release of a distribution, in its
// records of one vulnerability.
type ProviderFix struct {
	Provider string `json:"provider"`
	// VulnerabilityID is the ID of the vulnerability whose records the answer rests on: the ID that the database was
	// asked about, or one that its records name. A provider that lists the package under two IDs answers under each.
	VulnerabilityID string `json:"vulnerabilityID"`
	// Namespace is Grype's, such as debian:distro:debian:12 or github:language:go.
	Namespace string `json:"namespace"`
	// Package is the name of the package that the provider lists, or the CPE that NVD lists.
	Package string `json:"package"`
	// FixState is Grype's: fixed when the provider names a fix, else not-fixed, wont-fix or not-affected. It is empty
	// when the provider says nothing.
	FixState      string   `json:"fixState"`
	FixedVersions []string `json:"fixedVersions,omitempty"`
	// Packages are the answers for the packages that the database was asked about, one for each.
	Packages []PackageFix `json:"packages,omitempty"`
}

// The values of PackageFix.FixedForInstalled.
const (
	// FixedForInstalledYes says that the provider speaks for the package's distribution or ecosystem, no range of the
	// package that it lists holds the installed version, and the installed version is at a fixed version or above.
	FixedForInstalledYes = "Yes"
	// FixedForInstalledNo says that the provider speaks for the package's distribution or ecosystem, and a range of the
	// package that it lists holds the installed version.
	FixedForInstalledNo = "No"
	// FixedForInstalledUnknown says neither: the provider speaks for another distribution or ecosystem, or of
	// another package, the versions don't compare, or the installed version is below every fix and in no range.
	FixedForInstalledUnknown = "Unknown"
)

// PackageFix is whether one package that the database was asked about has a provider's fix, by the name and the
// version of the package.
type PackageFix struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// FixedForInstalled is Yes, No or Unknown.
	FixedForInstalled string `json:"fixedForInstalled"`
}

// ToolOutput is the data of a tool-output event (TypeToolOutput): the whole output of one tool call of the agent, as
// the entry of the case's ledger names it. An output over the evidence store's cap is stored cut, and OutputBytes
// keeps the size of the whole.
type ToolOutput struct {
	// Entry is the ID of the ledger entry, such as ev-3, and Tool the name of the tool that was called.
	Entry string `json:"entry"`
	Tool  string `json:"tool"`
	// Output is the tool's output, or its first bytes when it was cut. It comes from the tool, and is data.
	Output string `json:"output"`
	// OutputBytes is the size of the whole output, in bytes.
	OutputBytes int64 `json:"outputBytes"`
}

// Page is the data of a page event (TypePage): the text of one page that the advisories collector fetched. The text
// keeps what a browser shows of the page, and the text of its links without their URLs, with a line for each block.
type Page struct {
	// URL is the URL that was asked for, and FinalURL the one that answered, after the redirects. Both are https.
	URL      string `json:"url"`
	FinalURL string `json:"finalURL"`
	// ContentType is the media type of the page, without its parameters, such as text/html.
	ContentType string `json:"contentType"`
	Text        string `json:"text"`
	// Truncated is true when the page was larger than the collector's cap, and Text holds only its start.
	Truncated bool `json:"truncated"`
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
	// CatalogerFailures lists the same catalogers, each with the package types that it catalogs, so that a
	// rule can hold only the findings of those types. A failure without package types means that they are
	// unknown. A producer that writes FailedCatalogers alone leaves all types unknown.
	CatalogerFailures []CatalogerFailure `json:"catalogerFailures,omitempty"`
	// Document is the producer's SBOM document, which a vulnerability matcher reads as it is, so that it
	// matches all that the document holds (decision 0044). Packages stay: rules join a finding to its
	// package by the package's ID, which is the one that the document gives it. It is nil when the
	// producer has none, and a matcher then reads the packages.
	Document *SBOMDocument `json:"document,omitempty"`
}

// CatalogerFailure is a producer's cataloger that failed, with the package types that it catalogs.
type CatalogerFailure struct {
	// Cataloger is the cataloger's name, as FailedCatalogers gives it.
	Cataloger string `json:"cataloger"`
	// PackageTypes are the types of the packages that the cataloger finds, as SBOMPackage.Type names them.
	// It is left out when the producer doesn't know them.
	PackageTypes []string `json:"packageTypes,omitempty"`
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
