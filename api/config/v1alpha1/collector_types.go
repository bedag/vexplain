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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// RuntimeConfigReference names a CollectorRuntimeConfig.
type RuntimeConfigReference struct {
	// name is the name of the CollectorRuntimeConfig.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name,omitempty"`
}

// MCPHeadersLabel is the label that a Secret must carry, with the value "true", before an MCP collector may send its
// keys and values as headers. The operator never reads a Secret without it, so whoever may write a Collector can't
// have the operator send any other Secret of its namespace to a server.
const MCPHeadersLabel = "vexplain.bedag.ch/mcp-headers"

// SecretReference names a Secret in the operator's namespace. The config kinds are cluster-scoped, so the namespace is
// not part of the reference: it is always the operator's.
type SecretReference struct {
	// name is the name of the Secret.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name,omitempty"`
}

// MCPHeaders names a Secret whose keys and values are headers of the requests to an MCP server.
type MCPHeaders struct {
	// secretRef names a Secret in the operator's namespace that carries the label vexplain.bedag.ch/mcp-headers:
	// "true". Each key of the Secret is a header's name, and its value, trimmed of whitespace, the header's value. A
	// Secret without the label is treated as missing.
	// +required
	SecretRef SecretReference `json:"secretRef,omitzero"`
}

// CollectorMCP names an MCP server that runs elsewhere, and the tools of it that vexplain may call. Whoever deploys the
// server answers for its privileges, and vexplain doesn't judge what a tool does.
type CollectorMCP struct {
	// url is the endpoint of the server's Streamable HTTP transport of MCP, such as https://wiki-mcp.example/mcp: an
	// https URL with a host. HTTPS only, because the headers travel with every request.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:XValidation:rule="isURL(self) && url(self).getScheme() == 'https' && url(self).getHostname() != ''",message="url is an https URL with a host"
	URL string `json:"url,omitempty"`
	// headersFrom are the Secrets whose keys and values are the headers of every request to the server, such as its
	// Authorization. A header that two of them name takes the value of the later. vexplain shows a header's value
	// nowhere: an output or an error of the server that holds a value, or a word of one, of 8 bytes or more has it
	// withheld.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	HeadersFrom []MCPHeaders `json:"headersFrom,omitempty"`
	// tools are the names of the server's tools that vexplain may call, and the only ones: a tool off the list is never
	// offered to the agent and never called, whatever an AgentProfile allows. vexplain calls tools unattended, with
	// arguments that a model picked from text that anyone can write, so a tool that writes, such as one that deletes a
	// page, stays off the list unless that is meant. A name has the characters that a model's tool takes, and the agent
	// calls the tool <collector>__<tool>, which takes 64 characters at most: a name has 61 at most, what the shortest
	// Collector's name leaves, and fewer for a longer one. An AgentProfile's operations, of 63 at most, name each.
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=61
	// +kubebuilder:validation:items:Pattern=`^[A-Za-z0-9_-]+$`
	Tools []string `json:"tools,omitempty"`
}

// CollectorSpec says which package a Collector installs, how its Deployment is shaped and what its
// settings are, or which MCP server it names.
// +kubebuilder:validation:XValidation:rule="has(self.package) != has(self.mcp)",message="a Collector has exactly one of package and mcp"
// +kubebuilder:validation:XValidation:rule="!has(self.mcp) || !(has(self.runtimeConfigRef) || has(self.triggers) || has(self.produces))",message="a Collector of an MCP server has no runtimeConfigRef, triggers or produces: vexplain deploys nothing for it"
// +kubebuilder:validation:XValidation:rule="has(oldSelf.mcp) == has(self.mcp)",message="a Collector doesn't change between a package and an MCP server: delete it, and create it anew, so that what vexplain made for the package goes"
type CollectorSpec struct {
	// package is the OCI image that holds the collector, referenced by tag or by digest, such as
	// artifacts.example/collectors/hello:0.1.0. Upgrading the collector means changing it, and
	// changing it back is the rollback. The digest that actually runs is in status.packageDigest.
	// A Collector has exactly one of package and mcp.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Package *string `json:"package,omitempty"`
	// mcp names an MCP server that runs elsewhere, whose tools on its list the agent may call, in place of a package
	// (design of the agent on image cases, 5.9). vexplain deploys nothing for it: it connects, lists the server's
	// tools, and the Collector is Ready while the server serves every tool on the list. Its tools' outputs are
	// external evidence, always.
	// +optional
	MCP *CollectorMCP `json:"mcp,omitempty"`
	// runtimeConfigRef names the CollectorRuntimeConfig that shapes the collector's Deployment. When
	// it is absent, the config named default applies.
	// +optional
	RuntimeConfigRef *RuntimeConfigReference `json:"runtimeConfigRef,omitempty"`
	// settings are the collector's own settings, an object of any shape: vexplain can't know the
	// settings of a collector that someone else wrote, so the schema keeps them as they are. The
	// operator checks them against the settings schema that the collector declares and with the
	// collector's own check, and reports SettingsInvalid when they fail. A Collector of an MCP server has no
	// use for them, and vexplain sends them nowhere.
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Schemaless
	Settings *runtime.RawExtension `json:"settings,omitempty"`
	// triggers change the triggers that the collector declares, each named after one of them. In this version
	// a collector's triggers are its schedules, and a trigger replaces the cron expression of the schedule of its
	// name. A trigger that names no schedule of the collector, or a cron expression that the operator can't run,
	// makes the Collector TriggersInvalid.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=8
	Triggers []CollectorTrigger `json:"triggers,omitempty"`
	// produces override the maxAge that the collector declares for a type that it produces, each named after the
	// type. Evidence of the type that is older than its maxAge is missing for the rules, and vexplain asks the
	// collector for it again. A maxAge applies to the evidence that operations return: a stream can't be asked again,
	// and its records are written only when they change. An override of a type that the collector doesn't declare as
	// produced, or that no operation of the collector returns, makes the Collector ProducesInvalid.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=16
	Produces []ProducedTypeOverride `json:"produces,omitempty"`
}

// ProducedTypeOverride is what an admin changes of a type that a collector produces.
type ProducedTypeOverride struct {
	// type is the type of the evidence, named in reverse-DNS with a version, such as
	// ch.bedag.vexplain.presence.v1alpha1.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type string `json:"type,omitempty"`
	// maxAgeSeconds is how long evidence of the type stays current, in seconds, in place of the maxAge that the
	// collector declares. From 60 seconds to 30 days.
	// +required
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:validation:Maximum=2592000
	MaxAgeSeconds int64 `json:"maxAgeSeconds,omitempty"`
}

// CollectorTrigger is what an admin changes of a trigger that a collector declares.
type CollectorTrigger struct {
	// name is the name of the trigger: in this version, of a schedule that the collector declares, as
	// status.capabilities.schedules lists them.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name,omitempty"`
	// schedule is a five-field cron expression, in UTC and without a time zone, that the operator runs in
	// place of the one that the collector declares. When it is absent, the declared one runs. An expression
	// that never comes due, such as one for the 30th of February, leaves the schedule to run now alone.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Schedule *string `json:"schedule,omitempty"`
}

// CollectorRole says where a collector runs. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Spoke;Hub
type CollectorRole string

const (
	// CollectorRoleSpoke runs in a cluster with the spoke role, next to its workloads.
	CollectorRoleSpoke CollectorRole = "Spoke"
	// CollectorRoleHub runs in the hub's cluster.
	CollectorRoleHub CollectorRole = "Hub"
)

// EvidenceScope says where the evidence of a type goes. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Spoke;Hub
type EvidenceScope string

const (
	// EvidenceScopeSpoke evidence stays in its cluster.
	EvidenceScopeSpoke EvidenceScope = "Spoke"
	// EvidenceScopeHub evidence goes to the hub, which collects it across clusters. Its subjects are
	// unique across clusters.
	EvidenceScopeHub EvidenceScope = "Hub"
)

// CollectorWatch says whether a collector streams its evidence. Open enum; more values may follow.
// +kubebuilder:validation:Enum=Supported;NotSupported
type CollectorWatch string

const (
	// CollectorWatchSupported means the collector streams its evidence: a full snapshot first, then
	// each change.
	CollectorWatchSupported CollectorWatch = "Supported"
	// CollectorWatchNotSupported means the collector delivers evidence only when an operation runs.
	CollectorWatchNotSupported CollectorWatch = "NotSupported"
)

// ProducedType is a type of evidence that a collector produces.
type ProducedType struct {
	// type is the type of the evidence, named in reverse-DNS with a version, such as
	// ch.bedag.vexplain.presence.v1alpha1.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Type string `json:"type,omitempty"`
	// scope says where the evidence of the type goes: to the hub, or nowhere but its cluster. More
	// values may follow.
	// +required
	Scope EvidenceScope `json:"scope,omitempty"`
	// maxAgeSeconds is how long evidence of the type stays current, in seconds, as the collector declares it:
	// past it, the evidence is missing for the rules, and vexplain asks the collector again. It applies to the
	// evidence that operations return. It is absent when the collector declares none. spec.produces overrides it.
	// +optional
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:validation:Maximum=2592000
	MaxAgeSeconds *int64 `json:"maxAgeSeconds,omitempty"`
}

// CollectorOperation is work that a collector does on demand, for one subject.
type CollectorOperation struct {
	// name is the name of the operation, which is unique in the collector.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name,omitempty"`
	// role is the role that runs the operation. It is absent in a status that an older operator wrote.
	// +optional
	Role *CollectorRole `json:"role,omitempty"`
	// parameters are the names of the top-level properties of the operation's parameter schema, sorted, the first
	// 16 of them when there are more. They tell what the operation takes, such as hosts or addresses.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	Parameters []string `json:"parameters,omitempty"`
	// produces are the types of evidence that the operation returns.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Produces []string `json:"produces,omitempty"`
	// consumes are the types of evidence that the operation takes as input. vexplain gets the evidence
	// of these types for the subject before it runs the operation.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Consumes []string `json:"consumes,omitempty"`
}

// CollectorSchedule is work that vexplain asks a collector to do on a schedule.
type CollectorSchedule struct {
	// name is the name of the schedule, which is unique in the collector.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name,omitempty"`
	// cron is a five-field cron expression, in UTC.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Cron string `json:"cron,omitempty"`
}

// CollectorSource is a source of a collector's own, such as a vulnerability database, as its GetInfo
// reported it.
type CollectorSource struct {
	// name is the name of the source, which is unique in the collector.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name,omitempty"`
	// version is the version of the source's data.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Version string `json:"version,omitempty"`
	// builtTime is when the source's data was built, when the collector says.
	// +optional
	BuiltTime *metav1.Time `json:"builtTime,omitempty"`
}

// ScheduleStatus is a schedule that the operator runs for a collector, and what came of its last fire.
type ScheduleStatus struct {
	// name is the name of the schedule, which the collector declares.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name,omitempty"`
	// schedule is the cron expression that the operator runs, in UTC: the one that spec.triggers sets for the
	// schedule, or else the one that the collector declares.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Schedule string `json:"schedule,omitempty"`
	// lastFireTime is when the operator last fired the schedule, at its time or for run now, whether the
	// collector took the fire or not.
	// +optional
	LastFireTime *metav1.Time `json:"lastFireTime,omitempty"`
	// lastFailure says why the last fire failed: the error of the call of the collector's Fire, which can hold the
	// collector's own text. It is absent when the last fire succeeded.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	LastFailure *string `json:"lastFailure,omitempty"`
}

// CollectorCapabilities is what a collector answered to GetCapabilities, in a bounded form. What
// stays with the collector is the schema of each type of evidence, the schema of its settings, the
// schema of each operation's parameters and the Kubernetes permissions that it needs.
type CollectorCapabilities struct {
	// roles are where the collector runs: in a cluster next to its workloads, in the hub's cluster,
	// or both. More values may follow.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=2
	Roles []CollectorRole `json:"roles,omitempty"`
	// produces are the types of evidence that the collector produces, each with its scope.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=32
	Produces []ProducedType `json:"produces,omitempty"`
	// consumes are the types of evidence that the collector's operations take as input.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=32
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9-]+(\.[a-z0-9-]+)+\.v[0-9]+((alpha|beta)[0-9]+)?$`
	Consumes []string `json:"consumes,omitempty"`
	// watch says whether the collector streams its evidence. More values may follow.
	// +required
	Watch CollectorWatch `json:"watch,omitempty"`
	// operations are the work that the collector does on demand.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=16
	Operations []CollectorOperation `json:"operations,omitempty"`
	// schedules are the work that the operator asks the collector to do on a schedule.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=8
	Schedules []CollectorSchedule `json:"schedules,omitempty"`
}

// CollectorStatus is what the operator knows about the collector that a Collector installs.
type CollectorStatus struct {
	// conditions represent the current state of the Collector.
	// The Ready condition says whether the collector works. It is True with reason Healthy when the
	// collector answers its health check with SERVING. It is Unknown with reason Progressing while
	// its Deployment rolls out, and with reason NoData while a check fails within the grace after
	// the operator's start, or after the operator issued the collector's certificate. It is False
	// with reason CollectorFailing, and the error as its message, when the collector can't be
	// reached after that grace: a call of it fails, its Deployment has no available replica after
	// its rollout or exceeded its progress deadline, or an error keeps the operator from checking.
	// The other reasons of False say why the collector can't be used: PackageInvalid when its answer
	// to GetInfo or GetCapabilities is malformed, IncompatibleAPI when it speaks no version of the
	// collector API that the operator knows, TriggersInvalid when spec.triggers names a trigger that it
	// doesn't declare or a schedule has a cron expression that the operator can't run, ProducesInvalid when
	// spec.produces names a type that it doesn't produce, SettingsInvalid
	// when spec.settings fail the collector's check, PermissionsNotAllowed when, in the Grant mode,
	// the operator may not grant a permission that it declares, MissingPermissions when its service
	// account lacks permissions that it declares, and RuntimeConfigInvalid when what its runtime config
	// shapes can't be written. The message says what.
	// Reconciling and Stalled are present only while True, and give the reason and message of Ready,
	// so that kstatus can tell a collector in progress from one that is stuck. Reconciling comes with
	// Progressing and NoData: the operator waits on the rollout, or on the grace for health. Stalled
	// comes with every reason of False: PackageInvalid, IncompatibleAPI, TriggersInvalid, ProducesInvalid,
	// SettingsInvalid, PermissionsNotAllowed, MissingPermissions and RuntimeConfigInvalid need a change
	// of the package, the spec, the permissions or the runtime config, and CollectorFailing is reported
	// only once the rollout and the grace are over. Healthy has neither.
	// For a Collector of an MCP server, Ready is True with Healthy while the server serves every tool on
	// spec.mcp.tools, False with ToolsMissing while it lacks one, which the message names, and False with
	// CollectorFailing, and the error as its message, while it can't be reached: a Secret of its headers
	// doesn't exist or doesn't carry the label, the connection or the listing fails. Its status holds no
	// capabilities, since it streams nothing and runs no operation of the collector API.
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// observedGeneration is the generation of the Collector that the operator last acted on.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration *int64 `json:"observedGeneration,omitempty"`
	// packageDigest is the digest of the image that runs, as the collector's pod reports it. It
	// differs from spec.package when that names a tag.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	PackageDigest *string `json:"packageDigest,omitempty"`
	// version is the version that the collector's GetInfo answered. Evidence is written at this
	// version, so a new version replaces what an older one delivered.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	Version *string `json:"version,omitempty"`
	// capabilities are what the collector's GetCapabilities answered, bounded in size.
	// +optional
	Capabilities *CollectorCapabilities `json:"capabilities,omitempty"`
	// sources are the versions of the collector's own sources, as its GetInfo reported them at the
	// last check. The operator writes them only when they change.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=8
	Sources []CollectorSource `json:"sources,omitempty"`
	// schedules are the schedules that the operator runs for the collector: those that it declares, each
	// with the cron expression that spec.triggers sets for it, if it sets one, and with what came of its last
	// fire.
	// The operator fires a schedule only while the Collector is Ready, at the times of its cron expression
	// from when it started to run it, without catching up on times that passed before. A restart of the
	// operator leaves the last fires as they were.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=8
	Schedules []ScheduleStatus `json:"schedules,omitempty"`
	// lastHandledRunNow is the value of the annotation vexplain.bedag.ch/run-now that the operator handled
	// last, as its first 128 characters: it fired every schedule once for it, and each fire succeeded. A
	// value that differs from it asks for a run now, which waits until the Collector is Ready.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	LastHandledRunNow *string `json:"lastHandledRunNow,omitempty"`
	// lastSuccessTime is when the collector last passed its health check. While the collector stays
	// healthy, the operator writes a later time once this one is 5 minutes old, so it lags by up to
	// that. A later failure leaves it as it was, and so does a restart of the operator.
	// +optional
	LastSuccessTime *metav1.Time `json:"lastSuccessTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories=vexplain
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.status.version`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Last Success",type=date,JSONPath=`.status.lastSuccessTime`
// +kubebuilder:printcolumn:name="Package",type=string,priority=1,JSONPath=`.spec.package`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')",message="a Collector is named with a DNS-1123 label, which has no dots"
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 44",message="a Collector's name is at most 44 characters, because the Service vexplain-collector-<name> is a DNS-1035 label of at most 63 characters, and so is the first label of the collector's TLS server name"
// +kubebuilder:validation:XValidation:rule="!(self.metadata.name in ['defaults', 'namespaced', 'namespaced-defaults'])",message="a Collector isn't named defaults, namespaced or namespaced-defaults, because the operator grants a collector its permissions through objects named vexplain-collector-<name>, and the install's ceilings and their defaults take these names"
// +kubebuilder:validation:XValidation:rule="!has(self.spec.mcp) || self.spec.mcp.tools.all(t, size(self.metadata.name) + size(t) <= 62)",message="the agent calls each tool of an MCP collector <collector>__<tool>, which takes 64 characters at most, as a model's tool does"
// +kubebuilder:validation:XValidation:rule="!self.metadata.name.matches('^ev-[0-9]+$')",message="a Collector isn't named like an entry of the agent's ledger, such as ev-3: the outputs of the agent's tool calls are stored with their entry as their source, and deleting a Collector deletes the evidence whose source is its name"

// Collector installs one collector, a source of evidence, from its package, or names an MCP server whose tools the
// agent may call. It is cluster-scoped, and installed means enabled: deleting the Collector removes the collector,
// and the evidence that it delivered.
//
// A Collector is named with a DNS-1123 label, because playbooks name the collectors that they read,
// and with at most 44 characters, because the operator names the Service of the collector
// vexplain-collector-<name>. That name is a DNS-1035 label, and so is the first label of the
// collector's TLS server name, and a label has 63 characters at most, which leaves 44 for the name.
// It isn't defaults, namespaced or namespaced-defaults: the operator grants the collector the
// permissions that it declares through objects named vexplain-collector-<name> too, and the
// install's ceilings and their defaults take those names. Nor is it named like an entry of the agent's ledger,
// such as ev-3: the outputs of the agent's tool calls are stored with their entry as their source.
// The status shows the digest that runs, what the collector describes itself as, and whether it works.
type Collector struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines which package the Collector installs, and its settings, or which MCP server it names
	// +required
	Spec CollectorSpec `json:"spec"`

	// status defines the observed state of Collector
	// +optional
	Status CollectorStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// CollectorList contains a list of Collector
type CollectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Collector `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &Collector{}, &CollectorList{})
		return nil
	})
}
