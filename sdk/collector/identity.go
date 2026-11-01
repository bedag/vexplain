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

package collector

import (
	"context"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// APIVersion is the version of the collector API that this SDK speaks. GetInfo lists it, and vexplain
// uses the newest version that both sides know.
const APIVersion = "v1alpha1"

// Role is where a collector runs. The zero value is no role.
type Role int

// The roles, with the numbers of the API's enum.
const (
	// RoleSpoke runs in a cluster with the spoke role, next to its workloads.
	RoleSpoke = Role(collectorv1alpha1.Role_ROLE_SPOKE)
	// RoleHub runs on the hub.
	RoleHub = Role(collectorv1alpha1.Role_ROLE_HUB)
)

// Scope says where the evidence of a type goes. The zero value is no scope.
type Scope int

// The scopes, with the numbers of the API's enum.
const (
	// ScopeSpoke evidence stays in its cluster.
	ScopeSpoke = Scope(collectorv1alpha1.Scope_SCOPE_SPOKE)
	// ScopeHub evidence goes to the hub, which collects it across clusters. Its subjects are unique
	// across clusters.
	ScopeHub = Scope(collectorv1alpha1.Scope_SCOPE_HUB)
)

// Info is what GetInfo answers: the collector's name and version. vexplain stores evidence at the
// version, so a new version replaces what an old one delivered.
type Info struct{ Name, Version string }

// EvidenceType is a type of evidence that a collector produces.
//
// Type is the CloudEvents type, reverse-DNS and versioned, such as
// ch.bedag.vexplain.scanner.image-contents.v1alpha1. Schema is the JSON Schema of its data. The
// capabilities name the type's dataschema as evidence.New gives it to the type's events.
type EvidenceType struct {
	Type   string
	Scope  Scope
	Schema []byte
}

// Operation is work that vexplain can ask a collector to do for one subject, through Invoke.
//
// Role is the role that runs it. It returns events of the types it Produces, and gets the evidence
// of the types it Consumes as its inputs. ParameterSchema is the JSON Schema of its parameters,
// which the agent's tool for the operation takes as its input schema.
type Operation struct {
	Name, Description  string
	Role               Role
	Produces, Consumes []string
	ParameterSchema    []byte
}

// Permission is something that a collector needs from the Kubernetes API, in the form of an RBAC
// rule. Namespaced means only in the collector's own namespace.
type Permission struct {
	APIGroups, Resources, Verbs []string
	Namespaced                  bool
}

// Capabilities are what a collector does: what GetCapabilities answers. Serve reads them once, when
// it starts, and holds the collector to them.
//
//   - Roles are the roles that the collector takes. A Watch or Invoke for another is refused.
//   - Produces are the types of evidence that the collector produces, with their scopes and schemas.
//     Every event it sends is of one of them.
//   - Consumes are the types that its operations consume.
//   - Watches says that the collector streams evidence from Watch. It then implements Watcher.
//   - Operations are what Invoke runs. A collector that declares any implements Invoker.
//   - SettingsSchema is the JSON Schema of the collector's settings. It stands alone: it refers to
//     nothing outside itself. Without one, any JSON passes.
//   - Permissions are what the collector needs from the Kubernetes API. vexplain checks that its
//     service account holds them, and grants none.
type Capabilities struct {
	Roles          []Role
	Produces       []EvidenceType
	Consumes       []string
	Watches        bool
	Operations     []Operation
	SettingsSchema []byte
	Permissions    []Permission
}

// Collector is what every collector implements: it describes itself. A collector that watches also
// implements Watcher, one with operations Invoker, and one that checks its settings beyond their
// schema SettingsValidator.
type Collector interface {
	Info() Info
	Capabilities() Capabilities
}

// dataSchemaPrefix starts the dataschema that evidence.New gives every event. What follows is the
// event's type.
const dataSchemaPrefix = "urn:vexplain:schema:"

// identityServer serves the Identity service from what the collector declared when Serve started.
type identityServer struct {
	collectorv1alpha1.UnimplementedIdentityServer
	info         *collectorv1alpha1.GetInfoResponse
	capabilities *collectorv1alpha1.GetCapabilitiesResponse
	settings     *settingsCheck
}

func (s *identityServer) GetInfo(context.Context, *collectorv1alpha1.GetInfoRequest) (
	*collectorv1alpha1.GetInfoResponse, error) {
	return s.info, nil
}

func (s *identityServer) GetCapabilities(context.Context, *collectorv1alpha1.GetCapabilitiesRequest) (
	*collectorv1alpha1.GetCapabilitiesResponse, error) {
	return s.capabilities, nil
}

// ValidateSettings checks the settings against their schema first. Only settings that pass it reach
// the collector's own validator, which may rely on the schema.
func (s *identityServer) ValidateSettings(_ context.Context, req *collectorv1alpha1.ValidateSettingsRequest) (
	*collectorv1alpha1.ValidateSettingsResponse, error) {
	_, problems := s.settings.problems(req.GetSettings())
	return &collectorv1alpha1.ValidateSettingsResponse{Problems: problems}, nil
}

func infoResponse(info Info) *collectorv1alpha1.GetInfoResponse {
	return &collectorv1alpha1.GetInfoResponse{Name: info.Name, Version: info.Version, ApiVersions: []string{APIVersion}}
}

func capabilitiesResponse(caps Capabilities) *collectorv1alpha1.GetCapabilitiesResponse {
	resp := &collectorv1alpha1.GetCapabilitiesResponse{
		Consumes:       caps.Consumes,
		Watches:        caps.Watches,
		SettingsSchema: caps.SettingsSchema,
	}
	for _, role := range caps.Roles {
		resp.Roles = append(resp.Roles, collectorv1alpha1.Role(role))
	}
	for _, produced := range caps.Produces {
		resp.Produces = append(resp.Produces, &collectorv1alpha1.EvidenceType{
			Type:       produced.Type,
			Scope:      collectorv1alpha1.Scope(produced.Scope),
			Dataschema: dataSchemaPrefix + produced.Type,
			Schema:     produced.Schema,
		})
	}
	for _, op := range caps.Operations {
		resp.Operations = append(resp.Operations, &collectorv1alpha1.Operation{
			Name:            op.Name,
			Description:     op.Description,
			Role:            collectorv1alpha1.Role(op.Role),
			Produces:        op.Produces,
			Consumes:        op.Consumes,
			ParameterSchema: op.ParameterSchema,
		})
	}
	for _, permission := range caps.Permissions {
		resp.Permissions = append(resp.Permissions, &collectorv1alpha1.PolicyRule{
			ApiGroups:  permission.APIGroups,
			Resources:  permission.Resources,
			Verbs:      permission.Verbs,
			Namespaced: permission.Namespaced,
		})
	}
	return resp
}
