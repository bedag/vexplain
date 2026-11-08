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
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

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

// Source is a source of a collector's own, such as a vulnerability database: its name, the version
// of its data, and when that data was built. A zero BuiltTime is no time. vexplain reads the sources
// from GetInfo, and a change in a version tells it that the evidence that depends on the source may
// have changed.
type Source struct {
	Name, Version string
	BuiltTime     time.Time
}

// Sourcer is a collector that has sources of its own. Sources is called for every GetInfo, so it
// answers quickly, and with the versions that the collector has at that moment.
type Sourcer interface {
	Sources() []Source
}

// Schedule is work that vexplain asks a collector to do on a schedule, by calling Fire. Name is the
// name that Fire gets, and Cron a five-field cron expression, in UTC.
type Schedule struct{ Name, Cron string }

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
// Role is the role that runs it, one that the collector takes. It returns events of the types it
// Produces, which the collector produces, and gets the evidence of the types it Consumes, which the
// capabilities list as consumed, as its inputs. ParameterSchema is the JSON Schema of its parameters,
// which the agent's tool for the operation takes as its input schema. Invoke checks the parameters
// against it, and an operation without one takes any JSON. Like SettingsSchema, it stands alone.
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
// it starts, and holds the collector to them. It refuses capabilities that contradict themselves, or
// that vexplain would have to guess the meaning of.
//
//   - Roles are the roles that the collector takes, each RoleSpoke or RoleHub. A Watch or Invoke for
//     another is refused.
//   - Produces are the types of evidence that the collector produces, with their scopes and schemas.
//     Each type has a name, is listed once, and has the scope ScopeSpoke or ScopeHub. Every event the
//     collector sends is of one of them.
//   - Consumes are the types that its operations consume.
//   - Watches says that the collector streams evidence from Watch. It then implements Watcher.
//   - Operations are what Invoke runs. A collector that declares any implements Invoker. Each has a
//     name of its own and one of the collector's roles, produces only types of Produces, and consumes
//     only types of Consumes.
//   - Schedules are what vexplain runs by calling Fire, each with a name of its own and a cron
//     expression. A collector that declares any implements Firer, and one that implements Firer
//     declares at least one.
//   - SettingsSchema is the JSON Schema of the collector's settings. It stands alone: it refers to
//     nothing outside itself. Without one, any JSON passes.
//   - Permissions are what the collector needs from the Kubernetes API. vexplain grants them to its
//     service account, within the ceilings that the admin sets and outside the deny list, and checks
//     that the service account holds them. A collector that declares more than the ceilings allow
//     gets none of them, and isn't used. The collector starts without them, since vexplain learns
//     them from GetCapabilities: it uses them only for the work that it gets once it is Ready, and a
//     read that is refused fails that work, never the collector.
type Capabilities struct {
	Roles          []Role
	Produces       []EvidenceType
	Consumes       []string
	Watches        bool
	Operations     []Operation
	Schedules      []Schedule
	SettingsSchema []byte
	Permissions    []Permission
}

// Collector is what every collector implements: it describes itself. A collector that watches also
// implements Watcher, one with operations Invoker, and one that checks its settings beyond their
// schema SettingsValidator. One with schedules implements Firer, and one with sources of its own
// Sourcer.
type Collector interface {
	Info() Info
	Capabilities() Capabilities
}

// checkCapabilities refuses capabilities that contradict themselves, or that vexplain would have to
// guess the meaning of, as the doc of Capabilities lists them. The errors repeat the capabilities'
// own names: they go to the collector's author, not to vexplain.
func checkCapabilities(caps Capabilities) error {
	for _, role := range caps.Roles {
		if role != RoleSpoke && role != RoleHub {
			return fmt.Errorf("the capabilities list the role %d, which is neither RoleSpoke nor RoleHub", role)
		}
	}
	produced := make(map[string]bool, len(caps.Produces))
	for _, produces := range caps.Produces {
		switch {
		case produces.Type == "":
			return errors.New("the capabilities produce a type without a name")
		case produced[produces.Type]:
			return fmt.Errorf("the capabilities produce the type %q twice", produces.Type)
		case produces.Scope != ScopeSpoke && produces.Scope != ScopeHub:
			return fmt.Errorf("the type %q has the scope %d, which is neither ScopeSpoke nor ScopeHub",
				produces.Type, produces.Scope)
		}
		produced[produces.Type] = true
	}
	consumed := setOf(caps.Consumes)
	named := make(map[string]bool, len(caps.Operations))
	for _, op := range caps.Operations {
		switch {
		case op.Name == "":
			return errors.New("the capabilities declare an operation without a name")
		case named[op.Name]:
			return fmt.Errorf("the capabilities declare two operations named %q", op.Name)
		case !slices.Contains(caps.Roles, op.Role):
			// Roles holds no 0, so this refuses an operation without a role too.
			return fmt.Errorf("operation %q runs in the role %d, which the collector doesn't take", op.Name, op.Role)
		}
		named[op.Name] = true
		for _, t := range op.Produces {
			if !produced[t] {
				return fmt.Errorf("operation %q produces %q, which the collector doesn't produce", op.Name, t)
			}
		}
		for _, t := range op.Consumes {
			if !consumed[t] {
				return fmt.Errorf("operation %q consumes %q, which the capabilities don't list as consumed", op.Name, t)
			}
		}
	}
	scheduled := make(map[string]bool, len(caps.Schedules))
	for _, schedule := range caps.Schedules {
		switch {
		case schedule.Name == "":
			return errors.New("the capabilities declare a schedule without a name")
		case scheduled[schedule.Name]:
			return fmt.Errorf("the capabilities declare two schedules named %q", schedule.Name)
		case schedule.Cron == "":
			return fmt.Errorf("schedule %q has no cron expression", schedule.Name)
		}
		scheduled[schedule.Name] = true
	}
	return nil
}

// dataSchemaPrefix starts the dataschema that evidence.New gives every event. What follows is the
// event's type.
const dataSchemaPrefix = "urn:vexplain:schema:"

// identityServer serves the Identity service from what the collector declared when Serve started.
type identityServer struct {
	collectorv1alpha1.UnimplementedIdentityServer
	info         Info
	sourcer      Sourcer // nil for a collector without sources of its own
	capabilities *collectorv1alpha1.GetCapabilitiesResponse
	settings     *settingsCheck
}

func (s *identityServer) GetInfo(context.Context, *collectorv1alpha1.GetInfoRequest) (
	*collectorv1alpha1.GetInfoResponse, error) {
	resp := &collectorv1alpha1.GetInfoResponse{
		Name: s.info.Name, Version: s.info.Version, ApiVersions: []string{APIVersion},
	}
	if s.sourcer != nil {
		for _, source := range s.sourcer.Sources() {
			item := &collectorv1alpha1.Source{Name: source.Name, Version: source.Version}
			if !source.BuiltTime.IsZero() {
				item.BuiltTime = timestamppb.New(source.BuiltTime)
			}
			resp.Sources = append(resp.Sources, item)
		}
	}
	return resp, nil
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
	for _, schedule := range caps.Schedules {
		resp.Schedules = append(resp.Schedules, &collectorv1alpha1.Schedule{Name: schedule.Name, Cron: schedule.Cron})
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
