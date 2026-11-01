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

package collector_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
)

func TestGetInfo(t *testing.T) {
	s := serve(t, plainCollector{})

	info, err := s.identityClient().GetInfo(callContext(t), &collectorv1alpha1.GetInfoRequest{})
	require.NoError(t, err)
	require.Equal(t, collectorName, info.GetName())
	require.Equal(t, collectorVersion, info.GetVersion())
	require.Equal(t, []string{"v1alpha1"}, info.GetApiVersions())
	require.Equal(t, "v1alpha1", collector.APIVersion)
}

func TestGetCapabilities(t *testing.T) {
	findingsSchema, ok := evidence.Schema(evidence.TypeFindings)
	require.True(t, ok)
	caps := collector.Capabilities{
		Roles: []collector.Role{collector.RoleSpoke, collector.RoleHub},
		Produces: []collector.EvidenceType{
			{Type: typeHello, Scope: collector.ScopeSpoke, Schema: []byte(helloSchema)},
			{Type: evidence.TypeFindings, Scope: collector.ScopeHub, Schema: findingsSchema},
		},
		Consumes: []string{typeInput},
		Watches:  true,
		Operations: []collector.Operation{
			{
				Name:            operationGreet,
				Description:     greetsAWorkload,
				Role:            collector.RoleSpoke,
				Produces:        []string{typeHello},
				Consumes:        []string{typeInput},
				ParameterSchema: []byte(parameterSchema),
			},
			{
				Name:        "match",
				Description: "Matches a manifest.",
				Role:        collector.RoleHub,
				Produces:    []string{evidence.TypeFindings},
			},
		},
		SettingsSchema: []byte(settingsSchema),
		Permissions: []collector.Permission{
			readPods,
			{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"create", "delete"}, Namespaced: true},
		},
	}
	s := serve(t, &fakeCollector{caps: caps})

	got, err := s.identityClient().GetCapabilities(callContext(t), &collectorv1alpha1.GetCapabilitiesRequest{})
	require.NoError(t, err)
	want := &collectorv1alpha1.GetCapabilitiesResponse{
		Roles: []collectorv1alpha1.Role{collectorv1alpha1.Role_ROLE_SPOKE, collectorv1alpha1.Role_ROLE_HUB},
		Produces: []*collectorv1alpha1.EvidenceType{
			{
				Type:       typeHello,
				Scope:      collectorv1alpha1.Scope_SCOPE_SPOKE,
				Dataschema: dataSchema(t, typeHello),
				Schema:     []byte(helloSchema),
			},
			{
				Type:       evidence.TypeFindings,
				Scope:      collectorv1alpha1.Scope_SCOPE_HUB,
				Dataschema: dataSchema(t, evidence.TypeFindings),
				Schema:     findingsSchema,
			},
		},
		Consumes: []string{typeInput},
		Watches:  true,
		Operations: []*collectorv1alpha1.Operation{
			{
				Name:            operationGreet,
				Description:     greetsAWorkload,
				Role:            collectorv1alpha1.Role_ROLE_SPOKE,
				Produces:        []string{typeHello},
				Consumes:        []string{typeInput},
				ParameterSchema: []byte(parameterSchema),
			},
			{
				Name:        "match",
				Description: "Matches a manifest.",
				Role:        collectorv1alpha1.Role_ROLE_HUB,
				Produces:    []string{evidence.TypeFindings},
			},
		},
		SettingsSchema: []byte(settingsSchema),
		Permissions: []*collectorv1alpha1.PolicyRule{
			{ApiGroups: readPods.APIGroups, Resources: readPods.Resources, Verbs: readPods.Verbs},
			{ApiGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"create", "delete"}, Namespaced: true},
		},
	}
	require.Truef(t, proto.Equal(want, got), "want %v\ngot  %v", want, got)
}

// dataSchema is the dataschema that evidence.New gives every event of eventType: the capabilities
// name the same URI for the type.
func dataSchema(t *testing.T, eventType string) string {
	t.Helper()
	return newEvent(t, eventType).DataSchema()
}

func TestServeRefusesCapabilitiesThatContradictThemselves(t *testing.T) {
	// Each case changes one thing of capabilities that Serve takes.
	tests := map[string]func(caps *collector.Capabilities){
		"a role that is none":      func(caps *collector.Capabilities) { caps.Roles = append(caps.Roles, 0) },
		"a role that isn't a role": func(caps *collector.Capabilities) { caps.Roles = append(caps.Roles, 7) },
		"a type without a name": func(caps *collector.Capabilities) {
			caps.Produces = append(caps.Produces, collector.EvidenceType{Scope: collector.ScopeSpoke})
		},
		"a type produced twice": func(caps *collector.Capabilities) {
			caps.Produces = append(caps.Produces, caps.Produces[0])
		},
		"a type without a scope":      func(caps *collector.Capabilities) { caps.Produces[0].Scope = 0 },
		"a scope that isn't a scope":  func(caps *collector.Capabilities) { caps.Produces[0].Scope = 7 },
		"an operation without a name": func(caps *collector.Capabilities) { caps.Operations[0].Name = "" },
		"two operations of one name": func(caps *collector.Capabilities) {
			caps.Operations = append(caps.Operations, caps.Operations[0])
		},
		"an operation without a role": func(caps *collector.Capabilities) { caps.Operations[0].Role = 0 },
		"an operation in a role that the collector doesn't take": func(caps *collector.Capabilities) {
			caps.Operations[0].Role = collector.RoleHub
		},
		"an operation that produces a type that the collector doesn't": func(caps *collector.Capabilities) {
			caps.Operations[0].Produces = append(caps.Operations[0].Produces, typeUndeclared)
		},
		"an operation that consumes a type that the capabilities don't list": func(caps *collector.Capabilities) {
			caps.Operations[0].Consumes = append(caps.Operations[0].Consumes, typeUndeclared)
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			caps := capabilities()
			change(&caps)
			requireRefused(t, &fakeCollector{caps: caps},
				collector.Options{GRPCAddress: freeAddress(t), HealthAddress: freeAddress(t), Insecure: true})
		})
	}
}

func TestGetCapabilitiesOfACollectorThatDeclaresNothing(t *testing.T) {
	s := serve(t, plainCollector{})

	got, err := s.identityClient().GetCapabilities(callContext(t), &collectorv1alpha1.GetCapabilitiesRequest{})
	require.NoError(t, err)
	require.Truef(t, proto.Equal(&collectorv1alpha1.GetCapabilitiesResponse{}, got), "got %v", got)
}
