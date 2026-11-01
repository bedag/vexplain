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

func TestGetCapabilitiesOfACollectorThatDeclaresNothing(t *testing.T) {
	s := serve(t, plainCollector{})

	got, err := s.identityClient().GetCapabilities(callContext(t), &collectorv1alpha1.GetCapabilitiesRequest{})
	require.NoError(t, err)
	require.Truef(t, proto.Equal(&collectorv1alpha1.GetCapabilitiesResponse{}, got), "got %v", got)
}
