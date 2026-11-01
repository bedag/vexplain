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

package collectorv1alpha1_test

import (
	"testing"

	"github.com/cloudevents/sdk-go/binding/format/protobuf/v2/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// The names are the contract with every collector: they are on the wire, in the gRPC method paths.
func TestServices(t *testing.T) {
	tests := []struct {
		service string
		// methods maps each method's name to whether the server streams its answer. No method of
		// the API streams from the client.
		methods map[string]bool
	}{
		{
			service: "vexplain.collector.v1alpha1.Identity",
			methods: map[string]bool{"GetInfo": false, "GetCapabilities": false, "ValidateSettings": false},
		},
		{
			service: "vexplain.collector.v1alpha1.Evidence",
			methods: map[string]bool{"Watch": true, "Invoke": true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.service, func(t *testing.T) {
			d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(tc.service))
			require.NoError(t, err)
			service, ok := d.(protoreflect.ServiceDescriptor)
			require.True(t, ok)
			require.Equal(t, len(tc.methods), service.Methods().Len())
			for name, streams := range tc.methods {
				method := service.Methods().ByName(protoreflect.Name(name))
				require.NotNil(t, method, name)
				require.False(t, method.IsStreamingClient(), name)
				require.Equal(t, streams, method.IsStreamingServer(), name)
			}
		})
	}

	require.Equal(t, "/vexplain.collector.v1alpha1.Identity/GetInfo", collectorv1alpha1.Identity_GetInfo_FullMethodName)
	require.Equal(t, "/vexplain.collector.v1alpha1.Identity/GetCapabilities",
		collectorv1alpha1.Identity_GetCapabilities_FullMethodName)
	require.Equal(t, "/vexplain.collector.v1alpha1.Identity/ValidateSettings",
		collectorv1alpha1.Identity_ValidateSettings_FullMethodName)
	require.Equal(t, "/vexplain.collector.v1alpha1.Evidence/Watch", collectorv1alpha1.Evidence_Watch_FullMethodName)
	require.Equal(t, "/vexplain.collector.v1alpha1.Evidence/Invoke", collectorv1alpha1.Evidence_Invoke_FullMethodName)
}

func TestEnums(t *testing.T) {
	require.Equal(t, int32(0), int32(collectorv1alpha1.Role_ROLE_UNSPECIFIED))
	require.Equal(t, int32(1), int32(collectorv1alpha1.Role_ROLE_SPOKE))
	require.Equal(t, int32(2), int32(collectorv1alpha1.Role_ROLE_HUB))
	require.Equal(t, int32(0), int32(collectorv1alpha1.Scope_SCOPE_UNSPECIFIED))
	require.Equal(t, int32(1), int32(collectorv1alpha1.Scope_SCOPE_SPOKE))
	require.Equal(t, int32(2), int32(collectorv1alpha1.Scope_SCOPE_HUB))
}

// The items of the two streams have different numbers for the same name, event, which is easy to
// mix up and wouldn't show until a collector in another language sent its first event.
func TestStreamItems(t *testing.T) {
	tests := []struct {
		message proto.Message
		items   map[string]protoreflect.FieldNumber
	}{
		{
			message: &collectorv1alpha1.WatchResponse{},
			items: map[string]protoreflect.FieldNumber{
				"snapshot_start": 1, "event": 2, "tombstone": 3, "snapshot_end": 4, "source_changed": 5,
			},
		},
		{
			message: &collectorv1alpha1.InvokeResponse{},
			items:   map[string]protoreflect.FieldNumber{"event": 1, "failure": 2},
		},
	}
	for _, tc := range tests {
		descriptor := tc.message.ProtoReflect().Descriptor()
		t.Run(string(descriptor.Name()), func(t *testing.T) {
			require.Equal(t, len(tc.items), descriptor.Fields().Len())
			for name, number := range tc.items {
				field := descriptor.Fields().ByName(protoreflect.Name(name))
				require.NotNil(t, field, name)
				require.Equal(t, number, field.Number(), name)
				require.NotNil(t, field.ContainingOneof(), "%s is one of the items", name)
			}
		})
	}
}

// The API's events are the CloudEvents SDK's own type, and the API doesn't carry a copy of its
// message: a second registration of io.cloudevents.v1.CloudEvent would panic when the package loads.
func TestEventsAreTheCloudEventsSDKType(t *testing.T) {
	fields := (&collectorv1alpha1.WatchResponse{}).ProtoReflect().Descriptor().Fields()
	require.Equal(t, protoreflect.FullName("io.cloudevents.v1.CloudEvent"),
		fields.ByName("event").Message().FullName())

	messageType, err := protoregistry.GlobalTypes.FindMessageByName("io.cloudevents.v1.CloudEvent")
	require.NoError(t, err)
	require.IsType(t, &pb.CloudEvent{}, messageType.New().Interface())
}

func TestEventsCrossTheWire(t *testing.T) {
	e, err := evidence.New(evidence.TypePresence, subject.Image(digest), samplePresence(),
		evidence.WithSource("/clusters/cluster-a/collectors/workloads"))
	require.NoError(t, err)
	p, err := evidence.ToProto(e)
	require.NoError(t, err)

	t.Run("in a Watch stream", func(t *testing.T) {
		wire, err := proto.Marshal(&collectorv1alpha1.WatchResponse{
			Item: &collectorv1alpha1.WatchResponse_Event{Event: p},
		})
		require.NoError(t, err)

		var received collectorv1alpha1.WatchResponse
		require.NoError(t, proto.Unmarshal(wire, &received))
		got, err := evidence.FromProto(received.GetEvent())
		require.NoError(t, err)
		require.Equal(t, e, got)
		require.NoError(t, evidence.Validate(got))
	})

	t.Run("as the result of an Invoke, and as an input to one", func(t *testing.T) {
		wire, err := proto.Marshal(&collectorv1alpha1.InvokeResponse{
			Item: &collectorv1alpha1.InvokeResponse_Event{Event: p},
		})
		require.NoError(t, err)
		var received collectorv1alpha1.InvokeResponse
		require.NoError(t, proto.Unmarshal(wire, &received))
		got, err := evidence.FromProto(received.GetEvent())
		require.NoError(t, err)
		require.Equal(t, e, got)

		wire, err = proto.Marshal(&collectorv1alpha1.InvokeRequest{
			Operation: "match",
			Subject:   subject.Manifest(digest),
			Inputs:    []*pb.CloudEvent{p},
			Role:      collectorv1alpha1.Role_ROLE_HUB,
		})
		require.NoError(t, err)
		var request collectorv1alpha1.InvokeRequest
		require.NoError(t, proto.Unmarshal(wire, &request))
		require.Len(t, request.GetInputs(), 1)
		got, err = evidence.FromProto(request.GetInputs()[0])
		require.NoError(t, err)
		require.Equal(t, e, got)
	})
}

func samplePresence() evidence.Presence {
	return evidence.Presence{
		DigestKind: "RepoDigest",
		Workloads: []evidence.PresenceWorkload{{
			APIGroup:  "apps",
			Kind:      "Deployment",
			Namespace: "team-a",
			Name:      "web",
			UID:       "6f9619ff-8b86-4011-b42d-00c04fc964ff",
		}},
	}
}
