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
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
)

const scheduleRefresh = "refresh"

// scheduledCollector declares schedules, and fires them with fire. It also reports its sources.
type scheduledCollector struct {
	caps    collector.Capabilities
	fire    func(ctx context.Context, req collector.FireRequest) error
	sources []collector.Source
}

func (s *scheduledCollector) Info() collector.Info {
	return collector.Info{Name: collectorName, Version: collectorVersion}
}

func (s *scheduledCollector) Capabilities() collector.Capabilities { return s.caps }

func (s *scheduledCollector) Fire(ctx context.Context, req collector.FireRequest) error {
	if s.fire == nil {
		return nil
	}
	return s.fire(ctx, req)
}

func (s *scheduledCollector) Sources() []collector.Source { return s.sources }

func scheduledCaps() collector.Capabilities {
	return collector.Capabilities{
		Schedules:      []collector.Schedule{{Name: scheduleRefresh, Cron: "0 */6 * * *"}},
		SettingsSchema: []byte(settingsSchema),
	}
}

// requireCapabilitiesRefused checks that Serve refuses a collector with caps, which has a Firer.
func requireCapabilitiesRefused(t *testing.T, caps collector.Capabilities) {
	t.Helper()
	requireRefused(t, &scheduledCollector{caps: caps},
		collector.Options{GRPCAddress: freeAddress(t), HealthAddress: freeAddress(t), Insecure: true})
}

func TestServeRefusesSchedulesThatContradictThemselves(t *testing.T) {
	tests := map[string]func(caps *collector.Capabilities){
		"a schedule without a name": func(caps *collector.Capabilities) { caps.Schedules[0].Name = "" },
		"a schedule without a cron": func(caps *collector.Capabilities) { caps.Schedules[0].Cron = "" },
		"two schedules of one name": func(caps *collector.Capabilities) {
			caps.Schedules = append(caps.Schedules, caps.Schedules[0])
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			caps := scheduledCaps()
			change(&caps)
			requireCapabilitiesRefused(t, caps)
		})
	}
}

func TestServeRefusesAMismatchOfSchedulesAndFirer(t *testing.T) {
	tests := map[string]collector.Collector{
		"schedules without a Fire": plainCollector{caps: scheduledCaps()},
		"a Fire without schedules": &scheduledCollector{},
	}
	for name, c := range tests {
		t.Run(name, func(t *testing.T) {
			requireRefused(t, c,
				collector.Options{GRPCAddress: freeAddress(t), HealthAddress: freeAddress(t), Insecure: true})
		})
	}
}

func TestGetCapabilitiesListsTheSchedules(t *testing.T) {
	s := serve(t, &scheduledCollector{caps: scheduledCaps()})

	got, err := s.identityClient().GetCapabilities(callContext(t), &collectorv1alpha1.GetCapabilitiesRequest{})
	require.NoError(t, err)
	want := []*collectorv1alpha1.Schedule{{Name: scheduleRefresh, Cron: "0 */6 * * *"}}
	require.Len(t, got.GetSchedules(), 1)
	require.Truef(t, proto.Equal(want[0], got.GetSchedules()[0]), "got %v", got.GetSchedules())
}

func TestGetInfoReportsTheSources(t *testing.T) {
	built := time.Date(2026, 11, 8, 3, 0, 0, 0, time.UTC)
	s := serve(t, &scheduledCollector{
		caps: scheduledCaps(),
		sources: []collector.Source{
			{Name: "vulnerability-db", Version: "v7", BuiltTime: built}, {Name: "other", Version: "1"},
		},
	})

	info, err := s.identityClient().GetInfo(callContext(t), &collectorv1alpha1.GetInfoRequest{})
	require.NoError(t, err)
	want := []*collectorv1alpha1.Source{
		{Name: "vulnerability-db", Version: "v7", BuiltTime: timestamppb.New(built)},
		{Name: "other", Version: "1"},
	}
	require.Len(t, info.GetSources(), len(want))
	for i := range want {
		require.Truef(t, proto.Equal(want[i], info.GetSources()[i]), "source %d: got %v", i, info.GetSources()[i])
	}
}

func TestGetInfoReportsNoSourcesWithoutASourcer(t *testing.T) {
	s := serve(t, plainCollector{})

	info, err := s.identityClient().GetInfo(callContext(t), &collectorv1alpha1.GetInfoRequest{})
	require.NoError(t, err)
	require.Empty(t, info.GetSources())
}

func fireRequest(schedule string) *collectorv1alpha1.FireRequest {
	return &collectorv1alpha1.FireRequest{Schedule: schedule, Settings: []byte(validSettings), Context: protoContext()}
}

func TestFireRunsTheSchedule(t *testing.T) {
	var got collector.FireRequest
	s := serve(t, &scheduledCollector{
		caps: scheduledCaps(),
		fire: func(_ context.Context, req collector.FireRequest) error {
			got = req
			return nil
		},
	})

	_, err := s.evidenceClient().Fire(callContext(t), fireRequest(scheduleRefresh))
	require.NoError(t, err)
	require.Equal(t, scheduleRefresh, got.Schedule)
	require.JSONEq(t, validSettings, string(got.Settings))
	require.Equal(t, clusterA, got.Context.Cluster)
	require.Equal(t, "vexplain-system", got.Context.OperatorNamespace)
}

func TestFireRefusesAnUnknownScheduleBeforeTheFirer(t *testing.T) {
	fired := false
	s := serve(t, &scheduledCollector{
		caps: scheduledCaps(),
		fire: func(context.Context, collector.FireRequest) error {
			fired = true
			return nil
		},
	})

	_, err := s.evidenceClient().Fire(callContext(t), fireRequest("unknown"))
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.False(t, fired)
}

func TestFireChecksTheSettings(t *testing.T) {
	s := serve(t, &scheduledCollector{caps: scheduledCaps()})

	req := fireRequest(scheduleRefresh)
	req.Settings = json.RawMessage(`{"greeting": 7}`)
	_, err := s.evidenceClient().Fire(callContext(t), req)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestFireReturnsTheFirersError(t *testing.T) {
	s := serve(t, &scheduledCollector{
		caps: scheduledCaps(),
		fire: func(context.Context, collector.FireRequest) error {
			return status.Error(codes.FailedPrecondition, "not now")
		},
	})

	_, err := s.evidenceClient().Fire(callContext(t), fireRequest(scheduleRefresh))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}
