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
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector"
)

const (
	workloads = configv1alpha1.CollectorTypeWorkloads
	// other is a type that no CRD accepts yet. The registry keys on the type and doesn't check it.
	other = configv1alpha1.CollectorType("Other")
)

func TestHealthOfATypeThatNeverReportedIsUnknown(t *testing.T) {
	registry := collector.NewRegistry()

	lastSuccess, lastErr, known := registry.Health(workloads)

	require.False(t, known)
	require.True(t, lastSuccess.IsZero())
	require.NoError(t, lastErr)
}

func TestReportSuccessRecordsTheTime(t *testing.T) {
	registry := collector.NewRegistry()

	before := time.Now()
	registry.ReportSuccess(workloads)
	after := time.Now()

	lastSuccess, lastErr, known := registry.Health(workloads)
	require.True(t, known)
	require.NoError(t, lastErr)
	require.False(t, lastSuccess.Before(before), "the time of the success is not before the report")
	require.False(t, lastSuccess.After(after), "the time of the success is not after the report")
}

func TestReportFailureThenSuccessLeavesNoError(t *testing.T) {
	registry := collector.NewRegistry()

	registry.ReportFailure(workloads, errors.New("pods cannot be listed"))
	registry.ReportSuccess(workloads)

	lastSuccess, lastErr, known := registry.Health(workloads)
	require.True(t, known)
	require.NoError(t, lastErr)
	require.False(t, lastSuccess.IsZero())
}

func TestReportFailureAloneIsKnownAndHasNoSuccessTime(t *testing.T) {
	registry := collector.NewRegistry()
	failure := errors.New("pods cannot be listed")

	registry.ReportFailure(workloads, failure)

	lastSuccess, lastErr, known := registry.Health(workloads)
	require.True(t, known)
	require.ErrorIs(t, lastErr, failure)
	require.True(t, lastSuccess.IsZero())
}

func TestReportFailureKeepsTheTimeOfTheLastSuccess(t *testing.T) {
	registry := collector.NewRegistry()
	failure := errors.New("pods cannot be listed")
	registry.ReportSuccess(workloads)
	succeededAt, _, _ := registry.Health(workloads)

	registry.ReportFailure(workloads, failure)

	lastSuccess, lastErr, known := registry.Health(workloads)
	require.True(t, known)
	require.ErrorIs(t, lastErr, failure)
	require.True(t, lastSuccess.Equal(succeededAt), "a failure doesn't change the time of the last success")
}

func TestReportFailureWithoutAnErrorStillFails(t *testing.T) {
	registry := collector.NewRegistry()

	registry.ReportFailure(workloads, nil)

	_, lastErr, known := registry.Health(workloads)
	require.True(t, known)
	require.Error(t, lastErr, "a failure with no error must not read as healthy")
}

func TestTypesReportIndependently(t *testing.T) {
	registry := collector.NewRegistry()
	failure := errors.New("pods cannot be listed")

	registry.ReportFailure(workloads, failure)
	registry.ReportSuccess(other)

	_, workloadsErr, workloadsKnown := registry.Health(workloads)
	require.True(t, workloadsKnown)
	require.ErrorIs(t, workloadsErr, failure)
	_, otherErr, otherKnown := registry.Health(other)
	require.True(t, otherKnown)
	require.NoError(t, otherErr)
}

// TestConcurrentUse is meant to run under -race: reconcilers report while the Collector controller
// reads.
func TestConcurrentUse(t *testing.T) {
	registry := collector.NewRegistry()
	failure := errors.New("pods cannot be listed")

	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for step := range 200 {
				switch (worker + step) % 3 {
				case 0:
					registry.ReportSuccess(workloads)
				case 1:
					registry.ReportFailure(workloads, failure)
				default:
					lastSuccess, lastErr, known := registry.Health(workloads)
					if known && lastErr == nil && lastSuccess.IsZero() {
						t.Error("a type that has reported has neither a success time nor an error")
					}
				}
			}
		})
	}
	wg.Wait()

	_, _, known := registry.Health(workloads)
	require.True(t, known)
}
