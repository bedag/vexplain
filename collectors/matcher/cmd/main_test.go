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

package main

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/test/bufconn"

	"github.com/bedag/vexplain/sdk/collector"
)

func quietLogs(t *testing.T) {
	t.Helper()
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	t.Cleanup(func() { slog.SetDefault(previous) })
}

// The collector is named for its Collector, which vexplain's deployer says in the environment, and else it is the
// built-in one.
func TestTheCollectorIsNamedForItsCollector(t *testing.T) {
	require.Equal(t, "matcher", newMatcher(func(string) string { return "" }).Info().Name)
	require.Equal(t, "matcher-b", newMatcher(func(name string) string {
		if name == nameVariable {
			return "matcher-b"
		}
		return ""
	}).Info().Name)
	require.Equal(t, version, newMatcher(func(string) string { return "" }).Info().Version)
}

// The settings come from the Collector, so the binary takes no arguments: the flags of phase 2a's matcher are gone.
func TestTheMatcherTakesNoArguments(t *testing.T) {
	quietLogs(t)

	code := run(t.Context(), []string{"--listen", ":8080"}, func(string) string { return "" }, collector.Options{})

	require.Equal(t, exitUsage, code)
}

// run serves the collector until its context ends, and then returns success.
func TestRunServesUntilItsContextEnds(t *testing.T) {
	quietLogs(t)
	health, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, nil, func(string) string { return "" },
			collector.Options{Insecure: true, GRPCListener: bufconn.Listen(1 << 10), HealthListener: health})
	}()

	cancel()

	select {
	case code := <-done:
		require.Zero(t, code)
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the collector didn't stop with its context")
	}
}

// A collector that can't listen fails, with the code that tells the kubelet to restart it.
func TestRunFailsWhenTheCollectorCannotListen(t *testing.T) {
	quietLogs(t)
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()

	code := run(t.Context(), nil, func(string) string { return "" },
		collector.Options{Insecure: true, GRPCAddress: taken.Addr().String(), HealthAddress: taken.Addr().String()})

	require.Equal(t, exitFailed, code)
}
