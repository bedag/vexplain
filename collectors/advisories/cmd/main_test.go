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

// The settings come from the Collector, so the binary takes no arguments, and it serves until its context ends.
func TestRunServesUntilItsContextEnds(t *testing.T) {
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	t.Cleanup(func() { slog.SetDefault(previous) })
	none := func(string) string { return "" }

	require.Equal(t, 2, run(t.Context(), []string{"--allow", "any.example"}, none, collector.Options{}))

	health, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, nil, none, collector.Options{Insecure: true, GRPCListener: bufconn.Listen(1 << 10),
			HealthListener: health})
	}()
	cancel()
	select {
	case code := <-done:
		require.Zero(t, code)
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the collector didn't stop with its context")
	}
}
