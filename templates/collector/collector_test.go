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
	"encoding/json"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/conformance"
)

// TestConformance runs the conformance suite of the SDK against the collector. Every collector passes it, in its
// own repository and in CI, before vexplain runs it. The suite checks what the collector API asks of a collector:
// what it says about itself, how it streams its snapshot, and what its evidence looks like.
func TestConformance(t *testing.T) {
	conformance.Run(t, conformance.Target{
		Dial: serve(t, &hello{}),
		// Settings are valid settings, which the suite sends with every call. InvalidSettings are settings that
		// the collector must refuse: the suite then checks that the schema, or ValidateSettings, finds a problem.
		Settings:        json.RawMessage(`{"greeting": "Hello", "workload": "web"}`),
		InvalidSettings: json.RawMessage(`{"workload": "web/prod"}`),
		// Context is what vexplain tells the collector about its cluster, in every Watch and Invoke.
		Context: collector.Context{Cluster: "cluster-a"},
	})
}

// serve runs the collector in this process until the test ends, without TLS and on a listener that only this test
// reaches, and returns the Dial that connects the suite to it.
func serve(t *testing.T, c collector.Collector) func(ctx context.Context) (*grpc.ClientConn, error) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	health, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- collector.Serve(ctx, c, collector.Options{Insecure: true, GRPCListener: listener, HealthListener: health})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned an error after its context ended: %v", err)
		}
	})
	return func(context.Context) (*grpc.ClientConn, error) {
		return grpc.NewClient("passthrough:///bufconn",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
}
