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

// Command advisories is vexplain's advisories collector: on the hub, it fetches the advisory pages that the agent
// reads, from the hosts on its allowlist only, and turns them into text.
//
//	advisories
//
// It takes no arguments: vexplain's deployer tells it where to listen and where its TLS files are, in environment
// variables, and a Collector's spec.settings, which every request carries, name the allowed hosts and the limits. It
// reaches the hosts through the proxy that its runtime config sets in HTTPS_PROXY, if it sets one.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bedag/vexplain/collectors/advisories/internal/fetch"
	"github.com/bedag/vexplain/sdk/collector"
)

// version is the version of the collector, which GetInfo reports. The build sets it.
var version = "0.1.0"

const (
	// nameVariable holds the name of the collector's Collector, which vexplain's deployer sets, and which the
	// source of the collector's events names.
	nameVariable = "VEXPLAIN_COLLECTOR_NAME"
	// defaultName is the name of the built-in Collector, when the variable says none.
	defaultName = "advisories"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, collector.OptionsFromEnv())
	stop() // os.Exit doesn't run deferred calls.
	os.Exit(code)
}

// run serves the collector until ctx ends, and returns the exit code. It takes what main takes from the process, so
// that a test can serve it.
func run(ctx context.Context, args []string, getenv func(string) string, opts collector.Options) int {
	if len(args) > 0 {
		slog.Error("the advisories collector takes no arguments: its settings come from its Collector")
		return 2
	}
	name := getenv(nameVariable)
	if name == "" {
		name = defaultName
	}
	if err := collector.Serve(ctx, fetch.New(fetch.Options{Name: name, Version: version}), opts); err != nil {
		slog.Error("The collector failed", "error", err)
		return 1
	}
	return 0
}
