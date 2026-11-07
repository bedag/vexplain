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

// Command collector serves the hello collector, the template of a collector for vexplain.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bedag/vexplain/sdk/collector"
)

func main() { os.Exit(run()) }

func run() int {
	// The context ends on SIGTERM, which is how Kubernetes stops a pod. Serve then stops its servers, and returns.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// vexplain's deployer tells the collector where to listen, and where its TLS files are, in environment
	// variables, which OptionsFromEnv reads. They default to what the deployer sets: port 9443 for the collector
	// API, with mutual TLS, and port 8081 for /healthz, /readyz and /metrics.
	if err := collector.Serve(ctx, &hello{}, collector.OptionsFromEnv()); err != nil {
		slog.Error("The collector failed", "error", err)
		return 1
	}
	return 0
}
