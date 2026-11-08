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

// Command vulnerabilities is vexplain's vulnerabilities collector: the hub's one vulnerability database, which turns
// the SBOM of a manifest into findings. It runs the Grype CLI on the SBOM's document, or on a document of Syft's JSON
// that it makes of the SBOM's packages when there is none, and keeps the database that Grype matches against current.
//
//	vulnerabilities
//
// It takes no arguments: vexplain's deployer tells it where to listen and where its TLS files are, in environment
// variables, and a Collector's spec.settings, which every Watch and every match carries, say how often the database is
// updated, whether it is updated at all, how many matches run at once, and a database to start from. Its /db and /tmp
// volumes come from the Collector's runtime config.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/logr"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/bedag/vexplain/collectors/vulnerabilities/internal/grype"
	"github.com/bedag/vexplain/collectors/vulnerabilities/internal/match"
	"github.com/bedag/vexplain/sdk/collector"
)

// version is the version of the collector, which GetInfo reports. The build sets it.
var version = "0.1.0"

const (
	// nameVariable holds the name of the collector's Collector, which vexplain's deployer sets, and which the
	// source of the collector's events names.
	nameVariable = "VEXPLAIN_COLLECTOR_NAME"
	// defaultName is the name of the built-in Collector, when the variable says none.
	defaultName = "vulnerabilities"
	// grypeBinary is where the image holds Grype, and databaseDir where its database lives: the runtime config
	// mounts a volume there.
	grypeBinary = "/usr/local/bin/grype"
	databaseDir = "/db"
	// exitFailed and exitUsage are the exit codes of a collector that failed, and of one that got arguments.
	exitFailed = 1
	exitUsage  = 2
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
	// Grype's wrapper logs through controller-runtime's logger, and the SDK's server through slog: both go to slog.
	ctrllog.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))
	if len(args) > 0 {
		slog.Error("the vulnerabilities collector takes no arguments: its settings come from its Collector")
		return exitUsage
	}
	// Grype stops with the context, and the Watch with it. The context carries the logger that the wrapper writes its
	// debug lines to.
	if err := collector.Serve(ctx, newCollector(getenv), opts); err != nil {
		slog.Error("The collector failed", "error", err)
		return exitFailed
	}
	return 0
}

// newCollector returns the collector, under the name of its Collector.
func newCollector(getenv func(string) string) *match.Collector {
	name := getenv(nameVariable)
	if name == "" {
		name = defaultName
	}
	return match.New(match.Options{
		Name:    name,
		Version: version,
		Grype:   grype.NewGrype(grypeBinary, databaseDir),
		DBDir:   databaseDir,
	})
}
