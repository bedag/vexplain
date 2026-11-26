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

// Command measure-6 measures the hub's storage and load with two spokes (design of remote spokes, section 5.13), for
// the triggers of decision 0004: an object above 512 KiB, a sustained write rate above 5 per second, and inventory
// above 10% of etcd's database.
//
// It runs on three local kind clusters with a kubeconfig each, as make measure-6 sets them up: a hub, and two spokes
// whose OperatorConfigs name their clusters. hack/internal/localcluster checks each kubeconfig before the tool touches
// its cluster, and refuses one that isn't a local kind cluster's. The tool:
//
//   - adds the spokes to the hub as docs/remote-spokes.md does: a token of the hub's account on each spoke, the Secret
//     with the spoke's address, CA and token on the hub, and the Spoke;
//   - builds the load's 50 images, each the e2e's planted image installed-not-linked with a file of its own, so that
//     each has a digest of its own and that image's findings, and pushes them to the local registry;
//   - runs the load: on each spoke 100 Deployments of one replica over 30 of the images in 10 namespaces, 10 of the
//     images on both spokes (layout says how);
//   - waits until the hub has copied every image's presence, and scanned and judged every image;
//   - measures the hub's records and their bytes, fits the bytes that a workload adds to a presence record and that an
//     entry, a workload and a namespace add to an ImageInventory, and projects the counts at which the evidence store's
//     cap and 0004's 512 KiB would be reached;
//   - measures the hub's writes to etcd, idle, during a rollout of 50 workloads on the first spoke, and after a restart
//     of the hub's manager, the series of vexplain_open_case, the manager's memory, the scans and their Jobs' CPU and
//     memory, and the time to Synced after the restart.
//
// It prints the figures, and the raw numbers that they come from on lines that start with "raw". The figures are
// kind's: a measurement of a synthetic load on one machine.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/bedag/vexplain/hack/internal/localcluster"
)

// The exit codes.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// What the tool finds in the clusters, by the names of the install and of docs/remote-spokes.md.
const (
	operatorNamespace = "vexplain-system"
	// hubAccount is the ServiceAccount that a spoke's install makes for the hub.
	hubAccount = "vexplain-hub"
	// metricsReader is the ClusterRole of config/rbac that lets a token read the manager's metrics, which the tool's
	// own ServiceAccount, toolAccount, gets on the hub.
	metricsReader = "vexplain-metrics-reader"
	toolAccount   = "measure-6"
	// managerLease is the Lease of the manager's leader election, as cmd/main.go names it.
	managerLease = "779fcd0f.vexplain.bedag.ch"
	// managerLabels select the manager's pod, and scannerLabel the scan Jobs' pods.
	managerLabels = "control-plane=controller-manager"
	scannerLabel  = "vexplain.bedag.ch/scanner"
	// managerMetricsPort is where the manager serves its metrics, over HTTPS with a token, and collectorMetricsPort
	// where a collector serves them, in plain HTTP.
	managerMetricsPort   = 8443
	collectorMetricsPort = 8081
	// vulnerabilitiesCollector is the Deployment of the hub's matcher, which logs databaseLoaded once it can match.
	vulnerabilitiesCollector = "vexplain-collector-vulnerabilities"
	scannerCollector         = "vexplain-collector-scanner"
	databaseLoaded           = "Loaded the vulnerability database"
	// sheetPlaybook is the playbook of the install, whose sheets the hub writes for every manifest.
	sheetPlaybook  = "container-cves"
	inventoryGroup = "inventory.vexplain.bedag.ch"
)

// The triggers of decision 0004, and etcd's default limit of a request, which an object must fit in.
const (
	triggerBytes     = 512 * 1024
	triggerWriteRate = 5.0
	triggerEtcdShare = 0.10
	etcdRequestBytes = 1536 * 1024
)

// The load.
const (
	// loadImages are the images that the run builds, img-00 to img-49. spokeImages of them run on each spoke, and
	// sharedImages on both: img-20 to img-29.
	loadImages   = 50
	spokeImages  = 30
	sharedImages = 10
	// loadNamespaces are the namespaces of the load on each spoke, measure-6-00 to measure-6-09.
	loadNamespaces = 10
	// baseBuild is the image that every image of the load adds its file to: the e2e's planted image, Alpine with two
	// libraries, which the vulnerability database has findings for.
	baseBuild = "test/e2e/images/installed-not-linked"
	builtTag  = "measure"
	// rolloutAnnotation is the annotation of the pod template that the rollout changes.
	rolloutAnnotation = "measure-6.vexplain.bedag.ch/rollout"
	// containerName names the one container of a pod of the load.
	containerName = "load"
)

// How long the tool waits, and how often it looks.
const (
	defaultIdle    = 5 * time.Minute
	defaultTimeout = 40 * time.Minute
	// quietFor is how long the hub's writes to etcd must stand still, at most quietWrites of them, before a phase
	// counts as settled.
	quietFor    = time.Minute
	quietWrites = 2
	// writePoll is the time between two samples of the hub's writes, and lookPoll between two looks at its records.
	writePoll = 5 * time.Second
	lookPoll  = 5 * time.Second
)

const usage = `Usage: measure-6 --hub FILE --spokes FILE,FILE --registry HOST:PORT [--idle DURATION]
                 [--timeout DURATION]

  --hub       the kubeconfig of the hub's kind cluster, which runs test/e2e/config-hub
  --spokes    the kubeconfigs of the two spokes' kind clusters, which run test/e2e/config-spoke with OperatorConfigs
              that name their clusters
  --registry  the local registry that the load's images are pushed to, and that the clusters pull from, such as
              localhost:5001. It must be on a loopback address.
  --idle      how long the hub's idle writes are counted (default 5m)
  --timeout   how long each phase may take to settle (default 40m)

Each kubeconfig must be a local kind cluster's own, whose current context's name starts with kind-, whose API server
is on a loopback address and which sets no proxy-url: the tool refuses any other. make measure-6 sets the clusters up,
runs the tool and removes the clusters. The tool needs docker, to build the load's base image and to read the hub
node's cgroups, kind, for the spokes' addresses on the kind network, and kubectl, to reach the manager's metrics.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout)
	stop() // os.Exit doesn't run deferred calls.
	os.Exit(code)
}

// run is the tool. It returns the exit code.
func run(ctx context.Context, args []string, out io.Writer) int {
	opts, err := parseArguments(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		say(out, "%s", usage)
		return exitOK
	case err != nil:
		say(out, "measure-6: %v\n\n%s", err, usage)
		return exitUsage
	}
	if !localcluster.IsLoopback(opts.registry) {
		say(out, "measure-6: the registry is not on a loopback address, and the tool pushes only to a local one\n")
		return exitUsage
	}
	m, err := connectAll(opts, out)
	if err != nil {
		say(out, "measure-6: %v\n", err)
		return exitFailure
	}
	if err = m.measure(ctx); err != nil {
		say(out, "measure-6: %v\n", err)
		return exitFailure
	}
	return exitOK
}

// say prints to out. The tool can do nothing about a terminal that it can't write to.
func say(out io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(out, format, args...)
}

// arguments are what the command line says.
type arguments struct {
	hub, registry string
	spokes        []string
	idle, timeout time.Duration
}

// parseArguments reads the flags. Its errors are for the person who ran the tool.
func parseArguments(args []string) (arguments, error) {
	flags := flag.NewFlagSet("measure-6", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // run prints the error and the usage.
	hub := flags.String("hub", "", "")
	spokes := flags.String("spokes", "", "")
	registry := flags.String("registry", "", "")
	idle := flags.Duration("idle", defaultIdle, "")
	timeout := flags.Duration("timeout", defaultTimeout, "")
	if err := flags.Parse(args); err != nil {
		return arguments{}, err
	}
	opts := arguments{hub: *hub, registry: *registry, idle: *idle, timeout: *timeout}
	if *spokes != "" {
		opts.spokes = strings.Split(*spokes, ",")
	}
	switch {
	case flags.NArg() > 0:
		return arguments{}, errors.New("unexpected arguments")
	case opts.hub == "":
		return arguments{}, errors.New("--hub is required")
	case len(opts.spokes) != 2 || slices.Contains(opts.spokes, ""):
		return arguments{}, errors.New("--spokes must name two kubeconfigs, separated by a comma")
	case opts.registry == "":
		return arguments{}, errors.New("--registry is required")
	case opts.idle <= 0 || opts.timeout <= 0:
		return arguments{}, errors.New("--idle and --timeout must be longer than zero")
	}
	return opts, nil
}
