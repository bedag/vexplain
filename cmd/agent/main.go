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

// Command agent runs vexplain's agent workers (decision 0057): each replica claims the cases of the agent's queue,
// which the manager keeps in the Assessments' status, and judges them, and the replica that holds the workers' Lease
// probes the models.
//
//	agent [--leader-elect] [--metrics-bind-address=:8443] [--health-probe-bind-address=:8081]
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/bedag/vexplain/internal/agent/worker/setup"
)

const (
	// operatorNamespaceEnv names the environment variable that holds the operator's namespace, which the Deployment
	// sets from the pod's own namespace. defaultOperatorNamespace is the namespace when it is not set.
	operatorNamespaceEnv     = "POD_NAMESPACE"
	defaultOperatorNamespace = "vexplain-system"
	// leaderElectionID names the Lease of the workers' leader, apart from the manager's. It serves the probe of the models
	// alone.
	leaderElectionID = "agent.vexplain.bedag.ch"
)

func main() {
	os.Exit(run(ctrl.SetupSignalHandler(), os.Args[1:], os.Getenv, ctrl.GetConfig))
}

// run runs the workers until ctx ends, and returns the exit code: 2 for arguments that it can't parse, and 1 for a
// failure. It takes what main takes from the process, so that a test can run it against an API server of its own.
func run(ctx context.Context, args []string, getenv func(string) string, config func() (*rest.Config, error)) int {
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	// --kubeconfig, as the manager takes it.
	ctrlconfig.RegisterFlags(flags)
	metricsAddr := flags.String("metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	probeAddr := flags.String("health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	leaderElect := flags.Bool("leader-elect", false,
		"Enable leader election, so that one replica alone probes the models. The claims need no leader.")
	secureMetrics := flags.Bool("metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	enableHTTP2 := flags.Bool("enable-http2", false, "If set, HTTP/2 will be enabled for the metrics server")
	logOptions := zap.Options{Development: true}
	logOptions.BindFlags(flags)
	if err := flags.Parse(args); err != nil {
		return 2
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&logOptions)))
	log := ctrl.Log.WithName("setup")

	opts := setup.Options{OperatorNamespace: getenv(operatorNamespaceEnv)}
	if opts.OperatorNamespace == "" {
		opts.OperatorNamespace = defaultOperatorNamespace
	}
	if *leaderElect {
		opts.LeaderElectionID = leaderElectionID
	}
	cfg, err := config()
	if err != nil {
		log.Error(err, "Failed to read the configuration of the Kubernetes API")
		return 1
	}
	scheme := runtime.NewScheme()
	if err := setup.AddToScheme(scheme); err != nil {
		log.Error(err, "Failed to build the scheme")
		return 1
	}
	// HTTP/2 stays off unless asked for: the HTTP/2 Stream Cancellation and Rapid Reset CVEs, as the manager says.
	var tlsOpts []func(*tls.Config)
	if !*enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} })
	}
	metrics := metricsserver.Options{BindAddress: *metricsAddr, SecureServing: *secureMetrics, TLSOpts: tlsOpts}
	if *secureMetrics {
		// Only who may get /metrics reads them, as with the manager: config/rbac binds the role that checks it.
		metrics.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Cache:                  setup.CacheOptions(opts.OperatorNamespace),
		Client:                 setup.ClientOptions(),
		Metrics:                metrics,
		HealthProbeBindAddress: *probeAddr,
	})
	if err != nil {
		log.Error(err, "Failed to start the workers")
		return 1
	}
	if err := setup.Register(mgr, opts); err != nil {
		log.Error(err, "Failed to register the workers")
		return 1
	}
	checks := errors.Join(mgr.AddHealthzCheck("healthz", healthz.Ping), mgr.AddReadyzCheck("readyz", healthz.Ping))
	if checks != nil {
		log.Error(checks, "Failed to set up the health checks")
		return 1
	}
	log.Info("Starting the agent workers")
	if err := mgr.Start(ctx); err != nil {
		log.Error(err, "Failed to run the workers")
		return 1
	}
	return 0
}
