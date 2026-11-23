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

// Package setup wires the agent workers into a manager, as cmd/agent runs them (decision 0057): their scheme, cache
// and client, the claim loop, and the ModelConfig controller under an election of its own. It imports none of the
// manager's controllers, so that the workers' binary holds their own code alone, and the manager's none of theirs.
package setup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/leaderelection"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/models"
	"github.com/bedag/vexplain/internal/agent/worker"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/collectorclient"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/settings"
)

// eventSource is the name that the workers' events carry as their reporting controller, as the manager's do.
const eventSource = "vexplain"

var (
	schemeBuilder = runtime.NewSchemeBuilder(
		clientgoscheme.AddToScheme,
		configv1alpha1.AddToScheme,
		inventoryv1alpha1.AddToScheme,
		triagev1alpha1.AddToScheme,
	)
	// AddToScheme adds every API that the workers use to a scheme: the built-in kinds and the operator's own groups,
	// as the manager's scheme holds them.
	AddToScheme = schemeBuilder.AddToScheme
)

// Options configures Register.
type Options struct {
	// OperatorNamespace is the namespace the operator runs in, which holds the Secrets that the workers read. It must
	// not be empty, and it must be the namespace that the cache was given with CacheOptions.
	OperatorNamespace string
	// CollectorDialer opens the collector pool's connections to the collectors' Services. Nil means TCP. A test passes
	// its own, to reach the collectors that it serves in its process.
	CollectorDialer func(ctx context.Context, address string) (net.Conn, error)
	// ModelConfigClock is the ModelConfig controller's clock, which ends the grace within which an unreachable
	// endpoint leaves the ModelConfig Reconciling rather than Stalled. Nil means time.Now. A test passes its own, to
	// move past the grace.
	ModelConfigClock func() time.Time
	// HTTPClient is the HTTP client of the probes of the ModelConfig controller, of the agent's requests to the model,
	// and of the requests to the MCP collectors' servers. Nil means the default client of the llm package, and
	// http.DefaultTransport for the MCP servers, which honour HTTPS_PROXY and NO_PROXY. A test passes the client of its
	// TLS test server.
	HTTPClient *http.Client
	// LeaderElectionID names the Lease, in OperatorNamespace, through which the workers elect the replica that runs the
	// ModelConfig controller. Empty runs the controller on this replica without an election, as a test or a local run
	// does. The manager of the workers must not elect a leader itself: its leader would stop the worker on losing the
	// Lease, its judgements with it.
	LeaderElectionID string
}

// CacheOptions returns the options of the agent workers' cache. Its cache of Secrets holds
// only the Secrets of operatorNamespace that carry the label vexplain.bedag.ch/llm-api-key=true,
// the keys of the ModelConfigs, which the workers alone read: the MCP collectors' headers are read
// through the API reader, by their label, and the workers' client certificate from a cache of its
// own (Register). It never loads any other Secret, so their values stay out of the workers'
// memory. It holds the ConfigMaps of operatorNamespace only, where an AgentProfile's guidance must
// be.
//
// operatorNamespace must not be empty: Register refuses an empty one.
func CacheOptions(operatorNamespace string) cache.Options {
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {
				Namespaces: map[string]cache.Config{operatorNamespace: {}},
				Label:      labels.SelectorFromSet(labels.Set{configv1alpha1.LLMAPIKeyLabel: "true"}),
			},
			&corev1.ConfigMap{}: {Namespaces: map[string]cache.Config{operatorNamespace: {}}},
		},
	}
}

// ClientOptions returns the options of the workers' client. It reads Evidence, ImageVerdicts and Ledgers from the API
// server, and never through the cache, as the manager's client does: each is up to about 1 MiB, and a cache would hold
// every one of them in memory for as long as the workers run.
func ClientOptions() client.Options {
	return client.Options{
		Cache: &client.CacheOptions{
			DisableFor: []client.Object{&inventoryv1alpha1.Evidence{}, &inventoryv1alpha1.ImageVerdicts{},
				&inventoryv1alpha1.Ledger{}},
		},
	}
}

// Register sets up the agent workers, which cmd/agent runs in a Deployment of their own (decision 0057): the
// claim loop on every replica, which claims the cases of the queue in the Assessments' status and judges them, and the
// ModelConfig controller, which probes the models, on the replica that holds the Lease of opts.LeaderElectionID only.
// Losing that Lease stops the probes, and not the claim loop. A judge calls the collectors through a pool
// that presents the workers' client certificate, which the manager issues into the Secret vexplain-agent-client-tls.
// A cache of its own holds that Secret: the workers' cache selects its Secrets by the label of the LLM keys
// (CacheOptions), and one cache selects the objects of a kind by one label.
//
// It checks opts before it uses the manager.
func Register(mgr ctrl.Manager, opts Options) error {
	if opts.OperatorNamespace == "" {
		// To a cache, "" means every namespace, so the Secrets would come from the whole cluster.
		return errors.New("the operator namespace is empty")
	}
	modelConfigs := &models.ModelConfigReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		OperatorNamespace: opts.OperatorNamespace,
		Recorder:          mgr.GetEventRecorder(eventSource),
		HTTPClient:        opts.HTTPClient,
		Now:               opts.ModelConfigClock,
	}
	controllerOptions := controller.Options{Logger: mgr.GetLogger()}
	controllerOptions.DefaultFromConfig(mgr.GetControllerOptions())
	run := &probes{log: mgr.GetLogger().WithName("probes"), build: func() (controller.Controller, error) {
		return modelConfigs.NewController(mgr.GetCache(), controllerOptions)
	}}
	if opts.LeaderElectionID != "" {
		lock, err := leaderelection.NewResourceLock(mgr.GetConfig(), mgr, leaderelection.Options{LeaderElection: true,
			LeaderElectionID: opts.LeaderElectionID, LeaderElectionNamespace: opts.OperatorNamespace,
			RenewDeadline: renewDeadline})
		if err != nil {
			return fmt.Errorf("make the lock of the workers' leader: %w", err)
		}
		run.lock = lock
	}
	if err := mgr.Add(run); err != nil {
		return fmt.Errorf("add the ModelConfig controller: %w", err)
	}
	// A worker rebuilds a case from where its image runs, which the inventory store finds through this index.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &inventoryv1alpha1.ImageInventory{},
		inventory.ManifestDigestIndex, inventory.IndexManifestDigests); err != nil {
		return fmt.Errorf("index the ImageInventory objects by the manifest digests of their facts: %w", err)
	}
	certificate, err := cache.New(mgr.GetConfig(), cache.Options{HTTPClient: mgr.GetHTTPClient(),
		Scheme: mgr.GetScheme(), Mapper: mgr.GetRESTMapper(), ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {Namespaces: map[string]cache.Config{opts.OperatorNamespace: {}},
				Field: fields.OneTermEqualSelector("metadata.name", certs.AgentClientSecretName)},
		}})
	if err != nil {
		return fmt.Errorf("make the cache of the workers' client certificate: %w", err)
	}
	if err := mgr.Add(everyReplica{certificate}); err != nil {
		return fmt.Errorf("add the cache of the workers' client certificate: %w", err)
	}
	pool := collectorclient.NewPool(certs.SecretClientTLS(certificate, opts.OperatorNamespace), opts.OperatorNamespace)
	if opts.CollectorDialer != nil {
		pool.Dialer = opts.CollectorDialer
	}
	clusterName := clusterNameOf(mgr)
	verdicts := inventory.NewCRDVerdictsStore(mgr.GetClient(), clusterName)
	agent := &worker.Agent{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), OperatorNamespace: opts.OperatorNamespace,
		Verdicts: verdicts,
		// The workers read and write the evidence through the API server, and watch none of it.
		Evidence: evidence.NewCRDStore(mgr.GetClient(), nil, clusterName,
			evidence.WithMaxCompressedBytes(evidenceCapOf(mgr))),
		Ledgers: inventory.NewCRDLedgerStore(mgr.GetClient()), Pool: pool,
		// The Secrets of the MCP collectors' headers are listed through the API reader, by their label, since the
		// workers' cache doesn't hold them.
		MCP: &collectorclient.MCPPool{Reader: mgr.GetClient(), Secrets: mgr.GetAPIReader(),
			Namespace: opts.OperatorNamespace, HTTPClient: opts.HTTPClient},
		ClusterContext: collectorclient.ClusterContext(mgr.GetClient(), opts.OperatorNamespace),
		ClientConfig:   modelConfigs.ClientConfig, HTTPClient: opts.HTTPClient, Recorder: mgr.GetEventRecorder(eventSource),
	}
	name, err := worker.Name()
	if err != nil {
		return err
	}
	if err := mgr.Add(&worker.Loop{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Verdicts: verdicts,
		Store: inventory.NewCRDStore(mgr.GetClient(), mgr.GetCache(), clusterName), Name: name, Limit: agent.Workers,
		CanStart: agent.CanStart, Judge: agent.Judge}); err != nil {
		return fmt.Errorf("add the agent's claim loop: %w", err)
	}
	return nil
}

// everyReplica is a runnable that the manager starts on every replica, and not on its leader only: a cache, which every
// replica reads.
type everyReplica struct{ manager.Runnable }

func (everyReplica) NeedLeaderElection() bool { return false }

// clusterNameOf returns the function through which the stores read the name of this cluster, the
// label of their metrics, as the manager's do. It reads the OperatorConfig from the manager's cache at each
// call, so that the label follows a rename. The stores write from controllers, which start once the
// cache has synced, and the OperatorConfig controller keeps an informer for the OperatorConfig, so
// the read doesn't wait. A name that can't be read is logged and given as "", for which a store
// records no metric.
func clusterNameOf(mgr ctrl.Manager) func() string {
	log := mgr.GetLogger().WithName("inventory")
	return func() string {
		effective, err := settings.Load(context.Background(), mgr.GetClient())
		if err != nil {
			log.Error(err, "Could not read the cluster name, the label of the inventory metrics; the write is not counted")
			return ""
		}
		return effective.ClusterName
	}
}

// evidenceCapOf returns the function through which the evidence store reads its cap, the most data
// of a record once compressed. It reads the OperatorConfig at each write, so that a change of the
// setting applies to the next one. A cap that can't be read is logged and given as the default.
func evidenceCapOf(mgr ctrl.Manager) func() int64 {
	log := mgr.GetLogger().WithName("evidence")
	return func() int64 {
		effective, err := settings.Load(context.Background(), mgr.GetClient())
		if err != nil {
			log.Error(err, "Could not read the evidence store's cap; the default applies")
			return evidence.DefaultMaxCompressedBytes
		}
		return effective.EvidenceMaxCompressedBytes
	}
}
