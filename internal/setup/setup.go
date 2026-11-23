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

// Package setup wires the controllers into a manager.
//
// cmd/main.go and the envtest suites of the controller packages all build their scheme with
// AddToScheme, their manager's cache with CacheOptions, and call Register, so tests run the same
// scheme, watches, caches and field indexes as production.
package setup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	triagev1alpha1 "github.com/bedag/vexplain/api/triage/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/collectorclient"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/evidence"
	hubexposure "github.com/bedag/vexplain/internal/exposure"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/spoke"
	"github.com/bedag/vexplain/internal/tasks"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

const (
	// defaultCollectorResync is how often the Collector controller checks each collector when Options
	// does not say.
	defaultCollectorResync = 30 * time.Second
	// defaultGaugeInterval is how often the gauge of running images counts again when Options does
	// not say.
	defaultGaugeInterval = 30 * time.Second
)

// eventSource is the name that the operator's events carry as their reporting controller.
const eventSource = "vexplain"

var (
	schemeBuilder = runtime.NewSchemeBuilder(
		clientgoscheme.AddToScheme,
		configv1alpha1.AddToScheme,
		inventoryv1alpha1.AddToScheme,
		triagev1alpha1.AddToScheme,
	)
	// AddToScheme adds every API that the operator uses to a scheme: the built-in kinds and the
	// operator's own groups. cmd/main.go and the envtest suites build their schemes with it, so a
	// new group is added in one place.
	AddToScheme = schemeBuilder.AddToScheme
)

// CacheOptions returns the options of the manager's cache. It holds no Secret: the manager reads
// the Secrets of its certificates through the API reader, and so the Secrets of the MCP collectors'
// headers, which it lists by their label vexplain.bedag.ch/mcp-headers=true. Only the agent workers
// read the LLM keys, so their values stay out of the manager's memory, and the
// manager reads no Secret outside its namespace.
//
// It holds the Deployments, Services, service accounts and pods of operatorNamespace only, where the
// deployer runs the collectors, so the operator needs no right on them elsewhere: the collectors
// read the pods of the cluster, and the operator doesn't (design 5.5). It holds the ConfigMaps of
// operatorNamespace only, where an AgentProfile's guidance must be.
//
// It holds the ClusterRoles, ClusterRoleBindings, and the Roles and RoleBindings of
// operatorNamespace, that carry the collector label: those through which the deployer grants the
// collectors what they declare. The deployer reads the ceilings, which carry no such label, through
// the API reader. The operator holds the ceilings, whose rules reach Secrets and pods across the
// cluster, only because Kubernetes lets it grant no more than it holds (decision 0041), and it
// reads nothing through them. Its own rights never include the escalate or the bind verb.
//
// operatorNamespace must not be empty: to the cache, an empty namespace means every namespace.
// Register refuses an empty one.
func CacheOptions(operatorNamespace string) cache.Options {
	inOperatorNamespace := cache.ByObject{Namespaces: map[string]cache.Config{operatorNamespace: {}}}
	granted := cache.ByObject{Label: grantedSelector}
	grantedInOperatorNamespace := cache.ByObject{
		Namespaces: map[string]cache.Config{operatorNamespace: {}},
		Label:      grantedSelector,
	}
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.ConfigMap{}:          inOperatorNamespace,
			&appsv1.Deployment{}:         inOperatorNamespace,
			&corev1.Service{}:            inOperatorNamespace,
			&corev1.ServiceAccount{}:     inOperatorNamespace,
			&corev1.Pod{}:                inOperatorNamespace,
			&rbacv1.ClusterRole{}:        granted,
			&rbacv1.ClusterRoleBinding{}: granted,
			&rbacv1.Role{}:               grantedInOperatorNamespace,
			&rbacv1.RoleBinding{}:        grantedInOperatorNamespace,
		},
	}
}

// grantedSelector selects the objects that carry the collector label, whatever its value: those
// that the deployer makes for a collector.
var grantedSelector = labels.NewSelector().Add(collectorLabelExists())

// collectorLabelExists is the requirement that an object carries the collector label.
func collectorLabelExists() labels.Requirement {
	requirement, err := labels.NewRequirement(evidence.CollectorLabel, selection.Exists, nil)
	if err != nil {
		// The label is a constant, which is a valid label key.
		panic(fmt.Sprintf("the requirement of the label %s: %v", evidence.CollectorLabel, err))
	}
	return *requirement
}

// ClientOptions returns the options of the manager's client. cmd/main.go and the envtest suites
// build their managers with it, next to CacheOptions.
//
// The client reads Evidence and ImageVerdicts from the API server, and never through the cache. A
// piece of evidence and a result sheet are up to about 1 MiB each, and a cache would hold every one
// of them in memory for as long as the operator runs. Their stores read one object at a time, when a
// controller needs it, and watch the evidence through its metadata only. A Ledger, up to a few hundred KiB, is read
// from the API server for the same reason. It reads PlaybookClusterStatus from the API server too, which are small:
// the store writes counts only when they differ from the stored ones, and a cache that lags would show it counts that
// are no longer stored.
func ClientOptions() client.Options {
	return client.Options{
		Cache: &client.CacheOptions{
			DisableFor: []client.Object{&inventoryv1alpha1.Evidence{}, &inventoryv1alpha1.ImageVerdicts{},
				&inventoryv1alpha1.PlaybookClusterStatus{}, &inventoryv1alpha1.Ledger{}},
		},
	}
}

// Options configures Register.
type Options struct {
	// OperatorNamespace is the namespace the operator runs in. Cluster-scoped kinds reference
	// namespaced objects, such as Secrets, only in this namespace. It must not be empty, and it
	// must be the namespace that the manager's cache was given with CacheOptions.
	OperatorNamespace string
	// CollectorResync is how often the Collector controller checks each collector again: its health
	// check, its answers, its settings and its permissions. Zero means 30 seconds.
	CollectorResync time.Duration
	// CollectorDialer opens the collector pool's connections to the collectors' Services. Nil means
	// TCP. A test passes its own, to reach the collectors that it serves in its process.
	CollectorDialer func(ctx context.Context, address string) (net.Conn, error)
	// CollectorClock is the Collector controller's clock, which ends the grace after a start, or
	// after a collector's certificate was issued again, within which a failing health check says
	// nothing yet. Nil means time.Now. A test passes its own, to move past the grace.
	CollectorClock func() time.Time
	// ScheduleClock is the clock of the collectors' schedules, at whose times the scheduler fires
	// them. Nil means the real clock. A test passes its own, so that no schedule fires at a time of
	// day that the test happens to run at, unless the test moves the clock.
	ScheduleClock clock.Clock
	// InvestigationClock is the clock of the investigations' schedules and of the age of verdicts. Nil means the real
	// clock. A test passes its own, to move past a tick or an age.
	InvestigationClock clock.Clock
	// GaugeInterval is how often the gauge of running images counts the ImageInventory objects
	// again. Zero means 30 seconds.
	GaugeInterval time.Duration
	// HTTPClient is the HTTP client of the requests to the MCP collectors' servers, which the deployer
	// checks. Nil means http.DefaultTransport, which honours HTTPS_PROXY and NO_PROXY. A test passes
	// the client of its TLS test server.
	HTTPClient *http.Client
	// Executor is how the hub's assessor asks a spoke for evidence. Nil means the spoke's executor of
	// this process, which asks the collectors of its cluster. A test passes its own, to see the
	// requests.
	Executor tasks.Executor
	// RetryBase is how long an image waits after the first failed attempt of a collector to deliver
	// its evidence, doubled for each further failure in a row, a day at most. It is also how long the
	// assessor waits before it looks at an image again, after a request or after a look that found its
	// evidence current. Zero means an hour.
	RetryBase time.Duration
	// Findings is the findings collector of the hub's playbooks. Nil means the hub's own, which matches
	// through the operation match of the Collector that a playbook names, and learns of its database's
	// changes from that collector's stream. A test passes its own.
	Findings hub.Findings
	// JanitorInterval is how often the hub looks for evidence that no digest refers to. Zero means an
	// hour.
	JanitorInterval time.Duration
	// UnreferencedGrace is how long no digest must have referred to a manifest before its evidence and
	// its sheet are deleted. Zero means 24 hours.
	UnreferencedGrace time.Duration
	// DisableReports leaves out the renderer of the ResourceReports, which is otherwise set up with the
	// spoke. The envtest suite of the triage API sets it: that suite writes reports for resources that
	// don't exist, and the renderer would delete them.
	DisableReports bool
	// Queue is the agent's queue of cases, which the investigations fill. Nil means the queue in the Assessments'
	// status, with its sweep, whose cases the agent workers claim and judge. A test passes its own, to see what is
	// queued.
	Queue cases.Queue
	// InvestigationDebounce is how long the investigation controller waits after a change of what
	// investigations read before it reconciles them. Zero means 30 seconds.
	InvestigationDebounce time.Duration
}

// The defaults of the hub's intervals.
const (
	defaultRetryBase         = time.Hour
	defaultJanitorInterval   = time.Hour
	defaultUnreferencedGrace = 24 * time.Hour
)

// Register sets up every controller of the manager, and adds the updater of the gauge of running
// images. It creates no Collector: the install does. The agent workers run the ModelConfig
// controller and judge the cases (internal/agent/worker/setup). It checks opts before it uses the
// manager.
func Register(mgr ctrl.Manager, opts Options) error {
	if opts.OperatorNamespace == "" {
		// To a cache, "" means every namespace, so the Secrets would come from the whole cluster.
		return errors.New("the operator namespace is empty")
	}
	collectorResync := opts.CollectorResync
	if collectorResync == 0 {
		collectorResync = defaultCollectorResync
	}
	gaugeInterval := opts.GaugeInterval
	if gaugeInterval == 0 {
		gaugeInterval = defaultGaugeInterval
	}

	if err := (&configcontroller.OperatorConfigReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the OperatorConfig controller: %w", err)
	}
	if err := (&configcontroller.AgentProfileReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		OperatorNamespace: opts.OperatorNamespace,
		Recorder:          mgr.GetEventRecorder(eventSource),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the AgentProfile controller: %w", err)
	}
	// The store finds the ImageInventory objects whose facts name a platform manifest through this
	// index, which the manager's cache keeps with its informer for them.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &inventoryv1alpha1.ImageInventory{},
		inventory.ManifestDigestIndex, inventory.IndexManifestDigests); err != nil {
		return fmt.Errorf("index the ImageInventory objects by the manifest digests of their facts: %w", err)
	}
	// One store, the only door to the ImageInventory objects: the spoke's presence writes and watches
	// them through it, the facts of the evidence are written through it, the hub reads and watches
	// them through it, and the gauge counts them through it. The manager's client and cache keep one
	// informer for them.
	clusterName := clusterNameOf(mgr)
	store := inventory.NewCRDStore(mgr.GetClient(), mgr.GetCache(), clusterName)
	// The only doors to the evidence and to the sheets. The manager's client reads both from the API
	// server, and the cache holds the metadata of the evidence only, which its Source watches.
	evidenceStore := evidence.NewCRDStore(mgr.GetClient(), mgr.GetCache(), clusterName,
		evidence.WithMaxCompressedBytes(evidenceCapOf(mgr)))
	facts := evidence.NewFactsWriter(store)
	verdicts := inventory.NewCRDVerdictsStore(mgr.GetClient(), clusterName)
	// The only door to the playbooks' counts: the spoke writes its cluster's through it, and the hub sums and reads them.
	// The manager's client reads them from the API server, and the cache watches them through Source.
	counts := inventory.NewCRDCountsStore(mgr.GetClient(), mgr.GetCache())
	// One certificate authority for the process, which its first use loads from its Secret, whether the
	// deployer's or the pool's, and one pool of connections to the collectors, which presents the client
	// certificate that the authority issues. Whatever calls the collectors uses the pool. The authority
	// reads its Secret and the collectors' TLS Secrets through the API reader, since the manager's cache
	// doesn't hold them.
	authority := certs.NewAuthority(mgr.GetClient(), mgr.GetAPIReader(), opts.OperatorNamespace, time.Now)
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		ensureAgentCertificate(ctx, authority, collectorResync)
		return nil
	})); err != nil {
		return fmt.Errorf("add the issuer of the agent workers' client certificate: %w", err)
	}
	pool := collectorclient.NewPool(authority.ClientTLS, opts.OperatorNamespace)
	if opts.CollectorDialer != nil {
		pool.Dialer = opts.CollectorDialer
	}
	// The MCP collectors' servers, which the deployer checks and the agent calls. The Secrets of their headers are listed
	// through the API reader, by their label, since the manager's cache doesn't hold them.
	mcpPool := &collectorclient.MCPPool{Reader: mgr.GetClient(), Secrets: mgr.GetAPIReader(),
		Namespace: opts.OperatorNamespace, HTTPClient: opts.HTTPClient}
	// What vexplain tells its collectors about the cluster, which each call that needs it carries: the
	// scheduler's fires, the streams, the findings collector's requests and the asker's calls to the sources.
	clusterContext := collectorclient.ClusterContext(mgr.GetClient(), opts.OperatorNamespace)
	if err := registerDeployer(mgr, opts, collectorResync, authority, pool, mcpPool, clusterContext, evidenceStore,
		facts); err != nil {
		return err
	}
	exposure := spoke.NewExposure()
	presence := spoke.NewPresence(store, clusterIdentityOf(mgr), exposure, mgr.GetClient())
	// The hub's findings collector is also the sink of the streams of the Hub role: the vulnerabilities collector's stream
	// tells it when its database changed.
	collectorFindings := hub.NewCollectorFindings(mgr.GetClient(), pool, clusterContext)
	if err := registerStreams(mgr, clusterContext, pool, presence, exposure, collectorFindings, evidenceStore); err != nil {
		return err
	}
	executor, err := registerExecutor(mgr, opts, pool, presence, evidenceStore, facts)
	if err != nil {
		return err
	}
	if !opts.DisableReports {
		// The renderer reads what runs from presence, the facts of the images from the store, the sheets
		// from the verdicts store, the playbooks through the inventory's door to them, which it also watches
		// them through, and the labels of the namespaces from the metadata that the manager's cache holds of
		// them, and writes the reports of the workloads.
		if err := spoke.NewReports(mgr, presence, store, verdicts, inventory.NewPlaybooks(mgr.GetClient(), mgr.GetCache()), counts).
			SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up the renderer of the ResourceReports: %w", err)
		}
	}
	var findings hub.Findings = collectorFindings
	if opts.Findings != nil {
		findings = opts.Findings
	}
	if err := registerHub(mgr, opts, findings, executor, store, evidenceStore, facts, verdicts, counts, pool,
		clusterContext); err != nil {
		return err
	}
	// A RunnableFunc doesn't implement LeaderElectionRunnable, so the manager starts it only on the
	// leader, once the caches have synced. The leader is the one replica that keeps the inventory, so
	// that a sum over replicas counts each image once.
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		return runImagesRunningGauge(ctx, mgr, store, gaugeInterval)
	})); err != nil {
		return fmt.Errorf("add the gauge of running images: %w", err)
	}
	return nil
}

// ensureAgentCertificate keeps the agent workers' client certificate in its Secret until ctx is done, as the deployer
// keeps the collectors' server certificates: it ensures it at once, and again every interval, so that it is renewed
// with 30 days left. A failure is logged, and tried again at the next round.
func ensureAgentCertificate(ctx context.Context, authority *certs.Authority, interval time.Duration) {
	log := logf.FromContext(ctx).WithName("agent-certificate")
	wait.UntilWithContext(ctx, func(ctx context.Context) {
		if _, err := authority.EnsureClient(ctx); err != nil && ctx.Err() == nil {
			log.Error(err, "Could not issue the agent workers' client certificate; trying again")
		}
	}, interval)
}

// registerDeployer sets up the Collector controller, the deployer, which runs each collector from
// its package, with the certificates that authority issues, and checks it through pool, or checks the
// server of an MCP collector through mcpPool. It deletes a deleted collector's evidence from
// evidenceStore, and its entries from facts.
//
// It adds the deployer's scheduler, which fires the collectors' schedules through pool, with the
// context that clusterContext builds. A fire for run now that failed fires again after a resync. The
// scheduler is a runnable that the manager runs on its leader only, as it runs the deployer: two
// replicas would fire each schedule twice.
func registerDeployer(mgr ctrl.Manager, opts Options, resync time.Duration, authority *certs.Authority,
	pool *collectorclient.Pool, mcpPool *collectorclient.MCPPool,
	clusterContext func(context.Context) (*collectorv1alpha1.Context, error), evidenceStore evidence.Store,
	facts evidence.FactsWriter) error {
	scheduleClock := opts.ScheduleClock
	if scheduleClock == nil {
		scheduleClock = clock.RealClock{}
	}
	scheduler := configcontroller.NewScheduler(pool, clusterContext, resync, scheduleClock)
	if err := mgr.Add(scheduler); err != nil {
		return fmt.Errorf("add the scheduler of the collectors: %w", err)
	}
	if err := (&configcontroller.CollectorReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		APIReader:         mgr.GetAPIReader(),
		Recorder:          mgr.GetEventRecorder(eventSource),
		Authority:         authority,
		Pool:              pool,
		MCP:               mcpPool,
		Evidence:          evidenceStore,
		Facts:             facts,
		OperatorNamespace: opts.OperatorNamespace,
		Resync:            resync,
		Now:               opts.CollectorClock,
		Scheduler:         scheduler,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the Collector controller: %w", err)
	}
	metrics.SetSource("collectors", spoke.NewCollectorsCollector(mgr.GetClient(), ctrl.Log.WithName("collector-metrics")))
	return nil
}

// registerStreams sets up the streams of the collectors that watch, which call them through pool,
// the pool of the deployer, with the context that clusterContext builds. The spoke's Router takes the
// streams of the spoke role, and hands presence to the spoke's presence, which writes this cluster's
// entries through the inventory store, and exposure to the spoke's exposure, which presence reads. The spoke's store
// sink takes the same streams, and stores what they deliver of a type of the scope Hub in evidenceStore, keyed with
// this cluster, for the hub (decision 0058). hubSink takes the streams of the hub role: the findings collector's, which
// learns when a database changed.
//
// Streams and the store sink are runnables that the manager runs on its leader only, as it runs the
// presence's controller: what the streams delivered lives in the memory of one process.
func registerStreams(mgr ctrl.Manager, clusterContext func(context.Context) (*collectorv1alpha1.Context, error),
	pool *collectorclient.Pool, presence *spoke.Presence, exposure *spoke.Exposure, hubSink collectorclient.Sink,
	evidenceStore evidence.Store) error {
	if err := presence.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the spoke's presence: %w", err)
	}
	// The sink reads the cluster's name at each round of writes, so that its records follow a rename.
	storeSink := spoke.NewStoreSink(evidenceStore, mgr.GetClient(), func(ctx context.Context) (string, error) {
		effective, err := settings.Load(ctx, mgr.GetClient())
		return effective.ClusterName, err
	})
	if err := mgr.Add(storeSink); err != nil {
		return fmt.Errorf("add the spoke's store of streamed evidence: %w", err)
	}
	streams := collectorclient.NewStreams(pool, mgr.GetClient(), map[configv1alpha1.CollectorRole]collectorclient.Sink{
		configv1alpha1.CollectorRoleSpoke: collectorclient.Tee(spoke.NewRouter(mgr.GetClient(), presence, exposure),
			storeSink),
		configv1alpha1.CollectorRoleHub: hubSink,
	}, clusterContext)
	if err := mgr.Add(streams); err != nil {
		return fmt.Errorf("add the streams of the collectors: %w", err)
	}
	return nil
}

// clusterIdentityOf returns the function through which the spoke's presence reads this cluster's
// name and ID. It reads the name from the OperatorConfig in the manager's cache at each call, so
// that the entries follow a rename. It reads the ID once, through the API reader, which doesn't
// wait for a cache: it is the UID of kube-system, which doesn't change while the cluster lives. A
// failed read of the ID is tried again at the next call.
func clusterIdentityOf(mgr ctrl.Manager) func(ctx context.Context) (string, string, error) {
	var (
		mu sync.Mutex
		id string
	)
	return func(ctx context.Context) (string, string, error) {
		effective, err := settings.Load(ctx, mgr.GetClient())
		if err != nil {
			return "", "", err
		}
		mu.Lock()
		defer mu.Unlock()
		if id == "" {
			read, err := settings.ClusterID(ctx, mgr.GetAPIReader())
			if err != nil {
				return "", "", err
			}
			id = read
		}
		return effective.ClusterName, id, nil
	}
}

// registerExecutor adds the spoke's executor, which takes the hub's requests for evidence to the
// collectors of this cluster through pool, with the pods that presence holds, and writes what they
// deliver through evidenceStore and facts. It returns how the hub asks for evidence: opts.Executor
// when a test passes one, and else the spoke's executor.
//
// The executor is a runnable that the manager runs on its leader only, as it runs the assessor that
// asks it.
func registerExecutor(mgr ctrl.Manager, opts Options, pool *collectorclient.Pool, presence *spoke.Presence,
	evidenceStore evidence.Store, facts evidence.FactsWriter) (tasks.Executor, error) {
	executor := spoke.NewExecutor(pool, mgr.GetClient(), presence, evidenceStore, facts,
		mgr.GetEventRecorder(eventSource))
	if err := mgr.Add(executor); err != nil {
		return nil, fmt.Errorf("add the spoke's executor: %w", err)
	}
	if opts.Executor != nil {
		return opts.Executor, nil
	}
	return executor, nil
}

// registerHub sets up the hub: the rule and playbook controllers, which check the rules and the
// playbooks; the assessor, which asks a spoke for the evidence that the playbook needs through
// executor, and keeps the sheets current; the summaries, which keep the summary of each image current,
// through the inventory stores; the view of exposure; the investigation controller, which selects the cases of
// investigations, decides the exposure of their workloads with the playbooks' exposure rules over the view, and queues
// them for the agent workers in the Assessments' status, with the sweep of that queue; the janitor, which deletes the
// evidence, the sheets, the ledgers and the cases that no digest refers to; and the view's asker, which asks the sources
// about the entry points through pool, with the context that clusterContext builds.
//
// findings is how the assessor matches, and learns that a database changed. Its playbook takes the findings of every
// Collector that produces its type of findings: without one whose recorded capabilities have the operation match, no
// manifest gets a sheet, and no evidence is asked for, since nothing says what a match consumes. A findings
// collector's health gates the matches only.
//
// The assessor's controllers run on the leader only, as every controller does, and so do the janitor, the sweep and
// the asker: they implement no LeaderElectionRunnable. One replica deletes, one sweeps, and one asks.
func registerHub(mgr ctrl.Manager, opts Options, findings hub.Findings, executor tasks.Executor, store inventory.Store,
	evidenceStore evidence.Store, facts evidence.FactsWriter, verdicts inventory.VerdictsStore,
	counts inventory.CountsStore, pool *collectorclient.Pool,
	clusterContext func(context.Context) (*collectorv1alpha1.Context, error)) error {
	rules, evaluations := hub.NewRules(), hub.NewEvaluations()
	if err := (&hub.RuleReconciler{Client: mgr.GetClient(), Rules: rules, Evaluations: evaluations}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the rule controller: %w", err)
	}
	if err := (&hub.PlaybookReconciler{Client: mgr.GetClient(), Rules: rules, Counts: counts,
		Recorder: mgr.GetEventRecorder(eventSource)}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the playbook controller: %w", err)
	}
	// The findings of each rule are counted over the sheets on an interval, on the leader, and a scrape reads the count.
	ruleFindings := hub.NewRuleFindings(verdicts, ctrl.Log.WithName("rule-findings"))
	if err := mgr.Add(manager.RunnableFunc(ruleFindings.Start)); err != nil {
		return fmt.Errorf("add the count of the findings of the rules: %w", err)
	}
	metrics.SetSource("playbooks", hub.NewPlaybooksCollector(mgr.GetClient(), counts, ruleFindings, ctrl.Log.WithName("playbook-metrics")))

	assessor := &hub.Assessor{
		Client:      mgr.GetClient(),
		Store:       store,
		Evidence:    evidenceStore,
		Facts:       facts,
		Verdicts:    verdicts,
		Executor:    executor,
		Findings:    findings,
		Rules:       rules,
		Evaluations: evaluations,
		RetryBase:   orDefault(opts.RetryBase, defaultRetryBase),
		Recorder:    mgr.GetEventRecorder(eventSource),
	}
	if err := assessor.SetupRequestsWithManager(mgr); err != nil {
		return fmt.Errorf("set up the assessor's requests of evidence: %w", err)
	}
	if err := assessor.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the assessor: %w", err)
	}
	if err := (&hub.Summaries{Store: store, Verdicts: verdicts}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the summaries of the images: %w", err)
	}
	queue := opts.Queue
	if queue == nil {
		apiQueue := &hub.APIQueue{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader()}
		if err := mgr.Add(manager.RunnableFunc(apiQueue.Sweeps)); err != nil {
			return fmt.Errorf("add the sweep of the agent's queue: %w", err)
		}
		queue = apiQueue
	}
	metrics.SetSource("investigations", hub.NewInvestigationsCollector(mgr.GetClient(), ctrl.Log.WithName("investigation-metrics")))
	metrics.SetSource("vexstatements", hub.NewVexStatementsCollector(mgr.GetClient(), ctrl.Log.WithName("vexstatement-metrics")))
	// The view reads presence, exposure and the answers through the store's watch. The investigations decide each
	// case's exposure from it, and the asker reads the Collectors and the playbooks from the manager's cache.
	view := hubexposure.NewView(evidenceStore)
	if err := view.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the view of exposure: %w", err)
	}
	if err := (&hub.InvestigationReconciler{Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Store: store, Verdicts: verdicts,
		Evidence: evidenceStore, View: view, Rules: rules, Evaluations: evaluations, Queue: queue,
		Recorder: mgr.GetEventRecorder(eventSource), Debounce: opts.InvestigationDebounce,
		Clock: opts.InvestigationClock}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the investigation controller: %w", err)
	}

	if err := mgr.Add(&hub.Janitor{
		Client:   mgr.GetClient(),
		Store:    store,
		Evidence: evidenceStore,
		Verdicts: verdicts,
		Ledgers:  inventory.NewCRDLedgerStore(mgr.GetClient()),
		Interval: orDefault(opts.JanitorInterval, defaultJanitorInterval),
		Grace:    orDefault(opts.UnreferencedGrace, defaultUnreferencedGrace),
	}); err != nil {
		return fmt.Errorf("add the janitor of the evidence: %w", err)
	}

	if err := mgr.Add(hubexposure.NewAsker(view, evidenceStore, mgr.GetClient(), pool, clusterContext)); err != nil {
		return fmt.Errorf("add the asker of the sources: %w", err)
	}
	return nil
}

// orDefault returns d, or def when d is zero.
func orDefault(d, def time.Duration) time.Duration {
	if d == 0 {
		return def
	}
	return d
}

// clusterNameOf returns the function through which the inventory stores read the name of this
// cluster, the label of their metrics. It reads the OperatorConfig from the manager's cache at each
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

// runImagesRunningGauge runs an inventory.GaugeUpdater over store until ctx is done.
//
// The updater counts the objects that hold this cluster's ID, which it takes as a plain value. So
// the ID is read first, through the API reader, which doesn't wait for a cache, and read again
// every interval until it can be. The cluster name is read at every round, from the cache, so
// that the gauge follows a rename.
func runImagesRunningGauge(ctx context.Context, mgr ctrl.Manager, store inventory.Store, interval time.Duration) error {
	log := logf.FromContext(ctx).WithName("images-running-gauge")
	var clusterID string
	if err := wait.PollUntilContextCancel(ctx, interval, true, func(ctx context.Context) (bool, error) {
		id, err := settings.ClusterID(ctx, mgr.GetAPIReader())
		if err != nil {
			log.Error(err, "Could not read the cluster ID; trying again")
			return false, nil
		}
		clusterID = id
		return true, nil
	}); err != nil {
		// The condition never fails, so the poll only ends with an error when ctx is done: the
		// manager is stopping, and so is the gauge.
		return nil
	}

	clusterName := func() string {
		effective, err := settings.Load(ctx, mgr.GetClient())
		if err != nil {
			log.Error(err, "Could not read the cluster name; the gauge keeps its value")
			return ""
		}
		return effective.ClusterName
	}
	return (&inventory.GaugeUpdater{
		Store:     store,
		Cluster:   clusterName,
		ClusterID: clusterID,
		Interval:  interval,
	}).Start(ctx)
}
