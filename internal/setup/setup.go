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
	"net/http"
	"net/url"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/collector"
	configcontroller "github.com/bedag/vexplain/internal/controller/config"
	"github.com/bedag/vexplain/internal/controller/hub"
	inventorycontroller "github.com/bedag/vexplain/internal/controller/inventory"
	"github.com/bedag/vexplain/internal/controller/scan"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/tasks"
	"github.com/bedag/vexplain/internal/workloads"
)

const (
	// defaultCollectorResync is how often the Collector controller reads the registry when Options
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
	)
	// AddToScheme adds every API that the operator uses to a scheme: the built-in kinds and the
	// operator's own groups. cmd/main.go and the envtest suites build their schemes with it, so a
	// new group is added in one place.
	AddToScheme = schemeBuilder.AddToScheme
)

// CacheOptions returns the options of the manager's cache. Its cache of Secrets holds only the
// Secrets of operatorNamespace that carry the label vexplain.bedag.ch/llm-api-key=true, the only
// Secrets that the operator reads. It never loads any other Secret, so their values stay out of
// the operator's memory, and the operator needs no right on Secrets outside its namespace.
//
// operatorNamespace must not be empty: to the cache, an empty namespace means every namespace.
// Register refuses an empty one.
func CacheOptions(operatorNamespace string) cache.Options {
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Secret{}: {
				Namespaces: map[string]cache.Config{operatorNamespace: {}},
				Label:      labels.SelectorFromSet(labels.Set{configv1alpha1.LLMAPIKeyLabel: "true"}),
			},
		},
	}
}

// ClientOptions returns the options of the manager's client. cmd/main.go and the envtest suites
// build their managers with it, next to CacheOptions.
//
// The client reads ImagePackages and ImageVerdicts from the API server, and never through the
// cache. The evidence of a scan and a result sheet are up to about 1 MiB each, and a cache would
// hold every one of them in memory for as long as the operator runs. Their stores read one object
// at a time, when a controller needs it, and watch the evidence through its metadata only.
func ClientOptions() client.Options {
	return client.Options{
		Cache: &client.CacheOptions{
			DisableFor: []client.Object{&inventoryv1alpha1.ImagePackages{}, &inventoryv1alpha1.ImageVerdicts{}},
		},
	}
}

// Options configures Register.
type Options struct {
	// OperatorNamespace is the namespace the operator runs in. Cluster-scoped kinds reference
	// namespaced objects, such as Secrets, only in this namespace. It must not be empty, and it
	// must be the namespace that the manager's cache was given with CacheOptions.
	OperatorNamespace string
	// CollectorRegistry is where the collectors report their health, and where the Collector
	// controller reads it. Register creates one when it is nil. A test passes its own, to report
	// health the way a collector does.
	CollectorRegistry *collector.Registry
	// CollectorResync is how often the Collector controller reads the registry again for each
	// Collector. Zero means 30 seconds.
	CollectorResync time.Duration
	// GaugeInterval is how often the gauge of running images counts the ImageInventory objects
	// again. Zero means 30 seconds.
	GaugeInterval time.Duration
	// HTTPClient is the HTTP client of the probes of the ModelConfig controller. Nil means the
	// default client of the llm package, which honours HTTPS_PROXY and NO_PROXY. A test passes the
	// client of its TLS test server.
	HTTPClient *http.Client
	// ScannerImage is the image of the scanner that the scan Jobs run, at most 512 characters, as
	// the API records it. Empty turns scanning off: the hub asks for no scan, the scan runner drops
	// every request, and the Scanner reports that no scanner image is configured.
	ScannerImage string
	// ScanQueue takes the hub's scan requests to the scan runner. Register creates one when it is
	// nil, and the scheduler asks for its scans through it, unless ScanExecutor names another way. A
	// test passes its own, to ask for scans the way the hub does.
	ScanQueue *scan.Queue
	// ScanLogs reads the logs of the scan pods. Nil means a reader through the API server. A test
	// passes its own: envtest runs no kubelet.
	ScanLogs scan.LogReader
	// ScanCredentials builds the pull credentials of a scan from a pod that runs the image. Nil means
	// the pod's pull secrets and those of its service account, read through the API server.
	ScanCredentials scan.CredentialSource
	// ProxyEnv holds the manager's proxy variables, which every scan Job gets: HTTPS_PROXY, HTTP_PROXY
	// and NO_PROXY, in upper or lower case. Register refuses any other variable, because a scan
	// Job's environment holds its credentials' location and the proxy, and nothing else.
	ProxyEnv []corev1.EnvVar
	// ScanRegistryMirrors are the registry mirrors of the scanner, each host=url. Production leaves
	// it empty.
	ScanRegistryMirrors []string
	// ScanSlotWait is how long a scan request waits while every slot is taken, before it asks
	// again. Zero means 30 seconds.
	ScanSlotWait time.Duration
	// ScanExecutor is how the hub's scheduler asks a spoke for scans. Nil means ScanQueue, which takes
	// them to the scan runner of this process. A test passes its own, to see the requests.
	ScanExecutor tasks.Executor
	// ScanRetryBase is how long a digest waits after its first failed scan, doubled for each further
	// failure in a row, a day at most. It is also how long the scheduler waits after a request before
	// it looks at the digest again. Zero means an hour.
	ScanRetryBase time.Duration
	// MatcherURL is the address of the matcher, an http or https URL with a host, such as
	// http://matcher.vexplain-system.svc:8080. The hub reaches it without a proxy: the matcher runs in
	// its cluster.
	MatcherURL string
	// Matcher is the matcher of the hub. Nil means a client of the matcher at MatcherURL. With
	// neither, no manifest gets a verdict sheet, and Register logs that once. A test passes its own.
	Matcher hub.Matcher
	// MatcherPollInterval is how often the hub reads the version of the matcher's database, and so how
	// soon it matches every manifest against a new one. Zero means 10 minutes.
	MatcherPollInterval time.Duration
	// JanitorInterval is how often the hub looks for evidence that no digest refers to. Zero means an
	// hour.
	JanitorInterval time.Duration
	// UnreferencedGrace is how long no digest must have referred to a manifest before its evidence and
	// its sheet are deleted. Zero means 24 hours.
	UnreferencedGrace time.Duration
}

// The defaults of the hub's intervals.
const (
	defaultScanRetryBase       = time.Hour
	defaultMatcherPollInterval = 10 * time.Minute
	defaultJanitorInterval     = time.Hour
	defaultUnreferencedGrace   = 24 * time.Hour
)

// maxScannerImageLength is the longest scanner image that the inventory API records.
const maxScannerImageLength = 512

// proxyVariables are the variables of ProxyEnv that Register accepts.
var proxyVariables = map[string]bool{
	"HTTPS_PROXY": true, "HTTP_PROXY": true, "NO_PROXY": true,
	"https_proxy": true, "http_proxy": true, "no_proxy": true,
}

// Register sets up every controller with the manager, and adds the start-up work that creates the
// default Collectors and the updater of the gauge of running images. It checks opts before it uses
// the manager.
func Register(mgr ctrl.Manager, opts Options) error {
	if opts.OperatorNamespace == "" {
		// To a cache, "" means every namespace, so the Secrets would come from the whole cluster.
		return errors.New("the operator namespace is empty")
	}
	if len(opts.ScannerImage) > maxScannerImageLength {
		// The evidence and the facts of every scan would name it, and the API would refuse them all.
		return fmt.Errorf("the scanner image is %d characters long, more than the %d that the API records",
			len(opts.ScannerImage), maxScannerImageLength)
	}
	for _, env := range opts.ProxyEnv {
		if !proxyVariables[env.Name] {
			return fmt.Errorf("%q is no proxy variable: a scan Job gets the proxy variables, and no other", env.Name)
		}
	}
	if opts.MatcherURL != "" && !isHTTPURL(opts.MatcherURL) {
		// Every match and every read of the database would fail, over and over, and the hub would write
		// no sheet. The error doesn't repeat the URL, which can hold credentials.
		return errors.New("the matcher URL is not an http or https URL with a host")
	}
	registry := opts.CollectorRegistry
	if registry == nil {
		registry = collector.NewRegistry()
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
	if err := (&configcontroller.CollectorReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Registry: registry,
		Recorder: mgr.GetEventRecorder(eventSource),
		Resync:   collectorResync,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the Collector controller: %w", err)
	}
	if err := (&configcontroller.ModelConfigReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		OperatorNamespace: opts.OperatorNamespace,
		Recorder:          mgr.GetEventRecorder(eventSource),
		HTTPClient:        opts.HTTPClient,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the ModelConfig controller: %w", err)
	}
	// The pod inventory lists the pods that run a digest through this index. It leaves out the task
	// pods of the operator, which run in its namespace.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Pod{},
		workloads.PodDigestIndex, workloads.PodDigestIndexer(opts.OperatorNamespace)); err != nil {
		return fmt.Errorf("index the pods by the digests they report: %w", err)
	}
	// The store finds the ImageInventory objects whose facts name a platform manifest through this
	// index, which the manager's cache keeps with its informer for them.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &inventoryv1alpha1.ImageInventory{},
		inventory.ManifestDigestIndex, inventory.IndexManifestDigests); err != nil {
		return fmt.Errorf("index the ImageInventory objects by the manifest digests of their facts: %w", err)
	}
	// One store, the only door to the ImageInventory objects: the pod inventory writes and watches
	// them through it, the scan runner writes the facts of its scans through it, the hub reads and
	// watches them through it, and the gauge counts them through it. The manager's client and cache
	// keep one informer for them.
	clusterName := clusterNameOf(mgr)
	store := inventory.NewCRDStore(mgr.GetClient(), mgr.GetCache(), clusterName)
	// The only doors to the evidence and to the sheets. The manager's client reads both from the API
	// server.
	packages := inventory.NewCRDPackagesStore(mgr.GetClient(), mgr.GetCache(), clusterName)
	verdicts := inventory.NewCRDVerdictsStore(mgr.GetClient(), clusterName)
	if err := (&inventorycontroller.PodInventoryReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Store:     store,
		// The same registry as the Collector controller's, which shows the health it reports.
		Registry: registry,
		// The namespace that the index above was built for.
		OperatorNamespace: opts.OperatorNamespace,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the pod inventory controller: %w", err)
	}
	// One queue for both roles: the hub asks for scans through it, and the spoke's runner takes them
	// from it.
	queue := opts.ScanQueue
	if queue == nil {
		queue = scan.NewQueue()
	}
	if err := registerScanRunner(mgr, opts, queue, store, packages, registry); err != nil {
		return err
	}
	if err := registerHub(mgr, opts, queue, store, packages, verdicts); err != nil {
		return err
	}
	// A RunnableFunc doesn't implement LeaderElectionRunnable, so the manager starts it only on the
	// leader, once the caches have synced.
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		return collector.EnsureDefaults(ctx, mgr.GetClient())
	})); err != nil {
		return fmt.Errorf("add the start-up that creates the default Collectors: %w", err)
	}
	// Like the start-up above, the gauge runs on the leader only, the one replica that keeps the
	// inventory, so that a sum over replicas counts each image once.
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		return runImagesRunningGauge(ctx, mgr, store, gaugeInterval)
	})); err != nil {
		return fmt.Errorf("add the gauge of running images: %w", err)
	}
	return nil
}

// registerScanRunner sets up the spoke's scan runner, which takes the scan requests from queue,
// writes the evidence of its scans through packages and their facts through store, and reports the
// health of the Scanner into registry.
func registerScanRunner(mgr ctrl.Manager, opts Options, queue *scan.Queue, store inventory.Store,
	packages inventory.PackagesStore, registry *collector.Registry) error {
	logs, credentials := opts.ScanLogs, opts.ScanCredentials
	if logs == nil || credentials == nil {
		// Pod logs and pull secrets are read from the API server, never through a cache: a cache
		// would hold every Secret of the cluster.
		clientset, err := kubernetes.NewForConfigAndClient(mgr.GetConfig(), mgr.GetHTTPClient())
		if err != nil {
			return fmt.Errorf("build the clientset of the scan runner: %w", err)
		}
		if logs == nil {
			logs = scan.NewLogReader(clientset)
		}
		if credentials == nil {
			credentials = scan.NewKeychainCredentials(clientset)
		}
	}
	if err := (&scan.Runner{
		Client:      mgr.GetClient(),
		APIReader:   mgr.GetAPIReader(),
		Store:       store,
		Packages:    packages,
		Registry:    registry,
		Queue:       queue,
		Logs:        logs,
		Credentials: credentials,
		// The namespace that the pod index was built for, which leaves out the scan pods.
		OperatorNamespace: opts.OperatorNamespace,
		ScannerImage:      opts.ScannerImage,
		ProxyEnv:          opts.ProxyEnv,
		RegistryMirrors:   opts.ScanRegistryMirrors,
		SlotWait:          opts.ScanSlotWait,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up the scan runner: %w", err)
	}
	return nil
}

// registerHub sets up the hub: the scheduler, which asks for the scans that the inventory lacks; the
// verdicts controller and the poller of the matcher's database, which keep the verdict sheets
// current; and the janitor, which deletes the evidence and the sheets that no digest refers to. The
// scheduler asks through queue, the spoke's, unless opts names another executor.
//
// Without a scanner image nothing can scan, and there is no scheduler: the scan runner reports that
// no scanner image is configured. Without a matcher there is neither a verdicts controller nor a
// poller, and Register logs that once.
//
// The poller and the janitor run on the leader only, as the controllers do: they implement no
// LeaderElectionRunnable. The poller enqueues into the queue of the leader's verdicts controller,
// and one replica deletes.
func registerHub(mgr ctrl.Manager, opts Options, queue *scan.Queue, store inventory.Store,
	packages inventory.PackagesStore, verdicts inventory.VerdictsStore) error {
	if opts.ScannerImage != "" {
		var executor tasks.Executor = queue
		if opts.ScanExecutor != nil {
			executor = opts.ScanExecutor
		}
		if err := (&hub.Scheduler{
			Store:        store,
			Executor:     executor,
			ScannerImage: opts.ScannerImage,
			RetryBase:    orDefault(opts.ScanRetryBase, defaultScanRetryBase),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up the scan scheduler: %w", err)
		}
	}

	matcher := opts.Matcher
	if matcher == nil && opts.MatcherURL != "" {
		matcher = &matchapi.Client{BaseURL: opts.MatcherURL}
	}
	if matcher == nil {
		mgr.GetLogger().WithName("hub").Info("No matcher is configured, so no manifest gets a verdict sheet")
	} else {
		poller := &hub.DatabasePoller{
			Matcher:  matcher,
			Packages: packages,
			Interval: orDefault(opts.MatcherPollInterval, defaultMatcherPollInterval),
		}
		if err := mgr.Add(poller); err != nil {
			return fmt.Errorf("add the poller of the matcher's database: %w", err)
		}
		if err := (&hub.VerdictsReconciler{
			Client:   mgr.GetClient(),
			Packages: packages,
			Verdicts: verdicts,
			Matcher:  matcher,
			Database: poller,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("set up the verdicts controller: %w", err)
		}
	}

	if err := mgr.Add(&hub.Janitor{
		Store:    store,
		Packages: packages,
		Verdicts: verdicts,
		Interval: orDefault(opts.JanitorInterval, defaultJanitorInterval),
		Grace:    orDefault(opts.UnreferencedGrace, defaultUnreferencedGrace),
	}); err != nil {
		return fmt.Errorf("add the janitor of the evidence: %w", err)
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

// isHTTPURL reports whether raw is an http or https URL with a host.
func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
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
