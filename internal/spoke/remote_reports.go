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

package spoke

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// clustersName is the name of the request that has the remote clusters taken again.
const clustersName = "clusters"

// remoteWait is how long a look at the remote clusters waits for their views to know what runs, as after a start.
const remoteWait = 2 * time.Second

// RemoteCluster is a remote cluster that the hub renders: its name, its labels, as its Spoke has them, what runs in it,
// and the labels of each of its namespaces, as the hub copied them, with false where they are unknown.
type RemoteCluster struct {
	Name            string
	Labels          map[string]string
	Running         Running
	NamespaceLabels func(namespace string) (map[string]string, bool)
}

// RemoteReports renders, on the hub, what the ResourceReport of each workload of each remote cluster would say, as
// Reports renders the reports of its own cluster, and keeps it only as the cluster's series and its playbooks' counts:
// it writes no report object (decision 0065, design of remote spokes 5.9). It reads the remote clusters, and what runs
// in each, through clusters, the facts of the images from the inventory store, the sheets from the verdicts store and
// the playbooks through inventory.Playbooks, so it reaches the hub's state only through them (decision 0021).
//
//   - A report holds the results of every playbook that selects the cluster's labels and the labels of the workload's
//     namespace (playbooksFor). A namespace whose labels are unknown has the series of its workloads left as they are,
//     while a playbook that selects the cluster selects namespaces by their labels: the playbook can't be decided there,
//     and is never taken for one that doesn't select it.
//   - The urgency follows the hub's table, in its OperatorConfig, for every cluster.
//   - Each report's series are kept under its cluster's name, in the metrics source remote-reports. A workload's go
//     when it leaves its cluster's copies. A cluster that clusters no longer gives, as when its Spoke is deleted, has
//     every series forgotten and the counts of each playbook deleted, but under the name of the hub's own cluster,
//     whose counts are the hub's own.
//   - Until a cluster's Running knows what runs, it renders and forgets nothing of it, and a look at every report waits.
//   - It looks at a report whenever the copies change what its workload runs, its exposure or its namespace's labels
//     (Changed), whenever the facts of one of its images change, or one of their sheets, and at every report when a
//     Playbook comes, goes or changes its spec, or the OperatorConfig changes. A change of a Spoke has the clusters taken
//     again: the reports of one that came, or whose labels changed, are looked at, and one that went is forgotten.
//   - It writes each cluster's counts as Reports writes those of its own cluster, once the first look at each of the
//     cluster's reports has been tried.
//
// It takes one request at a time, so that a cluster that went is never rendered again behind its forgetting.
type RemoteReports struct {
	client    client.Client
	clusters  func(ctx context.Context) ([]RemoteCluster, error)
	store     inventory.Store
	verdicts  inventory.VerdictsStore
	playbooks inventory.Playbooks
	counts    inventory.CountsStore
	series    *ReportsCollector
	log       logr.Logger

	mu    sync.Mutex
	queue workqueue.TypedRateLimitingInterface[reconcile.Request]
	// known holds what the renderer keeps of each cluster that it renders, by the cluster's name. mu guards it, and
	// what each holds but written, which only the request of the counts uses.
	known map[string]*remoteState
}

// remoteState is what the renderer keeps of a remote cluster.
type remoteState struct {
	// labels are those that the cluster's reports were last looked at with.
	labels map[string]string
	// swept says that the reports of the cluster were looked at since it became known, and pending holds those that the
	// first such look asked for, until each has been tried.
	swept   bool
	pending map[types.NamespacedName]bool
	// held holds the digests of the images of each report whose series the renderer keeps, so that a change of an image
	// finds the reports of the workloads that ran it.
	held    map[types.NamespacedName][]string
	written map[string]writtenCounts
}

// The remote renderer watches the Spokes, whose changes have the remote clusters taken again.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=spokes,verbs=list;watch

// NewRemoteReports returns the renderer of the remote clusters' reports, which reads the clusters through clusters, the
// facts of the images from store, the sheets from verdicts and the playbooks from playbooks, and writes the counts of
// each playbook for each cluster to counts. The manager's client reads the hub's OperatorConfig.
func NewRemoteReports(mgr ctrl.Manager, clusters func(ctx context.Context) ([]RemoteCluster, error),
	store inventory.Store, verdicts inventory.VerdictsStore, playbooks inventory.Playbooks,
	counts inventory.CountsStore) *RemoteReports {
	r := &RemoteReports{client: mgr.GetClient(), clusters: clusters, store: store, verdicts: verdicts,
		playbooks: playbooks, counts: counts, series: NewReportsCollector(), log: ctrl.Log.WithName("remote-reports"),
		known: map[string]*remoteState{}}
	metrics.SetSource("remote-reports", remoteSource{r})
	return r
}

// remoteSource is the metrics source of the remote clusters' series. It leaves out those under the name of the hub's
// own cluster, as the OperatorConfig in the manager's cache names it at each scrape: while a rename of the hub onto a
// remote cluster's name reaches the renderer, the hub's own renderer already sends that name's series, and a scrape
// fails as a whole on a series sent twice.
type remoteSource struct{ r *RemoteReports }

// Describe sends nothing: the owner info's labels aren't known beforehand, so the source is unchecked.
func (s remoteSource) Describe(chan<- *prometheus.Desc) {}

// Collect sends the series of the remote clusters but the hub's own name's. A name that can't be read, as before the
// manager's cache starts, when the renderer has no series yet, has it send none: an invalid metric, like a series sent
// twice, would fail the whole scrape.
func (s remoteSource) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	cfg, err := settings.Load(ctx, s.r.client)
	if err != nil {
		s.r.log.Error(err, "Could not read the name of the hub's own cluster; the scrape has no series of the remote clusters")
		return
	}
	s.r.series.collect(ch, cfg.ClusterName)
}

// SetupWithManager sets up the controller, named remote-reports. Its requests have a namespace when they name a report,
// as the cluster and the report's name joined by a slash, or every report of the namespace, as the cluster alone. They
// have none when they name the ImageInventory of an image, the counts, the remote clusters, or the sweep.
func (r *RemoteReports) SetupWithManager(mgr ctrl.Manager) error {
	sheets := &metav1.PartialObjectMetadata{}
	sheets.SetGroupVersionKind(inventoryv1alpha1.GroupVersion.WithKind("ImageVerdicts"))
	named := func(name string) handler.EventHandler {
		return handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: name}}}
		})
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("remote-reports").
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		WatchesRawSource(r.store.Source()).
		Watches(sheets, handler.EnqueueRequestsFromMapFunc(r.sheetChanged)).
		Watches(&configv1alpha1.OperatorConfig{}, named(sweepName)).
		Watches(&configv1alpha1.Spoke{}, named(clustersName)).
		WatchesRawSource(r.playbooks.Source(named(sweepName))).
		WatchesRawSource(source.Func(func(ctx context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
			r.mu.Lock()
			r.queue = queue
			r.mu.Unlock()
			// Whatever happened before the queue existed has every report looked at.
			queue.Add(sweepRequest())
			return nil
		})).
		Complete(r)
}

// sheetChanged maps a sheet to the images whose facts name its manifest.
func (r *RemoteReports) sheetChanged(ctx context.Context, obj client.Object) []reconcile.Request {
	requests, err := imagesOfSheet(ctx, r.store, obj)
	if err != nil {
		r.log.Error(err, "Could not find the images of a sheet's manifest, so their series wait for the next change")
	}
	return requests
}

// Changed has the reports looked at that a change of the copies of the records about the subject can change: of an
// image's presence, those of the workloads that run it, or ran it, in each cluster; of a workload's exposure, the
// workload's; and of a namespace's labels, every report of the namespace. The hub's view of the copies calls it once it
// holds the change, and it doesn't block.
func (r *RemoteReports) Changed(about string) {
	parsed, err := subject.Parse(about)
	if err != nil {
		return
	}
	switch parsed.Kind {
	case subject.KindImage:
		r.add(requestFor(parsed.Digest))
	case subject.KindWorkload:
		w := parsed.Workload
		r.add(reportRequest(w.Cluster, types.NamespacedName{Namespace: w.Namespace,
			Name: ReportName(evidence.PresenceWorkload{APIGroup: w.Group, Kind: w.Kind, Name: w.Name})}))
	case subject.KindNamespace:
		r.add(reconcile.Request{NamespacedName: types.NamespacedName{Namespace: parsed.Namespace, Name: parsed.Cluster}})
	}
}

// reportRequest is the request of the report of the key in the cluster: neither the cluster's name nor the report's
// has a slash.
func reportRequest(cluster string, key types.NamespacedName) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: key.Namespace, Name: cluster + "/" + key.Name}}
}

// add puts a request in the controller's queue, or drops it before the queue exists: the sweep at the start covers it.
func (r *RemoteReports) add(req reconcile.Request) {
	r.mu.Lock()
	queue := r.queue
	r.mu.Unlock()
	if queue != nil {
		queue.Add(req)
	}
}

// requestCounts has the counts looked at, after a pause that lets the reports of a start settle.
func (r *RemoteReports) requestCounts() {
	r.mu.Lock()
	queue := r.queue
	r.mu.Unlock()
	if queue != nil {
		queue.AddAfter(reconcile.Request{NamespacedName: types.NamespacedName{Name: countsName}}, countsDelay)
	}
}

// Reconcile looks at a report, at the reports of a namespace or of an image, writes the counts, or takes the clusters
// again, by the request, with the clusters that the hub renders now.
func (r *RemoteReports) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	clusters, err := r.clusters(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if req.Namespace != "" {
		name, report, one := strings.Cut(req.Name, "/")
		c := clusterNamed(clusters, name)
		if !one {
			r.namespaceChanged(c, name, req.Namespace)
			return ctrl.Result{}, nil
		}
		key := types.NamespacedName{Namespace: req.Namespace, Name: report}
		err := r.render(ctx, c, name, key)
		// Tried, whatever came of it, as Reports has it.
		r.rendered(name, key)
		r.requestCounts()
		return ctrl.Result{}, err
	}
	switch req.Name {
	case countsName:
		return ctrl.Result{}, r.fleet(ctx, clusters)
	case sweepName, clustersName:
		return r.refresh(ctx, clusters, req.Name == sweepName)
	}
	if digest, ok := inventory.DigestForName(req.Name); ok {
		r.imageChanged(clusters, digest)
	}
	return ctrl.Result{}, nil
}

// clusterNamed returns the cluster of the name, or nil when the hub doesn't render it.
func clusterNamed(clusters []RemoteCluster, name string) *RemoteCluster {
	for i := range clusters {
		if clusters[i].Name == name {
			return &clusters[i]
		}
	}
	return nil
}

// state returns what the renderer keeps of the cluster of the name, which it starts to keep. r.mu is held.
func (r *RemoteReports) state(name string) *remoteState {
	s := r.known[name]
	if s == nil {
		s = &remoteState{held: map[types.NamespacedName][]string{}, written: map[string]writtenCounts{}}
		r.known[name] = s
	}
	return s
}

// refresh takes the clusters that the hub renders now: it forgets each that went, and has the reports looked at of each
// that came, whose labels changed, or that waited for its Running, and of every cluster for a sweep, all. A cluster
// whose Running doesn't know what runs yet has the request tried again after remoteWait.
func (r *RemoteReports) refresh(ctx context.Context, clusters []RemoteCluster, all bool) (ctrl.Result, error) {
	if all {
		// A Playbook that came or went changes the counts that are written, whether or not a report changes.
		r.requestCounts()
	}
	if err := r.forgetGone(ctx, clusters); err != nil {
		return ctrl.Result{}, err
	}
	wait := false
	for _, c := range clusters {
		r.mu.Lock()
		s := r.state(c.Name)
		look := all || !s.swept || !maps.Equal(s.labels, c.Labels)
		r.mu.Unlock()
		if !look {
			continue
		}
		knows, err := c.Running.KnowsWhatRuns(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !knows {
			wait = true
			continue
		}
		names := c.Running.RunningReports()
		r.mu.Lock()
		// A report whose series stay, and whose workload went, is forgotten when it is looked at.
		names = append(names, slices.Collect(maps.Keys(s.held))...)
		if !s.swept {
			s.swept, s.pending = true, map[types.NamespacedName]bool{}
			for _, name := range names {
				s.pending[name] = true
			}
		}
		s.labels = c.Labels
		r.mu.Unlock()
		for _, name := range names {
			r.add(reportRequest(c.Name, name))
		}
	}
	if wait {
		return ctrl.Result{RequeueAfter: remoteWait}, nil
	}
	return ctrl.Result{}, nil
}

// forgetGone forgets every cluster that it renders and that clusters no longer holds: its series, and the counts of
// each playbook for it, but under the name of the hub's own cluster. A deletion that fails is tried again with the
// request, and the cluster is kept until then.
func (r *RemoteReports) forgetGone(ctx context.Context, clusters []RemoteCluster) error {
	r.mu.Lock()
	var gone []string
	for name := range r.known {
		if clusterNamed(clusters, name) == nil {
			gone = append(gone, name)
		}
	}
	r.mu.Unlock()
	if len(gone) == 0 {
		return nil
	}
	cfg, err := settings.Load(ctx, r.client)
	if err != nil {
		return err
	}
	all, err := r.playbooks.List(ctx)
	if err != nil {
		return err
	}
	for _, name := range gone {
		r.series.Forget(name)
		// A Spoke refused for the hub's own name leaves the counts of the hub's own cluster, whose renderer wrote them.
		for i := 0; name != cfg.ClusterName && i < len(all); i++ {
			if err := r.counts.Delete(ctx, all[i].Name, name); err != nil {
				return fmt.Errorf("delete the counts of playbook %s for cluster %s: %w", all[i].Name, name, err)
			}
		}
		r.mu.Lock()
		delete(r.known, name)
		r.mu.Unlock()
	}
	return nil
}

// render keeps the series of what the report of the key would say of its workload in the cluster c, of the name, or
// forgets them when no workload of the report runs there, or c is nil: the hub no longer renders the cluster.
func (r *RemoteReports) render(ctx context.Context, c *RemoteCluster, name string, key types.NamespacedName) error {
	if c == nil {
		r.forget(name, key)
		return nil
	}
	knows, err := c.Running.KnowsWhatRuns(ctx)
	if err != nil || !knows {
		// The sweep that waits for it looks at the report.
		return err
	}
	running, runs := c.Running.Running(key.Namespace, key.Name)
	if !runs {
		r.forget(name, key)
		return nil
	}
	all, err := r.playbooks.List(ctx)
	if err != nil {
		return err
	}
	nsLabels, known := c.NamespaceLabels(key.Namespace)
	if !known && selectsNamespaces(all, c.Labels) {
		return nil
	}
	cfg, err := settings.Load(ctx, r.client)
	if err != nil {
		return err
	}
	exposureKnown, err := c.Running.ExposureKnown(ctx)
	if err != nil {
		return err
	}
	// No report keeps an exposure until it is known, so the workload's is Unknown, as a new report's is.
	exposure := WorkloadExposure{SSVC: configv1alpha1.SSVCExposureUnknown}
	if exposureKnown {
		exposure = c.Running.ExposureOf(running.Workload)
	}
	facts, sheets, err := inputsOf(ctx, r.store, r.verdicts, running.Images)
	if err != nil {
		return err
	}
	var playbooks []string
	for _, p := range playbooksFor(nsLabels, c.Labels, all) {
		playbooks = append(playbooks, p.Name)
	}
	rendered := renderStatus(running.Workload, running.Images, playbooks, sheets, facts, exposure, cfg)
	r.series.set(name, key, seriesOf(name, running.Workload.Kind, running.Workload.Name, rendered))
	r.mu.Lock()
	r.state(name).held[key] = digestsOf(running.Images)
	r.mu.Unlock()
	return nil
}

// selectsNamespaces reports whether a playbook of the images in presence that selects the cluster's labels selects
// namespaces by their labels, which it can't be decided for without them.
func selectsNamespaces(playbooks []configv1alpha1.Playbook, clusterLabels map[string]string) bool {
	return slices.ContainsFunc(playbooks, func(p configv1alpha1.Playbook) bool {
		return p.Spec.Subjects.Type == evidence.TypePresence && p.Spec.Match != nil &&
			p.Spec.Match.Namespaces != nil && selects(p.Spec.Match.Clusters, clusterLabels)
	})
}

// forget drops the series of the report of the key in the cluster of the name.
func (r *RemoteReports) forget(name string, key types.NamespacedName) {
	r.series.delete(name, key)
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := r.known[name]; s != nil {
		delete(s.held, key)
	}
}

// rendered notes that the report of the key in the cluster of the name has been tried, so that the cluster's counts
// wait for the first look at the cluster to have tried every report.
func (r *RemoteReports) rendered(name string, key types.NamespacedName) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := r.known[name]; s != nil {
		delete(s.pending, key)
	}
}

// namespaceChanged has every report of the namespace of the cluster c, of the name, looked at: those of the workloads
// that run there, and those whose series stay.
func (r *RemoteReports) namespaceChanged(c *RemoteCluster, name, namespace string) {
	var keys []types.NamespacedName
	if c != nil {
		for _, key := range c.Running.RunningReports() {
			if key.Namespace == namespace {
				keys = append(keys, key)
			}
		}
	}
	r.mu.Lock()
	if s := r.known[name]; s != nil {
		for key := range s.held {
			if key.Namespace == namespace {
				keys = append(keys, key)
			}
		}
	}
	r.mu.Unlock()
	for _, key := range keys {
		r.add(reportRequest(name, key))
	}
}

// imageChanged has the reports looked at that the image of a digest can change, in each cluster: those of the
// workloads that run it, and those whose series hold it, whose workloads may have left it.
func (r *RemoteReports) imageChanged(clusters []RemoteCluster, digest string) {
	var requests []reconcile.Request
	for _, c := range clusters {
		for _, w := range c.Running.Workloads(digest) {
			requests = append(requests, reportRequest(c.Name, types.NamespacedName{Namespace: w.Namespace,
				Name: ReportName(w)}))
		}
	}
	r.mu.Lock()
	for name, s := range r.known {
		for key, digests := range s.held {
			if slices.Contains(digests, digest) {
				requests = append(requests, reportRequest(name, key))
			}
		}
	}
	r.mu.Unlock()
	for _, req := range requests {
		r.add(req)
	}
}

// fleet writes, for each Playbook, what the reports of each cluster add up to, as Reports writes those of its own
// cluster, for each cluster whose first look has tried every report.
func (r *RemoteReports) fleet(ctx context.Context, clusters []RemoteCluster) error {
	all, err := r.playbooks.List(ctx)
	if err != nil {
		return err
	}
	totals := r.series.playbookTotals()
	for _, c := range clusters {
		r.mu.Lock()
		s := r.known[c.Name]
		settled := s != nil && s.swept && len(s.pending) == 0
		r.mu.Unlock()
		if !settled {
			continue
		}
		if err := putCounts(ctx, r.counts, c.Name, all, totals[c.Name], s.written); err != nil {
			return err
		}
	}
	return nil
}
