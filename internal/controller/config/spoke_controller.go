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

package config

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/conditions"
	"github.com/bedag/vexplain/internal/evidence"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/metrics"
	"github.com/bedag/vexplain/internal/remote"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/text"
)

// The controller reads the Spokes, adds and removes its finalizer, and writes their status.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=spokes,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=spokes/status,verbs=update

// The hub's own Secret of a spoke names its Spoke as its owner, which blocks the Spoke's deletion until the garbage
// collector has deleted it. A cluster that enforces the permissions of owner references allows that only to whoever may
// update the finalizers of Spokes.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=spokes/finalizers,verbs=update

// The controller reads the admin's Secret of each spoke, and the hub's own, through the API reader, and creates and
// updates the hub's own. Markers generate no bindings: config/rbac/manager_secrets_rolebinding.yaml binds the Role.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;create;update,namespace=vexplain-system

// The controller reads the name of the hub's own cluster from the OperatorConfig, and checks every Spoke when it
// changes.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=operatorconfigs,verbs=get;list;watch

// The controller lists the Playbooks, whose counts of a deleted Spoke's cluster it deletes through the counts store.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=playbooks,verbs=list;watch

const (
	// spokeFinalizer keeps a deleted Spoke until the hub has let go of the cluster: it has stopped copying from the
	// spoke, and deleted the copies of the spoke's records. The hub's own Secret of the spoke needs no step of its own:
	// the Spoke owns it, so the garbage collector deletes it with the Spoke.
	spokeFinalizer = "vexplain.bedag.ch/spoke"
	// spokeCheck is how often the hub checks each spoke: its connection, and whether its token is due, so a token is
	// renewed at most this long after half its lifetime. The manager's cache holds no Secret, so this is also how soon
	// the hub reads a changed Secret.
	spokeCheck = time.Minute
	// spokeGrace is how long a spoke may stay unreachable while its Spoke is Reconciling. After it, the Spoke is
	// Stalled, so that a spoke that is gone for good never reads as in progress for ever (decision 0036). It is the
	// grace of a collector's health, and of a model endpoint.
	spokeGrace = 2 * time.Minute
)

// SpokeReconciler connects the hub to the spoke that each Spoke records (design 5.4), and copies the spoke's records
// into the hub's stores (design 5.5): it builds the spoke's config through the seam, remote.Config, checks the
// cluster's identity, renews the hub's token at half its lifetime, runs a copier of the spoke while the hub reaches it,
// and records what it found in the Spoke's status.
//
// The first contact records the spoke's identity, the UID of its kube-system namespace, in status.clusterID. A later
// contact that finds another UID stops there, with Connected False and IdentityChanged, until an admin clears the
// field: a Secret that points at another cluster never acts under this Spoke's name. A token that the spoke refuses is
// no valid one, whatever its expiry says: when the spoke refuses the hub's own, the hub tries the admin's, and renews
// from it at once. Connected is False with TokenExpired when the hub holds no valid token, with CredentialsInvalid when
// the Secret can't be used or the spoke refuses every token that the hub holds, and with Unreachable when the call
// fails otherwise. A Spoke that has the name of the hub's own cluster is Connected False with NameInUse, and the hub
// contacts its spoke not at all: the copies of its records would take the keys of the hub's own, overwrite them, and
// with their deletion delete them. A Spoke whose Secret reaches the hub's own cluster is Connected False with
// OwnCluster, and records no identity, so that the Secret, once it names the right spoke, makes a first contact: its
// copies would carry the hub's own identity, and they and the hub's own entries would replace each other. A first
// contact with a cluster whose identity another Spoke records is Connected False with IdentityInUse, and records none
// either: the two Spokes' copies of one cluster would replace each other's entries. A spoke that names its cluster
// otherwise than the Spoke, in its OperatorConfig or by the default name, is Connected False with ClusterNameMismatch:
// its records carry the other name, and a copier that copies under the Spoke's would read their absence as "runs
// nothing". A check that can't read the spoke's OperatorConfig finds the spoke unreached, as for any failed call.
//
// While a check finds the spoke connected, a copier copies the spoke's records, over a cache of the spoke on the config
// that the check verified the spoke with. Another config, as at the check after a renewal or a change of the Secret,
// starts the cache anew, since the manager's cache holds no Secret whose change would tell; the copier goes on over it
// while the cluster's identity stays, and another identity gets a copier of its own. A spoke that a
// check doesn't find connected is copied from no more, and its copies stay. Synced is True while the copier's last
// round worked, and False with Syncing before that, or after a round that failed; while the spoke isn't connected, it
// is False with Connected's reason. A copier that goes on over a new cache keeps Synced True from its rounds over the
// former one until a round ends over the new one, for spokeGrace at most. status.collectors lists the spoke's
// collectors as the copier last read them, and is never cleared because the spoke can't be read;
// status.lastSyncTime says when the copy last became current, as at the end of the first round over a cache, or last
// took a change of the spoke, as the copier's rounds tell it: a check that finds nothing new writes nothing.
//
// Ready is True when Connected and Synced are, and else says what holds it back: Connected while the hub doesn't reach
// the spoke, and Synced while it copies. Unreachable and Syncing are Reconciling within the grace, and Stalled after
// it; each other failure needs a change of the Secret, of the spoke or of the Spoke, and is Stalled at once. Deleting a
// Spoke stops its copier, and deletes every copy of the spoke's records, the cluster's counts and the series of its
// copies, before the finalizer lets it go. Neither a round nor the deletion forgets an entry of the hub's own cluster's
// identity, though it has the Spoke's name, and a change of the OperatorConfig brings a check of every Spoke, so that
// one that now has the hub's own name stops copying at once.
type SpokeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// APIReader reads the admin's Secret of each spoke and the hub's own, which the manager's cache doesn't hold.
	APIReader client.Reader
	// OperatorNamespace is where both Secrets are.
	OperatorNamespace string
	// Renewer renews the hub's token for each spoke into the hub's own Secret.
	Renewer *remote.Renewer
	// Evidence and Inventory are the hub's stores, which the copies of each spoke's records go into.
	Evidence  evidence.Store
	Inventory inventory.Store
	// Counts holds the playbooks' counts of each cluster, which the deletion of a Spoke deletes for its cluster.
	Counts inventory.CountsStore
	// Now is the controller's clock, by which the graces end. Nil means time.Now. A test passes its own, to move past a
	// grace.
	Now func() time.Time

	mu sync.Mutex
	// runs are the copiers that run, by the name of their Spoke.
	runs map[string]*copying
	// closed says that the manager stops, and no copier starts any more.
	closed bool
	// ownID is the identity of the hub's own cluster, once read: the UID of kube-system doesn't change while the
	// cluster lives.
	ownID string
	// news asks for a check of a Spoke whose copier did a round that changed what the Spoke's status says.
	news chan event.GenericEvent
}

// copying is a copier that runs for a spoke, over a cache of the spoke that runs beside it.
type copying struct {
	// config is the fingerprint of what the cache started with, which another, at a check, replaces.
	config string
	// clusterID is the identity of the spoke's cluster that the copier copies.
	clusterID string
	copier    *remote.Copier
	started   time.Time
	stop      context.CancelFunc
	// done is closed once the copier and its cache have stopped.
	done chan struct{}
}

// running says whether the copier still runs: one that stopped on its own is started again at the next check.
func (c *copying) running() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// contact is what a check of a spoke found: its Connected condition, what a Connected that isn't True means for
// kstatus, what the status records, and the config that the check verified the spoke with, when it found it connected.
// A field that is nil leaves what the status holds.
type contact struct {
	status    metav1.ConditionStatus
	reason    string
	message   string
	progress  conditions.Progress
	clusterID *string
	expires   *time.Time
	cfg       *rest.Config
}

// Reconcile checks the connection to the spoke of a Spoke, records it, and asks to be called again after spokeCheck.
// It returns the errors of the hub's own API server, so that the request is tried again, and lets a deleted Spoke go.
func (r *SpokeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj configv1alpha1.Spoke
	if err := r.Get(ctx, req.NamespacedName, &obj); err != nil {
		if apierrors.IsNotFound(err) {
			// A Spoke that went past its finalizer, as when someone removed it, is copied from no more.
			r.stop(req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !obj.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, &obj)
	}
	if controllerutil.AddFinalizer(&obj, spokeFinalizer) {
		if err := r.Update(ctx, &obj); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}
	own, ownID, err := r.ownCluster(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if obj.Name == own {
		r.stop(obj.Name)
		if err := r.record(ctx, &obj, failure(configv1alpha1.ReasonNameInUse, errors.New("the hub's own cluster has this "+
			"name, as its OperatorConfig names it, and the hub's own records carry it: a Spoke needs a name of its own")),
			nil); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{RequeueAfter: spokeCheck}, nil
	}
	found, err := r.connect(ctx, &obj, ownID)
	if err != nil {
		return ctrl.Result{}, err
	}
	run := r.follow(ctx, &obj, found, ownID)
	// NotFound means the Spoke was deleted since it was read. Any other error, a conflict included, is returned, and
	// controller-runtime retries with a back-off.
	if err := r.record(ctx, &obj, found, run); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{RequeueAfter: spokeCheck}, nil
}

// finalize lets a deleted Spoke go once the hub has stopped copying from its spoke and deleted every copy of the
// spoke's records, of the types that its collectors produce as the Spoke lists them and as the copier last read them,
// the counts of each playbook for the cluster, which the remote renderer wrote, and the series of its refused records
// and of the store's writes of its entries, which the deletion of the copies wrote last. The renderer forgets the
// cluster's series, and deletes its counts too, once it sees the Spoke go: this deletion covers a Spoke deleted while
// the hub was down, which the renderer never knew. Under the name of the hub's own cluster, the hub copied nothing, and
// the records, the counts and the series are its own: it deletes none. A deletion that fails is tried again.
func (r *SpokeReconciler) finalize(ctx context.Context, obj *configv1alpha1.Spoke) error {
	if !controllerutil.ContainsFinalizer(obj, spokeFinalizer) {
		return nil
	}
	own, ownID, err := r.ownCluster(ctx)
	if err != nil {
		return err
	}
	run := r.stop(obj.Name)
	series := prometheus.Labels{"cluster": obj.Name}
	if obj.Name != own {
		listed := slices.Clone(obj.Status.Collectors)
		if run != nil {
			listed = append(listed, run.copier.Collectors()...)
		}
		if err := remote.DeleteCopies(ctx, r.Evidence, r.Inventory, obj.Name, ownID, listed); err != nil {
			return fmt.Errorf("delete the copies of the spoke's records: %w", err)
		}
		var playbooks configv1alpha1.PlaybookList
		if err := r.List(ctx, &playbooks); err != nil {
			return fmt.Errorf("list the Playbooks to delete the cluster's counts: %w", err)
		}
		for _, p := range playbooks.Items {
			if err := r.Counts.Delete(ctx, p.Name, obj.Name); err != nil {
				return fmt.Errorf("delete the cluster's counts: %w", err)
			}
		}
		metrics.InventoryWritesTotal.DeletePartialMatch(series)
		metrics.InventoryObjectBytes.DeletePartialMatch(series)
	}
	metrics.SpokeRecordsRefusedTotal.DeletePartialMatch(series)
	controllerutil.RemoveFinalizer(obj, spokeFinalizer)
	return client.IgnoreNotFound(r.Update(ctx, obj))
}

// follow runs a copier of the spoke while the check found it connected, on the config that the check verified, and
// with the identity that it found, and stops it otherwise: a Secret read again could name a server that the check never
// saw. ownID is the identity of the hub's own cluster. It returns the copier's run, or nil when none runs.
func (r *SpokeReconciler) follow(ctx context.Context, obj *configv1alpha1.Spoke, found contact, ownID string) *copying {
	if found.status != metav1.ConditionTrue {
		r.stop(obj.Name)
		return nil
	}
	r.mu.Lock()
	run := r.runs[obj.Name]
	r.mu.Unlock()
	config := fingerprint(found.cfg, *found.clusterID)
	if run != nil && run.config == config && run.running() {
		return run
	}
	return r.start(ctx, obj, found.cfg, *found.clusterID, ownID, config, r.stop(obj.Name))
}

// ownCluster returns the name of the hub's own cluster, as its OperatorConfig names it at each call, so that a rename
// counts at once, and its identity, which it reads once, through the API reader, as setup reads it for the spoke's
// presence. A failed read of the identity is tried again at the next call.
func (r *SpokeReconciler) ownCluster(ctx context.Context) (name, id string, err error) {
	effective, err := settings.Load(ctx, r.Client)
	if err != nil {
		return "", "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ownID == "" {
		if r.ownID, err = settings.ClusterID(ctx, r.APIReader); err != nil {
			return "", "", err
		}
	}
	return effective.ClusterName, r.ownID, nil
}

// everySpoke returns a request for each Spoke, so that a change of the OperatorConfig, which can give the hub's own
// cluster a Spoke's name, or take it away, brings a check of every Spoke.
func (r *SpokeReconciler) everySpoke(ctx context.Context, _ client.Object) []ctrl.Request {
	var spokes configv1alpha1.SpokeList
	if err := r.List(ctx, &spokes); err != nil {
		logf.FromContext(ctx).Error(err, "Could not list the Spokes after a change of the OperatorConfig; each is "+
			"checked at its next regular check")
		return nil
	}
	requests := make([]ctrl.Request, 0, len(spokes.Items))
	for i := range spokes.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&spokes.Items[i])})
	}
	return requests
}

// now returns the time on the controller's clock.
func (r *SpokeReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// fingerprint is the SHA-256 of what a copier starts with: the server, the CA bundle and the token of its config, and
// the identity of the spoke's cluster.
func fingerprint(cfg *rest.Config, id string) string {
	sum := sha256.New()
	for _, part := range [][]byte{[]byte(cfg.Host), cfg.CAData, []byte(cfg.BearerToken), []byte(id)} {
		// None of the parts holds a NUL, so it parts them.
		sum.Write(part)
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// start starts a cache of the spoke that cfg reaches, whose identity is id, and a copier over it, and returns their run.
// ownID is the identity of the hub's own cluster, whose entries the copier never forgets. When previous, the run that
// the new one replaces, copied the same cluster, as before a renewed token, its copier goes on over the new cache: it
// keeps what it copied, so that Synced holds until a round ends over the new cache, for spokeGrace at most, and its
// next round copies only what changed meanwhile. start returns nil when it can't make the cache, which the next check
// tries again, or once the manager stops.
func (r *SpokeReconciler) start(ctx context.Context, obj *configv1alpha1.Spoke, cfg *rest.Config, id, ownID,
	config string, previous *copying) *copying {
	log := logf.FromContext(ctx)
	spokeCluster, err := remote.NewCluster(cfg, obj.Name, r.Scheme, log.WithName("spoke-cache"))
	if err != nil {
		log.Error(err, "Could not make the cache of the spoke; the next check tries again")
		return nil
	}
	goesOn := previous != nil && previous.clusterID == id
	var copier *remote.Copier
	if goesOn {
		copier = previous.copier
		copier.UseCluster(spokeCluster)
	} else {
		copier = remote.NewCopier(obj.Name, id, r.Evidence, r.Inventory, spokeCluster)
		copier.HubCluster(ownID)
		copier.Knows(obj.Status.Collectors)
	}
	// A copier outlives the reconcile that starts it, until stop ends it, or the manager stops.
	running, stop := context.WithCancel(context.WithoutCancel(ctx))
	run := &copying{config: config, clusterID: id, copier: copier, started: r.now(), stop: stop,
		done: make(chan struct{})}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		stop()
		return nil
	}
	r.runs[obj.Name] = run
	r.mu.Unlock()
	log.Info("Started a cache of the spoke", "server", cfg.Host, "copierGoesOn", goesOn)
	news := event.GenericEvent{Object: &configv1alpha1.Spoke{ObjectMeta: metav1.ObjectMeta{Name: obj.Name}}}
	go func() {
		defer close(run.done)
		var spokeCache sync.WaitGroup
		spokeCache.Go(func() {
			if err := spokeCluster.Start(running); err != nil {
				log.Error(err, "The cache of the spoke stopped; the next check starts it again")
			}
			// The copier reads nothing more without its cache.
			stop()
		})
		if err := copier.Run(running, func() {
			select {
			case r.news <- news:
			case <-running.Done():
			}
		}); err != nil && running.Err() == nil {
			log.Error(err, "The copier of the spoke stopped; the next check starts it again")
		}
		stop()
		spokeCache.Wait()
	}()
	return run
}

// stop stops the run of the spoke of the name, if one runs, waits until its cache and its copier have stopped, and
// returns it, or nil.
func (r *SpokeReconciler) stop(name string) *copying {
	r.mu.Lock()
	run := r.runs[name]
	delete(r.runs, name)
	r.mu.Unlock()
	if run == nil {
		return nil
	}
	run.stop()
	<-run.done
	return run
}

// stopAll stops every copier, once the manager stops, and has none start after.
func (r *SpokeReconciler) stopAll() {
	r.mu.Lock()
	r.closed = true
	names := slices.Collect(maps.Keys(r.runs))
	r.mu.Unlock()
	for _, name := range names {
		r.stop(name)
	}
}

// connect builds the spoke's config, checks the cluster's identity and its name through it, and renews the token when
// it is due. A spoke that refuses the hub's own token gets a second check with the admin's, and a token renewed from it
// at once replaces the refused one. A cluster whose identity is ownID, the hub's own, is refused before any renewal, and
// so are another identity than the recorded one, at a first contact an identity that another Spoke records, and a
// cluster that names itself otherwise than the Spoke. It returns an error, and nothing found, only when the hub's own API
// server fails to give a Secret, or the Spokes, which says nothing about the spoke.
func (r *SpokeReconciler) connect(ctx context.Context, obj *configv1alpha1.Spoke, ownID string) (found contact,
	err error) {
	// A spoke's API server can echo the token that it got into its answer, which no message may show.
	var sent []string
	defer func() { found.message = withhold(found.message, sent) }()
	cfg, err := remote.Config(ctx, r.APIReader, r.OperatorNamespace, obj)
	if err != nil {
		return seamFailure(err)
	}
	sent = append(sent, cfg.BearerToken)
	renew := r.Renewer.Renew
	id, err := r.clusterID(ctx, cfg)
	if apierrors.IsUnauthorized(err) {
		admin, adminErr := remote.AdminConfig(ctx, r.APIReader, r.OperatorNamespace, obj)
		if adminErr != nil {
			return seamFailure(adminErr)
		}
		// Unless the refused token was the admin's already.
		if admin.BearerToken != cfg.BearerToken {
			cfg, renew = admin, r.Renewer.RenewNow
			sent = append(sent, cfg.BearerToken)
			id, err = r.clusterID(ctx, cfg)
		}
	}
	if err != nil {
		return unreached(err), nil
	}
	if id == ownID {
		return failure(configv1alpha1.ReasonOwnCluster, errors.New("the API server that the Secret names belongs to "+
			"the hub's own cluster, whose records the hub holds as its own: a Spoke names another cluster")), nil
	}
	if recorded := obj.Status.ClusterID; recorded != nil && *recorded != id {
		return failure(configv1alpha1.ReasonIdentityChanged, fmt.Errorf("the API server that the Secret names belongs "+
			"to the cluster %s, not to %s, which the hub recorded at its first contact; clear status.clusterID to "+
			"accept it", id, *recorded)), nil
	}
	if obj.Status.ClusterID == nil {
		other, err := r.recordedBy(ctx, obj.Name, id)
		if err != nil {
			return contact{}, err
		}
		if other != "" {
			return failure(configv1alpha1.ReasonIdentityInUse, fmt.Errorf("the API server that the Secret names "+
				"belongs to the cluster %s, which the Spoke %s records already: a cluster has one Spoke", id, other)), nil
		}
	}
	name, err := r.clusterName(ctx, cfg)
	if err != nil {
		return unreached(err), nil
	}
	if name != obj.Name {
		return failure(configv1alpha1.ReasonClusterNameMismatch, fmt.Errorf("the spoke names its cluster %q, as its "+
			"OperatorConfig gives it or by default, and its records carry that name, not the Spoke's: give the spoke's "+
			"OperatorConfig the clusterName %q", name, obj.Name)), nil
	}
	expires, err := within(ctx, func(ctx context.Context) (time.Time, error) { return renew(ctx, obj, cfg) })
	if err != nil {
		// shortcut: a failed write of the hub's own Secret reads as a failed call to the spoke, though its message says
		// which; it needs the hub's API server down, and the next check tries again. Tell them apart if it shows.
		found := unreached(err)
		found.clusterID = &id
		return found, nil
	}
	return contact{status: metav1.ConditionTrue, reason: configv1alpha1.ReasonConnected, clusterID: &id,
		expires: &expires, cfg: cfg, message: "The hub reaches the spoke's API server, its token works, and the " +
			"cluster is the one that it first recorded."}, nil
}

// minWithheld is the shortest token, or part of one, that a check withholds from a message: a shorter one would garble
// text that merely holds it, and is no credential worth the name.
const minWithheld = 8

// withhold returns message with each of tokens, and each part of one between its dots, of minWithheld bytes or more,
// replaced, as the MCP pool withholds the values of its headers. The longest go first, so that no part of a token
// shows after a shorter one was replaced.
func withhold(message string, tokens []string) string {
	var secrets []string
	for _, token := range tokens {
		for _, s := range append([]string{token}, strings.Split(token, ".")...) {
			if len(s) >= minWithheld {
				secrets = append(secrets, s)
			}
		}
	}
	slices.SortFunc(secrets, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	pairs := make([]string, 0, 2*len(secrets))
	for _, s := range secrets {
		pairs = append(pairs, s, "[withheld]")
	}
	return strings.NewReplacer(pairs...).Replace(message)
}

// checked maps the kinds that the check of a spoke reads: the namespaces, for the cluster's identity, and the
// OperatorConfig, for its name. A client with it needs no discovery, whose requests client-go sends with no context,
// so that callTimeout bounds the whole check.
var checked = func() meta.RESTMapper {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(corev1.SchemeGroupVersion.WithKind("Namespace"), meta.RESTScopeRoot)
	mapper.Add(configv1alpha1.GroupVersion.WithKind("OperatorConfig"), meta.RESTScopeRoot)
	return mapper
}()

// uuidPattern matches a UUID as an API server writes the UID of an object.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// errNoUUID says that a spoke's API server answers its kube-system namespace with a UID that is no UUID, which no
// Kubernetes API server does. The UID is the spoke's text, which the hub records nowhere, so the error doesn't quote it.
var errNoUUID = errors.New("the API server that the Secret names gives its kube-system namespace a UID that is no " +
	"UUID, as no Kubernetes API server does")

// clusterID reads the identity of the cluster that cfg reaches, a UUID, quietly, as every call to a spoke.
func (r *SpokeReconciler) clusterID(ctx context.Context, cfg *rest.Config) (string, error) {
	return within(remote.Quiet(ctx), func(ctx context.Context) (string, error) {
		spoke, err := client.New(cfg, client.Options{Scheme: r.Scheme, Mapper: checked})
		if err != nil {
			return "", err
		}
		id, err := settings.ClusterID(ctx, spoke)
		if err == nil && !uuidPattern.MatchString(id) {
			return "", errNoUUID
		}
		return id, err
	})
}

// clusterName reads the name that the cluster that cfg reaches gives itself, which its records carry: as its
// OperatorConfig names it, and the default name where it has none. It reads quietly, as every call to a spoke.
func (r *SpokeReconciler) clusterName(ctx context.Context, cfg *rest.Config) (string, error) {
	return within(remote.Quiet(ctx), func(ctx context.Context) (string, error) {
		spoke, err := client.New(cfg, client.Options{Scheme: r.Scheme, Mapper: checked})
		if err != nil {
			return "", err
		}
		effective, err := settings.Load(ctx, spoke)
		return effective.ClusterName, err
	})
}

// recordedBy returns the name of another Spoke than the one of the name that records the identity id, or "" when none
// does. A Spoke that is being deleted counts for none: its deletion takes its copies, which carry its own name. It reads
// through the API reader, so that a Spoke that recorded the identity a moment ago counts.
func (r *SpokeReconciler) recordedBy(ctx context.Context, name, id string) (string, error) {
	var spokes configv1alpha1.SpokeList
	if err := r.APIReader.List(ctx, &spokes); err != nil {
		return "", fmt.Errorf("list the Spokes to check the identity of a new spoke: %w", err)
	}
	for _, other := range spokes.Items {
		if other.Name != name && other.DeletionTimestamp.IsZero() && ptr.Deref(other.Status.ClusterID, "") == id {
			return other.Name, nil
		}
	}
	return "", nil
}

// seamFailure is what a check finds when the seam gives no config: TokenExpired when the hub holds no valid token, and
// CredentialsInvalid when the Secret can't be used. A failure of the hub's own API server to give a Secret is returned
// instead, since it says nothing about the spoke.
func seamFailure(err error) (contact, error) {
	var hubStatus apierrors.APIStatus
	switch {
	case errors.Is(err, remote.ErrTokenExpired):
		return failure(configv1alpha1.ReasonTokenExpired, err), nil
	case errors.As(err, &hubStatus) && !apierrors.IsNotFound(err):
		return contact{}, err
	}
	return failure(configv1alpha1.ReasonCredentialsInvalid, err), nil
}

// failure is a check that failed for reason, with the text of err. The controller is stalled: what failed needs a
// change of the Secret, of the spoke or of the Spoke.
func failure(reason string, err error) contact {
	return contact{status: metav1.ConditionFalse, reason: reason, message: err.Error(), progress: conditions.Stalled}
}

// unreached is a check whose call to the spoke failed. A spoke whose certificate doesn't verify against the Secret's
// CA bundle, or that refuses the token, one that answers no UUID for its identity, and a token that the hub can't
// renew, need a change of the Secret or of the spoke: CredentialsInvalid. Anything else may pass, as a spoke that
// restarts does: Unreachable, which is retried at each check.
func unreached(err error) contact {
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) || apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) ||
		errors.Is(err, remote.ErrNotRenewable) || errors.Is(err, errNoUUID) {
		return failure(configv1alpha1.ReasonCredentialsInvalid, err)
	}
	found := failure(configv1alpha1.ReasonUnreachable, err)
	found.progress = conditions.Reconciling
	return found
}

// record writes what found says, and what the copier of run says of the copy, into the status of obj, when that
// changes it. run is nil when no copier runs.
func (r *SpokeReconciler) record(ctx context.Context, obj *configv1alpha1.Spoke, found contact, run *copying) error {
	connected := metav1.Condition{
		Type:   configv1alpha1.ConditionConnected,
		Status: found.status,
		Reason: found.reason,
		// The message can be the text of the spoke's API server.
		Message:            truncate(text.Printable(found.message)),
		ObservedGeneration: obj.Generation,
	}
	now := r.now()
	synced, current := syncedOf(found, run, now)
	synced.ObservedGeneration = obj.Generation
	ready, progress, startedCopying := connected, found.progress, time.Time{}
	if found.status == metav1.ConditionTrue && synced.Status != metav1.ConditionTrue {
		ready, progress = synced, conditions.Reconciling
		if run != nil {
			startedCopying = run.started
		}
	}
	// The grace runs from when the condition that holds Ready back last turned False, or from the copier's start, as the
	// copier that follows an outage does: whichever came last.
	held := meta.FindStatusCondition(obj.Status.Conditions, ready.Type)
	if progress == conditions.Reconciling && held != nil && held.Status == metav1.ConditionFalse &&
		now.Sub(laterOf(held.LastTransitionTime.Time, startedCopying)) >= spokeGrace {
		progress = conditions.Stalled
	}
	before := obj.Status.DeepCopy()
	connectedChanged := meta.SetStatusCondition(&obj.Status.Conditions, connected)
	syncedChanged := meta.SetStatusCondition(&obj.Status.Conditions, synced)
	conditions.SetReady(&obj.Status.Conditions, ready, progress)
	conditions.Observe(&obj.Status.ObservedGeneration, obj.Generation)
	if obj.Status.ClusterID == nil && found.clusterID != nil {
		obj.Status.ClusterID = found.clusterID
		// A cluster that the hub records anew, as after an admin accepted another identity, has its copier copy over
		// the former cluster's copies until its first round ends: no copy of it was current yet.
		obj.Status.LastSyncTime = nil
	}
	// The API keeps whole seconds.
	if found.expires != nil {
		expires := metav1.NewTime(found.expires.Truncate(time.Second))
		obj.Status.TokenExpirationTime = &expires
	}
	// The collectors that the copier last read stay listed while none can read them.
	if run != nil {
		if listed := run.copier.Collectors(); listed != nil {
			obj.Status.Collectors = listed
		}
	}
	// Written only when the copy became current or changed since, so that a check that finds nothing new writes nothing.
	if current {
		lastSync := metav1.NewTime(run.copier.Copied().Truncate(time.Second))
		obj.Status.LastSyncTime = &lastSync
	}
	if equality.Semantic.DeepEqual(before, &obj.Status) {
		return nil
	}
	if err := r.Status().Update(ctx, obj); err != nil {
		return err
	}
	log := logf.FromContext(ctx)
	if connectedChanged {
		log.Info("Updated the Connected condition of the Spoke", "status", connected.Status, "reason", connected.Reason)
	}
	if syncedChanged {
		log.Info("Updated the Synced condition of the Spoke", "status", synced.Status, "reason", synced.Reason)
	}
	return nil
}

// syncedOf returns the Synced condition of a Spoke whose check found what found says, and whose copier runs as run
// says, which is nil when none runs, and whether the copy is current: whether the copier's last round worked over the
// cache that it reads. A copier that goes on over a new cache keeps Synced True from its rounds over the former one
// until a round ends over the new one, for spokeGrace from the new cache's start until now at most: a cache that never
// syncs, as when the spoke no longer lets the hub list its records, leaves the copies to fall behind.
func syncedOf(found contact, run *copying, now time.Time) (metav1.Condition, bool) {
	synced := metav1.Condition{Type: configv1alpha1.ConditionSynced, Status: metav1.ConditionFalse,
		Reason: configv1alpha1.ReasonSyncing}
	switch {
	case found.status != metav1.ConditionTrue:
		synced.Reason = found.reason
		synced.Message = "The hub copies nothing from the spoke while it isn't connected, and keeps the copies that it " +
			"made."
	case run == nil:
		synced.Message = "The hub starts to copy the spoke's records at its next check."
	default:
		switch ok, current, err := run.copier.Synced(); {
		case ok && (current || now.Sub(run.started) < spokeGrace):
			synced.Status, synced.Reason = metav1.ConditionTrue, configv1alpha1.ReasonSynced
			synced.Message = "The hub has copied what the spoke holds, and copies each change."
			return synced, current
		case err != nil:
			synced.Message = truncate(text.Printable("The hub's last round of copying failed, and is tried again: " +
				err.Error()))
		case ok:
			synced.Message = "The hub's new cache of the spoke hasn't synced, so the copies may lack what the spoke " +
				"changed since; the hub copies it once the cache has synced."
		default:
			synced.Message = "The hub waits for its cache of the spoke to sync, and then copies the spoke's records."
		}
	}
	return synced, false
}

// laterOf returns the later of two times.
func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// SetupWithManager sets up the controller with the Manager, and stops every copier when the manager stops.
func (r *SpokeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.runs, r.news = map[string]*copying{}, make(chan event.GenericEvent)
	if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		<-ctx.Done()
		r.stopAll()
		return nil
	})); err != nil {
		return fmt.Errorf("add the end of the spokes' copiers: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		// The controller's own status writes start no reconcile: the check every spokeCheck follows the spoke, and a
		// copier tells of what it changes of the status.
		For(&configv1alpha1.Spoke{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&configv1alpha1.OperatorConfig{}, handler.EnqueueRequestsFromMapFunc(r.everySpoke),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WatchesRawSource(source.Channel(r.news, &handler.EnqueueRequestForObject{})).
		// A failed reconcile is tried again within spokeCheck, so that the check keeps its pace.
		WithOptions(controller.Options{RateLimiter: retryLimiter(spokeCheck)}).
		Named("config-spoke").
		Complete(r)
}
