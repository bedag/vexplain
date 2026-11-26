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
	"archive/tar"
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/hack/internal/localcluster"
	"github.com/bedag/vexplain/internal/settings"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
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

// ---- the load ----

// imagesOf returns the numbers of the images that spoke s, 0 or 1, runs, in the order of their places in the layout:
// the shared images first, so that the one at the first place, which runs the most workloads, runs on both spokes.
func imagesOf(s int) []int {
	images := make([]int, 0, spokeImages)
	for g := spokeImages - sharedImages; g < spokeImages; g++ {
		images = append(images, g)
	}
	first := 0
	if s == 1 {
		first = spokeImages
	}
	for g := first; g < first+spokeImages-sharedImages; g++ {
		images = append(images, g)
	}
	return images
}

// layout returns how many workloads run the image at place k of a spoke's images, and in how many namespaces. The first
// image runs 28 workloads in all 10 namespaces, which makes the largest records. Each other image runs 1 to 4 workloads
// in 1 to 4 namespaces, the two counts varied apart, so that a fit can tell what a workload and a namespace each add to
// a record. The 30 places add up to 100 workloads.
func layout(k int) (workloads, namespaces int) {
	if k == 0 {
		return 28, loadNamespaces
	}
	workloads = 1 + k%4
	return workloads, min(workloads, 1+(k/4)%4)
}

// workload is a Deployment of the load.
type workload struct {
	namespace, name string
	image           int
}

// loadOf returns the Deployments of spoke s. The i-th workload of the image at place k runs in the namespace k+i%n,
// counted round the 10, where n is the image's count of namespaces.
func loadOf(s int) []workload {
	var load []workload
	for k, g := range imagesOf(s) {
		workloads, namespaces := layout(k)
		for i := range workloads {
			load = append(load, workload{namespace: namespaceOf((k + i%namespaces) % loadNamespaces),
				name: fmt.Sprintf("%s-%02d", imageName(g), i), image: g})
		}
	}
	return load
}

// rolled returns the workloads of the first spoke that the rollout changes: every second one in the order of the load,
// 50 workloads of 23 of the spoke's 30 images.
func rolled() []workload {
	var out []workload
	for j, w := range loadOf(0) {
		if j%2 == 0 {
			out = append(out, w)
		}
	}
	return out
}

func namespaceOf(i int) string { return fmt.Sprintf("measure-6-%02d", i) }

func imageName(g int) string { return fmt.Sprintf("img-%02d", g) }

// ---- the clusters ----

// cluster is one of the three kind clusters.
type cluster struct {
	// kind is the name of the kind cluster, whose node is the container <kind>-control-plane.
	kind       string
	kubeconfig string
	api        client.Client
	clientset  *kubernetes.Clientset
}

// connect returns the cluster of the kubeconfig, which localcluster checks first, and refuses unless it is a local kind
// cluster's own.
func connect(kubeconfig string, scheme *runtime.Scheme) (*cluster, error) {
	var cfg *rest.Config
	api, err := localcluster.ConnectTo(kubeconfig, scheme, func(c *rest.Config) {
		// The tool lists every record of the hub every few seconds while it waits.
		c.QPS, c.Burst = 50, 100
		cfg = rest.CopyConfig(c)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", kubeconfig, err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	// localcluster made sure that the current context is kind's, kind-<cluster>.
	raw, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		return nil, err
	}
	return &cluster{kind: strings.TrimPrefix(raw.CurrentContext, "kind-"), kubeconfig: kubeconfig, api: api,
		clientset: clientset}, nil
}

// node is the container of the cluster's one node.
func (c *cluster) node() string { return c.kind + "-control-plane" }

func newScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		inventoryv1alpha1.AddToScheme, configv1alpha1.AddToScheme, appsv1.AddToScheme, corev1.AddToScheme,
		rbacv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			return nil, fmt.Errorf("register the APIs: %w", err)
		}
	}
	return scheme, nil
}

// measurement is one run of the tool.
type measurement struct {
	out      io.Writer
	opts     arguments
	hub      *cluster
	spokes   []*cluster
	names    []string          // the spokes' cluster names, as their OperatorConfigs give them
	digests  map[int]string    // the digest of each image of the load
	pods     *podNames         // the hub's pods in the operator's namespace, by UID
	usage    *sampler          // what the hub's pods use, from their cgroups
	writes   []writeSample     // the hub's writes to etcd, sampled through the run
	phases   map[string][2]int // the samples of writes that begin and end each phase
	writesMu sync.Mutex
}

// connectAll connects to the three clusters, and reads the spokes' names.
func connectAll(opts arguments, out io.Writer) (*measurement, error) {
	scheme, err := newScheme()
	if err != nil {
		return nil, err
	}
	m := &measurement{out: out, opts: opts, phases: map[string][2]int{}}
	if m.hub, err = connect(opts.hub, scheme); err != nil {
		return nil, err
	}
	for _, kubeconfig := range opts.spokes {
		spoke, err := connect(kubeconfig, scheme)
		if err != nil {
			return nil, err
		}
		m.spokes = append(m.spokes, spoke)
	}
	return m, nil
}

// measure runs the phases one after the other.
func (m *measurement) measure(ctx context.Context) error {
	start := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, spoke := range m.spokes {
		var config configv1alpha1.OperatorConfig
		if err := spoke.api.Get(ctx, client.ObjectKey{Name: settings.ConfigName}, &config); err != nil {
			return fmt.Errorf("read the OperatorConfig of %s: %w", spoke.kind, err)
		}
		m.names = append(m.names, ptr.Deref(config.Spec.ClusterName, settings.DefaultClusterName))
	}
	if m.names[0] == m.names[1] {
		return fmt.Errorf("both spokes are named %s", m.names[0])
	}
	m.say("hub %s, spokes %s (%s) and %s (%s)\n", m.hub.kind, m.names[0], m.spokes[0].kind, m.names[1],
		m.spokes[1].kind)

	m.pods = watchPods(ctx, m.hub)
	var err error
	if m.usage, err = startSampler(ctx, m.hub.node()); err != nil {
		return err
	}
	go m.sampleWrites(ctx)

	for _, phase := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"spokes", m.addSpokes},
		{"images", m.buildImages},
		{"load", m.runLoad},
		{"idle", m.measureIdle},
		{"rollout", m.rollOut},
		{"restart", m.restart},
	} {
		m.say("== %s, at %s\n", phase.name, time.Since(start).Round(time.Second))
		if err := phase.run(ctx); err != nil {
			return fmt.Errorf("%s: %w", phase.name, err)
		}
	}
	m.reportUsage()
	m.say("== done, after %s\n", time.Since(start).Round(time.Second))
	return nil
}

func (m *measurement) say(format string, args ...any) { say(m.out, format, args...) }

// ---- the spokes ----

// addSpokes adds each spoke to the hub, as docs/remote-spokes.md does, and waits until the hub has copied what each
// holds, and until the hub's matcher has loaded its database: a match that fails before backs off.
func (m *measurement) addSpokes(ctx context.Context) error {
	for i, spoke := range m.spokes {
		if err := addSpoke(ctx, m.hub, spoke, m.names[i]); err != nil {
			return fmt.Errorf("add %s: %w", m.names[i], err)
		}
	}
	err := m.waitFor(ctx, "the Spokes to be Ready and Synced", func(ctx context.Context) (bool, error) {
		for _, spokeName := range m.names {
			var found configv1alpha1.Spoke
			if err := m.hub.api.Get(ctx, client.ObjectKey{Name: spokeName}, &found); err != nil {
				return false, err
			}
			if !meta.IsStatusConditionTrue(found.Status.Conditions, configv1alpha1.ConditionReady) ||
				!meta.IsStatusConditionTrue(found.Status.Conditions, configv1alpha1.ConditionSynced) {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	return m.waitFor(ctx, "the hub's matcher to load its database", func(ctx context.Context) (bool, error) {
		logs, err := deploymentLogs(ctx, m.hub, vulnerabilitiesCollector)
		return strings.Contains(logs, databaseLoaded), err
	})
}

// addSpoke makes the token of the hub's account on the spoke, and on the hub the Secret with the spoke's address on
// the kind network, its CA and the token, and the Spoke. The token stays in memory and in the Secret, and is never
// printed.
func addSpoke(ctx context.Context, hub, spoke *cluster, spokeName string) error {
	internal, err := exec.CommandContext(ctx, "kind", "get", "kubeconfig", "--internal", "--name", spoke.kind).Output()
	if err != nil {
		return fmt.Errorf("read the spoke's kubeconfig on the kind network: %w", err)
	}
	config, err := clientcmd.Load(internal)
	if err != nil {
		return err
	}
	current, ok := config.Contexts[config.CurrentContext]
	if !ok || config.Clusters[current.Cluster] == nil {
		return errors.New("the spoke's kubeconfig on the kind network has no current cluster")
	}
	server, ca := config.Clusters[current.Cluster].Server, config.Clusters[current.Cluster].CertificateAuthorityData
	request := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{
		ExpirationSeconds: ptr.To(int64(time.Hour / time.Second))}}
	token, err := spoke.clientset.CoreV1().ServiceAccounts(operatorNamespace).CreateToken(ctx, hubAccount, request,
		metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create a token of %s: %w", hubAccount, err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: spokeName + "-credentials", Namespace: operatorNamespace}}
	if _, err = controllerutil.CreateOrUpdate(ctx, hub.api, secret, func() error {
		secret.Data = map[string][]byte{"server": []byte(server), "ca.crt": ca, "token": []byte(token.Status.Token)}
		return nil
	}); err != nil {
		return fmt.Errorf("make the Secret of the spoke: %w", err)
	}
	record := &configv1alpha1.Spoke{ObjectMeta: metav1.ObjectMeta{Name: spokeName}}
	_, err = controllerutil.CreateOrUpdate(ctx, hub.api, record, func() error {
		record.Spec.CredentialsSecretRef.Name = secret.Name
		return nil
	})
	return err
}

// podsOf returns the pods of the Deployment of the name in the operator's namespace.
func podsOf(ctx context.Context, c *cluster, deployment string) ([]corev1.Pod, error) {
	var found appsv1.Deployment
	if err := c.api.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: deployment}, &found); err != nil {
		return nil, err
	}
	var pods corev1.PodList
	err := c.api.List(ctx, &pods, client.InNamespace(operatorNamespace),
		client.MatchingLabels(found.Spec.Selector.MatchLabels))
	return pods.Items, err
}

// deploymentLogs returns the logs of the pods of the Deployment of the name in the operator's namespace.
func deploymentLogs(ctx context.Context, c *cluster, deployment string) (string, error) {
	pods, err := podsOf(ctx, c, deployment)
	if err != nil {
		return "", err
	}
	var logs strings.Builder
	for _, pod := range pods {
		// A pod whose container hasn't started has no logs yet.
		raw, _ := c.clientset.CoreV1().Pods(operatorNamespace).GetLogs(pod.Name, &corev1.PodLogOptions{}).DoRaw(ctx)
		logs.Write(raw)
	}
	return logs.String(), nil
}

// waitFor looks every lookPoll until done says so, for the timeout at most.
func (m *measurement) waitFor(ctx context.Context, what string, done func(context.Context) (bool, error)) error {
	m.say("waiting for %s\n", what)
	err := wait.PollUntilContextTimeout(ctx, lookPoll, m.opts.timeout, true, done)
	if err != nil {
		return fmt.Errorf("waiting for %s: %w", what, err)
	}
	return nil
}

// ---- the images ----

// buildImages builds the base image, pushes it, and pushes each image of the load: the base with a file of its own,
// which gives it a digest of its own. An image is one manifest, so that the digest that the pods report is the one
// that the hub scans.
func (m *measurement) buildImages(ctx context.Context) error {
	base := m.opts.registry + "/measure-6/base:" + builtTag
	if _, err := docker(ctx, "build", "--provenance=false", "--sbom=false", "-t", base, baseBuild); err != nil {
		return err
	}
	if _, err := docker(ctx, "push", base); err != nil {
		return err
	}
	ref, err := name.ParseReference(base)
	if err != nil {
		return err
	}
	options := []remote.Option{remote.WithContext(ctx), remote.WithAuth(authn.Anonymous)}
	image, err := remote.Image(ref, options...)
	if err != nil {
		return fmt.Errorf("read the base image: %w", err)
	}
	m.digests = map[int]string{}
	for g := range loadImages {
		digest, err := pushVariant(image, m.opts.registry+"/measure-6/"+imageName(g)+":"+builtTag, g, options)
		if err != nil {
			return fmt.Errorf("push %s: %w", imageName(g), err)
		}
		m.digests[g] = digest
		m.say("raw image %s %s\n", imageName(g), digest)
	}
	return nil
}

// pushVariant pushes base with one more layer, which holds the file /measure-6-id with the image's number, to the tag,
// and returns the digest of what it pushed.
func pushVariant(base v1.Image, tag string, g int, options []remote.Option) (string, error) {
	var layerTar bytes.Buffer
	content := []byte(imageName(g) + "\n")
	w := tar.NewWriter(&layerTar)
	if err := w.WriteHeader(&tar.Header{Name: "measure-6-id", Mode: 0o644, Size: int64(len(content))}); err != nil {
		return "", err
	}
	if _, err := w.Write(content); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	// The layer takes the media type of the base's layers, OCI or Docker, as the base's manifest has them.
	mediaType := types.DockerLayer
	if manifestType, err := base.MediaType(); err == nil && manifestType == types.OCIManifestSchema1 {
		mediaType = types.OCILayer
	}
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layerTar.Bytes())), nil
	}, tarball.WithMediaType(mediaType))
	if err != nil {
		return "", err
	}
	image, err := mutate.AppendLayers(base, layer)
	if err != nil {
		return "", err
	}
	ref, err := name.NewTag(tag)
	if err != nil {
		return "", err
	}
	if err = remote.Write(ref, image, options...); err != nil {
		return "", err
	}
	digest, err := image.Digest()
	if err != nil {
		return "", err
	}
	return digest.String(), nil
}

// docker runs the docker CLI, and returns its output. An error carries the end of the output.
func docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		tail := output.String()
		if len(tail) > 2000 {
			tail = "..." + tail[len(tail)-2000:]
		}
		return "", fmt.Errorf("docker %s: %w\n%s", args[0], err, tail)
	}
	return output.String(), nil
}

// ---- the load and its settling ----

// runLoad deploys the load on both spokes, waits until the hub has copied, scanned and judged it, and measures what the
// hub then holds, the scans, and the series of vexplain_open_case.
func (m *measurement) runLoad(ctx context.Context) error {
	begin := m.mark()
	deployed := time.Now()
	for s, spoke := range m.spokes {
		if err := m.deploy(ctx, spoke, loadOf(s)); err != nil {
			return fmt.Errorf("deploy the load on %s: %w", m.names[s], err)
		}
	}
	err := m.waitFor(ctx, "the hub to copy, scan and judge the load", func(ctx context.Context) (bool, error) {
		held, err := m.readHub(ctx)
		if err != nil {
			return false, err
		}
		missing, err := m.missing(held)
		if missing != "" {
			m.say("  still waiting for %s\n", missing)
		}
		return missing == "" && err == nil, err
	})
	if err != nil {
		return err
	}
	m.say("the hub holds the load %s after its deployment\n", time.Since(deployed).Round(time.Second))
	if err = m.waitQuiet(ctx, begin); err != nil {
		return err
	}
	m.phases["load"] = [2]int{begin, m.mark()}
	m.reportWrites("load")
	held, err := m.readHub(ctx)
	if err != nil {
		return err
	}
	if err = m.reportHoldings(ctx, held); err != nil {
		return err
	}
	if err = m.reportScans(ctx, deployed); err != nil {
		return err
	}
	return m.reportSeries(ctx)
}

// deploy makes the namespaces and the Deployments of the load on a spoke. It updates what is there, so that a second
// run goes on where the first stopped.
func (m *measurement) deploy(ctx context.Context, spoke *cluster, load []workload) error {
	for i := range loadNamespaces {
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceOf(i)}}
		if _, err := controllerutil.CreateOrUpdate(ctx, spoke.api, namespace, func() error { return nil }); err != nil {
			return err
		}
	}
	for _, w := range load {
		want := deploymentOf(w, m.opts.registry+"/measure-6/"+imageName(w.image)+"@"+m.digests[w.image])
		have := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: want.Name, Namespace: want.Namespace}}
		if _, err := controllerutil.CreateOrUpdate(ctx, spoke.api, have, func() error {
			have.Labels, have.Spec = want.Labels, want.Spec
			return nil
		}); err != nil {
			return fmt.Errorf("make %s/%s: %w", w.namespace, w.name, err)
		}
	}
	return nil
}

// deploymentOf returns the Deployment of a workload: one replica of its image, which sleeps, as the pods of
// hack/measure-2a do. A scan reads an image's files and runs nothing, but the inventory sees images through the pods
// that run them.
func deploymentOf(w workload, image string) *appsv1.Deployment {
	labels := map[string]string{"app": w.name}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: w.name, Namespace: w.namespace, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To(int32(1)),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					// sleep as process 1 ignores SIGTERM, so the pod would wait for the end of its grace period.
					TerminationGracePeriodSeconds: ptr.To(int64(1)),
					AutomountServiceAccountToken:  ptr.To(false),
					EnableServiceLinks:            ptr.To(false),
					Containers: []corev1.Container{{
						Name: containerName, Image: image, Command: []string{"sleep", "86400"},
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
							SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
						},
					}},
				},
			},
		},
	}
}

// holdings are the hub's records of the inventory group, as one look read them.
type holdings struct {
	evidence    []inventoryv1alpha1.Evidence
	inventories []inventoryv1alpha1.ImageInventory
	sheets      []inventoryv1alpha1.ImageVerdicts
	ledgers     []inventoryv1alpha1.Ledger
	statuses    []inventoryv1alpha1.PlaybookClusterStatus
}

func (m *measurement) readHub(ctx context.Context) (*holdings, error) {
	var evidence inventoryv1alpha1.EvidenceList
	var inventories inventoryv1alpha1.ImageInventoryList
	var sheets inventoryv1alpha1.ImageVerdictsList
	var ledgers inventoryv1alpha1.LedgerList
	var statuses inventoryv1alpha1.PlaybookClusterStatusList
	for _, list := range []client.ObjectList{&evidence, &inventories, &sheets, &ledgers, &statuses} {
		if err := m.hub.api.List(ctx, list); err != nil {
			return nil, err
		}
	}
	return &holdings{evidence: evidence.Items, inventories: inventories.Items, sheets: sheets.Items,
		ledgers: ledgers.Items, statuses: statuses.Items}, nil
}

// missing returns what the hub doesn't hold yet of the load, or "" once it holds it all: an entry of each cluster that
// runs an image, with the workloads of the layout, the copy of each presence record with as many workloads, the facts
// of a scan of each image, and a sheet of each manifest. A failed scan is an error: the hub tries it again only after
// a while.
func (m *measurement) missing(held *holdings) (string, error) {
	inventories := map[string]*inventoryv1alpha1.ImageInventory{}
	for i := range held.inventories {
		inventories[held.inventories[i].Spec.Digest] = &held.inventories[i]
	}
	copied := map[[2]string]int{}
	for i := range held.evidence {
		e := &held.evidence[i]
		if e.Spec.Type != sdkevidence.TypePresence || e.Spec.Cluster == nil {
			continue
		}
		presence, err := presenceOf(e)
		if err != nil {
			return "", err
		}
		copied[[2]string{e.Spec.Subject, *e.Spec.Cluster}] = len(presence.Workloads)
	}
	sheets := map[string]bool{}
	for _, sheet := range held.sheets {
		if sheet.Spec.Playbook == sheetPlaybook && sheet.Status.Counts != nil {
			sheets[sheet.Spec.ManifestDigest] = true
		}
	}
	for s, spokeName := range m.names {
		for k, g := range imagesOf(s) {
			workloads, _ := layout(k)
			found := inventories[m.digests[g]]
			if found == nil {
				return fmt.Sprintf("the inventory of %s", imageName(g)), nil
			}
			entry := slices.IndexFunc(found.Status.Clusters, func(c inventoryv1alpha1.ClusterPresence) bool {
				return c.Cluster == spokeName && ptr.Deref(c.WorkloadCount, 0) == int32(workloads)
			})
			if entry < 0 {
				return fmt.Sprintf("the entry of %s in %s", spokeName, imageName(g)), nil
			}
			if copied[[2]string{subject.Image(m.digests[g]), spokeName}] != workloads {
				return fmt.Sprintf("the presence of %s in %s", imageName(g), spokeName), nil
			}
		}
	}
	for g := range loadImages {
		facts := inventories[m.digests[g]].Status.Facts
		switch {
		case facts == nil || len(facts.Manifests) == 0 && len(facts.Failures) == 0:
			return fmt.Sprintf("the scan of %s", imageName(g)), nil
		case len(facts.Manifests) == 0:
			return "", fmt.Errorf("the scan of %s failed: %s", imageName(g), facts.Failures[0].Reason)
		}
		for _, manifest := range facts.Manifests {
			if !sheets[manifest.Digest] {
				return fmt.Sprintf("the sheet of %s", imageName(g)), nil
			}
		}
	}
	return "", nil
}

// presenceOf decodes the data of a presence record.
func presenceOf(e *inventoryv1alpha1.Evidence) (*sdkevidence.Presence, error) {
	reader, err := gzip.NewReader(bytes.NewReader(e.Spec.Data))
	if err != nil {
		return nil, fmt.Errorf("the presence record %s: %w", e.Name, err)
	}
	var presence sdkevidence.Presence
	if err = json.NewDecoder(reader).Decode(&presence); err != nil {
		return nil, fmt.Errorf("the presence record %s: %w", e.Name, err)
	}
	return &presence, nil
}

// ---- what the hub holds ----

// sizeOf is the size of an object as the operator's own metrics measure it, such as vexplain_evidence_object_bytes:
// the length of the whole object as json.Marshal encodes it, managed fields included, close to what etcd holds.
func sizeOf(obj any) int {
	raw, err := json.Marshal(obj)
	if err != nil {
		return 0
	}
	return len(raw)
}

// tally is the count, the total and the largest of a group of sizes.
type tally struct {
	count, total, largest int
}

func (t *tally) add(size int) {
	t.count++
	t.total += size
	t.largest = max(t.largest, size)
}

// reportHoldings prints the hub's records by kind, the Evidence by collector and type with presence apart, the fits of
// the presence records and of the ImageInventory objects with their projections, and the share of etcd that the
// inventory group takes. The fits take the records of the load's images alone: those of the images that the spokes
// run for themselves, such as kind's own, have workloads of other kinds and names, and facts of failed scans.
func (m *measurement) reportHoldings(ctx context.Context, held *holdings) error {
	load := map[string]bool{}
	for _, digest := range m.digests {
		load[digest] = true
	}
	groups := map[string]*tally{}
	count := func(group string, size int) {
		if groups[group] == nil {
			groups[group] = &tally{}
		}
		groups[group].add(size)
	}
	var presence []point
	var largestPresence struct{ compressed, decoded, object, workloads int }
	for i := range held.evidence {
		e := &held.evidence[i]
		size := sizeOf(e)
		count("Evidence", size)
		if e.Spec.Type != sdkevidence.TypePresence {
			count("Evidence "+e.Spec.Source+" "+e.Spec.Type, size)
			continue
		}
		count("Evidence presence", size)
		decoded, err := presenceOf(e)
		if err != nil {
			return err
		}
		workloads, compressed := len(decoded.Workloads), len(e.Spec.Data)
		if load[strings.TrimPrefix(e.Spec.Subject, subject.Image(""))] {
			presence = append(presence, point{x: []float64{float64(workloads)}, y: []float64{float64(compressed),
				float64(ptr.Deref(e.Spec.UncompressedBytes, 0)), float64(size)}})
		}
		m.say("raw presence %s %s workloads=%d compressed=%d decoded=%d object=%d\n", ptr.Deref(e.Spec.Cluster, ""),
			e.Spec.Subject, workloads, compressed, ptr.Deref(e.Spec.UncompressedBytes, 0), size)
		if compressed > largestPresence.compressed {
			largestPresence.compressed, largestPresence.decoded = compressed, int(ptr.Deref(e.Spec.UncompressedBytes, 0))
			largestPresence.object, largestPresence.workloads = size, workloads
		}
	}
	var inventories []point
	for i := range held.inventories {
		inv := &held.inventories[i]
		size := sizeOf(inv)
		count("ImageInventory", size)
		var workloads, namespaces int
		for _, entry := range inv.Status.Clusters {
			workloads += len(entry.Workloads)
			namespaces += len(entry.Namespaces)
		}
		if load[inv.Spec.Digest] {
			inventories = append(inventories, point{x: []float64{float64(len(inv.Status.Clusters)),
				float64(workloads), float64(namespaces)}, y: []float64{float64(size)}})
		}
		m.say("raw inventory %s entries=%d workloads=%d namespaces=%d object=%d\n", inv.Spec.Digest,
			len(inv.Status.Clusters), workloads, namespaces, size)
	}
	for i := range held.sheets {
		count("ImageVerdicts", sizeOf(&held.sheets[i]))
	}
	for i := range held.ledgers {
		count("Ledger", sizeOf(&held.ledgers[i]))
	}
	for i := range held.statuses {
		count("PlaybookClusterStatus", sizeOf(&held.statuses[i]))
	}

	m.say("\nthe hub's records of the inventory group (bytes as JSON, managed fields included; %% of 512 KiB):\n")
	inventoryBytes := 0
	for _, group := range slices.Sorted(maps.Keys(groups)) {
		t := groups[group]
		m.say("  %-90s %5d objects %11d B, largest %9d B (%s)\n", group, t.count, t.total, t.largest,
			percent(float64(t.largest), triggerBytes))
		if !strings.Contains(group, " ") {
			inventoryBytes += t.total
		}
	}
	m.say("  all kinds: %d B\n", inventoryBytes)

	m.say("\nthe largest presence record: %d workloads, %d B compressed (%s of the evidence store's cap of %d B), "+
		"%d B decoded, %d B as an object (%s of 512 KiB)\n", largestPresence.workloads, largestPresence.compressed,
		percent(float64(largestPresence.compressed), settings.DefaultEvidenceMaxCompressedBytes),
		settings.DefaultEvidenceMaxCompressedBytes, largestPresence.decoded, largestPresence.object,
		percent(float64(largestPresence.object), triggerBytes))
	if err := m.reportPresenceFit(presence); err != nil {
		return err
	}
	if err := m.reportInventoryFit(inventories); err != nil {
		return err
	}
	return m.reportEtcd(ctx, inventoryBytes)
}

// percent formats part of whole as a percentage.
func percent(part, whole float64) string {
	return strconv.FormatFloat(100*part/whole, 'f', 1, 64) + "%"
}

// reportPresenceFit fits the bytes of a presence record against its workloads, compressed, decoded and as an object,
// and projects the workloads of one image in one cluster at which the record reaches the evidence store's cap, and at
// which its object reaches 512 KiB.
func (m *measurement) reportPresenceFit(points []point) error {
	m.say("\nbytes of a presence record = a + b x workloads, over the %d records of the load's images (each workload "+
		"with one pod of one container):\n", len(points))
	limits := []struct {
		what  string
		limit float64
	}{
		{"compressed, against the evidence store's cap of 768 KiB", settings.DefaultEvidenceMaxCompressedBytes},
		{"decoded, against the store's 64 MiB before compression", 64 << 20},
		{"as an object, against 0004's 512 KiB", triggerBytes},
	}
	for i, limit := range limits {
		fit, err := leastSquares(column(points, i))
		if err != nil {
			return fmt.Errorf("fit the presence records: %w", err)
		}
		m.say("  %-60s a=%8.1f b=%7.2f, largest residual %6.1f B; projected: reached at %.0f workloads\n",
			limit.what, fit.coefficients[0], fit.coefficients[1], fit.largestResidual,
			reachedAt(fit.coefficients[0], fit.coefficients[1], limit.limit))
	}
	return nil
}

// reportInventoryFit fits the bytes of an ImageInventory against its entries, the workloads that they list and the
// namespaces that they list, and projects the entries, one per cluster, at which an image's object reaches 512 KiB, and
// etcd's default limit of a request, 1.5 MiB, above which the hub can't write it at all. It does so for entries of a
// few sizes: the load's smallest, entries as large as the load's largest, and entries at the store's bounds, 100
// workloads and 100 namespaces by default, and 1000 namespaces at most.
func (m *measurement) reportInventoryFit(points []point) error {
	fit, err := leastSquares(column(points, 0))
	if err != nil {
		return fmt.Errorf("fit the ImageInventory objects: %w", err)
	}
	c := fit.coefficients
	m.say("\nbytes of an ImageInventory = a + b x entries + c x workloads listed + d x namespaces listed, over the %d "+
		"objects of the load's images:\n", len(points))
	m.say("  a=%.1f b=%.1f c=%.2f d=%.2f, largest residual %.1f B\n", c[0], c[1], c[2], c[3], fit.largestResidual)
	for _, entry := range []struct{ workloads, namespaces float64 }{{1, 1}, {28, 10}, {100, 100}, {100, 1000}} {
		perEntry := c[1] + c[2]*entry.workloads + c[3]*entry.namespaces
		m.say("  projected: entries of %3.0f workloads in %4.0f namespaces take %8.0f B each, and reach 512 KiB at "+
			"%.1f clusters, 1.5 MiB at %.1f\n", entry.workloads, entry.namespaces, perEntry,
			reachedAt(c[0], perEntry, triggerBytes), reachedAt(c[0], perEntry, etcdRequestBytes))
	}
	return nil
}

// reportEtcd prints the size of the hub's etcd, as the API server reports the file and etcd its use, and the share of
// it that the inventory group's objects take.
func (m *measurement) reportEtcd(ctx context.Context, inventoryBytes int) error {
	families, err := apiServerMetrics(ctx, m.hub)
	if err != nil {
		return err
	}
	file := gaugeOf(families, "apiserver_storage_size_bytes")
	raw, err := docker(ctx, "exec", m.hub.node(), "curl", "-s", "http://127.0.0.1:2381/metrics")
	if err != nil {
		return err
	}
	etcd, err := parseMetrics([]byte(raw))
	if err != nil {
		return err
	}
	inUse := gaugeOf(etcd, "etcd_mvcc_db_total_size_in_use_in_bytes")
	m.say("\netcd of the hub: the file %.0f B, in use %.0f B; the inventory group's objects %d B, %s of the file and "+
		"%s of the use (0004's trigger: %s)\n", file, inUse, inventoryBytes, percent(float64(inventoryBytes), file),
		percent(float64(inventoryBytes), inUse), percent(triggerEtcdShare, 1))
	for _, f := range families["apiserver_storage_objects"].GetMetric() {
		if resource := labelsOf(f)["resource"]; strings.HasSuffix(resource, "."+inventoryGroup) {
			m.say("raw objects %s %.0f\n", resource, f.GetGauge().GetValue())
		}
	}
	return nil
}

// ---- fits and projections ----

// point is one measured object: the counts x that its size is fitted against, and its sizes y, of which a fit takes
// one.
type point struct {
	x, y []float64
}

// column returns the points with their i-th size as their only one.
func column(points []point, i int) []point {
	out := make([]point, len(points))
	for j, p := range points {
		out[j] = point{x: p.x, y: []float64{p.y[i]}}
	}
	return out
}

// fit is the result of a least-squares fit: the coefficients of y = c0 + c1 x1 + c2 x2 ..., and the largest distance
// of a point's y from the fitted line, which shows how well the counts explain the sizes.
type fit struct {
	coefficients    []float64
	largestResidual float64
}

// leastSquares fits y = c0 + c1 x1 + ... to the points by least squares, through the normal equations solved by
// Gauss-Jordan elimination with partial pivoting. It fails when the points can't tell a term from the others, as when
// a count never varies or always varies with another.
func leastSquares(points []point) (fit, error) {
	if len(points) == 0 {
		return fit{}, errors.New("no points")
	}
	n := len(points[0].x) + 1
	// The augmented matrix [XᵀX | Xᵀy], where each row of X is 1 followed by a point's counts.
	a := make([][]float64, n)
	for i := range a {
		a[i] = make([]float64, n+1)
	}
	for _, p := range points {
		row := append([]float64{1}, p.x...)
		for i := range n {
			for j := range n {
				a[i][j] += row[i] * row[j]
			}
			a[i][n] += row[i] * p.y[0]
		}
	}
	for col := range n {
		pivot := col
		for r := col + 1; r < n; r++ {
			if math.Abs(a[r][col]) > math.Abs(a[pivot][col]) {
				pivot = r
			}
		}
		if math.Abs(a[pivot][col]) < 1e-9 {
			return fit{}, errors.New("the points don't tell the terms apart")
		}
		a[col], a[pivot] = a[pivot], a[col]
		for r := range n {
			if r == col {
				continue
			}
			factor := a[r][col] / a[col][col]
			for c := col; c <= n; c++ {
				a[r][c] -= factor * a[col][c]
			}
		}
	}
	result := fit{coefficients: make([]float64, n)}
	for i := range n {
		result.coefficients[i] = a[i][n] / a[i][i]
	}
	for _, p := range points {
		predicted := result.coefficients[0]
		for i, x := range p.x {
			predicted += result.coefficients[i+1] * x
		}
		result.largestResidual = max(result.largestResidual, math.Abs(p.y[0]-predicted))
	}
	return result, nil
}

// reachedAt returns the count at which intercept + slope x count reaches limit: a projection along the fitted line,
// which holds only as far as the bytes keep growing as they did in the load.
func reachedAt(intercept, slope, limit float64) float64 {
	if slope <= 0 {
		return math.Inf(1)
	}
	return (limit - intercept) / slope
}

// ---- the writes ----

// writeSample is the count of the API server's writes to etcd of the inventory group's objects, by resource, at a
// moment: its creates, updates and deletes, which a record that didn't change doesn't make.
type writeSample struct {
	at         time.Time
	byResource map[string]float64
}

func (s writeSample) total() float64 {
	total := 0.0
	for _, n := range s.byResource {
		total += n
	}
	return total
}

// sampleWrites samples the hub's writes every writePoll until ctx ends.
func (m *measurement) sampleWrites(ctx context.Context) {
	for {
		if families, err := apiServerMetrics(ctx, m.hub); err == nil {
			sample := writeSample{at: time.Now(), byResource: inventoryWrites(families)}
			m.writesMu.Lock()
			m.writes = append(m.writes, sample)
			m.writesMu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(writePoll):
		}
	}
}

// mark returns the index of the latest sample of writes, once there is one.
func (m *measurement) mark() int {
	for {
		m.writesMu.Lock()
		n := len(m.writes)
		m.writesMu.Unlock()
		if n > 0 {
			return n - 1
		}
		time.Sleep(time.Second)
	}
}

// samplesBetween returns a copy of the samples from begin to end, both included.
func (m *measurement) samplesBetween(begin, end int) []writeSample {
	m.writesMu.Lock()
	defer m.writesMu.Unlock()
	return slices.Clone(m.writes[begin : end+1])
}

// inventoryWrites sums etcd_requests_total of the inventory group by resource, over the operations that write.
func inventoryWrites(families map[string]*dto.MetricFamily) map[string]float64 {
	out := map[string]float64{}
	for _, metric := range families["etcd_requests_total"].GetMetric() {
		labels := labelsOf(metric)
		switch labels["operation"] {
		case "create", "update", "delete":
			if labels["group"] == inventoryGroup {
				out[labels["resource"]] += metric.GetCounter().GetValue()
			}
		}
	}
	return out
}

// waitQuiet waits until the hub has written at most quietWrites to the inventory group in the last quietFor of the
// phase whose first sample of writes is from: a write now and then, which the hub may make on a timer, doesn't keep a
// phase from ending, and a phase lasts quietFor at least.
func (m *measurement) waitQuiet(ctx context.Context, from int) error {
	return m.waitFor(ctx, "the hub's writes to stand still for "+quietFor.String(), func(context.Context) (bool, error) {
		m.writesMu.Lock()
		defer m.writesMu.Unlock()
		last := m.writes[len(m.writes)-1]
		for _, earlier := range slices.Backward(m.writes[from:]) {
			if last.at.Sub(earlier.at) >= quietFor {
				return last.total()-earlier.total() <= quietWrites, nil
			}
		}
		return false, nil
	})
}

// rates are the writes of a stretch of samples: their count, the mean rate, and the highest rates over a window of
// 10 seconds and of a minute.
type rates struct {
	writes                    float64
	duration                  time.Duration
	mean, peak10s, peakMinute float64
	byResource                map[string]float64
}

// ratesOf measures the samples, which are in the order of their times.
func ratesOf(samples []writeSample) rates {
	first, last := samples[0], samples[len(samples)-1]
	r := rates{writes: last.total() - first.total(), duration: last.at.Sub(first.at), byResource: map[string]float64{}}
	for resource, n := range last.byResource {
		r.byResource[resource] = n - first.byResource[resource]
	}
	if r.duration > 0 {
		r.mean = r.writes / r.duration.Seconds()
	}
	r.peak10s, r.peakMinute = peakRate(samples, 10*time.Second), peakRate(samples, time.Minute)
	return r
}

// peakRate returns the highest rate of writes over any stretch between two samples that is at least window long.
func peakRate(samples []writeSample, window time.Duration) float64 {
	peak := 0.0
	for i := range samples {
		for j := i + 1; j < len(samples); j++ {
			if took := samples[j].at.Sub(samples[i].at); took >= window {
				peak = max(peak, (samples[j].total()-samples[i].total())/took.Seconds())
			}
		}
	}
	return peak
}

// reportWrites prints the writes of a phase against 0004's trigger, and the raw samples.
func (m *measurement) reportWrites(phase string) {
	bounds := m.phases[phase]
	samples := m.samplesBetween(bounds[0], bounds[1])
	r := ratesOf(samples)
	m.say("writes to etcd of the inventory group, %s: %.0f in %s, %.2f/s on average, at most %.2f/s over 10 s and "+
		"%.2f/s over a minute (0004's trigger: %.0f/s sustained)\n", phase, r.writes, r.duration.Round(time.Second),
		r.mean, r.peak10s, r.peakMinute, triggerWriteRate)
	for _, resource := range slices.Sorted(maps.Keys(r.byResource)) {
		m.say("  %s: %.0f\n", resource, r.byResource[resource])
	}
	for _, s := range samples {
		m.say("raw writes %s %s %.0f\n", phase, s.at.Format(time.RFC3339), s.total())
	}
	if pod, u := m.manager(); u != nil {
		m.say("the manager's memory at the end of the phase: %.1f MiB, at most %.1f MiB since %s started\n",
			mebibytes(u.currentBytes), mebibytes(u.peakBytes), pod)
	}
}

// ---- the phases after the load ----

// measureIdle counts the hub's writes while nothing changes, for --idle.
func (m *measurement) measureIdle(ctx context.Context) error {
	begin := m.mark()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(m.opts.idle):
	}
	m.phases["idle"] = [2]int{begin, m.mark()}
	m.reportWrites("idle")
	return nil
}

// rollOut rolls 50 workloads of the first spoke out, by a new annotation on their pod templates, waits until each runs
// its new pod alone and the hub's writes stand still, and counts the writes from the first change on.
func (m *measurement) rollOut(ctx context.Context) error {
	spoke := m.spokes[0]
	begin := m.mark()
	started := time.Now()
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{%q:%q}}}}}`, rolloutAnnotation,
		started.Format(time.RFC3339))
	for _, w := range rolled() {
		deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: w.name, Namespace: w.namespace}}
		if err := spoke.api.Patch(ctx, deployment, client.RawPatch(k8stypes.MergePatchType, []byte(patch))); err != nil {
			return fmt.Errorf("roll %s/%s out: %w", w.namespace, w.name, err)
		}
	}
	err := m.waitFor(ctx, "the rollout on "+m.names[0], func(ctx context.Context) (bool, error) {
		for _, w := range rolled() {
			var found appsv1.Deployment
			if err := spoke.api.Get(ctx, client.ObjectKey{Namespace: w.namespace, Name: w.name}, &found); err != nil {
				return false, err
			}
			status := found.Status
			if status.ObservedGeneration < found.Generation || status.UpdatedReplicas != 1 || status.Replicas != 1 ||
				status.AvailableReplicas != 1 {
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	m.say("the rollout of %d workloads took %s\n", len(rolled()), time.Since(started).Round(time.Second))
	if err = m.waitQuiet(ctx, begin); err != nil {
		return err
	}
	m.phases["rollout"] = [2]int{begin, m.mark()}
	m.reportWrites("rollout")
	return nil
}

// restart deletes the hub's manager pod, and measures how long the new one takes until each Spoke is Synced again:
// the wait for the old manager's lease, which it doesn't release, and the copier's first round once the new one leads.
func (m *measurement) restart(ctx context.Context) error {
	old, err := managerPod(ctx, m.hub, "")
	if err != nil {
		return err
	}
	begin := m.mark()
	deleted := time.Now()
	if err = m.hub.api.Delete(ctx, old); err != nil {
		return err
	}
	// The conditions keep whole seconds, so the tool looks five times a second and takes the time of its look. A
	// condition that turned in the second of the deletion counts as after it.
	since := deleted.Truncate(time.Second)
	synced := map[string]time.Time{}
	m.say("waiting for the Spokes to be Synced again\n")
	err = wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, m.opts.timeout, true,
		func(ctx context.Context) (bool, error) {
			for _, spokeName := range m.names {
				if _, seen := synced[spokeName]; seen {
					continue
				}
				var found configv1alpha1.Spoke
				if err := m.hub.api.Get(ctx, client.ObjectKey{Name: spokeName}, &found); err != nil {
					return false, err
				}
				c := meta.FindStatusCondition(found.Status.Conditions, configv1alpha1.ConditionSynced)
				if c != nil && c.Status == metav1.ConditionTrue && !c.LastTransitionTime.Time.Before(since) {
					synced[spokeName] = time.Now()
				}
			}
			return len(synced) == len(m.names), nil
		})
	if err != nil {
		return fmt.Errorf("waiting for the Spokes to be Synced again: %w", err)
	}
	pod, err := managerPod(ctx, m.hub, old.UID)
	if err != nil || pod == nil || len(pod.Status.ContainerStatuses) == 0 ||
		pod.Status.ContainerStatuses[0].State.Running == nil {
		return fmt.Errorf("the new manager doesn't run: %w", err)
	}
	started := pod.Status.ContainerStatuses[0].State.Running.StartedAt.Time
	lease, err := m.hub.clientset.CoordinationV1().Leases(operatorNamespace).Get(ctx, managerLease,
		metav1.GetOptions{})
	if err != nil {
		return err
	}
	if !strings.HasPrefix(ptr.Deref(lease.Spec.HolderIdentity, ""), pod.Name+"_") || lease.Spec.AcquireTime == nil {
		return errors.New("the new manager doesn't hold the lease")
	}
	acquired := lease.Spec.AcquireTime.Time
	m.say("after the deletion, the new manager's container started within %s, and it took the lease after %s\n",
		started.Sub(since), acquired.Sub(deleted).Round(10*time.Millisecond))
	for _, spokeName := range m.names {
		m.say("%s: seen Synced %s after the deletion, %s after the new manager took the lease\n", spokeName,
			synced[spokeName].Sub(deleted).Round(10*time.Millisecond),
			synced[spokeName].Sub(acquired).Round(10*time.Millisecond))
	}
	if err = m.waitQuiet(ctx, begin); err != nil {
		return err
	}
	m.phases["restart"] = [2]int{begin, m.mark()}
	m.reportWrites("restart")
	return nil
}

// managerPod returns the hub's manager pod, other than the one of the UID not, or nil while there is none.
func managerPod(ctx context.Context, c *cluster, not k8stypes.UID) (*corev1.Pod, error) {
	pods, err := c.clientset.CoreV1().Pods(operatorNamespace).List(ctx, metav1.ListOptions{LabelSelector: managerLabels})
	if err != nil {
		return nil, err
	}
	for i := range pods.Items {
		if pod := &pods.Items[i]; pod.UID != not && pod.DeletionTimestamp == nil {
			return pod, nil
		}
	}
	if not == "" {
		return nil, errors.New("the hub runs no manager")
	}
	return nil, nil
}

// ---- the scans ----

// reportScans prints the scan Jobs that the hub made since the load's deployment, from their events, which outlive the
// Jobs, and the scanner's own count and times of its scans. A Job's events can't time a scan: the scanner deletes the
// Job once it has read the result, often before the Job's controller tells of its completion. The sampler times the
// scan pods instead (reportUsage).
func (m *measurement) reportScans(ctx context.Context, deployed time.Time) error {
	events, err := m.hub.clientset.CoreV1().Events(operatorNamespace).List(ctx,
		metav1.ListOptions{FieldSelector: "involvedObject.kind=Job"})
	if err != nil {
		return err
	}
	var created []time.Duration
	others := 0
	for _, event := range events.Items {
		if event.Reason != "SuccessfulCreate" || !strings.HasPrefix(event.InvolvedObject.Name, "scan-") {
			continue
		}
		at := event.FirstTimestamp.Time
		if !event.EventTime.IsZero() {
			at = event.EventTime.Time
		}
		m.say("raw scan %s load=%t %s\n", event.InvolvedObject.Name, m.ofLoad(event.InvolvedObject.Name),
			at.Format(time.RFC3339))
		if !m.ofLoad(event.InvolvedObject.Name) {
			others++
			continue
		}
		created = append(created, at.Sub(deployed).Round(time.Second))
	}
	slices.Sort(created)
	m.say("\nscan Jobs on the hub: %d of the load's images, made after the load's deployment: %s; %d of other images\n",
		len(created), spread(created), others)
	families, err := collectorMetrics(ctx, m.hub, scannerCollector)
	if err != nil {
		return err
	}
	for _, metric := range families["vexplain_scanner_scans_total"].GetMetric() {
		m.say("  the scanner's count: %s %.0f\n", labelsOf(metric)["result"], metric.GetCounter().GetValue())
	}
	for _, metric := range families["vexplain_scanner_scan_duration_seconds"].GetMetric() {
		h := metric.GetHistogram()
		if h.GetSampleCount() == 0 {
			continue
		}
		m.say("  the scanner's time in a slot, %s: %d scans, %.1f s on average;", labelsOf(metric)["result"],
			h.GetSampleCount(), h.GetSampleSum()/float64(h.GetSampleCount()))
		for _, bucket := range h.GetBucket() {
			m.say(" %d within %.0f s,", bucket.GetCumulativeCount(), bucket.GetUpperBound())
		}
		m.say("\n")
	}
	return nil
}

// spread formats sorted durations as their least, median and most.
func spread[T cmp.Ordered](values []T) string {
	if len(values) == 0 {
		return "none"
	}
	return fmt.Sprintf("least %v, median %v, most %v", values[0], values[len(values)/2], values[len(values)-1])
}

// ---- the series ----

// reportSeries prints the series of vexplain_open_case on the hub, by cluster, and the size of the whole scrape.
func (m *measurement) reportSeries(ctx context.Context) error {
	raw, err := m.scrapeManager(ctx)
	if err != nil {
		return err
	}
	families, err := parseMetrics(raw)
	if err != nil {
		return err
	}
	byCluster := map[string]int{}
	for _, metric := range families["vexplain_open_case"].GetMetric() {
		byCluster[labelsOf(metric)["cluster"]]++
	}
	series := 0
	for _, family := range families {
		series += len(family.GetMetric())
	}
	openCaseBytes := 0
	for line := range bytes.Lines(raw) {
		if bytes.HasPrefix(line, []byte("vexplain_open_case{")) {
			openCaseBytes += len(line)
		}
	}
	m.say("\nthe manager's metrics: %d B, %d series in %d families; vexplain_open_case: %d series in %d B\n", len(raw),
		series, len(families), len(families["vexplain_open_case"].GetMetric()), openCaseBytes)
	for _, clusterName := range slices.Sorted(maps.Keys(byCluster)) {
		m.say("  %s: %d\n", clusterName, byCluster[clusterName])
	}
	return nil
}

// scrapeManager reads the hub manager's metrics through a port forward of kubectl, with a token of the tool's own
// ServiceAccount, which may read them. The token stays in memory.
func (m *measurement) scrapeManager(ctx context.Context) ([]byte, error) {
	account := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: toolAccount, Namespace: operatorNamespace}}
	if err := m.hub.api.Create(ctx, account); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: toolAccount},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: metricsReader},
		Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: toolAccount, Namespace: operatorNamespace}}}
	if err := m.hub.api.Create(ctx, binding); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, err
	}
	token, err := m.hub.clientset.CoreV1().ServiceAccounts(operatorNamespace).CreateToken(ctx, toolAccount,
		&authenticationv1.TokenRequest{}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	pod, err := managerPod(ctx, m.hub, "")
	if err != nil {
		return nil, err
	}
	address, stop, err := portForward(ctx, m.hub, pod.Name, managerMetricsPort)
	if err != nil {
		return nil, err
	}
	defer stop()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/metrics", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token.Status.Token)
	// The manager serves its metrics with a certificate of its own making, at the end of a forward to 127.0.0.1. The
	// transport has no proxy, so the request stays on the machine.
	httpClient := &http.Client{Timeout: time.Minute, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // see above
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the manager's metrics answered %s", response.Status)
	}
	return io.ReadAll(response.Body)
}

// forwardingPattern finds the local port in what kubectl port-forward prints once it forwards.
var forwardingPattern = regexp.MustCompile(`^Forwarding from 127\.0\.0\.1:([0-9]+) `)

// portForward forwards a free local port to the port of the pod in the operator's namespace with kubectl, which reads
// the cluster's own kubeconfig, and returns its address and a function that stops the forward.
func portForward(ctx context.Context, c *cluster, pod string, port int) (string, func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", c.kubeconfig, "port-forward", "-n", operatorNamespace,
		"pod/"+pod, ":"+strconv.Itoa(port))
	output, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return "", nil, err
	}
	if err = cmd.Start(); err != nil {
		cancel()
		return "", nil, err
	}
	stop := func() {
		cancel()
		_ = cmd.Wait()
	}
	lines := bufio.NewScanner(output)
	for lines.Scan() {
		if found := forwardingPattern.FindStringSubmatch(lines.Text()); found != nil {
			go func() {
				for lines.Scan() { // kubectl blocks once nobody reads what it prints.
				}
			}()
			return "127.0.0.1:" + found[1], stop, nil
		}
	}
	stop()
	return "", nil, errors.New("kubectl port-forward ended before it forwarded")
}

// apiServerMetrics reads the metrics of the cluster's API server.
func apiServerMetrics(ctx context.Context, c *cluster) (map[string]*dto.MetricFamily, error) {
	raw, err := c.clientset.CoreV1().RESTClient().Get().AbsPath("/metrics").DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the API server's metrics: %w", err)
	}
	return parseMetrics(raw)
}

// collectorMetrics reads the metrics of the pod of a collector's Deployment, which a collector serves in plain HTTP,
// through the API server's proxy.
func collectorMetrics(ctx context.Context, c *cluster, deployment string) (map[string]*dto.MetricFamily, error) {
	pods, err := podsOf(ctx, c, deployment)
	if err != nil {
		return nil, err
	}
	if len(pods) == 0 {
		return nil, fmt.Errorf("%s has no pod", deployment)
	}
	raw, err := c.clientset.CoreV1().RESTClient().Get().Namespace(operatorNamespace).Resource("pods").
		Name(pods[0].Name + ":" + strconv.Itoa(collectorMetricsPort)).SubResource("proxy").Suffix("metrics").
		DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the metrics of %s: %w", deployment, err)
	}
	return parseMetrics(raw)
}

// parseMetrics parses metrics in Prometheus' text format.
func parseMetrics(raw []byte) (map[string]*dto.MetricFamily, error) {
	parser := expfmt.NewTextParser(model.UTF8Validation)
	return parser.TextToMetricFamilies(bytes.NewReader(raw))
}

// gaugeOf sums the values of the series of a gauge.
func gaugeOf(families map[string]*dto.MetricFamily, family string) float64 {
	total := 0.0
	for _, metric := range families[family].GetMetric() {
		total += metric.GetGauge().GetValue()
	}
	return total
}

func labelsOf(metric *dto.Metric) map[string]string {
	labels := map[string]string{}
	for _, pair := range metric.GetLabel() {
		labels[pair.GetName()] = pair.GetValue()
	}
	return labels
}

// ---- what the pods use ----

// podInfo is what the tool saw of a pod of the hub's operator namespace.
type podInfo struct {
	name      string
	scan      bool
	manager   bool
	resources corev1.ResourceRequirements
}

// podNames keeps the pods of the hub's operator namespace by UID, as the tool lists them every second, so that the
// cgroups that the sampler reads by UID can be named, those of the scan Jobs' pods too, which live seconds.
type podNames struct {
	mu   sync.Mutex
	byID map[string]podInfo
}

func watchPods(ctx context.Context, c *cluster) *podNames {
	names := &podNames{byID: map[string]podInfo{}}
	go func() {
		for ctx.Err() == nil {
			if pods, err := c.clientset.CoreV1().Pods(operatorNamespace).List(ctx, metav1.ListOptions{}); err == nil {
				names.mu.Lock()
				for _, pod := range pods.Items {
					_, scan := pod.Labels[scannerLabel]
					info := podInfo{name: pod.Name, scan: scan, manager: pod.Labels["control-plane"] == "controller-manager"}
					if len(pod.Spec.Containers) > 0 {
						info.resources = pod.Spec.Containers[0].Resources
					}
					names.byID[string(pod.UID)] = info
				}
				names.mu.Unlock()
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}()
	return names
}

func (p *podNames) get(uid string) (podInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	info, ok := p.byID[uid]
	return info, ok
}

// podUsage is what the sampler read of one pod's cgroup: its peak memory, which the kernel keeps since the pod's start,
// its memory and CPU time at the last reading, and when it read it first and last.
type podUsage struct {
	peakBytes, currentBytes, cpuMicros int64
	first, last                        time.Time
}

// sampler reads the cgroup of every pod on the hub's node every second, through one docker exec that runs while the
// tool does: its peak memory (memory.peak), its memory now (memory.current), and its CPU time (usage_usec of cpu.stat).
type sampler struct {
	mu   sync.Mutex
	pods map[string]*podUsage
}

// samplerScript prints a line for each pod's cgroup every second: the time, the pod's UID as the cgroup's name spells
// it, its peak memory, its memory now and its CPU time in microseconds. Kind's kubelet puts the pods of each QoS class
// under kubelet-kubepods.slice, the Guaranteed ones directly.
const samplerScript = `cd /sys/fs/cgroup/kubelet.slice/kubelet-kubepods.slice || exit 1
while :; do
  t=$(date +%s)
  for d in kubelet-kubepods-pod*.slice kubelet-kubepods-*.slice/kubelet-kubepods-*-pod*.slice; do
    [ -r "$d/memory.peak" ] || continue
    u=${d##*-pod}
    echo "$t ${u%.slice} $(cat "$d/memory.peak") $(cat "$d/memory.current") $(sed -n 's/^usage_usec //p' "$d/cpu.stat")"
  done
  sleep 1
done`

func startSampler(ctx context.Context, node string) (*sampler, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", node, "sh", "-c", samplerScript)
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("start the sampler of the hub's cgroups: %w", err)
	}
	s := &sampler{pods: map[string]*podUsage{}}
	go func() {
		lines := bufio.NewScanner(output)
		for lines.Scan() {
			s.record(lines.Text())
		}
		_ = cmd.Wait()
	}()
	return s, nil
}

// record keeps what a line of samplerScript says. A line that it can't read is left out.
func (s *sampler) record(line string) {
	fields := strings.Fields(line)
	if len(fields) != 5 {
		return
	}
	var numbers [4]int64
	for i, field := range append([]string{fields[0]}, fields[2:]...) {
		n, err := strconv.ParseInt(field, 10, 64)
		if err != nil {
			return
		}
		numbers[i] = n
	}
	at := time.Unix(numbers[0], 0)
	uid := strings.ReplaceAll(fields[1], "_", "-")
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.pods[uid]
	if u == nil {
		u = &podUsage{first: at}
		s.pods[uid] = u
	}
	u.peakBytes, u.currentBytes = max(u.peakBytes, numbers[1]), numbers[2]
	u.cpuMicros, u.last = max(u.cpuMicros, numbers[3]), at
}

// manager returns the name and the usage of the manager pod that the sampler read last, or nil before it read one.
func (m *measurement) manager() (string, *podUsage) {
	m.usage.mu.Lock()
	defer m.usage.mu.Unlock()
	var podName string
	var newest *podUsage
	for uid, u := range m.usage.pods {
		if info, ok := m.pods.get(uid); ok && info.manager && (newest == nil || u.last.After(newest.last)) {
			podName, newest = info.name, u
		}
	}
	if newest == nil {
		return "", nil
	}
	return podName, new(*newest)
}

func mebibytes(b int64) float64 { return float64(b) / (1 << 20) }

// ofLoad says whether a scan Job or its pod scans an image of the load: the scanner names a Job after the first 12
// digits of the image's digest, and the Job names its pods after itself.
func (m *measurement) ofLoad(scanName string) bool {
	for _, digest := range m.digests {
		if strings.HasPrefix(scanName, "scan-"+strings.TrimPrefix(digest, "sha256:")[:12]+"-") {
			return true
		}
	}
	return false
}

// reportUsage prints the memory and CPU time of each manager pod of the run, and the peak memory and CPU time of the
// scan Jobs' pods of the load's images, with their requests and limits.
func (m *measurement) reportUsage() {
	m.usage.mu.Lock()
	defer m.usage.mu.Unlock()
	var scanPeaks []int64
	var scanCPU, scanLives []time.Duration
	var resources corev1.ResourceRequirements
	others := 0
	for _, uid := range slices.Sorted(maps.Keys(m.usage.pods)) {
		u := m.usage.pods[uid]
		info, ok := m.pods.get(uid)
		switch {
		case !ok:
			continue
		case info.manager:
			m.say("\nthe manager's pod %s: memory at most %.1f MiB, %.1f MiB at the end of the run; CPU %.1f s, "+
				"seen from %s to %s\n", info.name, mebibytes(u.peakBytes), mebibytes(u.currentBytes),
				float64(u.cpuMicros)/1e6, u.first.Format(time.RFC3339), u.last.Format(time.RFC3339))
		case info.scan && m.ofLoad(info.name):
			// The sampler reads each cgroup once a second, so a pod that it read from first to last lived about a
			// second more.
			life := u.last.Sub(u.first) + time.Second
			scanPeaks = append(scanPeaks, u.peakBytes)
			scanCPU = append(scanCPU, time.Duration(u.cpuMicros)*time.Microsecond)
			scanLives = append(scanLives, life)
			resources = info.resources
			m.say("raw scanpod %s peak=%d cpu_us=%d life=%s\n", info.name, u.peakBytes, u.cpuMicros, life)
		case info.scan:
			others++
		}
	}
	slices.Sort(scanPeaks)
	slices.Sort(scanCPU)
	slices.Sort(scanLives)
	m.say("\nthe scan Jobs' pods of the load's images that the sampler saw: %d, and %d of other images; their lives on "+
		"the node: %s; memory at most: %s B; CPU time: %s; requests %s, limits %s\n", len(scanPeaks), others,
		spread(scanLives), spread(scanPeaks), spread(scanCPU), quantities(resources.Requests),
		quantities(resources.Limits))
}

// quantities formats a list of resources as name=quantity, sorted by name.
func quantities(list corev1.ResourceList) string {
	out := make([]string, 0, len(list))
	for _, resourceName := range slices.Sorted(maps.Keys(list)) {
		quantity := list[resourceName]
		out = append(out, string(resourceName)+"="+quantity.String())
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ",")
}
