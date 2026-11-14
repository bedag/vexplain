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

// Command scanner is vexplain's scanner collector, and the scan that its scan Jobs run. It has two
// subcommands:
//
//	scanner serve
//	scanner scan --image registry.example/team-a/app@sha256:… --platform linux/amd64 [--platform …]
//	        [--work /work] [--max-bytes N] [--syft /usr/local/bin/syft]
//	        [--registry-mirror registry.example=https://mirror.example …]
//
// serve serves the collector, for the spoke of vexplain in its cluster. It runs a scan Job for each
// image that vexplain asks it to scan, with its own image and the subcommand scan, and makes
// evidence of what the Job found. The image's default command is serve, which the collector's
// Deployment runs.
//
// scan scans one image, in its scan Job (decision 0022): it pulls the image by digest, unpacks the
// filesystem of each platform manifest to scan, catalogs it with Syft, analyses it, and prints one
// line, which the collector reads from the Job's log. stdout carries exactly that line: the result
// line of package result when the scan succeeds, with exit code 0, or its error line, with exit code
// 1. The scan fails as a whole when one manifest fails. Bad flags fail it too, with the reason
// Internal and no usage text.
//
// The image is untrusted, and the log is where the collector takes the evidence from. A file name in
// the image, or a platform in its index, can hold a newline followed by a forged result line. So the
// scan prints only lines of its own: stderr carries fixed progress texts with counts, Syft's output
// is discarded, and no error's text is ever printed, only its reason. The pull credentials come from
// the Docker configs $DOCKER_CONFIG/config-0.json, config-1.json and so on, whose logins the scan
// tries in that order, and are never printed either.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/bedag/vexplain/collectors/scanner/internal/analyze"
	"github.com/bedag/vexplain/collectors/scanner/internal/pull"
	"github.com/bedag/vexplain/collectors/scanner/internal/result"
	"github.com/bedag/vexplain/collectors/scanner/internal/scan"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/jobs"
	"github.com/bedag/vexplain/sdk/workloads"
)

// version is the version of the collector, which GetInfo reports. The build sets it.
var version = "0.1.0"

// The subcommands.
const (
	serveCommand = "serve"
	scanCommand  = "scan"
)

const (
	// nameVariable holds the name of the collector's Collector, and namespaceVariable its namespace, which
	// vexplain's deployer sets.
	nameVariable      = "VEXPLAIN_COLLECTOR_NAME"
	namespaceVariable = "POD_NAMESPACE"
	// defaultName is the name of the built-in Collector, when the variable says none.
	defaultName = "scanner"
	// collectorContainer is the container of the collector's Deployment, as vexplain's deployer names it.
	collectorContainer = "collector"
	// ownImagePatience is how long a scan waits for the status of the collector's container to report the image that
	// it runs, and ownImagePoll how often it reads the pod meanwhile. The kubelet reports it within seconds of the
	// container's start, which the first scan normally comes long after.
	ownImagePatience = 15 * time.Second
	ownImagePoll     = 500 * time.Millisecond
	// exitUsage is the exit code of a command line without a subcommand that the binary knows.
	exitUsage = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := dispatch(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop() // os.Exit doesn't run deferred calls.
	os.Exit(code)
}

// dispatch runs the subcommand that the first argument names, with the rest, and returns the exit code.
func dispatch(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case serveCommand:
			return serveMain(ctx, args[1:], getenv)
		case scanCommand:
			return run(ctx, args[1:], getenv, stdout, stderr)
		}
	}
	_, _ = fmt.Fprintln(stderr, "usage: scanner serve | scanner scan --image <repository@digest> --platform <os/arch> ...")
	return exitUsage
}

// serveMain serves the collector until ctx ends, in the cluster that it runs in, and returns the exit code. It takes
// no arguments.
func serveMain(ctx context.Context, args []string, getenv func(string) string) int {
	// The client logs through controller-runtime's logger, and the SDK's server through slog: both go to slog.
	ctrllog.SetLogger(logr.FromSlogHandler(slog.Default().Handler()))
	if len(args) > 0 {
		slog.Error("serve takes no arguments")
		return exitUsage
	}
	// The collector reads the cluster that it runs in, with its own service account, and no other: it never reads a
	// kubeconfig.
	cfg, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("The collector reads the cluster that it runs in, and runs in none", "error", err)
		return exitFailed
	}
	if err := serve(ctx, cfg, collector.OptionsFromEnv(), getenv); err != nil {
		slog.Error("The collector failed", "error", err)
		return exitFailed
	}
	return exitOK
}

// serve serves the collector, under the name of its Collector, until ctx ends. It reads the API server directly,
// without a cache: it reads a few objects per scan, by name, and must never hold the Secrets of the cluster. Its scan
// Jobs run the image of its own pod, in its namespace, with the environment that its settings' scanPod.env give them,
// and the pull secrets that the admin provides are in that namespace too, the operator's. It reads nothing of the
// cluster before it serves: the collector starts without its permissions, which vexplain grants once it has read them
// (decision 0041), and only a scan, which comes once the collector is Ready, reads with them. /metrics serves the
// scanner's metrics with the SDK's.
func serve(ctx context.Context, cfg *rest.Config, opts collector.Options, getenv func(string) string) error {
	namespace := getenv(namespaceVariable)
	if namespace == "" {
		return fmt.Errorf("%s says no namespace, where the scan Jobs run", namespaceVariable)
	}
	collectorName := getenv(nameVariable)
	if collectorName == "" {
		collectorName = defaultName
	}
	c, err := client.New(cfg, client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		return fmt.Errorf("build the client of the cluster: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("build the clientset of the cluster: %w", err)
	}
	pod, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("read the name of the collector's pod: %w", err)
	}
	metrics := scan.NewMetrics()
	registry := prometheus.NewRegistry()
	if err := registry.Register(metrics); err != nil {
		return fmt.Errorf("register the scanner's metrics: %w", err)
	}
	opts.Registry = registry
	return collector.Serve(ctx, scan.New(scan.Options{
		Name:        collectorName,
		Version:     version,
		Image:       ownImageOnce(c, namespace, pod),
		Namespace:   namespace,
		Client:      c,
		Credentials: scan.NewKeychainCredentials(clientset, namespace),
		Runner:      jobs.NewRunner(c, jobs.NewLogReader(clientset), namespace),
		Metrics:     metrics,
	}), opts)
}

// ownImageOnce returns how the scans find the collector's own image, which their Jobs run: the first scan that needs it
// reads it from the collector's pod, and the image is kept from then on. A read that fails, such as one that the API
// server refuses before vexplain has granted the collector its permissions, fails that scan alone, and the next scan
// reads again.
func ownImageOnce(c client.Reader, namespace, pod string) func(context.Context) (string, error) {
	var mu sync.Mutex
	var found string
	return func(ctx context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if found == "" {
			image, err := ownImage(ctx, c, namespace, pod, ownImagePatience)
			if err != nil {
				return "", err
			}
			found = image
		}
		return found, nil
	}
}

// ownImage returns the image that the collector's own container runs, which its scan Jobs run too: the container named
// collector of its pod, as vexplain's deployer names it. The kubelet reports the image a moment after the container
// started, so ownImage reads the pod again every ownImagePoll until it does, for patience at most, and runningImage
// then picks the reference. When the status says nothing in time, the image of the pod's spec is all there is.
func ownImage(ctx context.Context, c client.Reader, namespace, pod string, patience time.Duration) (string, error) {
	spec, imageID := "", ""
	err := wait.PollUntilContextTimeout(ctx, ownImagePoll, patience, true, func(ctx context.Context) (bool, error) {
		var own corev1.Pod
		if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: pod}, &own); err != nil {
			return false, fmt.Errorf("read the collector's pod %s/%s: %w", namespace, pod, err)
		}
		spec = ""
		for _, container := range own.Spec.Containers {
			if container.Name == collectorContainer {
				spec = container.Image
			}
		}
		if spec == "" {
			return false, fmt.Errorf("the collector's pod %s/%s has no container named %s", namespace, pod,
				collectorContainer)
		}
		for _, status := range own.Status.ContainerStatuses {
			if status.Name == collectorContainer && status.ImageID != "" {
				imageID = status.ImageID
				return true, nil
			}
		}
		return false, nil
	})
	switch {
	case err == nil:
		image, why := runningImage(spec, imageID)
		if why != "" {
			slog.Info("The scan Jobs run the image of the collector's spec: "+why, "image", image, "imageID", imageID)
		}
		return image, nil
	case spec != "" && ctx.Err() == nil && wait.Interrupted(err):
		slog.Info("The collector's container reports no image yet: its scan Jobs run the image of its spec",
			"image", spec)
		return spec, nil
	default:
		return "", err
	}
}

// runningImage returns the image that the scan Jobs run, from spec, the image of the collector's container in its
// pod's spec, and imageID, the image that the container's status says that it runs. It names the image by the digest
// that runs, so that a Job runs the very build of the collector, where a tag could name another build on a node that
// cached an older one, but only under the repository that spec names, where a node finds that digest. A node that
// imported an image, rather than pulling it, reports its digest under a repository that it made up, such as
// docker.io/library/import-<date>, which no registry serves, and a node may know an image under another name too. Then,
// and when the status names no repository digest at all, the Jobs run spec, and why says why.
func runningImage(spec, imageID string) (image, why string) {
	running, ok := workloads.DigestFromImageID(imageID)
	switch {
	case !ok || running.Repository == "":
		return spec, "the status of its container names no repository digest"
	case !sameRepository(spec, running.Repository):
		return spec, "the status of its container names the digest under another repository than its spec, " +
			"as for an image that the node imported"
	}
	return running.Repository + "@" + running.Digest, ""
}

// sameRepository says whether the image reference and the repository name the same repository, once each is
// normalized as the container runtime normalizes it: a name without a registry is Docker Hub's, and one without a path
// there is in library, so scanner:e2e is docker.io/library/scanner. A name that doesn't parse names no repository that
// a Job could pull from.
func sameRepository(image, repository string) bool {
	ref, err := name.ParseReference(image)
	if err != nil {
		return false
	}
	repo, err := name.NewRepository(repository)
	if err != nil {
		return false
	}
	return ref.Context().Name() == repo.Name()
}

// The defaults of the flags.
const (
	// defaultWork is the scratch volume of the scan Job.
	defaultWork = "/work"
	// defaultMaxBytes limits the space that the filesystem of one manifest takes: 8 GiB. The collector
	// passes three quarters of the Job's scratch volume, and leaves the rest to Syft's temporary
	// files, its home and the SBOM.
	defaultMaxBytes = 8 << 30
	// defaultSyft is where the scanner image holds Syft.
	defaultSyft = "/usr/local/bin/syft"
)

// The exit codes.
const (
	exitOK     = 0
	exitFailed = 1
)

// errBadFlag is the error of a flag that the flag package accepts, but the scanner doesn't. Like
// every error here, it is never printed.
var errBadFlag = errors.New("bad flag")

// run is the subcommand scan, with the arguments that follow it. It takes what main takes from the
// process, so that a test can give it the arguments and read what it printed, and returns the exit
// code. It reads only PATH, for Syft, and DOCKER_CONFIG, the directory of the credentials, through
// getenv.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) (code int) {
	// A panic must not end the scan without its line, and its value could hold text from the image,
	// so it isn't printed either.
	defer func() {
		if recover() != nil {
			code = fail(stdout, result.ErrorReasonInternal)
		}
	}()

	opts, err := parseOptions(args)
	if err != nil {
		return fail(stdout, result.ErrorReasonInternal)
	}
	keychain, err := loadKeychain(getenv("DOCKER_CONFIG"))
	if err != nil {
		return fail(stdout, result.ErrorReasonInternal)
	}
	s := &scanner{options: opts, keychain: keychain, path: getenv("PATH"), progress: stderr}
	line, reason := s.scan(ctx)
	if reason != "" {
		if ctx.Err() != nil {
			// A signal stopped the scan, not the image.
			reason = result.ErrorReasonInternal
		}
		return fail(stdout, reason)
	}
	_, _ = fmt.Fprintln(stdout, line)
	return exitOK
}

// fail prints the error line of reason, and returns the exit code of a failed scan.
func fail(stdout io.Writer, reason result.ErrorReason) int {
	_, _ = fmt.Fprintln(stdout, result.EncodeError(reason))
	return exitFailed
}

// options are what the flags say.
type options struct {
	// image is the --image argument as it is, which the result names.
	image string
	// ref is image, parsed.
	ref       name.Digest
	platforms []string
	work      string
	maxBytes  int64
	syft      string
	// mirrors maps a registry, as go-containerregistry names it, to its mirror.
	mirrors map[string]name.Registry
}

// parseOptions reads the flags.
func parseOptions(args []string) (options, error) {
	opts := options{mirrors: map[string]name.Registry{}}
	flags := flag.NewFlagSet("scanner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&opts.image, "image", "", "")
	flags.Func("platform", "", func(p string) error {
		// A platform of the form os/architecture[/variant] is one that matches itself.
		if !result.PlatformMatches(p, p) {
			return errBadFlag
		}
		opts.platforms = append(opts.platforms, p)
		return nil
	})
	flags.StringVar(&opts.work, "work", defaultWork, "")
	flags.Int64Var(&opts.maxBytes, "max-bytes", defaultMaxBytes, "")
	flags.StringVar(&opts.syft, "syft", defaultSyft, "")
	flags.Func("registry-mirror", "", opts.addMirror)
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() > 0 || len(opts.platforms) == 0 || opts.maxBytes <= 0 || opts.work == "" || opts.syft == "" {
		return options{}, errBadFlag
	}

	var err error
	if opts.ref, err = name.NewDigest(opts.image); err != nil {
		return options{}, err
	}
	// Syft runs in a directory of its own, where a relative path would name something else.
	if opts.work, err = filepath.Abs(opts.work); err != nil {
		return options{}, err
	}
	if opts.syft, err = filepath.Abs(opts.syft); err != nil {
		return options{}, err
	}
	return opts, nil
}

// addMirror reads a --registry-mirror flag: host=url. The host is a registry as go-containerregistry
// names it, which calls Docker Hub index.docker.io, and docker.io stands for it too. The URL is http
// or https, a host and an optional port, and nothing else.
func (o *options) addMirror(value string) error {
	host, rawURL, ok := strings.Cut(value, "=")
	if !ok {
		return errBadFlag
	}
	from, to, err := pull.ParseMirror(host, rawURL)
	if err != nil {
		return err
	}
	if _, ok := o.mirrors[from.RegistryStr()]; ok {
		return errBadFlag
	}
	o.mirrors[from.RegistryStr()] = to
	return nil
}

// pullRef returns where to pull the image from: its own registry, or that registry's mirror, with the
// same repository path. The digest keeps the content the same, and there is no fallback from a
// mirror to the registry. The keychain gives the credentials of the host that is pulled from.
func (o options) pullRef() name.Digest {
	mirror, ok := o.mirrors[o.ref.Context().RegistryStr()]
	if !ok {
		return o.ref
	}
	return mirror.Repo(o.ref.Context().RepositoryStr()).Digest(o.ref.DigestStr())
}

// scanner scans the image of its options.
type scanner struct {
	options
	// keychain holds the logins that the scan tries.
	keychain orderedKeychain
	// path is the PATH that Syft gets.
	path string
	// progress is where the progress texts go.
	progress io.Writer
}

// say prints a progress text. It takes counts only, so that no text from the image can reach it.
func (s *scanner) say(format string, counts ...int) {
	args := make([]any, 0, len(counts))
	for _, c := range counts {
		args = append(args, c)
	}
	_, _ = fmt.Fprintf(s.progress, "scanner: "+format+"\n", args...)
}

// scan scans the image, and returns its result line, or the reason it failed.
func (s *scanner) scan(ctx context.Context) (string, result.ErrorReason) {
	s.say("resolving the image")
	targets, err := s.resolve(ctx)
	if errors.Is(err, pull.ErrNoMatchingPlatform) {
		return "", result.ErrorReasonNoMatchingPlatform
	}
	if err != nil {
		return "", pullReason(err)
	}
	s.say("manifests to scan: %d", len(targets))

	r := result.Result{Image: s.image}
	for i, target := range targets {
		m, reason := s.scanTarget(ctx, target, i+1, len(targets))
		if reason != "" {
			return "", reason
		}
		r.Manifests = append(r.Manifests, m)
	}
	line, err := result.Encode(r)
	if err != nil {
		return "", result.ErrorReasonInternal
	}
	return line, ""
}

// resolve resolves the image with each login that the keychain holds for the registry that the scan
// pulls from, in their order, until the registry takes one: a login that it refuses, with 401 or 403,
// gives way to the next, and the answer to the last one stands. The image's manifests and layers are
// then pulled with the login that it took.
func (s *scanner) resolve(ctx context.Context) ([]pull.Target, error) {
	ref := s.pullRef()
	var targets []pull.Target
	var err error
	for _, login := range s.keychain.logins(ref.Context().Registry) {
		targets, err = pull.Resolve(ctx, ref, s.platforms, remote.WithAuth(login))
		if err == nil || pullReason(err) != result.ErrorReasonUnauthorized {
			break
		}
	}
	return targets, err
}

// orderedKeychain holds the logins of the scan's Docker configs, as a scan Job's Secret holds them: one
// config for each pull secret that has a login for the registry that the scan pulls from, the
// workload's first, then those that the admin provides (decision 0047). Each maps the key of a
// registry to its login.
type orderedKeychain []map[string]authn.AuthConfig

// loadKeychain reads the Docker configs of the directory dir, config-0.json, config-1.json and so on,
// up to the first that isn't there. An empty dir holds none. Its errors are never printed: one of a
// config that doesn't parse can quote it.
func loadKeychain(dir string) (orderedKeychain, error) {
	if dir == "" {
		return nil, nil
	}
	var keychain orderedKeychain
	for i := 0; ; i++ {
		raw, err := os.ReadFile(filepath.Join(dir, "config-"+strconv.Itoa(i)+".json"))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return keychain, nil
		case err != nil:
			return nil, err
		}
		var config struct {
			Auths map[string]authn.AuthConfig `json:"auths"`
		}
		if err := json.Unmarshal(raw, &config); err != nil {
			return nil, err
		}
		keychain = append(keychain, config.Auths)
	}
}

// logins returns the logins for registry, in the order of the configs: that of each config that holds
// one, or the anonymous login alone when none does, as the kubelet pulls without credentials when it
// has none for a registry. A config holds the login of Docker Hub under Docker's historical key, and
// that of any other registry under its host, as go-containerregistry's DefaultKeychain looks them up.
func (k orderedKeychain) logins(registry name.Registry) []authn.Authenticator {
	key := registry.RegistryStr()
	if key == name.DefaultRegistry {
		key = authn.DefaultAuthKey
	}
	var logins []authn.Authenticator
	for _, auths := range k {
		if login, ok := auths[key]; ok && login != (authn.AuthConfig{}) {
			logins = append(logins, authn.FromConfig(login))
		}
	}
	if len(logins) == 0 {
		return []authn.Authenticator{authn.Anonymous}
	}
	return logins
}

// scanTarget scans one platform manifest, the nth of count, in a directory of its own under the work
// directory. The directory holds the unpacked filesystem, Syft's JSON, and Syft's TMPDIR and HOME,
// and the scan removes it at the end, whether it succeeded or not.
func (s *scanner) scanTarget(ctx context.Context, target pull.Target, nth, count int) (
	result.Scanned, result.ErrorReason,
) {
	dir, err := os.MkdirTemp(s.work, "manifest-")
	if err != nil {
		return result.Scanned{}, result.ErrorReasonInternal
	}
	m, reason := s.scanIn(ctx, dir, target, nth, count)
	// What stays would take the next manifest's space.
	if err := os.RemoveAll(dir); err != nil && reason == "" {
		return result.Scanned{}, result.ErrorReasonInternal
	}
	return m, reason
}

// scanIn scans one platform manifest in the directory dir: the contents of its filesystem, and its
// SBOM, which the analysis makes of Syft's JSON.
func (s *scanner) scanIn(ctx context.Context, dir string, target pull.Target, nth, count int) (
	result.Scanned, result.ErrorReason,
) {
	root := filepath.Join(dir, "root")
	sbom := filepath.Join(dir, "sbom.json")
	tmp := filepath.Join(dir, "tmp")
	home := filepath.Join(dir, "home")
	for _, d := range []string{root, tmp, home} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return result.Scanned{}, result.ErrorReasonInternal
		}
	}
	config, err := target.Image.ConfigFile()
	if err != nil {
		return result.Scanned{}, pullReason(err)
	}

	s.say("manifest %d of %d: unpacking", nth, count)
	if err := pull.Extract(target.Image, root, s.maxBytes); err != nil {
		return result.Scanned{}, extractReason(err)
	}

	s.say("manifest %d of %d: cataloging", nth, count)
	if err := s.syftScan(ctx, dir, root, sbom); err != nil {
		return result.Scanned{}, result.ErrorReasonCatalogFailed
	}
	raw, err := os.ReadFile(sbom)
	if err != nil {
		return result.Scanned{}, result.ErrorReasonCatalogFailed
	}

	s.say("manifest %d of %d: analysing", nth, count)
	m, err := analyze.Analyze(root, raw, analyze.ImageConfig{
		Env: config.Config.Env, Entrypoint: config.Config.Entrypoint, Cmd: config.Config.Cmd,
	})
	switch {
	case errors.Is(err, analyze.ErrSBOM), errors.Is(err, analyze.ErrUnsupportedSBOM),
		errors.Is(err, analyze.ErrCatalogIncomplete):
		return result.Scanned{}, result.ErrorReasonCatalogFailed
	case err != nil:
		return result.Scanned{}, result.ErrorReasonInternal
	}
	m.Platform, m.Digest = target.Platform, target.Digest
	return m, ""
}

// syftScan runs Syft on the filesystem at root, in dir, and writes its SBOM to sbom.
//   - --base-path keeps Syft inside the root: without it, Syft resolves an absolute link of the image
//     against the scanner's own filesystem.
//   - The image catalogers find what a scan of an image finds, such as installed npm, gem and Rust
//     packages. A scan of a directory uses the catalogers of a source tree by default.
//   - Syft runs in dir, beside the root, so that it can't find a configuration file that the image
//     ships. The SBOM goes beside the root too, where the analysis doesn't search it for library
//     names.
//   - Syft gets only the environment it needs, with TMPDIR and HOME in dir. A scan of a directory
//     needs no network, so it gets neither the credentials nor a proxy.
//   - Its output is discarded: it could hold text from the image.
func (s *scanner) syftScan(ctx context.Context, dir, root, sbom string) error {
	cmd := exec.CommandContext(ctx, s.syft, "scan", "dir:"+root, "--base-path", root,
		"--override-default-catalogers", "image", "-o", "syft-json="+sbom, "--quiet")
	cmd.Dir = dir
	cmd.Env = []string{
		"SYFT_CHECK_FOR_APP_UPDATE=false",
		"TMPDIR=" + filepath.Join(dir, "tmp"),
		"HOME=" + filepath.Join(dir, "home"),
		"PATH=" + s.path,
	}
	return cmd.Run()
}

// pullReason returns the reason of an error of pulling the image: the registry refused the
// credentials or wanted some, it has no such image, or anything else went wrong.
func pullReason(err error) result.ErrorReason {
	var answer *transport.Error
	if errors.As(err, &answer) {
		switch answer.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return result.ErrorReasonUnauthorized
		case http.StatusNotFound:
			return result.ErrorReasonNotFound
		}
	}
	return result.ErrorReasonPullFailed
}

// extractReason returns the reason of an error of unpacking the image. Reading the image is part of
// the pull. A hard link that no build tool writes fails the scan visibly, rather than let it describe
// another filesystem than a container sees, and like an error of writing to the work directory it is
// the scanner's own.
func extractReason(err error) result.ErrorReason {
	switch {
	case errors.Is(err, pull.ErrTooLarge):
		return result.ErrorReasonTooLarge
	case errors.Is(err, pull.ErrImageRead):
		return pullReason(err)
	case errors.Is(err, pull.ErrBadHardLink):
		return result.ErrorReasonInternal
	default:
		return result.ErrorReasonInternal
	}
}
