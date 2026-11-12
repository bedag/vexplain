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

// Package scan is the scanner collector: its operation scan runs a throwaway Job for an image digest, as phase 2a's
// scan runner did (decision 0022), and returns what the Job found in each platform manifest of the image, two pieces
// of evidence per manifest: its SBOM, of the core type ch.bedag.vexplain.sbom.v1alpha1 (decision 0044), which the
// vulnerabilities collector matches, and its image contents, of the scanner's own type
// ch.bedag.vexplain.scanner.image-contents.v1alpha1, which the rules read.
//
// A scan Job runs the collector's own image, with the scan subcommand, without access to the Kubernetes API. It pulls
// the image with the logins of the pull secrets of a pod that runs it, then with those that the admin provides
// (decision 0047), from a Secret that the Job owns, and prints one line to its log: what it found, or why it failed.
// The collector reads that line back through the SDK's Job runner, checks it against the scan that it asked for, and
// only then makes evidence of it.
//
// The design of collectors, evidence and rules gives the reasons, in docs/design/2026-10-31-collectors-evidence-rules.md,
// sections 5.4, 5.6 and 5.12.
package scan

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/collectors/scanner/internal/result"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/jobs"
	"github.com/bedag/vexplain/sdk/podtemplate"
	"github.com/bedag/vexplain/sdk/subject"
	"github.com/bedag/vexplain/sdk/workloads"
)

const (
	// collectorName is the name that GetInfo reports, and operationName the name of the collector's operation.
	collectorName = "scanner"
	operationName = "scan"
	// scanSubcommand is the subcommand of the collector's binary that a scan Job runs, and scannerContainer the name
	// of the Job's one container.
	scanSubcommand   = "scan"
	scannerContainer = "scanner"
	// scanTask is the value of the label of vexplain's own pods on what a scan creates.
	scanTask = "scan"
	// digestLabel marks the scan Job of a digest, its pod and its Secret. A label value holds 63 characters at most,
	// so the label holds the first 63 hex digits of the digest.
	digestLabel = "vexplain.bedag.ch/digest"
	// scannerLabel marks the scan Jobs of a scanner, their pods and their Secrets, with the name of its Collector: the
	// slots of a scanner count its own Jobs, and not those of another scanner Collector in the namespace.
	scannerLabel = "vexplain.bedag.ch/scanner"
	// maxManifests is the most platforms that the facts of an image hold.
	maxManifests = 16
	// maxPlatformLength is the longest platform that the API holds.
	maxPlatformLength = 64
	// maxResultBytes is the most JSON that a result line may decode to: 64 MiB.
	maxResultBytes = 64 << 20
	// maxCompressedBytes is the most of an event's data that vexplain's evidence store holds once compressed, 768
	// KiB. Evidence above it fails as TooLarge before it is emitted, and so does an event whose message is more than
	// the collector API's collector.MaxMessageSize, which bounds the data before it is compressed.
	maxCompressedBytes = 786432
	// defaultSlotWait is how long a scan that waits for a slot waits before it counts the scan Jobs again, unless
	// Options say otherwise. A Job of this process that finishes frees its slot at once.
	defaultSlotWait = 30 * time.Second
)

// The reasons of the failures that the scanner gives, besides those of a scan's error line, which are phase 2a's, and
// the reason of that line that the scanner explains.
const (
	internal     = string(result.ErrorReasonInternal)
	tooLarge     = string(result.ErrorReasonTooLarge)
	timedOut     = jobs.ReasonTimedOut
	notRunning   = "NotRunning"
	unauthorized = string(result.ErrorReasonUnauthorized)
)

var (
	// digestPattern matches a sha256 digest: the algorithm, a colon and 64 lowercase hex digits.
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	// platformPattern matches a platform as the API holds one: os/architecture[/variant].
	platformPattern = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`)
)

// Runner runs the scan Jobs: the SDK's *jobs.Runner, or a test's own.
type Runner interface {
	Run(ctx context.Context, s jobs.Spec) (jobs.Result, error)
	Active(ctx context.Context, labels map[string]string) (int, error)
}

// Options configure a Scanner.
type Options struct {
	// Name is the name of the collector's Collector, which the source of its events names, and Version the version
	// that GetInfo reports.
	Name, Version string
	// Image finds the collector's own image, which its scan Jobs run. A scan asks for it once it holds a slot, and
	// before it reads anything else: the collector starts without its permissions, which vexplain grants once it has
	// read them (decision 0041), so the image can't be read as the collector starts. An error fails that scan alone.
	Image func(ctx context.Context) (string, error)
	// Namespace is the collector's namespace, where its scan Jobs run.
	Namespace string
	// Client reads the pods that a request names, and their nodes, one at a time with get, from the API server.
	Client client.Reader
	// Credentials builds the pull credentials of a scan from a pod that runs the image, and from the Secrets that the
	// admin provides, and names those of the admin that gave none.
	Credentials CredentialSource
	// Runner runs the scan Jobs.
	Runner Runner
	// Metrics counts the scans. Nil means metrics of the scanner's own, which nothing serves.
	Metrics *Metrics
	// SlotWait is how long a scan that waits for a slot waits before it counts the scan Jobs again, for those that
	// another process of the collector runs, such as one that a restart left. Zero means 30 seconds.
	SlotWait time.Duration
	// Now tells the time at which a scan ended. Nil means time.Now.
	Now func() time.Time
}

// Scanner is the scanner collector. It takes the spoke role, where the images run, and has one operation, scan. It
// doesn't watch.
type Scanner struct {
	opts Options

	mu sync.Mutex
	// running counts the scans of this process that hold a slot, and freed closes when one of them gives it back.
	running int
	freed   chan struct{}
}

// New returns the scanner collector.
func New(opts Options) *Scanner {
	if opts.SlotWait == 0 {
		opts.SlotWait = defaultSlotWait
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Metrics == nil {
		opts.Metrics = NewMetrics()
	}
	return &Scanner{opts: opts, freed: make(chan struct{})}
}

// ---- what the collector declares ----

// parameterSchema is the schema of the parameters of scan: the repositories to pull the image from, as presence names
// them, and the pods that run it, of which the scan takes the credentials and the platforms.
const parameterSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "What a scan of an image needs: the repositories that the image was pulled from, and pods that run it.",
  "type": "object",
  "additionalProperties": false,
  "required": ["repositories"],
  "properties": {
    "repositories": {
      "description": "The repositories that the image was pulled from. The scan pulls it from one that a pod pulled it from, or else from the first.",
      "type": "array",
      "minItems": 1,
      "maxItems": 256,
      "items": { "type": "string", "minLength": 1, "maxLength": 255 }
    },
    "pods": {
      "description": "Pods that run the image. The scan pulls the image with the credentials of one of them, and scans the platforms of their nodes.",
      "type": "array",
      "maxItems": 16,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["namespace", "name"],
        "properties": {
          "namespace": { "type": "string", "minLength": 1, "maxLength": 63 },
          "name": { "type": "string", "minLength": 1, "maxLength": 253 }
        }
      }
    }
  }
}`

// settingsSchema is the schema of the collector's settings, with podtemplate's schema as that of scanPod.
var settingsSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "How the scanner's scan Jobs run. A setting that is left out takes its default.",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "maxConcurrentScans": {
      "description": "How many scan Jobs may run at once. 4 by default, and 16 at most: vexplain asks a collector for at most 16 scans at once.",
      "type": "integer", "minimum": 1, "maximum": 16
    },
    "scanTimeoutSeconds": {
      "description": "How long a scan Job may run before it is stopped. 1800 by default.",
      "type": "integer", "minimum": 60, "maximum": 21600
    },
    "workspaceMebibytes": {
      "description": "The size of the scratch volume that an image is unpacked into, and so the largest unpacked image that a scan takes. 10240 by default.",
      "type": "integer", "minimum": 1024, "maximum": 1048576
    },
    "registryMirrors": {
      "description": "Mirrors to pull from in place of registries: a scan pulls an image of the registry host from url, with the same repository path and digest, and never from the registry itself.",
      "type": "array",
      "maxItems": 16,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["host", "url"],
        "properties": {
          "host": { "type": "string", "minLength": 1, "maxLength": 253 },
          "url": { "type": "string", "minLength": 1, "maxLength": 512 }
        }
      }
    },
    "adminPullSecrets": {
      "description": "Secrets of the type kubernetes.io/dockerconfigjson in the operator's namespace, whose logins for the registry that a scan pulls from it tries in this order, after those of the pull secrets of the pod and of its service account, until the registry takes one. None by default, and 16 at most.",
      "type": "array",
      "maxItems": 16,
      "uniqueItems": true,
      "items": { "type": "string", "minLength": 1, "maxLength": 253, "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" }
    },
    "scanPod": ` + string(podtemplate.Schema()) + `
  }
}`

// Info says that the collector is the scanner, at its version.
func (s *Scanner) Info() collector.Info {
	return collector.Info{Name: collectorName, Version: s.opts.Version}
}

// Capabilities say that the collector takes the spoke role, where the images run, and has the operation scan, which
// consumes nothing and produces each manifest's SBOM and its image contents, which go to the hub. It doesn't watch.
func (s *Scanner) Capabilities() collector.Capabilities {
	sbomSchema, _ := evidence.Schema(evidence.TypeSBOM)
	return collector.Capabilities{
		Roles: []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{
			{Type: evidence.TypeSBOM, Scope: collector.ScopeHub, Schema: sbomSchema},
			{Type: result.EvidenceType, Scope: collector.ScopeHub, Schema: result.Schema()},
		},
		Operations: []collector.Operation{{
			Name: operationName,
			Description: "Scans an image digest in a Job of its own: what the filesystem of each platform manifest " +
				"that the pods' nodes run holds, as an SBOM, and the facts of its files and libraries.",
			Role:            collector.RoleSpoke,
			Produces:        []string{evidence.TypeSBOM, result.EvidenceType},
			ParameterSchema: []byte(parameterSchema),
		}},
		SettingsSchema: []byte(settingsSchema),
		Permissions:    permissions,
	}
}

// The resources and verbs of the scanner's permissions.
const (
	pods    = "pods"
	secrets = "secrets"
	get     = "get"
	create  = "create"
	remove  = "delete"
)

// permissions are what the scanner needs from the Kubernetes API: in the whole cluster, the pods that a request names
// and their nodes, and the pull secrets and service accounts of those pods, each read with get, never listed or
// watched, which covers the pull secrets that the admin provides in the operator's namespace; in its own namespace, its
// scan Jobs, their Secrets, their pods and their logs.
var permissions = []collector.Permission{
	{APIGroups: []string{corev1.GroupName}, Resources: []string{pods, "nodes", secrets, "serviceaccounts"},
		Verbs: []string{get}},
	{APIGroups: []string{batchv1.GroupName}, Resources: []string{"jobs"},
		Verbs: []string{create, get, "list", "watch", remove}, Namespaced: true},
	{APIGroups: []string{corev1.GroupName}, Resources: []string{secrets}, Verbs: []string{create, get, remove},
		Namespaced: true},
	{APIGroups: []string{corev1.GroupName}, Resources: []string{pods}, Verbs: []string{get, "list"}, Namespaced: true},
	{APIGroups: []string{corev1.GroupName}, Resources: []string{pods + "/log"}, Verbs: []string{get}, Namespaced: true},
}

// ---- the operation ----

// parameters are the parameters of scan.
type parameters struct {
	Repositories []string `json:"repositories"`
	Pods         []podRef `json:"pods"`
}

// podRef names a pod.
type podRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// scanCall is what a scan Job asks the scanner for.
type scanCall struct {
	// digest is the digest that the Job scans, and image its --image argument: the repository to pull from, and the
	// digest.
	digest, image string
	// platforms are its --platform arguments.
	platforms []string
}

// Invoke runs scan for an image, image/ and a digest:
//   - It waits for a slot, while maxConcurrentScans scan Jobs of its Collector run. It reads nothing of the cluster
//     before it has one, so that a scan that waits holds no credentials, and scans what runs once it starts.
//   - It finds the collector's own image, which its Job runs.
//   - It takes the pods that the parameters name and whose status says that they run the digest. Without any, it
//     fails with NotRunning.
//   - It builds the pull credentials from one of them, as phase 2a did: a pod that pulled the digest from one of the
//     parameters' repositories, from that repository, or else the first pod, from the first repository. They are the
//     logins of the pod's pull secrets and of its service account's, then those of the Secrets that adminPullSecrets
//     names (decision 0047), each for the registry that the scan pulls from: the repository's, or its mirror's.
//   - It scans the platforms of the pods' nodes. Without a node that says its platform, it fails with Internal.
//   - It runs the Job with its own image and the scan subcommand, with phase 2a's arguments.
//   - It checks the Job's line as phase 2a did, and returns two events per manifest, about manifest/ and its digest:
//     its SBOM and its image contents, each with its platform, its completeness as the coverage, and the time the
//     scan ended. An event whose data compresses above what vexplain's evidence store holds, or whose message is more
//     than the collector API holds, fails the scan as TooLarge, and none of the evidence is returned.
//
// A Job that failed gives phase 2a's reasons: those of the scan's error line, TimedOut for a Job past its deadline,
// and Internal for a scan that doesn't fit what was asked. Unauthorized, when the registry took none of the logins,
// names the registry and the pull secrets that it tried, and nothing of their content. An error is for what keeps the
// scan from running at all, such as the collector's own image, a pod or a pull secret that can't be read, or a Job
// that can't be created.
//
// The metrics count each scan that held a slot, by its result, and how long it held it.
func (s *Scanner) Invoke(ctx context.Context, req collector.InvokeRequest) (events []cloudevents.Event,
	failure *collector.Failure, err error) {
	about, err := subject.Parse(req.Subject)
	if err != nil || about.Kind != subject.KindImage {
		return nil, nil, status.Error(codes.InvalidArgument, "the scanner scans an image: image/ and a digest")
	}
	var params parameters
	if err := json.Unmarshal(req.Parameters, &params); err != nil || len(params.Repositories) == 0 {
		return nil, nil, status.Error(codes.InvalidArgument, "the parameters name no repository to pull the image from")
	}
	set, problems := s.settingsOf(req.Settings)
	if len(problems) > 0 {
		return nil, nil, status.Error(codes.InvalidArgument, "the settings: "+strings.Join(problems, "; "))
	}
	release, err := s.takeSlot(ctx, set.MaxConcurrentScans, s.slotLabels(req.Context))
	if err != nil {
		return nil, nil, err
	}
	defer release()
	started := s.opts.Now()
	defer func() {
		s.opts.Metrics.scanned(req.Context.Cluster, scanResult(failure, err), s.opts.Now().Sub(started))
	}()
	image, err := s.opts.Image(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("find the image that the scan Jobs run, the collector's own: %w", err)
	}

	pods, err := s.podsRunning(ctx, about.Digest, params.Pods)
	if err != nil {
		return nil, nil, err
	}
	if len(pods) == 0 {
		return nil, &collector.Failure{Reason: notRunning, Message: "no pod that the request names runs the image"}, nil
	}
	pod, repository := pullSource(pods, about.Digest, params.Repositories)
	from, err := set.pullFrom(repository)
	if err != nil {
		return nil, nil, err
	}
	creds, err := s.opts.Credentials.Credentials(ctx, pod, from.Name(), set.AdminPullSecrets)
	if err != nil {
		return nil, nil, fmt.Errorf("build the credentials to pull %s with pod %s/%s: %w",
			from.Name(), pod.Namespace, pod.Name, err)
	}
	platforms, err := scanPlatforms(ctx, s.opts.Client, pods)
	switch {
	case errors.Is(err, errNoPlatform):
		return nil, &collector.Failure{Reason: internal, Message: err.Error()}, nil
	case err != nil:
		return nil, nil, err
	}

	call := scanCall{digest: about.Digest, image: repository + "@" + about.Digest, platforms: platforms}
	ran, err := s.opts.Runner.Run(ctx, s.jobSpec(req.Context, call, image, creds.Logins, set))
	if err != nil {
		return nil, nil, fmt.Errorf("run the scan Job of %s: %w", about.Digest, err)
	}
	outcome := outcomeOf(ran, call)
	if outcome.result == nil {
		why := outcome.why
		if outcome.reason == unauthorized {
			why = noLoginWorked(from.RegistryStr(), creds)
		}
		return nil, &collector.Failure{Reason: outcome.reason, Message: why}, nil
	}
	return s.eventsOf(req.Context.Cluster, s.opts.Now(), outcome.result.Manifests)
}

// maxMessage is the most characters of a failure's message that vexplain keeps: the spoke cuts a longer one.
const maxMessage = 256

// noLoginWorked says why a scan failed whose registry took none of its logins, or wanted one where it had none, in
// maxMessage characters at most, by names only, and never the content of the Secrets. The registry that the scan pulled
// from comes first, then the Secrets of adminPullSecrets that gave no login, which the admin is to see: those that
// don't exist, and those that hold no login for the registry. The pull secrets whose logins the scan tried come last,
// by namespace and name, in the order that it tried them. A list names as many as fit, and counts the rest.
func noLoginWorked(registry string, creds Credentials) string {
	why := "registry " + registry + ": no credentials worked"
	if len(creds.Logins) == 0 {
		why += ", no pull secret holds a login for it"
	}
	why = withNames(why, "; adminPullSecrets not found: ", creds.Missing)
	why = withNames(why, "; adminPullSecrets without a login for it: ", creds.NoLogin)
	tried := make([]string, 0, len(creds.Logins))
	for _, login := range creds.Logins {
		tried = append(tried, login.Secret)
	}
	why = withNames(why, "; tried: ", tried)
	// The host and the names are ASCII, so the cut falls between characters. Only a host longer than any registry's
	// reaches it.
	return why[:min(len(why), maxMessage)]
}

// withNames returns why followed by the label and as many of names as fit into maxMessage, with a count of the rest,
// such as "a, b and 3 more", or the count alone, such as "3 Secrets", when none fits. It returns why as it is when
// there are no names, or when not even the count fits.
func withNames(why, label string, names []string) string {
	if len(names) == 0 {
		return why
	}
	for n := len(names); n >= 0; n-- {
		part := strings.Join(names[:n], ", ")
		switch left := len(names) - n; {
		case left == 0:
		case n > 0:
			part += " and " + strconv.Itoa(left) + " more"
		case left == 1:
			part = "1 Secret"
		default:
			part = strconv.Itoa(left) + " Secrets"
		}
		if len(why)+len(label)+len(part) <= maxMessage {
			return why + label + part
		}
	}
	return why
}

// ownPodLabel returns the label of vexplain's own pods, which the context names, or the SDK's when it names none.
func ownPodLabel(c collector.Context) string {
	if c.OwnPodLabel != "" {
		return c.OwnPodLabel
	}
	return workloads.TaskLabel
}

// podsRunning reads the pods that refs name, and returns those whose status says that they run digest. A pod that is
// gone is left out, and so is one that runs it no more.
func (s *Scanner) podsRunning(ctx context.Context, digest string, refs []podRef) ([]corev1.Pod, error) {
	var running []corev1.Pod
	for _, ref := range refs {
		var pod corev1.Pod
		if err := s.opts.Client.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &pod); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("read pod %s/%s: %w", ref.Namespace, ref.Name, err)
		}
		images, _ := workloads.PodImages(&pod)
		// An image that has no digest can't be pulled by one: its key is the hash of its reference.
		if slices.ContainsFunc(images, func(image workloads.ImageRef) bool { return image.Digest == digest && !image.Reference }) {
			running = append(running, pod)
		}
	}
	return running, nil
}

// pullSource picks the pod whose credentials pull the image of digest, and the repository to pull it from, one of
// repositories: those are what presence took from the pods. A pod that pulled the digest from one of them comes first,
// with that repository, since its pull secrets are for that registry. Otherwise the first pod pulls from the first
// repository. The pods are taken in the order of their namespaces and names, so that the pick stays the same.
func pullSource(pods []corev1.Pod, digest string, repositories []string) (*corev1.Pod, string) {
	slices.SortFunc(pods, func(a, b corev1.Pod) int {
		if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	for i := range pods {
		images, _ := workloads.PodImages(&pods[i])
		for _, image := range images {
			if image.Digest == digest && !image.Reference && slices.Contains(repositories, image.Repository) {
				return &pods[i], image.Repository
			}
		}
	}
	return &pods[0], repositories[0]
}

// jobSpec returns the scan Job of call: image, the collector's own, with the scan subcommand and phase 2a's arguments,
// in the collector's namespace, with a Docker config for each of logins, in their order, and the settings. Its
// environment is scanPod's env and nothing else: the collector's own proxy is not copied (decision 0037).
//
// The scanner may take three quarters of the workspace for the filesystem of a manifest: Syft's temporary files, its
// home and the SBOM need the rest, and a pod that fills its workspace is evicted, and leaves no line.
func (s *Scanner) jobSpec(c collector.Context, call scanCall, image string, logins []Login, set settings) jobs.Spec {
	workspace := int64(set.WorkspaceMebibytes) << 20
	args := make([]string, 0, 3+2*len(call.platforms)+4+2*len(set.RegistryMirrors))
	args = append(args, scanSubcommand, "--image", call.image)
	for _, platform := range call.platforms {
		args = append(args, "--platform", platform)
	}
	args = append(args, "--work", jobs.WorkspaceDir, "--max-bytes", strconv.FormatInt(workspace*3/4, 10))
	for _, mirror := range set.RegistryMirrors {
		args = append(args, "--registry-mirror", mirror.Host+"="+mirror.URL)
	}
	labels := s.slotLabels(c)
	labels[digestLabel] = strings.TrimPrefix(call.digest, "sha256:")[:63]
	configs := make([][]byte, 0, len(logins))
	for _, login := range logins {
		configs = append(configs, login.Config)
	}
	return jobs.Spec{
		Name:          jobName(call.digest),
		Namespace:     s.opts.Namespace,
		Image:         image,
		Container:     scannerContainer,
		Args:          args,
		DockerConfigs: configs,
		Workspace:     *resource.NewQuantity(workspace, resource.BinarySI),
		Deadline:      time.Duration(set.ScanTimeoutSeconds) * time.Second,
		Template:      set.template(),
		Labels:        labels,
		ResultPrefix:  result.ResultPrefix,
		ErrorPrefix:   result.ErrorPrefix,
	}
}

// jobName returns a name for a new scan Job of digest, and its Secret: the start of the digest, and a random suffix.
func jobName(digest string) string {
	return "scan-" + strings.TrimPrefix(digest, "sha256:")[:12] + "-" + utilrand.String(5)
}

// eventsOf returns the scanner's evidence about each manifest that a scan found, which ended at the time ended: two
// events about the manifest, its SBOM and its image contents, each with its platform and its coverage, which is its
// completeness, or 0 when a cataloger failed, and with the collector in the cluster as the source. A piece of evidence
// that the store can't hold, or an event that is more than a message of the collector API holds, fails the scan as
// TooLarge, and no event is returned.
func (s *Scanner) eventsOf(cluster string, ended time.Time, manifests []result.Scanned) ([]cloudevents.Event,
	*collector.Failure, error) {
	source := "/clusters/" + cluster + "/collectors/" + s.opts.Name
	events := make([]cloudevents.Event, 0, 2*len(manifests))
	for _, m := range manifests {
		for _, of := range []struct {
			eventType string
			data      any
		}{{evidence.TypeSBOM, m.SBOM}, {result.EvidenceType, m.Manifest}} {
			e, err := evidence.New(of.eventType, subject.Manifest(m.Digest), of.data,
				evidence.WithPlatform(m.Platform), evidence.WithCoverage(m.Coverage()),
				evidence.WithTime(ended), evidence.WithSource(source))
			if err == nil {
				err = evidence.Validate(e)
			}
			if err != nil {
				// The checks of the result make every manifest evidence, so this is a failure of the scanner's own. The
				// error can quote the result, which came from a log, so it isn't passed on.
				return nil, &collector.Failure{Reason: internal, Message: "the result of the scan can't be made into evidence"}, nil
			}
			if failure, err := fits(e); failure != nil || err != nil {
				return nil, failure, err
			}
			events = append(events, e)
		}
	}
	return events, nil, nil
}

// fits checks that vexplain can take the event e: that its data compresses to what the evidence store holds, and that
// the message that carries it is no more than the collector API holds. It returns the failure TooLarge when it can't.
func fits(e cloudevents.Event) (*collector.Failure, error) {
	compressed, err := compressedSize(e.Data())
	if err != nil {
		return nil, fmt.Errorf("compress the evidence of %s: %w", e.Subject(), err)
	}
	if compressed > maxCompressedBytes {
		return &collector.Failure{Reason: tooLarge,
			Message: "the evidence of a manifest is more than vexplain's evidence store holds"}, nil
	}
	size, err := messageSize(e)
	if err != nil {
		return nil, fmt.Errorf("measure the evidence of %s: %w", e.Subject(), err)
	}
	if size > collector.MaxMessageSize {
		return &collector.Failure{Reason: tooLarge,
			Message: "the evidence of a manifest is more than a message of the collector API holds"}, nil
	}
	return nil, nil
}

// compressedSize returns the size of data as vexplain's evidence store holds it: gzip at its best compression.
func compressedSize(data []byte) (int, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return 0, err
	}
	if _, err = zw.Write(data); err != nil {
		return 0, err
	}
	if err = zw.Close(); err != nil {
		return 0, err
	}
	return buf.Len(), nil
}

// messageSize returns the size of the message that carries e to vexplain, an item of the answer of Invoke, as the SDK
// sends it and vexplain counts it, once decompressed.
func messageSize(e cloudevents.Event) (int, error) {
	p, err := evidence.ToProto(e)
	if err != nil {
		return 0, err
	}
	return proto.Size(&collectorv1alpha1.InvokeResponse{Item: &collectorv1alpha1.InvokeResponse_Event{Event: p}}), nil
}

// ---- the metrics ----

// Metrics are the scanner's own metrics, which the collector's /metrics serves with the SDK's: the scans that held a
// slot, by the cluster that the request's context names and their result, and how long each held its slot. The result
// is Succeeded, the reason of the scan's failure, or Error for a scan that couldn't run. A registry takes them as a
// prometheus.Collector.
type Metrics struct {
	scans    *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewMetrics returns the scanner's metrics, with no scan counted.
func NewMetrics() *Metrics {
	labels := []string{"cluster", "result"}
	return &Metrics{
		scans: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vexplain_scanner_scans_total",
			Help: "Scans of images, by the cluster that the request names and the result: Succeeded, the reason of " +
				"the failure, or Error for a scan that couldn't run.",
		}, labels),
		// A scan takes from seconds to the 6 hours that scanTimeoutSeconds allows at most, where the default buckets stop
		// at 10 seconds.
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "vexplain_scanner_scan_duration_seconds",
			Help: "How long a scan of an image held its slot, from before it read anything until its Job was done, by " +
				"the cluster that the request names and the result, in seconds.",
			Buckets: []float64{10, 30, 60, 120, 300, 600, 1200, 1800, 3600, 7200, 21600},
		}, labels),
	}
}

// Describe sends the descriptions of the metrics, as a prometheus.Collector does.
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.scans.Describe(ch)
	m.duration.Describe(ch)
}

// Collect sends the metrics, as a prometheus.Collector does.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	m.scans.Collect(ch)
	m.duration.Collect(ch)
}

// scanned counts a scan for the cluster that ended with the outcome, and held its slot for took.
func (m *Metrics) scanned(cluster, outcome string, took time.Duration) {
	m.scans.WithLabelValues(cluster, outcome).Inc()
	m.duration.WithLabelValues(cluster, outcome).Observe(took.Seconds())
}

// scanResult returns the result of a scan that ended with failure or err, as the metrics name it: Error for an error,
// the reason of a failure, which comes from the scanner's own vocabulary, and Succeeded for evidence.
func scanResult(failure *collector.Failure, err error) string {
	switch {
	case err != nil:
		return "Error"
	case failure != nil:
		return failure.Reason
	}
	return "Succeeded"
}
