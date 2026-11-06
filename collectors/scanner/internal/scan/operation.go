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
// scan runner did (decision 0022), and returns what the Job found in each platform manifest of the image, one piece of
// evidence per manifest, of the type ch.bedag.vexplain.scanner.image-contents.v1alpha1.
//
// A scan Job runs the collector's own image, with the scan subcommand, without access to the Kubernetes API. It pulls
// the image with the credentials of a pod that runs it, from a Secret that the Job owns, and prints one line to its
// log: what it found, or why it failed. The collector reads that line back through the SDK's Job runner, checks it
// against the scan that it asked for, and only then makes evidence of it.
//
// The design of collectors, evidence and rules gives the reasons, in docs/design/2026-10-31-collectors-evidence-rules.md,
// sections 5.4, 5.6 and 5.12.
package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/collectors/scanner/internal/pull"
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

// The reasons of the failures that the scanner gives, besides those of a scan's error line, which are phase 2a's.
const (
	internal   = string(result.ErrorReasonInternal)
	tooLarge   = string(result.ErrorReasonTooLarge)
	timedOut   = jobs.ReasonTimedOut
	notRunning = "NotRunning"
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
	// Image is the collector's own image, which its scan Jobs run, and Namespace its namespace, where they run.
	Image, Namespace string
	// ProxyEnv holds the collector's proxy variables, which every scan Job gets, and no other variable.
	ProxyEnv []corev1.EnvVar
	// Client reads the pods that a request names, and their nodes, one at a time with get, from the API server.
	Client client.Reader
	// Credentials builds the pull credentials of a scan from a pod that runs the image.
	Credentials CredentialSource
	// Runner runs the scan Jobs.
	Runner Runner
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
      "description": "How many scan Jobs may run at once. 2 by default.",
      "type": "integer", "minimum": 1, "maximum": 32
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
    "scanPod": ` + string(podtemplate.Schema()) + `
  }
}`

// Info says that the collector is the scanner, at its version.
func (s *Scanner) Info() collector.Info {
	return collector.Info{Name: collectorName, Version: s.opts.Version}
}

// Capabilities say that the collector takes the spoke role, where the images run, and has the operation scan, which
// consumes nothing and produces the scanner's evidence, which goes to the hub. It doesn't watch.
func (s *Scanner) Capabilities() collector.Capabilities {
	return collector.Capabilities{
		Roles: []collector.Role{collector.RoleSpoke},
		Produces: []collector.EvidenceType{
			{Type: result.EvidenceType, Scope: collector.ScopeHub, Schema: result.Schema()},
		},
		Operations: []collector.Operation{{
			Name: operationName,
			Description: "Scans an image digest in a Job of its own: what the filesystem of each platform manifest " +
				"that the pods' nodes run holds, as an SBOM with the facts of its files and libraries.",
			Role:            collector.RoleSpoke,
			Produces:        []string{result.EvidenceType},
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
// watched; in its own namespace, its scan Jobs, their Secrets, their pods and their logs.
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

// ---- the settings ----

// settings are the collector's settings, with the defaults filled in.
type settings struct {
	MaxConcurrentScans int32                    `json:"maxConcurrentScans,omitempty"`
	ScanTimeoutSeconds int32                    `json:"scanTimeoutSeconds,omitempty"`
	WorkspaceMebibytes int32                    `json:"workspaceMebibytes,omitempty"`
	RegistryMirrors    []registryMirror         `json:"registryMirrors,omitempty"`
	ScanPod            *podtemplate.PodTemplate `json:"scanPod,omitempty"`
}

// registryMirror is a mirror to pull the images of a registry from.
type registryMirror struct {
	Host string `json:"host"`
	URL  string `json:"url"`
}

// defaultScanMemory is the memory that a scan pod requests, and its limit, when the settings name no memory.
var defaultScanMemory = resource.MustParse("2Gi")

// ValidateSettings checks what the settings' schema can't: that they decode, quantities included, that each mirror is
// a registry and a URL that a scan pulls from, for a registry of its own, and that the scan pod's template, with the
// default memory, is one that Kubernetes takes and that loosens nothing, as podtemplate's Validate checks it. A
// template that every scan Job would fail with is a problem of the settings, and not a failure of each image.
func (s *Scanner) ValidateSettings(raw json.RawMessage) []string {
	_, problems := settingsOf(raw)
	return problems
}

// settingsOf reads the settings, which passed their schema, with the defaults for what they leave out, and returns
// what is wrong with them.
func settingsOf(raw json.RawMessage) (settings, []string) {
	set := settings{MaxConcurrentScans: 2, ScanTimeoutSeconds: 1800, WorkspaceMebibytes: 10240}
	if len(bytes.TrimSpace(raw)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&set); err != nil {
			// The settings are the admin's own, so the decoder's error may name what it couldn't read.
			return settings{}, []string{"the settings can't be read: " + err.Error()}
		}
	}
	var problems []string
	hosts := map[string]bool{}
	for i, mirror := range set.RegistryMirrors {
		from, _, err := pull.ParseMirror(mirror.Host, mirror.URL)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("registryMirrors[%d]: %v", i, err))
		case hosts[from.RegistryStr()]:
			problems = append(problems, fmt.Sprintf("registryMirrors[%d]: a registry has one mirror at most", i))
		default:
			hosts[from.RegistryStr()] = true
		}
	}
	for _, problem := range set.template().Validate() {
		problems = append(problems, "scanPod."+problem)
	}
	return set, problems
}

// template returns the pod template of the scan Jobs: scanPod, whose resources add to the default ones. Memory keeps
// its default request and limit unless scanPod names memory, so that every scan pod has a memory limit (decision 0022):
// a memory request alone is the limit too, and a memory limit alone is the request too, as Kubernetes makes it.
func (set settings) template() podtemplate.PodTemplate {
	var t podtemplate.PodTemplate
	if set.ScanPod != nil {
		t = *set.ScanPod
	}
	var r corev1.ResourceRequirements
	if t.Resources != nil {
		r = *t.Resources.DeepCopy()
	}
	request, requested := r.Requests[corev1.ResourceMemory]
	_, limited := r.Limits[corev1.ResourceMemory]
	switch {
	case !requested && !limited:
		r.Requests = withQuantity(r.Requests, corev1.ResourceMemory, defaultScanMemory)
		r.Limits = withQuantity(r.Limits, corev1.ResourceMemory, defaultScanMemory)
	case !limited:
		r.Limits = withQuantity(r.Limits, corev1.ResourceMemory, request)
	}
	t.Resources = &r
	return t
}

// withQuantity returns list with a copy of quantity for the resource name, in a new list when list is nil.
func withQuantity(list corev1.ResourceList, name corev1.ResourceName, quantity resource.Quantity) corev1.ResourceList {
	if list == nil {
		list = corev1.ResourceList{}
	}
	list[name] = quantity.DeepCopy()
	return list
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
//   - It takes the pods that the parameters name and whose status says that they run the digest. Without any, it
//     fails with NotRunning.
//   - It builds the pull credentials from one of them, as phase 2a did: a pod that pulled the digest from one of the
//     parameters' repositories, from that repository, or else the first pod, from the first repository.
//   - It scans the platforms of the pods' nodes. Without a node that says its platform, it fails with Internal.
//   - It runs the Job with its own image and the scan subcommand, with phase 2a's arguments.
//   - It checks the Job's line as phase 2a did, and returns one event per manifest, about manifest/ and its digest,
//     with its platform, its completeness as the coverage, and the time the scan ended. Evidence that compresses above
//     what vexplain's evidence store holds, or whose message is more than the collector API holds, fails as TooLarge,
//     and none of it is returned.
//
// A Job that failed gives phase 2a's reasons: those of the scan's error line, TimedOut for a Job past its deadline,
// and Internal for a scan that doesn't fit what was asked. An error is for what keeps the scan from running at all,
// such as a pod or a pull secret that can't be read, or a Job that can't be created.
func (s *Scanner) Invoke(ctx context.Context, req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure,
	error) {
	about, err := subject.Parse(req.Subject)
	if err != nil || about.Kind != subject.KindImage {
		return nil, nil, status.Error(codes.InvalidArgument, "the scanner scans an image: image/ and a digest")
	}
	var params parameters
	if err := json.Unmarshal(req.Parameters, &params); err != nil || len(params.Repositories) == 0 {
		return nil, nil, status.Error(codes.InvalidArgument, "the parameters name no repository to pull the image from")
	}
	set, problems := settingsOf(req.Settings)
	if len(problems) > 0 {
		return nil, nil, status.Error(codes.InvalidArgument, "the settings: "+strings.Join(problems, "; "))
	}
	release, err := s.takeSlot(ctx, set.MaxConcurrentScans, s.slotLabels(req.Context))
	if err != nil {
		return nil, nil, err
	}
	defer release()

	pods, err := s.podsRunning(ctx, about.Digest, params.Pods)
	if err != nil {
		return nil, nil, err
	}
	if len(pods) == 0 {
		return nil, &collector.Failure{Reason: notRunning, Message: "no pod that the request names runs the image"}, nil
	}
	pod, repository := pullSource(pods, about.Digest, params.Repositories)
	config, err := s.opts.Credentials.DockerConfig(ctx, pod, repository)
	if err != nil {
		return nil, nil, fmt.Errorf("build the credentials to pull %s with pod %s/%s: %w",
			repository, pod.Namespace, pod.Name, err)
	}
	platforms, err := scanPlatforms(ctx, s.opts.Client, pods)
	switch {
	case errors.Is(err, errNoPlatform):
		return nil, &collector.Failure{Reason: internal, Message: err.Error()}, nil
	case err != nil:
		return nil, nil, err
	}

	call := scanCall{digest: about.Digest, image: repository + "@" + about.Digest, platforms: platforms}
	ran, err := s.opts.Runner.Run(ctx, s.jobSpec(req.Context, call, config, set))
	if err != nil {
		return nil, nil, fmt.Errorf("run the scan Job of %s: %w", about.Digest, err)
	}
	outcome := outcomeOf(ran, call)
	if outcome.result == nil {
		return nil, &collector.Failure{Reason: outcome.reason, Message: outcome.why}, nil
	}
	return s.eventsOf(req.Context.Cluster, s.opts.Now(), outcome.result.Manifests)
}

// ownPodLabel returns the label of vexplain's own pods, which the context names, or the SDK's when it names none.
func ownPodLabel(c collector.Context) string {
	if c.OwnPodLabel != "" {
		return c.OwnPodLabel
	}
	return workloads.TaskLabel
}

// slotLabels returns the labels of the scan Jobs of the scanner's Collector, which hold its slots: the label of
// vexplain's own pods, which the context c names, as a scan's, and the name of the Collector.
func (s *Scanner) slotLabels(c collector.Context) map[string]string {
	return map[string]string{ownPodLabel(c): scanTask, scannerLabel: s.opts.Name}
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
		if slices.ContainsFunc(images, func(image workloads.ImageRef) bool { return image.Digest == digest }) {
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
			if image.Digest == digest && slices.Contains(repositories, image.Repository) {
				return &pods[i], image.Repository
			}
		}
	}
	return &pods[0], repositories[0]
}

// jobSpec returns the scan Job of call: the collector's own image, with the scan subcommand and phase 2a's arguments,
// in the collector's namespace, with the credentials of config, the collector's proxy, and the settings.
//
// The scanner may take three quarters of the workspace for the filesystem of a manifest: Syft's temporary files, its
// home and the SBOM need the rest, and a pod that fills its workspace is evicted, and leaves no line.
func (s *Scanner) jobSpec(c collector.Context, call scanCall, config []byte, set settings) jobs.Spec {
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
	return jobs.Spec{
		Name:         jobName(call.digest),
		Namespace:    s.opts.Namespace,
		Image:        s.opts.Image,
		Container:    scannerContainer,
		Args:         args,
		Env:          slices.Clone(s.opts.ProxyEnv),
		DockerConfig: config,
		Workspace:    *resource.NewQuantity(workspace, resource.BinarySI),
		Deadline:     time.Duration(set.ScanTimeoutSeconds) * time.Second,
		Template:     set.template(),
		Labels:       labels,
		ResultPrefix: result.ResultPrefix,
		ErrorPrefix:  result.ErrorPrefix,
	}
}

// jobName returns a name for a new scan Job of digest, and its Secret: the start of the digest, and a random suffix.
func jobName(digest string) string {
	return "scan-" + strings.TrimPrefix(digest, "sha256:")[:12] + "-" + utilrand.String(5)
}

// takeSlot waits until fewer scan Jobs than maxScans hold a slot, and takes one, until ctx ends. A slot is held by a
// Job that the API server has with the labels, those of slotLabels, and that hasn't finished, and by a scan of this
// process, from before it reads anything of the cluster until its Job is gone: of the two counts, the larger counts,
// since the Jobs of this process's scans are among the first once they are created. A scan of this process that ends
// frees its slot at once; a Job of another process, such as one that a restart left, is counted again every SlotWait.
// It returns the function that gives the slot back.
func (s *Scanner) takeSlot(ctx context.Context, maxScans int32, labels map[string]string) (func(), error) {
	for {
		s.mu.Lock()
		active, err := s.opts.Runner.Active(ctx, labels)
		if err != nil {
			s.mu.Unlock()
			return nil, fmt.Errorf("count the scan Jobs: %w", err)
		}
		if max(active, s.running) < int(maxScans) {
			s.running++
			s.mu.Unlock()
			var once sync.Once
			return func() { once.Do(s.giveSlotBack) }, nil
		}
		freed := s.freed
		s.mu.Unlock()
		timer := time.NewTimer(s.opts.SlotWait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-freed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// giveSlotBack frees the slot of a scan of this process, and tells the scans that wait.
func (s *Scanner) giveSlotBack() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running--
	close(s.freed)
	s.freed = make(chan struct{})
}

// eventsOf returns the scanner's evidence about each manifest that a scan found, which ended at the time ended: an
// event about the manifest, with its platform and its completeness as the coverage, whose data is the manifest's JSON,
// and whose source is the collector in the cluster. A manifest whose evidence the store can't hold, or whose event is
// more than a message of the collector API holds, fails the scan as TooLarge, and no event is returned.
func (s *Scanner) eventsOf(cluster string, ended time.Time, manifests []result.Manifest) ([]cloudevents.Event,
	*collector.Failure, error) {
	source := "/clusters/" + cluster + "/collectors/" + s.opts.Name
	events := make([]cloudevents.Event, 0, len(manifests))
	for _, m := range manifests {
		compressed, _, err := result.EncodeManifest(m)
		if err != nil {
			return nil, nil, fmt.Errorf("encode the evidence of manifest %s: %w", m.Digest, err)
		}
		if len(compressed) > maxCompressedBytes {
			return nil, &collector.Failure{Reason: tooLarge,
				Message: "the evidence of a manifest is more than vexplain's evidence store holds"}, nil
		}
		e, err := evidence.New(result.EvidenceType, subject.Manifest(m.Digest), m,
			evidence.WithPlatform(m.Platform), evidence.WithCoverage(m.Completeness()),
			evidence.WithTime(ended), evidence.WithSource(source))
		if err == nil {
			err = evidence.Validate(e)
		}
		if err != nil {
			// The checks of the result make every manifest evidence, so this is a failure of the scanner's own. The
			// error can quote the result, which came from a log, so it isn't passed on.
			return nil, &collector.Failure{Reason: internal, Message: "the result of the scan can't be made into evidence"}, nil
		}
		size, err := messageSize(e)
		if err != nil {
			return nil, nil, fmt.Errorf("measure the evidence of manifest %s: %w", m.Digest, err)
		}
		if size > collector.MaxMessageSize {
			return nil, &collector.Failure{Reason: tooLarge,
				Message: "the evidence of a manifest is more than a message of the collector API holds"}, nil
		}
		events = append(events, e)
	}
	return events, nil, nil
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

// ---- the line of a scan Job ----

// scanOutcome is what a finished scan found: a result whose every manifest passed the checks, or the reason why the
// scan failed, and never both.
type scanOutcome struct {
	// result is what the scan found. It is nil when the scan failed.
	result *result.Result
	// reason is why the scan failed, and why says it in a fixed text: nothing in it comes from the log. Both are
	// empty when the scan succeeded.
	reason, why string
}

// failedWith returns the outcome of a scan that failed for reason, for the cause why.
func failedWith(reason, why string) scanOutcome {
	return scanOutcome{reason: reason, why: why}
}

// outcomeOf returns what the Job of call came to: the result of its line, once checked, or why it failed.
func outcomeOf(r jobs.Result, call scanCall) scanOutcome {
	switch reason := r.FailureReason; {
	case reason == "":
		return resultOf(r.Line, call)
	case reason == timedOut:
		return failedWith(timedOut, "the scan Job ran past its deadline")
	case reason == internal:
		return failedWith(internal, "the scan failed for a reason of its own, or its pod said nothing that tells why")
	case reason == tooLarge:
		return failedWith(tooLarge, "the image unpacks to more than the workspace holds, or the scan's log is more "+
			"than the collector reads")
	case result.ErrorReason(reason).Valid():
		return failedWith(reason, "the scan reported why it failed")
	default:
		// The scanner prints its own reasons only, so the line is no line of the scanner's.
		return failedWith(internal, "the scan pod reported a reason that the scanner doesn't give")
	}
}

// resultOf reads the result line of a scan pod that succeeded, the only kind of pod that delivers a result. The result
// must fit the scan that call asked for in every manifest, or the scan failed: TooLarge when the result is larger than
// the collector reads, and Internal for anything else, since the scanner never prints such a result.
func resultOf(line string, call scanCall) scanOutcome {
	r, reason, err := result.Parse(line, maxResultBytes)
	switch {
	case errors.Is(err, result.ErrTooLarge):
		return failedWith(tooLarge, err.Error())
	case err != nil:
		// The errors of Parse are fixed texts.
		return failedWith(internal, err.Error())
	case reason != "":
		return failedWith(internal, "the scan pod succeeded, but printed an error line")
	}
	if why := check(r, call); why != "" {
		return failedWith(internal, why)
	}
	return scanOutcome{result: r}
}

// check returns why r doesn't fit the scan that call asked for, or "" when it does:
//   - it names the image of the --image argument, byte for byte
//   - it has 1 to 16 manifests, each of a platform of its own
//   - each manifest fits the scan, as checkManifest says
func check(r *result.Result, call scanCall) string {
	if r.Image != call.image {
		return "the result names another image than the scan asked for"
	}
	if len(r.Manifests) == 0 || len(r.Manifests) > maxManifests {
		return fmt.Sprintf("the result has %d manifests, and not 1 to %d", len(r.Manifests), maxManifests)
	}
	platforms := make(map[string]bool, len(r.Manifests))
	for _, m := range r.Manifests {
		if why := checkManifest(m, call); why != "" {
			return why
		}
		if platforms[m.Platform] {
			return "two manifests of the result have the same platform"
		}
		platforms[m.Platform] = true
	}
	return ""
}

// checkManifest returns why m doesn't fit the scan that call asked for, or "" when it does. Its digest and its
// platform must be values that the API holds. Its platform must match one that the scan asked for, unless the
// manifest is the digest of the scan itself: an image of one manifest, and no index, is scanned whatever its platform.
// Its SBOM must be a JSON object with members, and its count of ELF files a number that the API holds.
func checkManifest(m result.Manifest, call scanCall) string {
	switch {
	case !digestPattern.MatchString(m.Digest):
		return "a manifest of the result has no sha256 digest"
	case len(m.Platform) > maxPlatformLength || !platformPattern.MatchString(m.Platform):
		return "a manifest of the result has a platform that the API can't hold"
	case m.Digest != call.digest && !slices.ContainsFunc(call.platforms, func(requested string) bool {
		return result.PlatformMatches(requested, m.Platform)
	}):
		return "a manifest of the result is of a platform that the scan didn't ask for"
	case !isObjectWithMembers(m.SBOM):
		return "a manifest of the result has no SBOM"
	case m.ELF.Total < 0 || m.ELF.Total > math.MaxInt32:
		return "a manifest of the result has a count of ELF files that the API can't hold"
	}
	return ""
}

// isObjectWithMembers reports whether raw is a JSON object with at least one member. raw comes from a JSON decoder,
// which has checked that it is valid JSON, so its first characters tell.
func isObjectWithMembers(raw json.RawMessage) bool {
	const space = " \t\r\n"
	value := bytes.TrimLeft(raw, space)
	if len(value) == 0 || value[0] != '{' {
		return false
	}
	members := bytes.TrimLeft(value[1:], space)
	return len(members) > 0 && members[0] != '}'
}
