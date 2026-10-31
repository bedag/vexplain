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

// Command measure-2a measures what the deterministic rules of phase 2a leave for a person, on a test set
// whose answers are known, and checks the rules' answers on one CVE against those known answers.
//
// The test set is a list of images with an expected answer each (cases.yaml). The tool puts every image into
// a local registry by digest, starts one Deployment per image in the namespace measure-2a, and waits until the
// operator has scanned each image, matched its packages and written its sheet. It reads what the operator
// made of the images through the stores of internal/inventory, and prints:
//
//   - the answer of each case, for the target CVE's finding in the Brotli library package, next to the known
//     answer: as the rules are built, and without the known-exploited override
//   - the findings of the cases' manifests, and those of the target CVE, by outcome, severity, fix state and the
//     rule that decided them, and again as the rules without the override would make them, and for each case
//   - the completeness of each manifest, the sizes of its evidence and of its sheet against the first trigger of
//     decision 0004, the time of its scan, and the length of the line that its scan printed
//
// The answer without the override is not in the sheet: the sheet holds the answer of the rules as built, where a
// vulnerability that the catalog lists as exploited is tracked before any other rule looks at it. The tool
// computes the other answer from the evidence, by running the rules again on the finding as if the catalog did
// not list it. It first runs them on every finding as the sheet has it, and stops if they don't give the sheet
// back: the rebuild of the finding then lost an input that the rules read, and the second answer would be wrong
// with nobody seeing it.
//
// The tool exits with 1 when any case's answer is "not affected" and its known answer is anything else, in
// either column, and when a case has no answer. That is the worst error of the rules (decision 0025).
//
// It refuses a cluster whose API server is not on a loopback address, and a registry that is not, with the check
// that hack/inventory-load makes too (hack/internal/localcluster). It needs the operator running on a kind
// cluster, as make deploy DEPLOY_CONFIG=test/e2e/config sets it up.
package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/hack/internal/localcluster"
	"github.com/bedag/vexplain/internal/inventory"
	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/rules"
	"github.com/bedag/vexplain/internal/scan/result"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/workloads"
)

// The exit codes.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

const (
	// namespaceName is the namespace of the Deployments that the cases run in.
	namespaceName = "measure-2a"
	// builtTag is the tag of the images that the tool builds, in the registry.
	builtTag = "measure"
	// triggerBytes is the size above which an object fires the first trigger of decision 0004: 512 KiB.
	triggerBytes = 512 * 1024
	// defaultTimeout is how long a case may take from the start of the wait for it to the sheet of each of
	// its manifests.
	defaultTimeout = 10 * time.Minute
	// pollInterval is the time between two looks at the stores.
	pollInterval = 3 * time.Second

	// appLabel labels the pods of a case with its name, and containerName names their one container.
	appLabel      = "app"
	containerName = "case"
	// The names of the Brotli library package on Alpine, and on Debian and Ubuntu.
	alpineLibrary = "brotli-libs"
	debianLibrary = "libbrotli1"
)

// defaultCommand keeps a container alive, without starting any of the servers of its image.
var defaultCommand = []string{"sleep", "86400"}

// Grype's words for the states of a fix, which the matcher passes on and the rules map.
const (
	grypeFixed    = "fixed"
	grypeNotFixed = "not-fixed"
	grypeWontFix  = "wont-fix"
	grypeUnknown  = "unknown"
)

const usage = `Usage: measure-2a --cases FILE --registry HOST:PORT [--timeout DURATION]

  --cases     the cases to measure: the target CVE, and for each case an image to build or to copy, with
              the answer that the rules should give, as built and without the known-exploited override
  --registry  the local registry that the images are put into, by digest: the one next to the kind
              cluster, such as localhost:5001. It must be on a loopback address.
  --timeout   how long to wait for each case, from the Deployment to the sheets of its manifests
              (default 10m)

The cluster is the one of the current context of the kubeconfig that KUBECONFIG names, which must be the own
kubeconfig of a local kind cluster, such as bin/kind-e2e.kubeconfig of the e2e setup:

  KUBECONFIG=bin/kind-e2e.kubeconfig go run ./hack/measure-2a --cases hack/measure-2a/cases.yaml \
    --registry localhost:5001

The tool refuses to run without KUBECONFIG, when the name of the current context doesn't start with kind-, and
when the API server is not on a loopback address. The operator must run on the cluster, with the matcher and
the registry of the e2e setup (make setup-test-e2e, then make deploy with DEPLOY_CONFIG=test/e2e/config). The
tool needs docker to build the planted images and to push them.

It exits with 1 when an answer is "not affected" where the known answer is anything else, in either column,
and when a case has no answer.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	env := environment{connect: connectToLocalCluster, prepare: prepareImages, poll: pollInterval}
	code := run(ctx, os.Args[1:], os.Stdout, env)
	stop() // os.Exit doesn't run deferred calls.
	os.Exit(code)
}

// environment is what run takes from the machine, so that a test can give it a cluster that is not one.
type environment struct {
	// connect returns a client for the cluster, or an error when it must not be used.
	connect func() (client.Client, error)
	// prepare puts the image of every case into the registry, and returns the digest of each by case name.
	prepare func(ctx context.Context, registry string, cases []testCase, out io.Writer) (map[string]string, error)
	// poll is the time between two looks at the stores.
	poll time.Duration
}

// run is the tool. It returns the exit code.
func run(ctx context.Context, args []string, out io.Writer, env environment) int {
	opts, err := parseArguments(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		say(out, "%s", usage)
		return exitOK
	case err != nil:
		say(out, "measure-2a: %v\n\n%s", err, usage)
		return exitUsage
	}
	if !localcluster.IsLoopback(opts.registry) {
		say(out, "measure-2a: the registry is not on a loopback address, and the tool puts images only into a local one\n")
		return exitUsage
	}

	// The cases are read and checked before the cluster is touched, and the cluster is known to be local before
	// any image is built, copied or pushed.
	file, err := readCases(opts.cases)
	if err != nil {
		say(out, "measure-2a: %v\n", err)
		return exitFailure
	}
	api, err := env.connect()
	if err != nil {
		say(out, "measure-2a: %v\n", err)
		return exitFailure
	}
	effective, err := settings.Load(ctx, api)
	if err != nil {
		say(out, "measure-2a: %v\n", err)
		return exitFailure
	}

	hubRules := rules.Settings{MinCompletenessPercent: effective.Rules.MinCompletenessPercent}

	digests, err := env.prepare(ctx, opts.registry, file.Cases, out)
	if err != nil {
		say(out, "measure-2a: %v\n", err)
		return exitFailure
	}
	if err = deploy(ctx, api, opts.registry, file.Cases, digests); err != nil {
		say(out, "measure-2a: %v\n", err)
		return exitFailure
	}

	noName := func() string { return "" }
	s := stores{
		api: api, inventory: inventory.NewCRDStore(api, nil, noName),
		packages: inventory.NewCRDPackagesStore(api, nil, noName), verdicts: inventory.NewCRDVerdictsStore(api, noName),
	}
	say(out, "waiting for the scans of %d cases\n", len(file.Cases))
	measured := make([]measurement, 0, len(file.Cases))
	for _, c := range file.Cases {
		m := measurement{c: c}
		image := imageOf(opts.registry, c.Name, digests[c.Name])
		m.data, m.err = s.gather(ctx, c, image, digests[c.Name], env.poll, opts.timeout)
		if ctx.Err() != nil {
			say(out, "measure-2a: interrupted\n")
			return exitFailure
		}
		if m.err != nil {
			say(out, "  %s: no answer: %v\n", c.Name, m.err)
		} else {
			// A rebuild that doesn't give the sheet back is an error of the tool and not of a case: stop.
			if err = m.evaluate(file.TargetCVE, hubRules); err != nil {
				say(out, "measure-2a: case %s: %v\n", c.Name, err)
				return exitFailure
			}
			say(out, "  %s: scanned and matched\n", c.Name)
		}
		measured = append(measured, m)
	}
	return report(out, file, hubRules.MinCompletenessPercent, measured)
}

// say prints to out. The tool can do nothing about a terminal that it can't write to.
func say(out io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(out, format, args...)
}

// arguments are what the command line says.
type arguments struct {
	cases, registry string
	timeout         time.Duration
}

// parseArguments reads the flags. Its errors are for the person who ran the tool.
func parseArguments(args []string) (arguments, error) {
	flags := flag.NewFlagSet("measure-2a", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // run prints the error and the usage.
	cases := flags.String("cases", "", "")
	registry := flags.String("registry", "", "")
	timeout := flags.Duration("timeout", defaultTimeout, "")
	if err := flags.Parse(args); err != nil {
		return arguments{}, err
	}
	switch {
	case flags.NArg() > 0:
		return arguments{}, errors.New("unexpected arguments")
	case *cases == "":
		return arguments{}, errors.New("--cases is required")
	case *registry == "":
		return arguments{}, errors.New("--registry is required")
	case *timeout <= 0:
		return arguments{}, errors.New("--timeout must be longer than zero")
	}
	return arguments{cases: *cases, registry: *registry, timeout: *timeout}, nil
}

// ---- the cases ----

// caseFile is the file of cases.
type caseFile struct {
	// TargetCVE is the vulnerability whose finding in the Brotli library package answers each case.
	TargetCVE string `json:"targetCVE"`
	// Approved is set to true by the owner, after reviewing every expected answer. Until then the output
	// calls the known answers provisional.
	Approved bool       `json:"approved"`
	Cases    []testCase `json:"cases"`
}

// testCase is one image with the answers that the rules should give for it.
type testCase struct {
	// Name is the name of the case: the name of its Deployment and of its repository in the registry.
	Name string `json:"name"`
	// Build is the directory of a Dockerfile to build, or Image the public image to copy, by digest. One of
	// the two is set.
	Build string `json:"build,omitempty"`
	Image string `json:"image,omitempty"`
	// Package is the name of the Brotli library package, for an image where it is not brotli-libs (Alpine) or
	// libbrotli1 (Debian and Ubuntu).
	Package string `json:"package,omitempty"`
	// Command keeps the container alive, so that no server of the image starts. It defaults to sleep, which an
	// image without it can't use.
	Command []string `json:"command,omitempty"`
	// Expected is the answer of the rules as built, for the target CVE's finding in the library package:
	// Suppressed, NeedsAssessment or Tracked, or NotFound or NoPackage when the sheet should hold no such
	// finding. NotFound is a copy that the scanner can't see, which is a blind spot, and NoPackage an image with
	// no affected Brotli package.
	Expected string `json:"expected"`
	// ExpectedWithoutKEV is the answer of the rules without the known-exploited override: what the later
	// rules say, or the same NotFound or NoPackage.
	ExpectedWithoutKEV string `json:"expectedWithoutKEV"`
	// Basis says how the answers were worked out, without the rules under test.
	Basis string `json:"basis"`
}

// The answers. The outcomes are those of a finding. None is the actual answer of a case whose sheet holds no
// finding of the target CVE in the library package, which matches both of the expected answers that say there
// should be none. The tool can't tell them apart: a copy that the scanner can't see leaves no trace.
const (
	answerNone      = "None"
	answerNotFound  = "NotFound"
	answerNoPackage = "NoPackage"
)

var (
	// cvePattern is the form of the target CVE, and labelPattern that of a case's name: a DNS label, because
	// the name is also the name of a Deployment and of a repository.
	cvePattern   = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	labelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	// pinnedPattern is an image that is named by its digest, as a registry gives it.
	pinnedPattern = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)
)

func isOutcome(answer string) bool {
	switch inventoryv1alpha1.Outcome(answer) {
	case inventoryv1alpha1.OutcomeSuppressed, inventoryv1alpha1.OutcomeTracked, inventoryv1alpha1.OutcomeNeedsAssessment:
		return true
	}
	return false
}

func isNoFinding(answer string) bool { return answer == answerNotFound || answer == answerNoPackage }

// parseCases reads and checks a file of cases. It rejects what can't be measured, or can't mean what it says:
// a name that is no DNS label, an image that isn't pinned, and a pair of expected answers that no run of the
// rules can give.
func parseCases(data []byte) (*caseFile, error) {
	var file caseFile
	if err := yaml.UnmarshalStrict(data, &file); err != nil {
		return nil, fmt.Errorf("read the cases: %w", err)
	}
	if !cvePattern.MatchString(file.TargetCVE) {
		return nil, errors.New("targetCVE must be a CVE ID, such as CVE-2026-111497")
	}
	if len(file.Cases) == 0 {
		return nil, errors.New("the file has no cases")
	}
	seen := map[string]bool{}
	for _, c := range file.Cases {
		if seen[c.Name] {
			return nil, fmt.Errorf("the name %q is used twice", c.Name)
		}
		seen[c.Name] = true
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("case %q: %w", c.Name, err)
		}
	}
	return &file, nil
}

func (c testCase) validate() error {
	switch {
	case !labelPattern.MatchString(c.Name):
		return errors.New("the name must be a DNS label: lower case letters, digits and '-'")
	case (c.Build == "") == (c.Image == ""):
		return errors.New("exactly one of build and image is required")
	case c.Image != "" && !pinnedPattern.MatchString(c.Image):
		return errors.New("image must name a digest, as repository@sha256:<64 hex digits>")
	case c.Basis == "":
		return errors.New("basis is required: say how the answers were worked out")
	case !isOutcome(c.Expected) && !isNoFinding(c.Expected):
		return errors.New("expected must be Suppressed, NeedsAssessment, Tracked, NotFound or NoPackage")
	case c.ExpectedWithoutKEV == string(inventoryv1alpha1.OutcomeTracked) ||
		(!isOutcome(c.ExpectedWithoutKEV) && !isNoFinding(c.ExpectedWithoutKEV)):
		return errors.New("expectedWithoutKEV must be Suppressed, NeedsAssessment, NotFound or NoPackage: " +
			"only the known-exploited rule tracks a finding")
	}
	// Without the override, only a finding that the catalog took gets another answer, which the later rules
	// give. Any other finding keeps its answer, and an image with no such finding keeps having none.
	if c.Expected == string(inventoryv1alpha1.OutcomeTracked) {
		if isNoFinding(c.ExpectedWithoutKEV) {
			return errors.New("expectedWithoutKEV can't be NotFound or NoPackage for a finding that is Tracked")
		}
	} else if c.ExpectedWithoutKEV != c.Expected {
		return fmt.Errorf("expectedWithoutKEV must be %s, like expected: without the catalog, "+
			"only a Tracked finding changes its answer", c.Expected)
	}
	return nil
}

// readCases reads the cases file at path. A build directory is read from the place of the file, wherever the
// tool runs, and must hold a Dockerfile.
func readCases(path string) (*caseFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	file, err := parseCases(data)
	if err != nil {
		return nil, err
	}
	for i := range file.Cases {
		c := &file.Cases[i]
		if c.Build == "" {
			continue
		}
		if !filepath.IsAbs(c.Build) {
			c.Build = filepath.Join(filepath.Dir(path), c.Build)
		}
		if _, err = os.Stat(filepath.Join(c.Build, "Dockerfile")); err != nil {
			return nil, fmt.Errorf("case %q: there is no Dockerfile in its build directory %s", c.Name, c.Build)
		}
	}
	return file, nil
}

// libraryPackages returns the names that the Brotli library package of the case can have.
func (c testCase) libraryPackages() []string {
	if c.Package != "" {
		return []string{c.Package}
	}
	return []string{alpineLibrary, debianLibrary}
}

// ---- images ----

// prepareImages puts the image of every case into the registry, and returns its digest by case name. A
// planted image is built and pushed as a single manifest, so that the digest that the registry holds is the
// digest of the manifest that gets scanned. A public image is copied with the digest that it has, an index
// with its platforms, so that a pod pulls it for real and the scanner can fetch it again.
func prepareImages(ctx context.Context, registry string, cases []testCase, out io.Writer) (map[string]string, error) {
	digests := make(map[string]string, len(cases))
	for _, c := range cases {
		var digest string
		var err error
		if c.Build != "" {
			say(out, "building and pushing %s\n", c.Name)
			digest, err = buildAndPush(ctx, registry, c)
		} else {
			say(out, "copying %s\n", c.Name)
			digest = c.Image[strings.LastIndexByte(c.Image, '@')+1:]
			err = copyImage(ctx, c.Image, imageOf(registry, c.Name, digest))
		}
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", c.Name, err)
		}
		digests[c.Name] = digest
	}
	return digests, nil
}

// buildAndPush builds the image of a case, and pushes it to the registry. The image carries neither
// provenance nor an SBOM attestation: with them the push would make an index, whose digest is not the digest of
// the manifest that gets scanned.
func buildAndPush(ctx context.Context, registry string, c testCase) (string, error) {
	reference := registry + "/" + c.Name + ":" + builtTag
	if _, err := docker(ctx, "build", "--provenance=false", "--sbom=false", "-t", reference, c.Build); err != nil {
		return "", err
	}
	output, err := docker(ctx, "push", reference)
	if err != nil {
		return "", err
	}
	digest, ok := pushedDigest(output)
	if !ok {
		return "", errors.New("the output of docker push names no digest")
	}
	return digest, nil
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

// pushedDigest finds the digest of a pushed manifest in the output of docker push.
var pushedDigestPattern = regexp.MustCompile(`digest: (sha256:[0-9a-f]{64})`)

func pushedDigest(output string) (string, bool) {
	found := pushedDigestPattern.FindStringSubmatch(output)
	if found == nil {
		return "", false
	}
	return found[1], true
}

// copyImage copies the image or index at source to destination, which both name the same digest. The digest
// is kept: the manifests are copied as they are, an index with its platform manifests. The images are public,
// so the copy is anonymous, and never looks into the credentials of whoever runs the tool. An image that the
// destination holds already is not copied again: a registry takes an index only with all of its manifests.
func copyImage(ctx context.Context, source, destination string) error {
	from, err := name.NewDigest(source)
	if err != nil {
		return fmt.Errorf("the source %q: %w", source, err)
	}
	to, err := name.NewDigest(destination)
	if err != nil {
		return fmt.Errorf("the destination %q: %w", destination, err)
	}
	if from.DigestStr() != to.DigestStr() {
		return errors.New("a copy keeps the digest, and the source and the destination name different ones")
	}
	options := []remote.Option{remote.WithContext(ctx), remote.WithAuth(authn.Anonymous)}
	if present, err := remote.Head(to, options...); err == nil && present.Digest.String() == to.DigestStr() {
		return nil
	}
	puller, err := remote.NewPuller(options...)
	if err != nil {
		return err
	}
	found, err := puller.Get(ctx, from)
	if err != nil {
		return fmt.Errorf("read %s: %w", source, err)
	}
	pusher, err := remote.NewPusher(options...)
	if err != nil {
		return err
	}
	if err = pusher.Push(ctx, to, found); err != nil {
		return fmt.Errorf("write %s: %w", destination, err)
	}
	return nil
}

// ---- the cluster ----

// deploy makes the namespace and one Deployment for each case. It updates what is there, so that a second run,
// after a failed one, goes on.
func deploy(ctx context.Context, api client.Client, registry string, cases []testCase,
	digests map[string]string) error {
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
	if _, err := controllerutil.CreateOrUpdate(ctx, api, namespace, func() error { return nil }); err != nil {
		return fmt.Errorf("make namespace %s: %w", namespaceName, err)
	}
	for _, c := range cases {
		want := deploymentFor(c, imageOf(registry, c.Name, digests[c.Name]))
		have := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: want.Name, Namespace: want.Namespace}}
		if _, err := controllerutil.CreateOrUpdate(ctx, api, have, func() error {
			have.Labels, have.Spec = want.Labels, want.Spec
			return nil
		}); err != nil {
			return fmt.Errorf("make the Deployment of %s: %w", c.Name, err)
		}
	}
	return nil
}

// imageOf returns the reference that the Deployment of a case runs: its image in the registry, by digest.
func imageOf(registry, caseName, digest string) string {
	return registry + "/" + caseName + "@" + digest
}

// deploymentFor returns the Deployment of a case: one replica of its image, which sleeps. A scan reads the
// files of an image and runs nothing, but the inventory sees images through the pods that run them. The pod
// runs sleep, so that none of the image's servers start, unless the image has no sleep and the case names
// a program of its own.
func deploymentFor(c testCase, image string) *appsv1.Deployment {
	command := c.Command
	if len(command) == 0 {
		command = defaultCommand
	}
	labels := map[string]string{appLabel: c.Name}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: c.Name, Namespace: namespaceName, Labels: labels},
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
						Name: containerName, Image: image, Command: command, ImagePullPolicy: corev1.PullIfNotPresent,
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

// newScheme returns the scheme of the objects that the tool reads and makes.
func newScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		inventoryv1alpha1.AddToScheme, configv1alpha1.AddToScheme, appsv1.AddToScheme, corev1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			return nil, fmt.Errorf("register the APIs: %w", err)
		}
	}
	return scheme, nil
}

// connectToLocalCluster returns a client for the local kind cluster of the kubeconfig that KUBECONFIG names, and
// refuses any other cluster, as localcluster.Connect does. The tool starts Deployments and reads what the
// operator made of them, which belongs on a local kind cluster and nowhere else.
func connectToLocalCluster() (client.Client, error) {
	scheme, err := newScheme()
	if err != nil {
		return nil, err
	}
	return localcluster.Connect(scheme)
}

// ---- what the stores hold ----

// stores are the doors to what the operator made of the images. The tool reads the inventory, the evidence and
// the sheets only through them, and the pods only to learn the digest that the inventory has.
type stores struct {
	api       client.Reader
	inventory inventory.Store
	packages  inventory.PackagesStore
	verdicts  inventory.VerdictsStore
}

// caseData is what the stores hold about one case.
type caseData struct {
	// digest is the digest of the case's ImageInventory, and repository the repository of its image.
	digest, repository string
	// firstSeen is when the inventory first saw the digest running, and scanned when the last scan ended.
	firstSeen, scanned time.Time
	manifests          []manifestData
}

// manifestData is what the stores hold about one platform manifest of a case.
type manifestData struct {
	platform string
	digest   string
	facts    inventoryv1alpha1.PlatformFacts
	evidence result.Manifest
	info     inventory.PackagesInfo
	sheet    *inventoryv1alpha1.ImageVerdicts
}

// gather waits for everything that a case's answer needs: the scan of its image, the evidence of each platform
// manifest that the scan covered, and the sheet that the match of each made. It looks every poll, and gives up
// after timeout. A scan that failed without covering any platform is not waited for: the hub tries a failed
// scan again only after an hour. image is the reference that the tool deployed for the case, and pinned the
// digest in it.
func (s stores) gather(ctx context.Context, c testCase, image, pinned string, poll,
	timeout time.Duration) (caseData, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	waiting := "the stores to answer"
	for {
		data, stillWaiting, err := s.look(waitCtx, c, image, pinned)
		switch {
		case err == nil && stillWaiting == "":
			return data, nil
		case ctx.Err() != nil:
			return caseData{}, ctx.Err()
		case waitCtx.Err() != nil: // a read that the timeout cut short is a timeout, whatever it says
			return caseData{}, fmt.Errorf("timed out after %s, waiting for %s", timeout, waiting)
		case err != nil:
			return caseData{}, err
		}
		waiting = stillWaiting
		select {
		case <-waitCtx.Done():
		case <-time.After(poll):
		}
	}
}

// look reads what the stores hold of a case once. It returns what the case still waits for, or "" when
// the data is complete, and an error for what no waiting would change.
func (s stores) look(ctx context.Context, c testCase, image, pinned string) (caseData, string, error) {
	digest, err := s.reportedDigest(ctx, c, image, pinned)
	if err != nil {
		return caseData{}, "", err
	}
	found, err := s.inventory.Get(ctx, digest)
	if err != nil {
		return caseData{}, "", err
	}
	if found == nil {
		return caseData{}, "the inventory to see the image", nil
	}
	facts := found.Status.Facts
	switch {
	case facts == nil:
		return caseData{}, "the scan of the image", nil
	case len(facts.Platforms) == 0 && facts.Failure != nil:
		return caseData{}, "", fmt.Errorf("the scan failed with %s", facts.Failure.Reason)
	case len(facts.Platforms) == 0:
		return caseData{}, "the platforms of the scan", nil
	}

	data := caseData{digest: digest}
	for _, presence := range found.Status.Clusters {
		if t := presence.FirstSeenTime; t != nil && (data.firstSeen.IsZero() || t.Time.Before(data.firstSeen)) {
			data.firstSeen = t.Time
		}
		if data.repository == "" && len(presence.Repositories) > 0 {
			data.repository = presence.Repositories[0]
		}
	}
	for _, platform := range facts.Platforms {
		evidence, info, err := s.packages.Get(ctx, platform.ManifestDigest)
		if err != nil {
			return caseData{}, "", err
		}
		if evidence == nil {
			return caseData{}, "the evidence of " + platform.Platform, nil
		}
		sheet, err := s.verdicts.Get(ctx, platform.ManifestDigest)
		if err != nil {
			return caseData{}, "", err
		}
		// A sheet that doesn't say which database found its findings reads as no verdict yet.
		if sheet == nil || sheet.Status.DatabaseVersion == nil {
			return caseData{}, "the sheet of " + platform.Platform, nil
		}
		data.manifests = append(data.manifests, manifestData{
			platform: platform.Platform, digest: platform.ManifestDigest, facts: platform,
			evidence: *evidence, info: *info, sheet: sheet,
		})
		data.scanned = latest(data.scanned, info.ScannedTime)
	}
	return data, "", nil
}

// reportedDigest returns the digest that the inventory has for a case: the one that its pod reports, which
// for an index is the digest of the index, and the pinned one before the pod reports any.
//
// Only a pod that runs the image that the tool deployed counts. When a run deploys another image under the name
// of a case, the Deployment rolls out, and the pod of the earlier image keeps running until the new one is ready.
// It reports the earlier digest, and the stores still hold the complete data of the earlier run for it.
func (s stores) reportedDigest(ctx context.Context, c testCase, image, pinned string) (string, error) {
	var pods corev1.PodList
	err := s.api.List(ctx, &pods, client.InNamespace(namespaceName), client.MatchingLabels{appLabel: c.Name})
	if err != nil {
		return "", fmt.Errorf("list the pods of %s: %w", c.Name, err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !slices.ContainsFunc(pod.Spec.Containers, func(k corev1.Container) bool { return k.Image == image }) {
			continue
		}
		if images, _ := workloads.PodImages(pod); len(images) > 0 {
			return images[0].Digest, nil
		}
	}
	return pinned, nil
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// ---- the evaluation ----

// check says how an actual answer compares with the known one.
type check int

const (
	// checkMatches means the actual answer is the known one.
	checkMatches check = iota
	// checkDiffers means that it is another one, and errs towards a person looking at the finding.
	checkDiffers
	// checkFalseNotAffected means that the rules call the finding not affected where the known answer is
	// anything else: the worst error.
	checkFalseNotAffected
)

// compare compares an actual answer, which is an outcome or None, with an expected one.
func compare(expected, actual string) check {
	switch {
	case actual == string(inventoryv1alpha1.OutcomeSuppressed) && expected != actual:
		return checkFalseNotAffected
	case isNoFinding(expected) && actual == answerNone, expected == actual:
		return checkMatches
	}
	return checkDiffers
}

// answerOf returns the answer that findings come to: None for no finding, and the outcome of the findings
// when they agree. Manifests that disagree make the answer that keeps a finding open, Tracked before
// NeedsAssessment before Suppressed, so that no case says "not affected" while any manifest says anything else.
func answerOf(findings []inventoryv1alpha1.Finding) string {
	rank := func(o inventoryv1alpha1.Outcome) int {
		switch o {
		case inventoryv1alpha1.OutcomeTracked:
			return 0
		case inventoryv1alpha1.OutcomeNeedsAssessment:
			return 1
		}
		return 2
	}
	if len(findings) == 0 {
		return answerNone
	}
	best := slices.MinFunc(findings, func(a, b inventoryv1alpha1.Finding) int {
		return cmp.Compare(rank(a.Outcome), rank(b.Outcome))
	})
	return string(best.Outcome)
}

// libraryFindings returns the findings of a vulnerability in the packages with the names.
func libraryFindings(findings []inventoryv1alpha1.Finding, cve string, packages []string) []inventoryv1alpha1.Finding {
	return slices.DeleteFunc(slices.Clone(findings), func(f inventoryv1alpha1.Finding) bool {
		return f.VulnerabilityID != cve || !slices.Contains(packages, f.Package.Name)
	})
}

// otherBrotliFindings returns the findings of the vulnerability in the Brotli packages that are not the
// library, such as a command or a development package of the same source. Grype matches an Alpine package by its
// origin, so they get findings of their own. They appear in the output and never decide a case's answer.
func otherBrotliFindings(findings []inventoryv1alpha1.Finding, cve string,
	packages []string) []inventoryv1alpha1.Finding {
	return slices.DeleteFunc(slices.Clone(findings), func(f inventoryv1alpha1.Finding) bool {
		return f.VulnerabilityID != cve || slices.Contains(packages, f.Package.Name) ||
			!strings.Contains(strings.ToLower(f.Package.Name), "brotli")
	})
}

// matchFrom rebuilds the match that the rules turned into a finding. The finding holds every field that the
// rules read of a match: they decide by the package ID and the flag, and copy the rest, which the package's
// entry in the evidence supplies in the finding when the SBOM names the package. The flag is the argument.
func matchFrom(f inventoryv1alpha1.Finding, knownExploited bool) matchapi.Match {
	return matchapi.Match{
		VulnerabilityID: f.VulnerabilityID,
		PackageID:       f.Package.ID,
		Severity:        string(f.Severity),
		FixState:        grypeFixState(f.FixState),
		FixedVersions:   f.FixedVersions,
		KnownExploited:  knownExploited,
		PackageName:     f.Package.Name,
		PackageVersion:  ptr.Deref(f.Package.Version, ""),
		PackageType:     f.Package.Type,
	}
}

// grypeFixState returns the fix state in Grype's words, which the matcher passes on and the rules map.
func grypeFixState(state inventoryv1alpha1.FixState) string {
	switch state {
	case inventoryv1alpha1.FixStateFixed:
		return grypeFixed
	case inventoryv1alpha1.FixStateNotFixed:
		return grypeNotFixed
	case inventoryv1alpha1.FixStateWontFix:
		return grypeWontFix
	}
	return grypeUnknown
}

// withoutOverride returns the findings of a manifest as the rules would make them if no vulnerability were known
// to be exploited, in the order of findings: a finding that the catalog took gets the answer of the later
// rules, and every other finding keeps its own. It rebuilds the matches of the findings and runs the rules.
//
// Before that it runs the rules on the matches as the findings record them, with the flag set for the findings
// that the catalog decided, and demands the sheet back: the same outcome, rule, justification, conditions and
// reason for every finding. If one comes back different, the rebuild has lost an input that the rules read, or
// the sheet came from other rules, and the error names the finding.
func withoutOverride(ev result.Manifest, findings []inventoryv1alpha1.Finding,
	s rules.Settings) ([]inventoryv1alpha1.Finding, error) {
	asRecorded := make([]matchapi.Match, len(findings))
	without := make([]matchapi.Match, len(findings))
	for i, f := range findings {
		exploited := ptr.Deref(f.Rule, "") == inventoryv1alpha1.RuleKnownExploited
		asRecorded[i], without[i] = matchFrom(f, exploited), matchFrom(f, false)
	}

	again := indexByKey(rules.Evaluate(ev, asRecorded, s))
	for _, f := range findings {
		got, ok := again[keyOf(f)]
		if !ok || !sameDecision(f, got) {
			return nil, fmt.Errorf("the rebuild of the finding of %s in %s (package ID %s) gives %s, and the sheet has %s: "+
				"the rebuilt match lacks an input that the rules read, or the sheet comes from other rules",
				f.VulnerabilityID, f.Package.Name, f.Package.ID, describe(got, ok), describe(f, true))
		}
	}
	later := indexByKey(rules.Evaluate(ev, without, s))
	out := make([]inventoryv1alpha1.Finding, len(findings))
	for i, f := range findings {
		got, ok := later[keyOf(f)]
		if !ok {
			return nil, fmt.Errorf("the rules gave no finding of %s in %s without the override",
				f.VulnerabilityID, f.Package.Name)
		}
		out[i] = got
	}
	return out, nil
}

// keyOf is what tells a finding from the others of its sheet: a vulnerability in a package.
func keyOf(f inventoryv1alpha1.Finding) string { return f.VulnerabilityID + "\x00" + f.Package.ID }

func indexByKey(findings []inventoryv1alpha1.Finding) map[string]inventoryv1alpha1.Finding {
	index := make(map[string]inventoryv1alpha1.Finding, len(findings))
	for _, f := range findings {
		index[keyOf(f)] = f
	}
	return index
}

// sameDecision reports whether two findings were decided the same way. Their other fields are copies of what
// the matches say.
func sameDecision(a, b inventoryv1alpha1.Finding) bool {
	return a.Outcome == b.Outcome && ptr.Deref(a.Rule, "") == ptr.Deref(b.Rule, "") &&
		ptr.Deref(a.Justification, "") == ptr.Deref(b.Justification, "") &&
		slices.Equal(a.Conditions, b.Conditions) && ptr.Deref(a.Reason, "") == ptr.Deref(b.Reason, "")
}

// describe says how a finding was decided, for an error: its outcome, its rule and its reason.
func describe(f inventoryv1alpha1.Finding, present bool) string {
	if !present {
		return "no finding"
	}
	text := string(f.Outcome)
	if f.Rule != nil {
		text += " by " + string(*f.Rule)
	}
	if f.Reason != nil {
		text += fmt.Sprintf(" (%q)", *f.Reason)
	}
	return text
}

// measurement is a case with what the stores hold of it, and the answers that its evaluation gave.
type measurement struct {
	c    testCase
	data caseData
	// err says why the case has no answer, when it has none.
	err error

	// answer is the answer of the sheets, and answerWithout the answer of the rules without the override.
	answer, answerWithout string
	// library names the library packages that the answer comes from. It is empty when the answer is None.
	library []string
	// others are the findings of the target CVE in the other Brotli packages, as "package:Outcome".
	others []string
	// without holds the findings of each manifest without the override, in the order of its sheet.
	without [][]inventoryv1alpha1.Finding
}

// evaluate gives the case its answers. It returns an error only when the rules can't rebuild a sheet.
func (m *measurement) evaluate(cve string, s rules.Settings) error {
	packages := m.c.libraryPackages()
	var library, libraryWithout []inventoryv1alpha1.Finding
	for _, manifest := range m.data.manifests {
		findings := manifest.sheet.Status.Findings
		free, err := withoutOverride(manifest.evidence, findings, s)
		if err != nil {
			return fmt.Errorf("manifest %s: %w", manifest.platform, err)
		}
		m.without = append(m.without, free)
		library = append(library, libraryFindings(findings, cve, packages)...)
		libraryWithout = append(libraryWithout, libraryFindings(free, cve, packages)...)
		for _, f := range otherBrotliFindings(findings, cve, packages) {
			m.others = append(m.others, f.Package.Name+":"+string(f.Outcome))
		}
	}
	m.answer, m.answerWithout = answerOf(library), answerOf(libraryWithout)
	for _, f := range library {
		if !slices.Contains(m.library, f.Package.Name) {
			m.library = append(m.library, f.Package.Name)
		}
	}
	return nil
}

// totals counts findings by outcome, severity and fix state, and the severities and fix states within each
// outcome: the residual, the findings that wait for an assessment, is the row of NeedsAssessment. It also counts
// the findings of each outcome by the rule that decided it, or that kept it from being suppressed.
type totals struct {
	total             int
	outcome           map[inventoryv1alpha1.Outcome]int
	severity          map[inventoryv1alpha1.Severity]int
	fixState          map[inventoryv1alpha1.FixState]int
	outcomeBySeverity map[inventoryv1alpha1.Outcome]map[inventoryv1alpha1.Severity]int
	outcomeByFixState map[inventoryv1alpha1.Outcome]map[inventoryv1alpha1.FixState]int
	// outcomeByRule is keyed by the rule too, where the empty rule is no rule: none applied.
	outcomeByRule map[inventoryv1alpha1.Outcome]map[inventoryv1alpha1.Rule]int
}

func tally(findings []inventoryv1alpha1.Finding) totals {
	t := totals{
		outcome:           map[inventoryv1alpha1.Outcome]int{},
		severity:          map[inventoryv1alpha1.Severity]int{},
		fixState:          map[inventoryv1alpha1.FixState]int{},
		outcomeBySeverity: map[inventoryv1alpha1.Outcome]map[inventoryv1alpha1.Severity]int{},
		outcomeByFixState: map[inventoryv1alpha1.Outcome]map[inventoryv1alpha1.FixState]int{},
		outcomeByRule:     map[inventoryv1alpha1.Outcome]map[inventoryv1alpha1.Rule]int{},
	}
	for _, f := range findings {
		t.total++
		t.outcome[f.Outcome]++
		t.severity[f.Severity]++
		t.fixState[f.FixState]++
		if t.outcomeBySeverity[f.Outcome] == nil {
			t.outcomeBySeverity[f.Outcome] = map[inventoryv1alpha1.Severity]int{}
			t.outcomeByFixState[f.Outcome] = map[inventoryv1alpha1.FixState]int{}
			t.outcomeByRule[f.Outcome] = map[inventoryv1alpha1.Rule]int{}
		}
		t.outcomeBySeverity[f.Outcome][f.Severity]++
		t.outcomeByFixState[f.Outcome][f.FixState]++
		t.outcomeByRule[f.Outcome][ptr.Deref(f.Rule, "")]++
	}
	return t
}

// against says how a size compares with the first trigger of decision 0004, as a percentage rounded down.
// A size over the trigger says so.
func against(size int64) string {
	text := fmt.Sprintf("%d%%", size*100/triggerBytes)
	if size > triggerBytes {
		text += " OVER"
	}
	return text
}

// ---- the report ----

// The columns that every table that has a row for each case starts with, and the rest of the headings.
const (
	columnCase     = "CASE"
	columnPlatform = "PLATFORM"
	columnFindings = "FINDINGS"
)

// report prints what the run measured, and returns the exit code.
func report(out io.Writer, file *caseFile, minCompleteness int32, measured []measurement) int {
	answered := slices.DeleteFunc(slices.Clone(measured), func(m measurement) bool { return m.err != nil })

	say(out, "\nmeasure-2a: %s, %d cases\n", file.TargetCVE, len(measured))
	if file.Approved {
		say(out, "known answers: approved by the owner\n")
	} else {
		say(out, "known answers: provisional until the owner approves them (approved: false)\n")
	}
	say(out, "database: %s\nscanner image: %s\ncompleteness guard: %d%%\n",
		joined(answered, func(m manifestData) string { return ptr.Deref(m.sheet.Status.DatabaseVersion, "") }),
		joined(answered, func(m manifestData) string { return m.info.ScannerImage }), minCompleteness)

	failures := printAnswers(out, file.TargetCVE, measured)

	// The totals cover the findings of the cases' manifests, as their sheets list them.
	var listed, without []inventoryv1alpha1.Finding
	manifests, omitted := 0, 0
	for _, m := range answered {
		for i, manifest := range m.data.manifests {
			manifests++
			listed = append(listed, manifest.sheet.Status.Findings...)
			without = append(without, m.without[i]...)
			omitted += int(ptr.Deref(manifest.sheet.Status.OmittedFindings, 0))
		}
	}
	forTarget := slices.DeleteFunc(slices.Clone(listed), func(f inventoryv1alpha1.Finding) bool {
		return f.VulnerabilityID != file.TargetCVE
	})
	printTotals(out, fmt.Sprintf("findings: %d in %d manifests (%d left out of the sheets)",
		len(listed), manifests, omitted), tally(listed))
	printTotals(out, fmt.Sprintf("findings of %s: %d in %d manifests", file.TargetCVE, len(forTarget), manifests),
		tally(forTarget))
	printTotals(out, fmt.Sprintf("findings without the known-exploited override: %d in %d manifests",
		len(without), manifests), tally(without))

	printFindingsByCase(out, answered)
	printCompleteness(out, minCompleteness, answered)
	printSizes(out, answered)
	printScans(out, answered)

	if failures > 0 {
		say(out, "\n%d false not-affected or missing answers: the measurement fails\n", failures)
		return exitFailure
	}
	return exitOK
}

// joined returns the distinct values that get of the manifests of the cases, sorted and joined with commas.
func joined(measured []measurement, get func(manifestData) string) string {
	values := map[string]bool{}
	for _, m := range measured {
		for _, manifest := range m.data.manifests {
			if v := get(manifest); v != "" {
				values[v] = true
			}
		}
	}
	return strings.Join(slices.Sorted(maps.Keys(values)), ",")
}

// table prints rows with their columns aligned.
func table(out io.Writer, header []string, rows [][]string) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, strings.Join(header, "\t"))
	for _, row := range rows {
		_, _ = fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	_ = w.Flush()
}

// printAnswers prints the answer of each case next to the known one, in both columns, and what each column
// comes to. It returns the number of failures: false "not affected" in either column, and cases without an answer.
func printAnswers(out io.Writer, cve string, measured []measurement) int {
	say(out, "\n== answers for %s, in the library package of each case\n", cve)
	rows := make([][]string, 0, len(measured))
	var asBuilt, without [3]int
	missing := 0
	for _, m := range measured {
		if m.err != nil {
			rows = append(rows, []string{m.c.Name + "\tno answer: " + m.err.Error()})
			missing++
			continue
		}
		first, second := compare(m.c.Expected, m.answer), compare(m.c.ExpectedWithoutKEV, m.answerWithout)
		asBuilt[first]++
		without[second]++
		rows = append(rows, []string{
			m.c.Name, platformsOf(m), orDash(strings.Join(m.library, ",")),
			m.c.Expected, m.answer, verdictOf(first), m.c.ExpectedWithoutKEV, m.answerWithout, verdictOf(second),
			orDash(strings.Join(m.others, ",")),
		})
	}
	table(out, []string{columnCase, columnPlatform, "LIBRARY", "EXPECTED", "ACTUAL", "CHECK",
		"EXPECTED WITHOUT KEV", "ACTUAL WITHOUT KEV", "CHECK WITHOUT KEV", "OTHER BROTLI"}, rows)

	answered := len(measured) - missing
	say(out, "\nas built: %d of %d as expected, %d differ, %d false not-affected\n",
		asBuilt[checkMatches], answered, asBuilt[checkDiffers], asBuilt[checkFalseNotAffected])
	say(out, "without the override: %d of %d as expected, %d differ, %d false not-affected\n",
		without[checkMatches], answered, without[checkDiffers], without[checkFalseNotAffected])
	switch missing {
	case 0:
	case 1:
		say(out, "1 case without an answer\n")
	default:
		say(out, "%d cases without an answer\n", missing)
	}
	return asBuilt[checkFalseNotAffected] + without[checkFalseNotAffected] + missing
}

func verdictOf(c check) string {
	switch c {
	case checkMatches:
		return "ok"
	case checkDiffers:
		return "DIFFERS"
	}
	return "FALSE NOT-AFFECTED"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// platformsOf returns the platforms of a case's manifests, joined with commas.
func platformsOf(m measurement) string {
	platforms := make([]string, 0, len(m.data.manifests))
	for _, manifest := range m.data.manifests {
		platforms = append(platforms, manifest.platform)
	}
	return strings.Join(platforms, ",")
}

// The columns of the totals, and the rows: the outcomes, the residual first.
var (
	severityColumns = []string{
		string(inventoryv1alpha1.SeverityCritical), string(inventoryv1alpha1.SeverityHigh),
		string(inventoryv1alpha1.SeverityMedium), string(inventoryv1alpha1.SeverityLow),
		string(inventoryv1alpha1.SeverityNegligible), string(inventoryv1alpha1.SeverityUnknown),
	}
	fixStateColumns = []string{
		string(inventoryv1alpha1.FixStateFixed), string(inventoryv1alpha1.FixStateNotFixed),
		string(inventoryv1alpha1.FixStateWontFix), string(inventoryv1alpha1.FixStateUnknown),
	}
	outcomeRows = []inventoryv1alpha1.Outcome{
		inventoryv1alpha1.OutcomeNeedsAssessment, inventoryv1alpha1.OutcomeTracked, inventoryv1alpha1.OutcomeSuppressed,
	}
)

// printTotals prints findings by outcome, once by severity and once by fix state.
func printTotals(out io.Writer, heading string, t totals) {
	say(out, "\n== %s\n", heading)
	breakdown(out, t, severityColumns, func(o inventoryv1alpha1.Outcome, label string) int {
		return t.outcomeBySeverity[o][inventoryv1alpha1.Severity(label)]
	}, func(label string) int { return t.severity[inventoryv1alpha1.Severity(label)] })
	say(out, "\n")
	breakdown(out, t, fixStateColumns, func(o inventoryv1alpha1.Outcome, label string) int {
		return t.outcomeByFixState[o][inventoryv1alpha1.FixState(label)]
	}, func(label string) int { return t.fixState[inventoryv1alpha1.FixState(label)] })

	// What decided each outcome, or stopped the rules from suppressing a finding: "none" is a finding to which
	// no rule applied, such as one in a package that owns an executable.
	var rows [][]string
	for _, o := range outcomeRows {
		for _, rule := range slices.Sorted(maps.Keys(t.outcomeByRule[o])) {
			rows = append(rows, []string{string(o), orDash(string(rule)), strconv.Itoa(t.outcomeByRule[o][rule])})
		}
	}
	say(out, "\n")
	table(out, []string{"OUTCOME", "RULE", columnFindings}, rows)
}

// breakdown prints a row for each outcome, and one for all the findings, with a column for each label. cell
// counts the findings of an outcome with a label, and sum those of all outcomes.
func breakdown(out io.Writer, t totals, labels []string, cell func(inventoryv1alpha1.Outcome, string) int,
	sum func(string) int) {
	rows := make([][]string, 0, len(outcomeRows)+1)
	for _, o := range outcomeRows {
		row := make([]string, 0, 2+len(labels))
		row = append(row, string(o), strconv.Itoa(t.outcome[o]))
		for _, label := range labels {
			row = append(row, strconv.Itoa(cell(o, label)))
		}
		rows = append(rows, row)
	}
	all := make([]string, 0, 2+len(labels))
	all = append(all, "all", strconv.Itoa(t.total))
	for _, label := range labels {
		all = append(all, strconv.Itoa(sum(label)))
	}
	table(out, append([]string{"OUTCOME", "TOTAL"}, labels...), append(rows, all))
}

// eachManifest returns a row for every manifest of the cases, made by row.
func eachManifest(measured []measurement, row func(m measurement, manifest manifestData) []string) [][]string {
	var rows [][]string
	for _, m := range measured {
		for _, manifest := range m.data.manifests {
			rows = append(rows, row(m, manifest))
		}
	}
	return rows
}

// printFindingsByCase prints the findings of each case by outcome, as its sheets list them.
func printFindingsByCase(out io.Writer, measured []measurement) {
	say(out, "\n== findings of each case\n")
	rows := make([][]string, 0, len(measured))
	for _, m := range measured {
		var findings []inventoryv1alpha1.Finding
		for _, manifest := range m.data.manifests {
			findings = append(findings, manifest.sheet.Status.Findings...)
		}
		t := tally(findings)
		row := append(make([]string, 0, 2+len(outcomeRows)), m.c.Name, strconv.Itoa(t.total))
		for _, o := range outcomeRows {
			row = append(row, strconv.Itoa(t.outcome[o]))
		}
		rows = append(rows, row)
	}
	header := append(make([]string, 0, 2+len(outcomeRows)), columnCase, columnFindings)
	for _, o := range outcomeRows {
		header = append(header, string(o))
	}
	table(out, header, rows)
}

func printCompleteness(out io.Writer, minCompleteness int32, measured []measurement) {
	say(out, "\n== completeness: the share of the ELF files that packages own, against the guard at %d%%\n",
		minCompleteness)
	table(out, []string{columnCase, columnPlatform, "ELF FILES", "OWNED", "COMPLETENESS"},
		eachManifest(measured, func(m measurement, manifest manifestData) []string {
			ev := manifest.evidence
			return []string{m.c.Name, manifest.platform, strconv.Itoa(ev.ELF.Total), strconv.Itoa(ev.ELF.Owned),
				fmt.Sprintf("%d%%", ev.Completeness())}
		}))
}

func printSizes(out io.Writer, measured []measurement) {
	say(out, "\n== sizes, against the first trigger of decision 0004: an object above %d KiB\n", triggerBytes/1024)
	table(out, []string{columnCase, columnPlatform, "EVIDENCE COMPRESSED", "EVIDENCE AS BASE64", "EVIDENCE DECODED",
		"SHEET", "PACKAGES", columnFindings, "LEFT OUT"},
		eachManifest(measured, func(m measurement, manifest manifestData) []string {
			compressed, decoded := manifest.info.CompressedBytes, manifest.info.UncompressedBytes
			encoded := int64(base64.StdEncoding.EncodedLen(int(compressed)))
			var sheet int64
			if raw, err := json.Marshal(manifest.sheet); err == nil {
				sheet = int64(len(raw))
			}
			return []string{
				m.c.Name, manifest.platform,
				fmt.Sprintf("%d B (%s)", compressed, against(compressed)), fmt.Sprintf("%d B (%s)", encoded, against(encoded)),
				fmt.Sprintf("%d B", decoded), fmt.Sprintf("%d B (%s)", sheet, against(sheet)),
				strconv.Itoa(int(ptr.Deref(manifest.facts.Packages, 0))), strconv.Itoa(len(manifest.sheet.Status.Findings)),
				strconv.Itoa(int(ptr.Deref(manifest.sheet.Status.OmittedFindings, 0))),
			}
		}))
}

// printScans prints the time of each case's scan, from the inventory's first sight of the digest to the end of
// the scan, queue included, and the length of the line that the scan printed. The line isn't stored, so its
// length is that of the line that the scanner makes of the stored evidence: the log line of the whole result, with
// every manifest that the scan covered, and the newline.
func printScans(out io.Writer, measured []measurement) {
	say(out, "\n== scans: from the first sight of the image to the end of its scan, and its result line\n")
	rows := make([][]string, 0, len(measured))
	for _, m := range measured {
		manifests := make([]result.Manifest, 0, len(m.data.manifests))
		for _, manifest := range m.data.manifests {
			manifests = append(manifests, manifest.evidence)
		}
		line := "-"
		scanned := result.Result{Image: m.data.repository + "@" + m.data.digest, Manifests: manifests}
		if encoded, err := result.Encode(scanned); err == nil {
			line = fmt.Sprintf("%d B", len(encoded)+1)
		}
		scan := "-"
		if !m.data.firstSeen.IsZero() && !m.data.scanned.IsZero() {
			scan = max(m.data.scanned.Sub(m.data.firstSeen), 0).Round(time.Second).String()
		}
		rows = append(rows, []string{m.c.Name, platformsOf(m), scan, line})
	}
	table(out, []string{columnCase, columnPlatform, "SCAN", "LINE"}, rows)
}
