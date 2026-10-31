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

// Command scanner scans one image for the operator. It runs in the scan Job that a spoke starts for
// each image (0022): it pulls the image by digest, unpacks the filesystem of each platform manifest
// to scan, catalogs it with Syft, analyses it, and prints one line, which the operator reads from the
// Job's log.
//
//	scanner --image registry.example/team-a/app@sha256:… --platform linux/amd64 [--platform …]
//	        [--work /work] [--max-bytes N] [--syft /usr/local/bin/syft]
//	        [--registry-mirror registry.example=https://mirror.example …]
//
// stdout carries exactly one line: the result line of package result when the scan succeeds, with
// exit code 0, or its error line, with exit code 1. The scan fails as a whole when one manifest
// fails. Bad flags fail it too, with the reason Internal and no usage text.
//
// The image is untrusted, and the log is where the operator takes the evidence from. A file name in
// the image, or a platform in its index, can hold a newline followed by a forged result line. So the
// scanner prints only lines of its own: stderr carries fixed progress texts with counts, Syft's
// output is discarded, and no error's text is ever printed, only its reason. The pull credentials
// come from $DOCKER_CONFIG/config.json, and are never printed either.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/bedag/vexplain/internal/scan/analyze"
	"github.com/bedag/vexplain/internal/scan/pull"
	"github.com/bedag/vexplain/internal/scan/result"
)

// The defaults of the flags.
const (
	// defaultWork is the scratch volume of the scan Job.
	defaultWork = "/work"
	// defaultMaxBytes limits the space that the filesystem of one manifest takes: 8 GiB. The operator
	// passes 90% of the Job's scratch volume.
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

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop() // os.Exit doesn't run deferred calls.
	os.Exit(code)
}

// run is the scanner. It takes what main takes from the process, so that a test can give it the
// arguments and read what it printed, and returns the exit code. It reads only PATH through getenv,
// for Syft. The credentials come from DOCKER_CONFIG in the process's environment, which
// authn.DefaultKeychain reads.
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
	s := &scanner{options: opts, path: getenv("PATH"), progress: stderr}
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
	from, err := name.NewRegistry(host, name.StrictValidation)
	if err != nil {
		return err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Path != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return errBadFlag
	}
	nameOpts := []name.Option{name.StrictValidation}
	if u.Scheme == "http" {
		nameOpts = append(nameOpts, name.Insecure)
	}
	to, err := name.NewRegistry(u.Host, nameOpts...)
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
	targets, err := pull.Resolve(ctx, s.pullRef(), s.platforms, remote.WithAuthFromKeychain(authn.DefaultKeychain))
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

// scanTarget scans one platform manifest, the nth of count, in a directory of its own under the work
// directory. The directory holds the unpacked filesystem, the SBOM, and Syft's TMPDIR and HOME, and
// the scan removes it at the end, whether it succeeded or not.
func (s *scanner) scanTarget(ctx context.Context, target pull.Target, nth, count int) (
	result.Manifest, result.ErrorReason,
) {
	dir, err := os.MkdirTemp(s.work, "manifest-")
	if err != nil {
		return result.Manifest{}, result.ErrorReasonInternal
	}
	m, reason := s.scanIn(ctx, dir, target, nth, count)
	// What stays would take the next manifest's space.
	if err := os.RemoveAll(dir); err != nil && reason == "" {
		return result.Manifest{}, result.ErrorReasonInternal
	}
	return m, reason
}

// scanIn scans one platform manifest in the directory dir.
func (s *scanner) scanIn(ctx context.Context, dir string, target pull.Target, nth, count int) (
	result.Manifest, result.ErrorReason,
) {
	root := filepath.Join(dir, "root")
	sbom := filepath.Join(dir, "sbom.json")
	tmp := filepath.Join(dir, "tmp")
	home := filepath.Join(dir, "home")
	for _, d := range []string{root, tmp, home} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return result.Manifest{}, result.ErrorReasonInternal
		}
	}
	config, err := target.Image.ConfigFile()
	if err != nil {
		return result.Manifest{}, pullReason(err)
	}

	s.say("manifest %d of %d: unpacking", nth, count)
	if err := pull.Extract(target.Image, root, s.maxBytes); err != nil {
		return result.Manifest{}, extractReason(err)
	}

	s.say("manifest %d of %d: cataloging", nth, count)
	if err := s.syftScan(ctx, dir, root, sbom); err != nil {
		return result.Manifest{}, result.ErrorReasonCatalogFailed
	}
	raw, err := os.ReadFile(sbom)
	if err != nil {
		return result.Manifest{}, result.ErrorReasonCatalogFailed
	}

	s.say("manifest %d of %d: analysing", nth, count)
	m, err := analyze.Analyze(root, raw, analyze.ImageConfig{
		Env: config.Config.Env, Entrypoint: config.Config.Entrypoint, Cmd: config.Config.Cmd,
	})
	switch {
	case errors.Is(err, analyze.ErrSBOM), errors.Is(err, analyze.ErrUnsupportedSBOM),
		errors.Is(err, analyze.ErrCatalogIncomplete):
		return result.Manifest{}, result.ErrorReasonCatalogFailed
	case err != nil:
		return result.Manifest{}, result.ErrorReasonInternal
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
