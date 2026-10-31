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

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/scan/result"
)

const (
	// syftPath is the PATH that the tests give the scanner, which passes it on to Syft.
	syftPath = "/usr/bin:/bin"
	// markerVariable is a variable of the pod's environment, which Syft must not see.
	markerVariable = "VEXPLAIN_TEST_MARKER"
	markerValue    = "pod-environment-marker"
	// proxy is the proxy of the pod's environment. Syft must not see it either: a scan of a
	// directory needs no network.
	proxy = "http://proxy.example:3128"
	// bigEnough is a limit on the result that no test comes near.
	bigEnough = 1 << 20

	// validSBOM is the smallest Syft JSON that the analysis accepts.
	validSBOM = `{"schema":{"version":"16.1.11"},"artifacts":[]}`
	// forgedResult and forgedError look like the scanner's own lines. The fake Syft prints them, and
	// a test image holds them in file names. Their spaces can't be part of the base64 of a result.
	forgedResult = result.ResultPrefix + "forged by the image"
	forgedError  = result.ErrorPrefix + "ForgedReason"

	// The flags of the scanner, and the platform that most tests scan.
	flagImage    = "--image"
	flagPlatform = "--platform"
	flagMaxBytes = "--max-bytes"
	flagMirror   = "--registry-mirror"
	amd64        = "linux/amd64"
)

// The platforms of the test images.
var (
	linuxAMD64   = v1.Platform{OS: "linux", Architecture: "amd64"}
	linuxARM64v8 = v1.Platform{OS: linuxAMD64.OS, Architecture: "arm64", Variant: "v8"}
)

// fakeSyft is a script in place of Syft. It records its arguments, working directory and
// environment, prints lines that look like the scanner's own, writes its SBOM to the file of its
// -o flag, runs a command of the test, and exits with its code.
type fakeSyft struct {
	path   string
	record string
}

// syftScript is the script of a fakeSyft: the record directory, the command that writes the SBOM, the
// exit code and the test's command fill it in. The test's command finds the root in $root. The
// script gets no variable from the test, because the scanner passes on none, so it names everything
// itself.
const syftScript = `#!/bin/sh
printf '%%s\n' "$@" > '%[1]s/args'
pwd > '%[1]s/cwd'
/usr/bin/env > '%[1]s/env'
echo '%[4]s'
echo '%[5]s' >&2
for arg in "$@"; do
	case "$arg" in
	dir:*) root="${arg#dir:}" ;;
	syft-json=*) %[2]s ;;
	esac
done
%[6]s
exit %[3]d
`

// newFakeSyft writes a fakeSyft. It writes sbom as its SBOM, or no file when sbom is empty.
func newFakeSyft(t *testing.T, sbom string, exitCode int) fakeSyft {
	t.Helper()
	return newFakeSyftRunning(t, sbom, exitCode, ":")
}

// newFakeSyftRunning writes a fakeSyft that runs the shell command before it exits.
func newFakeSyftRunning(t *testing.T, sbom string, exitCode int, command string) fakeSyft {
	t.Helper()
	dir := t.TempDir()
	record := filepath.Join(dir, "record")
	require.NoError(t, os.Mkdir(record, 0o755))
	write := ":"
	if sbom != "" {
		require.NotContains(t, sbom, "'")
		write = fmt.Sprintf(`printf '%%s' '%s' > "${arg#syft-json=}"`, sbom)
	}
	script := fmt.Sprintf(syftScript, record, write, exitCode, forgedResult, forgedError, command)
	path := filepath.Join(dir, "syft")
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
	return fakeSyft{path: path, record: record}
}

// lines returns the lines of the record file.
func (s fakeSyft) lines(t *testing.T, file string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(s.record, file))
	require.NoError(t, err)
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// ran reports whether the fake Syft ran.
func (s fakeSyft) ran(t *testing.T) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(s.record, "args"))
	return err == nil
}

// harness is what a test of the scanner sets up: the pod's environment, a work directory and a fake
// Syft.
type harness struct {
	t    *testing.T
	work string
	syft fakeSyft
}

// newHarness sets the pod's environment, with a DOCKER_CONFIG that has no credentials, so that no
// test reads the developer's own.
func newHarness(t *testing.T) *harness {
	t.Helper()
	setCredentials(t, nil)
	t.Setenv("HTTPS_PROXY", proxy)
	t.Setenv(markerVariable, markerValue)
	return &harness{t: t, work: t.TempDir(), syft: newFakeSyft(t, validSBOM, 0)}
}

// output is what one run of the scanner gave.
type output struct {
	code           int
	stdout, stderr string
}

// scan runs the scanner with the arguments, after --work and --syft of the harness, and checks what
// holds for every run: stdout is one line, stderr holds no line of the scan, and the work directory
// is empty again.
func (h *harness) scan(args ...string) output {
	return h.scanContext(context.Background(), args...)
}

// scanContext is scan with the context ctx.
func (h *harness) scanContext(ctx context.Context, args ...string) output {
	t := h.t
	t.Helper()
	var stdout, stderr bytes.Buffer
	getenv := func(key string) string {
		if key == "PATH" {
			return syftPath
		}
		return os.Getenv(key)
	}
	args = append([]string{"--work", h.work, "--syft", h.syft.path}, args...)
	code := run(ctx, args, getenv, &stdout, &stderr)
	out := output{code: code, stdout: stdout.String(), stderr: stderr.String()}

	require.Equal(t, 1, strings.Count(out.stdout, "\n"), "stdout is one line:\n%s", out.stdout)
	require.True(t, strings.HasSuffix(out.stdout, "\n"))
	for line := range strings.SplitSeq(out.stderr, "\n") {
		require.False(t, strings.HasPrefix(line, "vexplain-scan-"), "stderr has a line of the scan: %q", line)
	}
	requireEmpty(t, h.work)
	return out
}

// requireEmpty requires that the directory dir is empty.
func requireEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries)
}

// requireResult requires that the run succeeded, and returns its result.
func requireResult(t *testing.T, out output) *result.Result {
	t.Helper()
	require.Equal(t, 0, out.code, "stdout: %s", out.stdout)
	r, reason, err := result.Parse(out.stdout, bigEnough)
	require.NoError(t, err)
	require.Empty(t, reason)
	return r
}

// requireReason requires that the run failed with the reason.
func requireReason(t *testing.T, out output, want result.ErrorReason) {
	t.Helper()
	require.Equal(t, 1, out.code)
	require.Equal(t, result.EncodeError(want)+"\n", out.stdout)
}

// setCredentials points DOCKER_CONFIG at a new config.json that holds a user and a password for each
// registry host in creds.
func setCredentials(t *testing.T, creds map[string][2]string) {
	t.Helper()
	auths := map[string]any{}
	for host, c := range creds {
		auths[host] = map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(c[0] + ":" + c[1]))}
	}
	data, err := json.Marshal(map[string]any{"auths": auths})
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600))
	t.Setenv("DOCKER_CONFIG", dir)
}

// newRegistry starts an in-process registry that logs nothing, behind wrap when it isn't nil, and
// returns its host.
func newRegistry(t *testing.T, wrap func(http.Handler) http.Handler) string {
	t.Helper()
	handler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	if wrap != nil {
		handler = wrap(handler)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://")
}

// basicAuth lets through only requests with the user and password.
func basicAuth(user, password string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u, p, ok := r.BasicAuth(); !ok || u != user || p != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// testImage returns an image of the platform p with one layer that holds the files, and Env env.
func testImage(t *testing.T, p v1.Platform, env []string, files map[string]string) v1.Image {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		header := &tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: 0o644, Size: int64(len(files[n]))}
		require.NoError(t, tw.WriteHeader(header))
		_, err := tw.Write([]byte(files[n]))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	cfg = cfg.DeepCopy()
	cfg.OS, cfg.Architecture, cfg.Variant = p.OS, p.Architecture, p.Variant
	cfg.Config.Env = env
	img, err = mutate.ConfigFile(img, cfg)
	require.NoError(t, err)
	return img
}

// crossLayerLinkImage returns a linux/amd64 image whose upper layer holds a hard link to a file of the
// layer below it, which no build tool writes.
func crossLayerLinkImage(t *testing.T) v1.Image {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{Typeflag: tar.TypeLink, Name: "y", Linkname: "x", Mode: 0o644}))
	require.NoError(t, tw.Close())
	data := buf.Bytes()
	upper, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	require.NoError(t, err)
	img, err := mutate.AppendLayers(testImage(t, linuxAMD64, nil, map[string]string{"x": "a file"}), upper)
	require.NoError(t, err)
	return img
}

// duplicateEntryImage returns a linux/amd64 image whose upper layer holds two entries for one path, which no
// build tool writes.
func duplicateEntryImage(t *testing.T) v1.Image {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, content := range []string{"first", "second"} {
		header := &tar.Header{Typeflag: tar.TypeReg, Name: "x", Mode: 0o644, Size: int64(len(content))}
		require.NoError(t, tw.WriteHeader(header))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	data := buf.Bytes()
	upper, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	require.NoError(t, err)
	img, err := mutate.AppendLayers(testImage(t, linuxAMD64, nil, nil), upper)
	require.NoError(t, err)
	return img
}

// tarLayer returns a layer of the headers, in their order. A regular file holds the content that contents
// gives for its name.
func tarLayer(t *testing.T, contents map[string]string, headers ...tar.Header) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, header := range headers {
		content := contents[header.Name]
		if header.Typeflag == tar.TypeReg {
			header.Size = int64(len(content))
		}
		require.NoError(t, tw.WriteHeader(&header))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	require.NoError(t, err)
	return layer
}

// The packages of the merged-usr images, and the library below lib.
const (
	// basePackage owns the base's library, and upperPackage upperLibrary.
	basePackage  = "base-libs"
	upperPackage = "upper-libs"
	// upperLibrary is the library below lib of the layer above the base.
	upperLibrary = "lib/x86_64-linux-gnu/libfoo.so.1"
)

// mergedUsrImage returns a linux/amd64 image of a merged-usr base, where lib links to target, and of a layer
// that a tool assembled from files above it, which holds a library below lib and no entry for lib.
func mergedUsrImage(t *testing.T, target string) v1.Image {
	t.Helper()
	return mergedUsrImageWith(t, target,
		tarLayer(t, map[string]string{upperLibrary: "a library of the upper layer"},
			tar.Header{Typeflag: tar.TypeReg, Name: upperLibrary, Mode: 0o644},
		))
}

// mergedUsrImageWith returns a linux/amd64 image of a merged-usr base, where lib links to target and
// usr/lib/x86_64-linux-gnu holds libbar.so.1, and of the layer upper above it.
func mergedUsrImageWith(t *testing.T, target string, upper v1.Layer) v1.Image {
	t.Helper()
	const libs = "usr/lib/x86_64-linux-gnu"
	base := tarLayer(t, map[string]string{libs + "/libbar.so.1": "a library of the base"},
		tar.Header{Typeflag: tar.TypeSymlink, Name: "lib", Linkname: target, Mode: 0o777},
		tar.Header{Typeflag: tar.TypeDir, Name: "usr/", Mode: 0o755},
		tar.Header{Typeflag: tar.TypeDir, Name: "usr/lib/", Mode: 0o755},
		tar.Header{Typeflag: tar.TypeDir, Name: libs + "/", Mode: 0o755},
		tar.Header{Typeflag: tar.TypeReg, Name: libs + "/libbar.so.1", Mode: 0o644},
	)
	img, err := mutate.AppendLayers(testImage(t, linuxAMD64, nil, nil), base, upper)
	require.NoError(t, err)
	return img
}

// amd64Image returns a linux/amd64 image with a few files, whose configuration sets LD_PRELOAD.
func amd64Image(t *testing.T) v1.Image {
	t.Helper()
	return testImage(t, linuxAMD64,
		[]string{"PATH=/usr/bin:/bin", "LD_PRELOAD=/opt/hook.so"},
		map[string]string{"etc/os-release": "ID=example\n", "usr/bin/tool": "#!/bin/sh\n"})
}

// push writes img to the repository at host, as repository@digest, and returns that reference.
func push(t *testing.T, host, repository string, img v1.Image, opts ...remote.Option) string {
	t.Helper()
	digest, err := img.Digest()
	require.NoError(t, err)
	ref, err := name.NewDigest(host + "/" + repository + "@" + digest.String())
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img, opts...))
	return ref.String()
}

// pushIndex writes an index of the images, each under the platform of its configuration, and
// returns its reference.
func pushIndex(t *testing.T, host, repository string, images ...v1.Image) string {
	t.Helper()
	idx := v1.ImageIndex(empty.Index)
	for _, img := range images {
		cfg, err := img.ConfigFile()
		require.NoError(t, err)
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: cfg.Platform()}})
	}
	digest, err := idx.Digest()
	require.NoError(t, err)
	ref, err := name.NewDigest(host + "/" + repository + "@" + digest.String())
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(ref, idx))
	return ref.String()
}

func digestOf(t *testing.T, img v1.Image) string {
	t.Helper()
	digest, err := img.Digest()
	require.NoError(t, err)
	return digest.String()
}

func TestScanPrintsOneResultLine(t *testing.T) {
	h := newHarness(t)
	host := newRegistry(t, nil)
	img := amd64Image(t)
	ref := push(t, host, "team-a/app", img)

	out := h.scan(flagImage, ref, flagPlatform, amd64)

	r := requireResult(t, out)
	require.Equal(t, ref, r.Image)
	require.Len(t, r.Manifests, 1)
	m := r.Manifests[0]
	require.Equal(t, amd64, m.Platform)
	require.Equal(t, digestOf(t, img), m.Digest)
	require.JSONEq(t, `{"artifacts":[],"schema":{"version":"16.1.11"}}`, string(m.SBOM))
	require.True(t, m.Preload.LDPreload, "the analysis gets the Env of the image's configuration")
	require.NotEmpty(t, out.stderr, "progress goes to stderr")
}

// withCommand returns img with entrypoint and cmd as the command of its configuration.
func withCommand(t *testing.T, img v1.Image, entrypoint, cmd []string) v1.Image {
	t.Helper()
	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	cfg = cfg.DeepCopy()
	cfg.Config.Entrypoint, cfg.Config.Cmd = entrypoint, cmd
	img, err = mutate.ConfigFile(img, cfg)
	require.NoError(t, err)
	return img
}

func TestScanSeesAPreloadThatTheImagesCommandSets(t *testing.T) {
	h := newHarness(t)
	host := newRegistry(t, nil)
	base := testImage(t, linuxAMD64, []string{"PATH=/usr/bin:/bin"}, map[string]string{"usr/bin/app": "#!/bin/sh\n"})
	img := withCommand(t, base, []string{"/bin/sh", "-c"},
		[]string{"LD_PRELOAD=/opt/hook-marker.so LD_AUDIT=/opt/audit-marker.so exec /usr/bin/app"})
	ref := push(t, host, "team-a/app", img)

	out := h.scan(flagImage, ref, flagPlatform, amd64)

	r := requireResult(t, out)
	require.Equal(t, result.Preload{LDPreload: true, LDAudit: true}, r.Manifests[0].Preload,
		"the analysis gets the command of the image's configuration")
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	for _, value := range []string{"/opt/hook-marker.so", "/opt/audit-marker.so"} {
		require.NotContains(t, string(raw), value, "only that they are set travels")
		require.NotContains(t, out.stderr, value)
	}
}

func TestScanKeepsTheImageArgumentAsItIs(t *testing.T) {
	h := newHarness(t)
	host := newRegistry(t, nil)
	img := amd64Image(t)
	push(t, host, "team-a/app", img)
	// A tag next to the digest changes nothing that is pulled, and stays in the result.
	ref := host + "/team-a/app:v1@" + digestOf(t, img)

	r := requireResult(t, h.scan(flagImage, ref, flagPlatform, amd64))
	require.Equal(t, ref, r.Image)
}

func TestScanOfSeveralPlatforms(t *testing.T) {
	h := newHarness(t)
	host := newRegistry(t, nil)
	first := amd64Image(t)
	second := testImage(t, linuxARM64v8, nil, map[string]string{"etc/os-release": "ID=example\n"})
	ref := pushIndex(t, host, "team-a/app", first, second)

	r := requireResult(t, h.scan(flagImage, ref, flagPlatform, amd64, flagPlatform, "linux/arm64"))

	require.Equal(t, ref, r.Image)
	require.Len(t, r.Manifests, 2)
	require.Equal(t, amd64, r.Manifests[0].Platform)
	require.Equal(t, digestOf(t, first), r.Manifests[0].Digest)
	require.Equal(t, "linux/arm64/v8", r.Manifests[1].Platform)
	require.Equal(t, digestOf(t, second), r.Manifests[1].Digest)
}

// mergedUsrSBOM lists two packages of a dpkg database, as Syft reports them for mergedUsrImage: dpkg lists
// the library of each below /lib, which links to usr/lib.
const mergedUsrSBOM = `{"schema":{"version":"16.1.11"},"artifacts":[` +
	`{"id":"base-libs","metadataType":"dpkg-db-entry",` +
	`"metadata":{"files":[{"path":"/lib/x86_64-linux-gnu/libbar.so.1"}]}},` +
	`{"id":"upper-libs","metadataType":"dpkg-db-entry",` +
	`"metadata":{"files":[{"path":"/lib/x86_64-linux-gnu/libfoo.so.1"}]}}]}`

func TestScanFindsTheFilesThatPackagesListBelowALinkOfALowerLayer(t *testing.T) {
	// A layer that a tool assembled from files holds lib/x86_64-linux-gnu/libfoo.so.1 over a merged-usr base,
	// where lib links to usr/lib. The file lands in usr/lib, through the link, and the link stays, so the files
	// that the packages list below /lib are present: the base's and the new one. A link that climbs above the
	// root stops at the root.
	for _, target := range []string{"usr/lib", "../../../usr/lib"} {
		t.Run(target, func(t *testing.T) {
			h := newHarness(t)
			seen := t.TempDir()
			h.syft = newFakeSyftRunning(t, mergedUsrSBOM, 0, fmt.Sprintf(
				`readlink "$root/lib" > '%[1]s/lib'; ls "$root/usr/lib/x86_64-linux-gnu" > '%[1]s/libs'`, seen))
			host := newRegistry(t, nil)
			ref := push(t, host, "team-a/app", mergedUsrImage(t, target))

			r := requireResult(t, h.scan(flagImage, ref, flagPlatform, amd64))

			link, err := os.ReadFile(filepath.Join(seen, "lib"))
			require.NoError(t, err)
			require.Equal(t, target+"\n", string(link), "Syft sees the link")
			libs, err := os.ReadFile(filepath.Join(seen, "libs"))
			require.NoError(t, err)
			require.Equal(t, "libbar.so.1\nlibfoo.so.1\n", string(libs), "Syft sees both libraries where the link leads")
			require.Len(t, r.Manifests, 1)
			require.Equal(t, []result.PackageFacts{
				{ID: basePackage, FilesListed: 1, FilesPresent: 1},
				{ID: upperPackage, FilesListed: 1, FilesPresent: 1},
			}, r.Manifests[0].Packages)
		})
	}
}

func TestScanFindsTheFilesThatPackagesListBelowALinkOfTheirOwnLayer(t *testing.T) {
	// A tool flattened packages into one layer, with lib -> usr/lib as a merged-usr base has it, and the
	// packages' files: one in usr/lib, one below lib. Tar extraction puts the second through the layer's
	// own link, in usr/lib too, and both packages' files are present.
	const libs = "usr/lib/x86_64-linux-gnu"
	h := newHarness(t)
	h.syft = newFakeSyft(t, mergedUsrSBOM, 0)
	host := newRegistry(t, nil)
	layer := tarLayer(t, map[string]string{
		libs + "/libbar.so.1": "a library of one package",
		upperLibrary:          "a library of another package",
	},
		tar.Header{Typeflag: tar.TypeSymlink, Name: "lib", Linkname: "usr/lib", Mode: 0o777},
		tar.Header{Typeflag: tar.TypeReg, Name: libs + "/libbar.so.1", Mode: 0o644},
		tar.Header{Typeflag: tar.TypeReg, Name: upperLibrary, Mode: 0o644},
	)
	img, err := mutate.AppendLayers(testImage(t, linuxAMD64, nil, nil), layer)
	require.NoError(t, err)
	ref := push(t, host, "team-a/app", img)

	r := requireResult(t, h.scan(flagImage, ref, flagPlatform, amd64))

	require.Len(t, r.Manifests, 1)
	require.Equal(t, []result.PackageFacts{
		{ID: basePackage, FilesListed: 1, FilesPresent: 1},
		{ID: upperPackage, FilesListed: 1, FilesPresent: 1},
	}, r.Manifests[0].Packages)
}

// baseLibsSBOM lists the base's package of mergedUsrImageWith, whose library dpkg lists below /lib.
const baseLibsSBOM = `{"schema":{"version":"16.1.11"},"artifacts":[` +
	`{"id":"base-libs","metadataType":"dpkg-db-entry",` +
	`"metadata":{"files":[{"path":"/lib/x86_64-linux-gnu/libbar.so.1"}]}}]}`

func TestScanKeepsTheFilesThatAWhiteoutBelowALinkOfALowerLayerWouldDelete(t *testing.T) {
	// A layer above the merged-usr base deletes libbar.so.1 below lib, or hides the directory below lib. Whether
	// that reaches usr/lib depends on the runtime's snapshotter, so the scan keeps the file, and the base's
	// package isn't read as removed in a later layer.
	for what, upper := range map[string][]tar.Header{
		"a whiteout":         {{Typeflag: tar.TypeReg, Name: "lib/x86_64-linux-gnu/.wh.libbar.so.1", Mode: 0o644}},
		"an opaque whiteout": {{Typeflag: tar.TypeReg, Name: "lib/x86_64-linux-gnu/.wh..wh..opq", Mode: 0o644}},
	} {
		t.Run(what, func(t *testing.T) {
			h := newHarness(t)
			h.syft = newFakeSyft(t, baseLibsSBOM, 0)
			host := newRegistry(t, nil)
			ref := push(t, host, "team-a/app", mergedUsrImageWith(t, "usr/lib", tarLayer(t, nil, upper...)))

			r := requireResult(t, h.scan(flagImage, ref, flagPlatform, amd64))

			require.Len(t, r.Manifests, 1)
			require.Equal(t, []result.PackageFacts{{ID: basePackage, FilesListed: 1, FilesPresent: 1}},
				r.Manifests[0].Packages)
		})
	}
}

func TestScanRunsSyftOutsideTheRoot(t *testing.T) {
	h := newHarness(t)
	host := newRegistry(t, nil)
	ref := push(t, host, "team-a/app", amd64Image(t))

	requireResult(t, h.scan(flagImage, ref, flagPlatform, amd64))

	args := h.syft.lines(t, "args")
	require.Len(t, args, 9, "%q", args)
	root, ok := strings.CutPrefix(args[1], "dir:")
	require.True(t, ok, "%q", args)
	sbom, ok := strings.CutPrefix(args[7], "syft-json=")
	require.True(t, ok, "%q", args)
	require.Equal(t, []string{
		"scan", "dir:" + root, "--base-path", root, "--override-default-catalogers", "image",
		"-o", "syft-json=" + sbom, "--quiet",
	}, args)

	// The root, the SBOM file and Syft's working directory are in the work directory, and the SBOM
	// and the working directory are outside the root.
	work := realPath(t, h.work)
	within := func(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator)) }
	require.True(t, filepath.IsAbs(root))
	require.True(t, within(realPath(t, root), work), "the root %s is in the work directory", root)
	require.True(t, within(realPath(t, sbom), work))
	require.False(t, within(realPath(t, sbom), realPath(t, root)), "the SBOM %s is outside the root %s", sbom, root)
	cwd := h.syft.lines(t, "cwd")[0]
	require.True(t, within(realPath(t, cwd), work))
	require.False(t, within(realPath(t, cwd), realPath(t, root)), "Syft runs in %s, outside the root %s", cwd, root)

	env := map[string]string{}
	for _, line := range h.syft.lines(t, "env") {
		key, value, _ := strings.Cut(line, "=")
		env[key] = value
	}
	require.Equal(t, "false", env["SYFT_CHECK_FOR_APP_UPDATE"])
	require.Equal(t, syftPath, env["PATH"])
	for _, key := range []string{"TMPDIR", "HOME"} {
		require.True(t, within(realPath(t, env[key]), work), "%s=%s", key, env[key])
		require.False(t, within(realPath(t, env[key]), realPath(t, root)), "%s=%s", key, env[key])
	}
	for _, key := range []string{"DOCKER_CONFIG", "HTTPS_PROXY", markerVariable} {
		require.NotContains(t, env, key)
	}
	for _, line := range h.syft.lines(t, "env") {
		require.NotContains(t, line, markerValue)
		require.NotContains(t, line, proxy)
	}
}

// realPath returns p with its links resolved. The work directory of a test can be below a link,
// such as /var on macOS, and Syft's shell reports its working directory in its own way.
func realPath(t *testing.T, p string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		// The SBOM file, TMPDIR and HOME are gone with the work directory: resolve their directory.
		dir, rest := filepath.Split(p)
		return filepath.Join(realPath(t, filepath.Clean(dir)), rest)
	}
	return resolved
}

func TestScanNeverPrintsTextFromTheImageOrSyft(t *testing.T) {
	h := newHarness(t)
	host := newRegistry(t, nil)
	// File names can hold a newline and what looks like a line of the scan.
	img := testImage(t, linuxAMD64, nil, map[string]string{
		"etc/x\n" + forgedResult:    "",
		"etc/y\n" + forgedError:     "",
		"etc/" + forgedResult + "z": forgedError,
	})
	ref := push(t, host, "team-a/app", img)

	out := h.scan(flagImage, ref, flagPlatform, amd64)

	requireResult(t, out)
	require.True(t, h.syft.ran(t))
	for _, text := range []string{forgedResult, forgedError} {
		require.NotContains(t, out.stdout, text)
		require.NotContains(t, out.stderr, text)
	}
}

func TestScanFailures(t *testing.T) {
	host := newRegistry(t, nil)
	img := amd64Image(t)
	ref := push(t, host, "team-a/app", img)
	missing := host + "/team-a/app@sha256:" + strings.Repeat("0", 64)
	index := pushIndex(t, host, "team-a/app", img)
	// An image with an apk database, for which the fake Syft reports no package.
	withDatabase := push(t, host, "team-a/app", testImage(t, linuxAMD64, nil,
		map[string]string{"lib/apk/db/installed": "P:musl\nV:1.2.5-r10\n\n"}))
	crossLayerLink := push(t, host, "team-a/app", crossLayerLinkImage(t))
	duplicateEntry := push(t, host, "team-a/app", duplicateEntryImage(t))
	linkToAFile := push(t, host, "team-a/app", mergedUsrImage(t, "usr/lib/x86_64-linux-gnu/libbar.so.1"))
	linkIntoALoop := push(t, host, "team-a/app", mergedUsrImage(t, "lib"))

	closed := httptest.NewServer(http.NotFoundHandler())
	unreachable := strings.TrimPrefix(closed.URL, "http://") + "/team-a/app@" + digestOf(t, img)
	closed.Close()
	forbidding := newRegistry(t, func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	})

	cases := []struct {
		name   string
		args   []string
		sbom   string
		exit   int
		reason result.ErrorReason
	}{
		{"the registry has no such image", []string{flagImage, missing}, validSBOM, 0, result.ErrorReasonNotFound},
		{"the registry can't be reached", []string{flagImage, unreachable}, validSBOM, 0, result.ErrorReasonPullFailed},
		{"the registry forbids the pull",
			[]string{flagImage, forbidding + "/team-a/app@" + digestOf(t, img)}, validSBOM, 0, result.ErrorReasonUnauthorized},
		{"the index has no manifest for the platform",
			[]string{flagImage, index, flagPlatform, "linux/s390x"}, validSBOM, 0, result.ErrorReasonNoMatchingPlatform},
		{"the image unpacks to more than the limit",
			[]string{flagImage, ref, flagMaxBytes, "1"}, validSBOM, 0, result.ErrorReasonTooLarge},
		{"Syft fails", []string{flagImage, ref}, validSBOM, 1, result.ErrorReasonCatalogFailed},
		{"Syft writes no SBOM", []string{flagImage, ref}, "", 0, result.ErrorReasonCatalogFailed},
		{"Syft writes an SBOM of another schema", []string{flagImage, ref},
			`{"schema":{"version":"15.0.0"},"artifacts":[]}`, 0, result.ErrorReasonCatalogFailed},
		{"Syft writes no JSON", []string{flagImage, ref}, "not JSON", 0, result.ErrorReasonCatalogFailed},
		{"Syft leaves a package database out", []string{flagImage, withDatabase}, validSBOM, 0,
			result.ErrorReasonCatalogFailed},
		{"a hard link to a file of another layer", []string{flagImage, crossLayerLink}, validSBOM, 0,
			result.ErrorReasonInternal},
		{"a layer with two entries for one path", []string{flagImage, duplicateEntry}, validSBOM, 0,
			result.ErrorReasonInternal},
		{"a link of a lower layer, below which a layer above has entries, that leads to a file",
			[]string{flagImage, linkToAFile}, validSBOM, 0, result.ErrorReasonInternal},
		{"a link of a lower layer, below which a layer above has entries, that loops",
			[]string{flagImage, linkIntoALoop}, validSBOM, 0, result.ErrorReasonInternal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.syft = newFakeSyft(t, c.sbom, c.exit)
			args := c.args
			if !slices.Contains(args, flagPlatform) {
				args = append(args, flagPlatform, amd64)
			}
			requireReason(t, h.scan(args...), c.reason)
		})
	}
}

func TestScanFailsWhenOneManifestFails(t *testing.T) {
	h := newHarness(t)
	host := newRegistry(t, nil)
	small := amd64Image(t)
	large := testImage(t, linuxARM64v8, nil, map[string]string{"big": strings.Repeat("x", 64<<10)})
	ref := pushIndex(t, host, "team-a/app", small, large)

	// The first manifest fits the limit, and the second doesn't.
	out := h.scan(flagImage, ref, flagPlatform, amd64, flagPlatform, "linux/arm64", flagMaxBytes, strconv.Itoa(32<<10))

	requireReason(t, out, result.ErrorReasonTooLarge)
	require.True(t, h.syft.ran(t), "the first manifest was scanned")
}

func TestScanOfARootThatCantBeRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a file of mode 0000")
	}
	h := newHarness(t)
	host := newRegistry(t, nil)
	ref := push(t, host, "team-a/app", amd64Image(t))
	// The analysis fails on a file that it can't read, and so does the scan: with a reason of its
	// own, and not CatalogFailed, because Syft did its part.
	h.syft = newFakeSyftRunning(t, validSBOM, 0, `chmod 000 "$root/etc/os-release"`)

	requireReason(t, h.scan(flagImage, ref, flagPlatform, amd64), result.ErrorReasonInternal)
}

func TestScanWithAMissingSyft(t *testing.T) {
	h := newHarness(t)
	host := newRegistry(t, nil)
	ref := push(t, host, "team-a/app", amd64Image(t))
	h.syft.path = filepath.Join(t.TempDir(), "no-syft")

	requireReason(t, h.scan(flagImage, ref, flagPlatform, amd64), result.ErrorReasonCatalogFailed)
}

func TestScanThatIsInterrupted(t *testing.T) {
	h := newHarness(t)
	host := newRegistry(t, nil)
	ref := push(t, host, "team-a/app", amd64Image(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	requireReason(t, h.scanContext(ctx, flagImage, ref, flagPlatform, amd64), result.ErrorReasonInternal)
}

func TestScanWithCredentials(t *testing.T) {
	const user, password = "marker-user-4711", "marker-password-0815"
	host := newRegistry(t, basicAuth(user, password))
	ref := push(t, host, "team-a/app", amd64Image(t), remote.WithAuth(&authn.Basic{Username: user, Password: password}))
	encoded := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))

	cases := []struct {
		name   string
		creds  map[string][2]string
		reason result.ErrorReason
	}{
		{"the right credentials", map[string][2]string{host: {user, password}}, ""},
		{"a wrong password", map[string][2]string{host: {user, "marker-wrong-password-1234"}},
			result.ErrorReasonUnauthorized},
		{"no credentials", nil, result.ErrorReasonUnauthorized},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			setCredentials(t, c.creds)

			out := h.scan(flagImage, ref, flagPlatform, amd64)

			if c.reason == "" {
				requireResult(t, out)
			} else {
				requireReason(t, out, c.reason)
			}
			for _, secret := range []string{"marker-user", "marker-password", "marker-wrong-password", encoded} {
				require.NotContains(t, out.stdout, secret)
				require.NotContains(t, out.stderr, secret)
			}
		})
	}
}

func TestScanFromAMirror(t *testing.T) {
	h := newHarness(t)
	var originHits atomic.Int32
	origin := newRegistry(t, func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			originHits.Add(1)
			w.WriteHeader(http.StatusNotFound)
		})
	})
	const user, password = "mirror-user", "mirror-password"
	mirror := newRegistry(t, basicAuth(user, password))
	img := amd64Image(t)
	push(t, mirror, "team-a/app", img, remote.WithAuth(&authn.Basic{Username: user, Password: password}))
	// The mirror's credentials are those of its own host.
	setCredentials(t, map[string][2]string{mirror: {user, password}})
	ref := origin + "/team-a/app@" + digestOf(t, img)

	out := h.scan(flagImage, ref, flagPlatform, amd64, flagMirror, origin+"=http://"+mirror)

	r := requireResult(t, out)

	require.Equal(t, ref, r.Image, "the result names the requested image, not the mirror")
	require.Equal(t, digestOf(t, img), r.Manifests[0].Digest)
	require.Zero(t, originHits.Load(), "nothing is pulled from the origin")
}

func TestScanFromADockerHubMirror(t *testing.T) {
	h := newHarness(t)
	mirror := newRegistry(t, nil)
	img := amd64Image(t)
	// Docker Hub's official images are in the library namespace, on the mirror too.
	push(t, mirror, "library/alpine", img)

	for _, ref := range []string{"docker.io/library/alpine", "alpine", "index.docker.io/library/alpine"} {
		t.Run(ref, func(t *testing.T) {
			image := ref + "@" + digestOf(t, img)
			out := h.scan(flagImage, image, flagPlatform, amd64, flagMirror, "docker.io=http://"+mirror)
			r := requireResult(t, out)
			require.Equal(t, image, r.Image)
		})
	}
}

func TestScanRefusesBadFlags(t *testing.T) {
	image := "registry.example/team-a/app@sha256:" + strings.Repeat("1", 64)
	// valid returns flags that are valid, followed by more.
	valid := func(more ...string) []string {
		return append([]string{flagImage, image, flagPlatform, amd64}, more...)
	}
	mirror := func(flag string) []string { return valid(flagMirror, flag) }
	cases := map[string][]string{
		"no image":                      {flagPlatform, amd64},
		"an image without a digest":     {flagImage, "registry.example/team-a/app:v1", flagPlatform, amd64},
		"an image with a bad digest":    {flagImage, "registry.example/team-a/app@sha256:1234", flagPlatform, amd64},
		"no platform":                   {flagImage, image},
		"a platform without an arch":    {flagImage, image, flagPlatform, "linux"},
		"a platform with an empty part": {flagImage, image, flagPlatform, "linux//v8"},
		"a limit of zero":               valid(flagMaxBytes, "0"),
		"a limit that is no number":     valid(flagMaxBytes, "many"),
		"an unknown flag":               valid("--verbose"),
		"an argument":                   valid("extra"),
		"help":                          {"--help"},
		"a mirror without a URL":        mirror("registry.example"),
		"a mirror of no registry":       mirror("=http://mirror.example"),
		"a mirror with a path":          mirror("registry.example=http://mirror.example/v2"),
		"a mirror with a slash":         mirror("registry.example=http://mirror.example/"),
		"a mirror with a query":         mirror("registry.example=http://mirror.example?x=1"),
		"a mirror with a user":          mirror("registry.example=http://user:pw@mirror.example"),
		"a mirror of another scheme":    mirror("registry.example=ftp://mirror.example"),
		"a mirror without a host":       mirror("registry.example=http://"),
		"a registry mirrored twice": valid(flagMirror, "registry.example=http://a.example",
			flagMirror, "registry.example=http://b.example"),
	}
	for title, args := range cases {
		t.Run(title, func(t *testing.T) {
			h := newHarness(t)
			out := h.scan(args...)
			requireReason(t, out, result.ErrorReasonInternal)
			require.Empty(t, out.stderr, "no usage text")
			require.False(t, h.syft.ran(t))
		})
	}
}
