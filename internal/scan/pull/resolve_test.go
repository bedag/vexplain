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

package pull_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/scan/pull"
)

// The platforms of the requests.
const (
	amd64   = "linux/amd64"
	arm64   = "linux/arm64"
	arm64v8 = "linux/arm64/v8"
)

// The platforms of the test images.
var (
	linuxAMD64   = v1.Platform{OS: "linux", Architecture: "amd64"}
	linuxARM64v8 = v1.Platform{OS: linuxAMD64.OS, Architecture: "arm64", Variant: "v8"}
	attestation  = v1.Platform{OS: "unknown", Architecture: "unknown"}
	windows      = v1.Platform{OS: "windows", Architecture: "amd64", OSVersion: "10.0.20348.2700"}
)

// newRepository starts an in-process registry that logs nothing, and returns a repository in it.
func newRepository(t *testing.T) name.Repository {
	t.Helper()
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	repo, err := name.NewRepository(strings.TrimPrefix(server.URL, "http://") + "/team-a/app")
	require.NoError(t, err)
	return repo
}

// configImage returns an image without layers, with the configuration cfg. Images with different
// configurations have different digests.
func configImage(t *testing.T, cfg v1.ConfigFile) v1.Image {
	t.Helper()
	img, err := mutate.ConfigFile(empty.Image, &cfg)
	require.NoError(t, err)
	return img
}

// platformImage returns an image without layers whose configuration names the platform p.
func platformImage(t *testing.T, p v1.Platform) v1.Image {
	t.Helper()
	return authoredImage(t, p, "")
}

// authoredImage returns an image like platformImage, whose configuration names an author too. Images
// of the same platform and another author have different digests.
func authoredImage(t *testing.T, p v1.Platform, author string) v1.Image {
	t.Helper()
	return configImage(t, v1.ConfigFile{
		OS: p.OS, Architecture: p.Architecture, Variant: p.Variant, OSVersion: p.OSVersion, Author: author,
	})
}

// push writes img to repo by its digest, and returns the reference.
func push(t *testing.T, repo name.Repository, img v1.Image) name.Digest {
	t.Helper()
	digest, err := img.Digest()
	require.NoError(t, err)
	ref := repo.Digest(digest.String())
	require.NoError(t, remote.Write(ref, img))
	return ref
}

// entry pushes img to repo, and returns its descriptor for an index, under the platform p.
func entry(t *testing.T, repo name.Repository, img v1.Image, p v1.Platform) v1.Descriptor {
	t.Helper()
	push(t, repo, img)
	desc, err := partial.Descriptor(img)
	require.NoError(t, err)
	desc.Platform = &p
	return *desc
}

// rawIndex is the JSON of an index, as remote.Put writes it.
type rawIndex []byte

func (r rawIndex) RawManifest() ([]byte, error)        { return r, nil }
func (r rawIndex) MediaType() (types.MediaType, error) { return types.OCIImageIndex, nil }

// putIndex writes an index of the entries to repo, and returns its reference. The index is written
// as JSON, so that it can hold any entry, such as one for an artifact.
func putIndex(t *testing.T, repo name.Repository, entries ...v1.Descriptor) name.Digest {
	t.Helper()
	raw, err := json.Marshal(v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: entries})
	require.NoError(t, err)
	digest, _, err := v1.SHA256(bytes.NewReader(raw))
	require.NoError(t, err)
	ref := repo.Digest(digest.String())
	require.NoError(t, remote.Put(ref, rawIndex(raw)))
	return ref
}

// digestOf returns the digest of img as a string.
func digestOf(t *testing.T, img v1.Image) string {
	t.Helper()
	digest, err := img.Digest()
	require.NoError(t, err)
	return digest.String()
}

// targetsOf returns the platforms and digests of the targets, in their order.
func targetsOf(targets []pull.Target) [][2]string {
	got := make([][2]string, 0, len(targets))
	for _, target := range targets {
		got = append(got, [2]string{target.Platform, target.Digest})
	}
	return got
}

// nestedIndexEntry writes an index that holds an image of the platform p, and returns its entry for
// another index, under p.
func nestedIndexEntry(t *testing.T, repo name.Repository, p v1.Platform) v1.Descriptor {
	t.Helper()
	img := authoredImage(t, p, "nested")
	nested := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &p}})
	digest, err := nested.Digest()
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(repo.Digest(digest.String()), nested))
	desc, err := partial.Descriptor(nested)
	require.NoError(t, err)
	desc.Platform = &p
	return *desc
}

// artifactEntry returns an index entry of the platform p for an artifact that isn't an image. The
// registry doesn't have it, so a pull of it fails.
func artifactEntry(t *testing.T, p v1.Platform) v1.Descriptor {
	t.Helper()
	digest, _, err := v1.SHA256(strings.NewReader("an artifact"))
	require.NoError(t, err)
	return v1.Descriptor{MediaType: "application/vnd.example.artifact.v1+json", Digest: digest, Size: 11, Platform: &p}
}

// multiPlatformIndex writes an index like that of a multi-platform image with attestations, and with
// entries for linux/amd64 that aren't image manifests before its image. It returns the index and its
// linux images.
func multiPlatformIndex(t *testing.T, repo name.Repository) (ref name.Digest, amd64Image, arm64Image v1.Image) {
	t.Helper()
	amd64Image = platformImage(t, linuxAMD64)
	arm64Image = platformImage(t, linuxARM64v8)
	ref = putIndex(t, repo,
		nestedIndexEntry(t, repo, linuxAMD64),
		artifactEntry(t, linuxAMD64),
		entry(t, repo, amd64Image, linuxAMD64),
		entry(t, repo, arm64Image, linuxARM64v8),
		entry(t, repo, platformImage(t, attestation), attestation),
		entry(t, repo, platformImage(t, windows), windows),
	)
	return ref, amd64Image, arm64Image
}

func TestResolveAnIndex(t *testing.T) {
	repo := newRepository(t)
	ref, amd64Image, arm64Image := multiPlatformIndex(t, repo)

	cases := []struct {
		name      string
		platforms []string
		want      [][2]string
	}{
		{"one platform gives one target", []string{amd64},
			[][2]string{{amd64, digestOf(t, amd64Image)}}},
		{"a request without a variant matches the entry's variant", []string{arm64},
			[][2]string{{arm64v8, digestOf(t, arm64Image)}}},
		{"two platforms give two targets in the order of the index", []string{arm64, amd64},
			[][2]string{{amd64, digestOf(t, amd64Image)}, {arm64v8, digestOf(t, arm64Image)}}},
		{"the platform leaves out the OS version", []string{"windows/amd64"},
			[][2]string{{"windows/amd64", digestOf(t, platformImage(t, windows))}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			targets, err := pull.Resolve(context.Background(), ref, c.platforms)
			require.NoError(t, err)
			require.Equal(t, c.want, targetsOf(targets))
		})
	}
}

func TestResolveGivesImagesToScan(t *testing.T) {
	repo := newRepository(t)
	ref, amd64Image, _ := multiPlatformIndex(t, repo)

	targets, err := pull.Resolve(context.Background(), ref, []string{amd64})
	require.NoError(t, err)
	require.Len(t, targets, 1)

	require.Equal(t, digestOf(t, amd64Image), digestOf(t, targets[0].Image))
	cfg, err := targets[0].Image.ConfigFile()
	require.NoError(t, err)
	require.Equal(t, linuxAMD64.Architecture, cfg.Architecture)
}

func TestResolveFindsNoMatchingPlatform(t *testing.T) {
	repo := newRepository(t)
	ref, _, _ := multiPlatformIndex(t, repo)

	for _, platforms := range [][]string{
		{"linux/s390x"},
		// An attestation is never scanned, even when asked for.
		{"unknown/unknown"},
		// The variant of a request must be the entry's.
		{"linux/arm64/v7"},
	} {
		t.Run(strings.Join(platforms, ","), func(t *testing.T) {
			_, err := pull.Resolve(context.Background(), ref, platforms)
			require.ErrorIs(t, err, pull.ErrNoMatchingPlatform)
		})
	}
}

func TestResolveSkipsEntriesThatAreNoImageManifests(t *testing.T) {
	repo := newRepository(t)
	ref := putIndex(t, repo, nestedIndexEntry(t, repo, linuxAMD64), artifactEntry(t, linuxAMD64))

	_, err := pull.Resolve(context.Background(), ref, []string{amd64})
	require.ErrorIs(t, err, pull.ErrNoMatchingPlatform)
}

func TestResolveTakesTheFirstEntryOfAPlatform(t *testing.T) {
	repo := newRepository(t)
	first := platformImage(t, linuxAMD64)
	second := authoredImage(t, linuxAMD64, "second")
	ref := putIndex(t, repo, entry(t, repo, first, linuxAMD64), entry(t, repo, second, linuxAMD64))

	targets, err := pull.Resolve(context.Background(), ref, []string{amd64})
	require.NoError(t, err)
	require.Equal(t, [][2]string{{amd64, digestOf(t, first)}}, targetsOf(targets))
}

func TestResolveASingleManifest(t *testing.T) {
	repo := newRepository(t)
	img := platformImage(t, linuxARM64v8)
	ref := push(t, repo, img)

	// A single manifest is the image, whatever platform was asked for.
	targets, err := pull.Resolve(context.Background(), ref, []string{amd64})
	require.NoError(t, err)
	require.Equal(t, [][2]string{{arm64v8, digestOf(t, img)}}, targetsOf(targets))
	require.Equal(t, digestOf(t, img), digestOf(t, targets[0].Image))
}

func TestResolveASingleManifestWithoutAPlatform(t *testing.T) {
	repo := newRepository(t)
	for title, cfg := range map[string]v1.ConfigFile{
		"no OS and no architecture": {},
		"no architecture":           {OS: linuxAMD64.OS},
		"no OS":                     {Architecture: linuxAMD64.Architecture},
	} {
		t.Run(title, func(t *testing.T) {
			ref := push(t, repo, configImage(t, cfg))
			_, err := pull.Resolve(context.Background(), ref, []string{amd64})
			require.ErrorIs(t, err, pull.ErrNoMatchingPlatform)
		})
	}
}

func TestResolveKeepsTheRegistrysAnswer(t *testing.T) {
	repo := newRepository(t)
	missing, _, err := v1.SHA256(strings.NewReader("no such manifest"))
	require.NoError(t, err)

	_, err = pull.Resolve(context.Background(), repo.Digest(missing.String()), []string{amd64})
	var answer *transport.Error
	require.True(t, errors.As(err, &answer), "the error is %v", err)
	require.Equal(t, http.StatusNotFound, answer.StatusCode)
}
