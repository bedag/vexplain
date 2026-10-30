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

// Package pull fetches the image that a scan analyses: it resolves the platform manifests to scan,
// and unpacks the filesystem of each. The scanner calls it, and the operator never imports it.
//
// The image is untrusted input: its index, its configuration and its layers can all be crafted. So
// Resolve takes from an index only image manifests of the requested platforms, and Extract never
// writes outside the directory it unpacks into, nor through a link. Their errors can hold text from
// the image, such as a path or a media type, so they must never be printed.
package pull

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/bedag/vexplain/internal/scan/result"
)

// ErrNoMatchingPlatform means that the image has no manifest to scan: an index has no image
// manifest of the requested platforms, or a single manifest doesn't say its platform.
var ErrNoMatchingPlatform = errors.New("the image has no manifest for the platforms to scan")

// attestationPlatform is the platform of the attestation manifests that build tools put in an index.
// They are never scanned.
const attestationPlatform = "unknown/unknown"

// Target is a platform manifest of an image, to scan.
type Target struct {
	// Platform is the platform of the manifest, as os/architecture[/variant].
	Platform string
	// Digest is the digest of the platform manifest.
	Digest string
	// Image is the image of the manifest. Its layers and configuration are fetched when they are
	// read.
	Image v1.Image
}

// Resolve returns what to scan of ref.
//
// For an index, it returns the entries whose platform matches one of platforms by
// result.PlatformMatches: the OS and the architecture always, and the variant when the request gives
// one. Of several entries of the same platform, it takes the first, as a container runtime does. It
// skips unknown/unknown (attestations), and every entry that isn't an image manifest, such as a
// nested index or an artifact.
//
// For a single manifest, it returns that manifest with the platform of its configuration, whatever
// platforms holds. A configuration that names no OS or architecture can't say which platform the
// manifest is for, so it gives ErrNoMatchingPlatform, as does anything that is neither.
//
// Errors from the registry are returned as go-containerregistry gives them, so that errors.As finds
// a *transport.Error and its status. ctx bounds every fetch, including those of the targets' images.
func Resolve(ctx context.Context, ref name.Digest, platforms []string, opts ...remote.Option) ([]Target, error) {
	opts = append(slices.Clone(opts), remote.WithContext(ctx))
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, err
	}
	switch {
	case desc.MediaType.IsIndex():
		return resolveIndex(desc, platforms)
	case desc.MediaType.IsImage():
		return resolveImage(desc)
	default:
		return nil, ErrNoMatchingPlatform
	}
}

// resolveIndex returns the targets of an index.
func resolveIndex(desc *remote.Descriptor, platforms []string) ([]Target, error) {
	index, err := desc.ImageIndex()
	if err != nil {
		return nil, err
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}
	var targets []Target
	for _, entry := range manifest.Manifests {
		platform, ok := platformString(entry.Platform)
		if !ok || !entry.MediaType.IsImage() || platform == attestationPlatform || !requested(platform, platforms) ||
			slices.ContainsFunc(targets, func(t Target) bool { return t.Platform == platform }) {
			continue
		}
		img, err := index.Image(entry.Digest)
		if err != nil {
			return nil, err
		}
		targets = append(targets, Target{Platform: platform, Digest: entry.Digest.String(), Image: img})
	}
	if len(targets) == 0 {
		return nil, ErrNoMatchingPlatform
	}
	return targets, nil
}

// resolveImage returns the target of a single manifest.
func resolveImage(desc *remote.Descriptor) ([]Target, error) {
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}
	config, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	platform, ok := platformString(config.Platform())
	if !ok {
		return nil, ErrNoMatchingPlatform
	}
	return []Target{{Platform: platform, Digest: desc.Digest.String(), Image: img}}, nil
}

// requested reports whether platform matches one of the requested platforms.
func requested(platform string, platforms []string) bool {
	return slices.ContainsFunc(platforms, func(r string) bool { return result.PlatformMatches(r, platform) })
}

// platformString returns p as os/architecture[/variant], without the OS version. It returns false
// when p names no OS or no architecture, or has a part with a slash, which would read as another
// platform.
func platformString(p *v1.Platform) (string, bool) {
	if p == nil || p.OS == "" || p.Architecture == "" {
		return "", false
	}
	parts := []string{p.OS, p.Architecture}
	if p.Variant != "" {
		parts = append(parts, p.Variant)
	}
	if slices.ContainsFunc(parts, func(part string) bool { return strings.Contains(part, "/") }) {
		return "", false
	}
	return strings.Join(parts, "/"), true
}
