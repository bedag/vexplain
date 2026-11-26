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
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/bedag/vexplain/hack/internal/docker"
)

// buildImages builds the base image, pushes it, and pushes each image of the load: the base with a file of its own,
// which gives it a digest of its own. An image is one manifest, so that the digest that the pods report is the one
// that the hub scans.
func (m *measurement) buildImages(ctx context.Context) error {
	base := m.opts.registry + "/measure-6/base:" + builtTag
	if _, err := docker.Run(ctx, "build", "--provenance=false", "--sbom=false", "-t", base, baseBuild); err != nil {
		return err
	}
	if _, err := docker.Run(ctx, "push", base); err != nil {
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
