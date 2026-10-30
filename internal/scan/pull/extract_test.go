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
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/scan/pull"
)

// plenty is a limit that no test image comes near.
const plenty = 1 << 30

// tarEntry is an entry of a test layer.
type tarEntry struct {
	header  tar.Header
	content string
}

func file(name, content string) tarEntry {
	return fileMode(name, content, 0o644)
}

func fileMode(name, content string, mode int64) tarEntry {
	return tarEntry{tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: int64(len(content))}, content}
}

func directory(name string, mode int64) tarEntry {
	return tarEntry{header: tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: mode}}
}

func symlink(name, target string) tarEntry {
	return tarEntry{header: tar.Header{Typeflag: tar.TypeSymlink, Name: name, Linkname: target, Mode: 0o777}}
}

func hardLink(name, target string) tarEntry {
	return tarEntry{header: tar.Header{Typeflag: tar.TypeLink, Name: name, Linkname: target, Mode: 0o644}}
}

func device(name string) tarEntry {
	return tarEntry{header: tar.Header{Typeflag: tar.TypeChar, Name: name, Mode: 0o666, Devmajor: 1, Devminor: 3}}
}

func fifo(name string) tarEntry {
	return tarEntry{header: tar.Header{Typeflag: tar.TypeFifo, Name: name, Mode: 0o644}}
}

// tarOf returns a tar of the entries, in their order.
func tarOf(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		header := e.header
		require.NoError(t, tw.WriteHeader(&header))
		_, err := tw.Write([]byte(e.content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	return buf.Bytes()
}

// layerOf returns a layer that holds the entries.
func layerOf(t *testing.T, entries ...tarEntry) v1.Layer {
	t.Helper()
	data := tarOf(t, entries...)
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	require.NoError(t, err)
	return layer
}

// imageOf returns an image of the layers, the lowest first.
func imageOf(t *testing.T, layers ...v1.Layer) v1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	require.NoError(t, err)
	return img
}

// unpack extracts img into the directory "root" of a new directory, base, and returns both. Paths
// outside root but inside base show whether anything escaped.
func unpack(t *testing.T, img v1.Image, maxBytes int64) (base, root string, err error) {
	t.Helper()
	base = t.TempDir()
	root = filepath.Join(base, "root")
	require.NoError(t, os.Mkdir(root, 0o755))
	return base, root, pull.Extract(img, root, maxBytes)
}

// requireEntries requires that dir holds exactly the names.
func requireEntries(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Name())
	}
	require.ElementsMatch(t, names, got)
}

// requireContent requires that p is a regular file, and no link, that holds content.
func requireContent(t *testing.T, p, content string) {
	t.Helper()
	info, err := os.Lstat(p)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular(), "%s is %v", p, info.Mode())
	data, err := os.ReadFile(p)
	require.NoError(t, err)
	require.Equal(t, content, string(data))
}

// requireAbsent requires that nothing, not even a link, is at p.
func requireAbsent(t *testing.T, p string) {
	t.Helper()
	_, err := os.Lstat(p)
	require.ErrorIs(t, err, fs.ErrNotExist, "%s exists", p)
}

func TestExtractKeepsEverythingInsideDir(t *testing.T) {
	lower := layerOf(t,
		file("gone", "deleted by the layer above"),
		file("kept", "from the lower layer"),
	)
	upper := layerOf(t,
		file("../escape", "climbs out"),
		file("/abs/path", "absolute"),
		symlink("passwd", "/etc/passwd"),
		file("x", "a file"),
		hardLink("outside", "../x"),
		hardLink("inside", "x"),
		device("dev/null"),
		fifo("run/pipe"),
		file(".wh.gone", ""),
	)

	base, root, err := unpack(t, imageOf(t, lower, upper), plenty)
	require.NoError(t, err)

	requireEntries(t, base, "root")
	// Names are taken inside the image's root, as a container runtime takes them.
	requireContent(t, filepath.Join(root, "escape"), "climbs out")
	requireContent(t, filepath.Join(root, "abs", "path"), "absolute")
	// The link is kept as it is, and not followed.
	target, err := os.Readlink(filepath.Join(root, "passwd"))
	require.NoError(t, err)
	require.Equal(t, "/etc/passwd", target)
	// A hard link out of the root is refused; one inside it is a copy.
	requireAbsent(t, filepath.Join(root, "outside"))
	requireContent(t, filepath.Join(root, "inside"), "a file")
	// Devices and FIFOs are skipped.
	requireAbsent(t, filepath.Join(root, "dev", "null"))
	requireAbsent(t, filepath.Join(root, "run", "pipe"))
	// The whiteout deletes the lower layer's file, and isn't unpacked itself.
	requireAbsent(t, filepath.Join(root, "gone"))
	requireAbsent(t, filepath.Join(root, ".wh.gone"))
	requireContent(t, filepath.Join(root, "kept"), "from the lower layer")
}

func TestExtractNeverWritesThroughALink(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.Mkdir(outside, 0o755))

	lower := layerOf(t,
		// The layer above puts a link where this directory is, which hides it and what it holds.
		directory("c", 0o755),
		file("c/z", "hidden by the link above"),
	)
	upper := layerOf(t,
		symlink("a", outside),
		file("a/x", "through an absolute link"),
		symlink("b", ".."),
		file("b/y", "through a relative link"),
		symlink("c", outside),
		file("f", "a file"),
		file("f/w", "below a file"),
	)
	root := filepath.Join(base, "root")
	require.NoError(t, os.Mkdir(root, 0o755))

	require.NoError(t, pull.Extract(imageOf(t, lower, upper), root, plenty))

	requireEntries(t, base, "root", "outside")
	requireEntries(t, outside)
	requireEntries(t, root, "a", "b", "c", "f")
	for _, link := range []string{"a", "b", "c"} {
		info, err := os.Lstat(filepath.Join(root, link))
		require.NoError(t, err)
		require.Equal(t, fs.ModeSymlink, info.Mode().Type(), "%s", link)
	}
	requireContent(t, filepath.Join(root, "f"), "a file")
}

func TestExtractFlattensTheLayers(t *testing.T) {
	lower := layerOf(t,
		file("etc/conf", "old"),
		directory("opt/app", 0o755),
		file("opt/app/lib.so", "hidden by the file above"),
		file("usr/bin/tool", "kept"),
	)
	upper := layerOf(t,
		file("etc/conf", "new"),
		file("opt/app", "a file where a directory was"),
		file("usr/bin/other", "added"),
	)

	_, root, err := unpack(t, imageOf(t, lower, upper), plenty)
	require.NoError(t, err)

	requireContent(t, filepath.Join(root, "etc", "conf"), "new")
	requireContent(t, filepath.Join(root, "opt", "app"), "a file where a directory was")
	requireContent(t, filepath.Join(root, "usr", "bin", "tool"), "kept")
	requireContent(t, filepath.Join(root, "usr", "bin", "other"), "added")
}

func TestExtractAppliesWhiteouts(t *testing.T) {
	bottom := layerOf(t,
		file("d/old", "hidden by the opaque directory"),
		file("d/sub/older", "hidden by the opaque directory"),
		file("e/keep", "kept"),
		file("e/drop", "deleted"),
		directory("tree", 0o755),
		file("tree/leaf", "deleted with its directory"),
		file("both", "replaced in the layer above"),
	)
	top := layerOf(t,
		directory("d", 0o755),
		file("d/.wh..wh..opq", ""),
		file("d/new", "next to the opaque marker"),
		file("e/.wh.drop", ""),
		file(".wh.tree", ""),
		// A whiteout deletes only what the layers below hold, and not the file of its own layer.
		file(".wh.both", ""),
		file("both", "from the top layer"),
	)

	_, root, err := unpack(t, imageOf(t, bottom, top), plenty)
	require.NoError(t, err)

	requireEntries(t, filepath.Join(root, "d"), "new")
	requireEntries(t, filepath.Join(root, "e"), "keep")
	requireAbsent(t, filepath.Join(root, "tree"))
	requireContent(t, filepath.Join(root, "both"), "from the top layer")
}

func TestExtractCopiesHardLinks(t *testing.T) {
	img := imageOf(t, layerOf(t,
		directory("bin", 0o755),
		fileMode("bin/tool", "the tool", 0o755),
		hardLink("bin/alias", "bin/tool"),
		hardLink("bin/absolute", "/bin/tool"),
		hardLink("bin/dotted", "./bin/../bin/tool"),
		symlink("bin/link", "tool"),
		hardLink("bin/to-link", "bin/link"),
		hardLink("bin/to-directory", "bin"),
		hardLink("bin/to-nothing", "bin/missing"),
		hardLink("bin/later", "bin/after"),
		file("bin/after", "written after its hard link"),
	))

	_, root, err := unpack(t, img, plenty)
	require.NoError(t, err)

	for _, name := range []string{"alias", "absolute", "dotted"} {
		p := filepath.Join(root, "bin", name)
		requireContent(t, p, "the tool")
		info, err := os.Stat(p)
		require.NoError(t, err)
		require.NotZero(t, info.Mode().Perm()&0o100, "the copy keeps the execute bit")
		original, err := os.Stat(filepath.Join(root, "bin", "tool"))
		require.NoError(t, err)
		require.False(t, os.SameFile(original, info), "%s is a copy, not a link", name)
	}
	// Only an earlier regular file can be the target.
	for _, name := range []string{"to-link", "to-directory", "to-nothing", "later"} {
		requireAbsent(t, filepath.Join(root, "bin", name))
	}
}

func TestExtractMakesEntriesReadable(t *testing.T) {
	img := imageOf(t, layerOf(t,
		directory("locked", 0),
		fileMode("locked/inner", "inside a directory of mode 0000", 0),
		fileMode("etc/shadow", "a file of mode 0000", 0),
		fileMode("bin/tool", "an executable", 0o700),
	))

	_, root, err := unpack(t, img, plenty)
	require.NoError(t, err)

	requireContent(t, filepath.Join(root, "locked", "inner"), "inside a directory of mode 0000")
	requireContent(t, filepath.Join(root, "etc", "shadow"), "a file of mode 0000")
	info, err := os.Stat(filepath.Join(root, "locked"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), info.Mode().Perm()&0o700, "the owner can list, enter and change it")
	info, err = os.Stat(filepath.Join(root, "bin", "tool"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o500), info.Mode().Perm()&0o500, "the owner can read and run it")

	require.NoError(t, filepath.WalkDir(root, func(_ string, _ fs.DirEntry, err error) error { return err }))
	require.NoError(t, os.RemoveAll(root))
}

func TestExtractStopsAtTheLimit(t *testing.T) {
	const kib = 1 << 10
	cases := []struct {
		name     string
		maxBytes int64
		entries  []tarEntry
		tooLarge bool
	}{
		{"a file over the limit", 64 * kib,
			[]tarEntry{file("big", strings.Repeat("x", 100*kib))}, true},
		{"a file within it", 128 * kib,
			[]tarEntry{file("big", strings.Repeat("x", 100*kib))}, false},
		{"a hard link's copy counts", kib * kib,
			[]tarEntry{file("big", strings.Repeat("x", 600*kib)), hardLink("copy", "big")}, true},
		// The limit counts the space that files take on disk: each takes whole blocks of 4 KiB.
		{"small files count as whole blocks", 64 * kib, manyFiles(20), true},
		{"fewer small files fit", 64 * kib, manyFiles(10), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, root, err := unpack(t, imageOf(t, layerOf(t, c.entries...)), c.maxBytes)
			if !c.tooLarge {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, pull.ErrTooLarge)
			// It stops before writing past the limit.
			requireAbsent(t, filepath.Join(root, c.entries[len(c.entries)-1].header.Name))
		})
	}
}

// manyFiles returns n files of one byte each.
func manyFiles(n int) []tarEntry {
	entries := make([]tarEntry, 0, n)
	for i := range n {
		entries = append(entries, file(strings.Repeat("f", i+1), "x"))
	}
	return entries
}

// brokenLayer is a layer whose content can't be read: opening it fails with open, or its content,
// the tar, is followed by the error tail, as a registry's digest check fails at the end of a blob.
type brokenLayer struct {
	tar  []byte
	open error
	tail error
}

func (l brokenLayer) Digest() (v1.Hash, error) {
	return v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}, nil
}
func (l brokenLayer) DiffID() (v1.Hash, error)            { return l.Digest() }
func (l brokenLayer) Compressed() (io.ReadCloser, error)  { return l.Uncompressed() }
func (l brokenLayer) Size() (int64, error)                { return int64(len(l.tar)), nil }
func (l brokenLayer) MediaType() (types.MediaType, error) { return types.DockerUncompressedLayer, nil }

func (l brokenLayer) Uncompressed() (io.ReadCloser, error) {
	if l.open != nil {
		return nil, l.open
	}
	return io.NopCloser(io.MultiReader(bytes.NewReader(l.tar), failingReader{l.tail})), nil
}

// failingReader fails every read with its error.
type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestExtractTellsReadErrorsFromWriteErrors(t *testing.T) {
	cause := errors.New("the registry failed")
	complete := tarOf(t, file("a", "content"))
	// The tar ends in the middle of the content of its file.
	truncated := tarOf(t, file("a", strings.Repeat("x", 2048)))[:1024]

	for name, layer := range map[string]v1.Layer{
		"the layer can't be opened":            brokenLayer{open: cause},
		"the tar is truncated":                 brokenLayer{tar: truncated, tail: io.EOF},
		"the stream fails after the tar's end": brokenLayer{tar: complete, tail: cause},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := unpack(t, imageOf(t, layer), plenty)
			require.ErrorIs(t, err, pull.ErrImageRead)
			if layer.(brokenLayer).tail != io.EOF {
				require.ErrorIs(t, err, cause, "the cause is kept, for the registry's answer")
			}
		})
	}

	t.Run("the directory is missing", func(t *testing.T) {
		err := pull.Extract(imageOf(t, layerOf(t, file("a", "content"))), filepath.Join(t.TempDir(), "missing"), plenty)
		require.Error(t, err)
		require.NotErrorIs(t, err, pull.ErrImageRead)
		require.NotErrorIs(t, err, pull.ErrTooLarge)
	})
	t.Run("a name is too long to create", func(t *testing.T) {
		_, _, err := unpack(t, imageOf(t, layerOf(t, file(strings.Repeat("n", 300), "content"))), plenty)
		require.Error(t, err)
		require.NotErrorIs(t, err, pull.ErrImageRead)
		require.NotErrorIs(t, err, pull.ErrTooLarge)
	})
}

func TestExtractTakesNamesThatTarCallsInsecure(t *testing.T) {
	// With this setting, the tar reader reports names such as ../escape as insecure. Extract takes
	// them inside the root all the same.
	t.Setenv("GODEBUG", "tarinsecurepath=0")
	img := imageOf(t, layerOf(t, file("../escape", "climbs out"), file("/abs/path", "absolute")))

	base, root, err := unpack(t, img, plenty)
	require.NoError(t, err)

	requireEntries(t, base, "root")
	requireContent(t, filepath.Join(root, "escape"), "climbs out")
	requireContent(t, filepath.Join(root, "abs", "path"), "absolute")
}
