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
	"strconv"
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

// globalHeader is a PAX global header, which sets the records for the entries after it. Go's tar reader
// returns it as an entry of its own, whose name is the one of its header, or of its path record.
func globalHeader(name string, records map[string]string) tarEntry {
	return tarEntry{header: tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: name, PAXRecords: records}}
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

// requireLink requires that p is a link to target.
func requireLink(t *testing.T, p, target string) {
	t.Helper()
	got, err := os.Readlink(p)
	require.NoError(t, err, "%s is no link", p)
	require.Equal(t, target, got)
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
	// A hard link inside the root is a copy. One out of it fails Extract (TestExtractRefusesHardLinks).
	requireContent(t, filepath.Join(root, "inside"), "a file")
	// Devices and FIFOs are skipped.
	requireAbsent(t, filepath.Join(root, "dev", "null"))
	requireAbsent(t, filepath.Join(root, "run", "pipe"))
	// The whiteout deletes the lower layer's file, and isn't unpacked itself.
	requireAbsent(t, filepath.Join(root, "gone"))
	requireAbsent(t, filepath.Join(root, ".wh.gone"))
	requireContent(t, filepath.Join(root, "kept"), "from the lower layer")
}

func TestExtractNeverWritesThroughALinkAtTheEntrysOwnPath(t *testing.T) {
	// An entry never writes through a link at its own path. Where a layer below holds a link at that path,
	// the entry replaces it, as tar extraction does: Extract never makes the link, and its target stays as
	// it is. The directories above an entry resolve through links inside the root, so nothing lands
	// outside it.
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.Mkdir(outside, 0o755))

	lower := layerOf(t,
		file("etc/passwd", "root:x:0:0"),
		// Links at the paths of the entries above: to a file elsewhere in the root, to one outside it on this
		// host, and one where lib leads.
		symlink("x", "etc/passwd"),
		symlink("y", filepath.Join(outside, "y")),
		symlink("lib", usrLibDir),
		symlink("usr/lib/z", "../../etc/passwd"),
		// The layer above puts a link where this directory is, which hides it and what it holds.
		directory("c", 0o755),
		file("c/w", "hidden by the link above"),
	)
	upper := layerOf(t,
		file("x", "replaces the link"),
		file("y", "replaces the link"),
		file("lib/z", "replaces the link where lib leads"),
		symlink("a", outside),
		file("a/v", "below an absolute link of its own layer"),
		symlink("b", "../.."),
		file("b/u", "below a link of its own layer that climbs above the root"),
		symlink("c", outside),
	)
	root := filepath.Join(base, "root")
	require.NoError(t, os.Mkdir(root, 0o755))

	require.NoError(t, pull.Extract(imageOf(t, lower, upper), root, plenty))

	requireEntries(t, base, "root", "outside")
	requireEntries(t, outside)
	requireContent(t, filepath.Join(root, "etc", "passwd"), "root:x:0:0")
	requireContent(t, filepath.Join(root, "x"), "replaces the link")
	requireContent(t, filepath.Join(root, "y"), "replaces the link")
	requireContent(t, filepath.Join(root, usrLibDir, "z"), "replaces the link where lib leads")
	requireLink(t, filepath.Join(root, "a"), outside)
	requireContent(t, filepath.Join(root, outside, "v"), "below an absolute link of its own layer")
	requireLink(t, filepath.Join(root, "b"), "../..")
	requireContent(t, filepath.Join(root, "u"), "below a link of its own layer that climbs above the root")
	requireLink(t, filepath.Join(root, "c"), outside)

	t.Run("a file after a link at its path in its own layer", func(t *testing.T) {
		// Two entries for one path in one layer: Extract fails, and writes nothing through the link.
		layer := layerOf(t, file("etc/passwd", "root:x:0:0"), symlink("x", "etc/passwd"), file("x", "hostile"))

		_, root, err := unpack(t, imageOf(t, layer), plenty)

		require.ErrorIs(t, err, pull.ErrDuplicateEntry)
		requireContent(t, filepath.Join(root, "etc", "passwd"), "root:x:0:0")
	})
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

// The paths of the merged-usr base of the tests of links of a lower layer.
const (
	// usrLibDir is where lib links to, and absUsrLibDir the same as an absolute link names it.
	usrLibDir    = "usr/lib"
	absUsrLibDir = "/" + usrLibDir
	// libDir is the directory of the libraries.
	libDir = usrLibDir + "/x86_64-linux-gnu"
	// baseLib is the library of the base, upperLib the one that the layer above it holds below lib, and
	// bottomLib one that a layer below the base holds where lib leads.
	baseLib   = "libbar.so.1"
	upperLib  = "libfoo.so.1"
	bottomLib = "libold.so.1"
)

// usrLibEntries returns the entries of usr/lib in the merged-usr base.
func usrLibEntries() []tarEntry {
	return []tarEntry{
		directory("usr", 0o755),
		directory(usrLibDir, 0o755),
		directory(libDir, 0o755),
		file(libDir+"/"+baseLib, "a library of the base"),
	}
}

// mergedUsrBase returns a lower layer as a merged-usr base holds it, in the order of a sorted tar: lib
// links to target, and the libraries are in usr/lib.
func mergedUsrBase(t *testing.T, target string) v1.Layer {
	t.Helper()
	return layerOf(t, append([]tarEntry{symlink("lib", target)}, usrLibEntries()...)...)
}

// linkedLast returns the merged-usr base with its link to usr/lib after usr/lib, so that the entries
// that go through the link merge into what is there.
func linkedLast(t *testing.T) v1.Layer {
	t.Helper()
	return layerOf(t, append(usrLibEntries(), symlink("lib", usrLibDir))...)
}

// assembled returns an upper layer that a tool assembled from files, and not from the diff of a
// snapshot: it holds a library below lib, and no entry for lib or for the directory below it.
func assembled(t *testing.T) v1.Layer {
	t.Helper()
	return layerOf(t, file("lib/x86_64-linux-gnu/libfoo.so.1", "a library of the upper layer"))
}

func TestExtractPutsAnEntryBelowALinkOfALowerLayerWhereTheLinkLeads(t *testing.T) {
	// A layer that a tool assembled from files can hold lib/x86_64-linux-gnu/libfoo.so.1 over a merged-usr
	// base, where lib links to usr/lib. containerd's applier, which unpacks the layer onto the base, resolves
	// lib through the link inside the root: the file lands in usr/lib, and the link stays. So the files that
	// the base's packages list below /lib stay present.
	for name, tc := range map[string]struct {
		lower  v1.Layer
		target string
	}{
		"a relative link":  {mergedUsrBase(t, usrLibDir), usrLibDir},
		"an absolute link": {mergedUsrBase(t, absUsrLibDir), absUsrLibDir},
		"a link after the directory that it leads to": {linkedLast(t), usrLibDir},
	} {
		t.Run(name, func(t *testing.T) {
			base, root, err := unpack(t, imageOf(t, tc.lower, assembled(t)), plenty)
			require.NoError(t, err)

			requireEntries(t, base, "root")
			requireEntries(t, root, "lib", "usr")
			requireLink(t, filepath.Join(root, "lib"), tc.target)
			requireEntries(t, filepath.Join(root, libDir), baseLib, upperLib)
			requireContent(t, filepath.Join(root, libDir, upperLib), "a library of the upper layer")
			requireContent(t, filepath.Join(root, libDir, baseLib), "a library of the base")
		})
	}
}

func TestExtractPutsTheEntriesOfTheLayersAboveALinkWhereItLeads(t *testing.T) {
	t.Run("from several layers", func(t *testing.T) {
		middle := layerOf(t, file("lib/x86_64-linux-gnu/libmid.so.1", "a library of the middle layer"))
		top := layerOf(t,
			// A directory below lib, and none for lib.
			directory("lib/x86_64-linux-gnu", 0o755),
			file("lib/x86_64-linux-gnu/libfoo.so.1", "a library of the top layer"),
			file(libDir+"/libdirect.so.1", "written to usr/lib itself"),
		)

		_, root, err := unpack(t, imageOf(t, mergedUsrBase(t, usrLibDir), middle, top), plenty)
		require.NoError(t, err)

		requireEntries(t, root, "lib", "usr")
		requireLink(t, filepath.Join(root, "lib"), usrLibDir)
		requireEntries(t, filepath.Join(root, libDir), baseLib, "libdirect.so.1", upperLib, "libmid.so.1")
	})

	// usr/lib links to lib64 in the base: the entries go through both links.
	for name, lower := range map[string]v1.Layer{
		"through a link that comes before": layerOf(t,
			directory("usr", 0o755),
			symlink(usrLibDir, "lib64"),
			directory("usr/lib64", 0o755),
			symlink("lib", usrLibDir),
		),
		"through a link that comes after": layerOf(t,
			symlink("lib", usrLibDir),
			directory("usr", 0o755),
			symlink(usrLibDir, "lib64"),
			directory("usr/lib64", 0o755),
		),
	} {
		t.Run(name, func(t *testing.T) {
			_, root, err := unpack(t, imageOf(t, lower, assembled(t)), plenty)
			require.NoError(t, err)

			requireLink(t, filepath.Join(root, "lib"), usrLibDir)
			requireLink(t, filepath.Join(root, "usr", "lib"), "lib64")
			requireEntries(t, filepath.Join(root, "usr"), "lib", "lib64")
			requireContent(t, filepath.Join(root, "usr", "lib64", "x86_64-linux-gnu", upperLib),
				"a library of the upper layer")
		})
	}

	// A layer between that holds lib, or deletes it, replaces the link, as in a container: the entries above
	// stay below lib.
	for name, middle := range map[string]v1.Layer{
		"where a layer between holds a directory": layerOf(t, directory("lib", 0o755), file("lib/libmid.so.1", "x")),
		"where a layer between deletes the link":  layerOf(t, file(".wh.lib", "")),
	} {
		t.Run(name, func(t *testing.T) {
			_, root, err := unpack(t, imageOf(t, mergedUsrBase(t, usrLibDir), middle, assembled(t)), plenty)
			require.NoError(t, err)

			requireContent(t, filepath.Join(root, "lib", "x86_64-linux-gnu", upperLib), "a library of the upper layer")
			requireEntries(t, filepath.Join(root, libDir), baseLib)
		})
	}
}

func TestExtractKeepsWhatAWhiteoutBelowALinkOfALowerLayerWouldDeleteWhereTheLinkLeads(t *testing.T) {
	// A whiteout below lib deletes what is where lib leads only for an applier that resolves lib through the
	// link. containerd's overlayfs snapshotter unpacks the layer on its own, where lib is a directory that
	// hides the link. Which of the two a cluster uses can't be told, so Extract keeps the files: a whiteout or
	// an opaque whiteout below a link deletes nothing where the link leads.
	//
	// The bottom layer holds libold.so.1 where the base above it holds libbar.so.1 and the link, and the top
	// layer deletes both below lib, or hides them with an opaque whiteout.
	bottom := layerOf(t, file(libDir+"/"+bottomLib, "a library of the bottom layer"))
	whiteouts := layerOf(t, file("lib/x86_64-linux-gnu/.wh.libbar.so.1", ""), file("lib/x86_64-linux-gnu/.wh."+bottomLib, ""))
	opaque := layerOf(t,
		file("lib/x86_64-linux-gnu/.wh..wh..opq", ""),
		file("lib/x86_64-linux-gnu/libfoo.so.1", "a library of the upper layer"),
	)
	opaqueLib := layerOf(t, file("lib/.wh..wh..opq", ""), file("lib/libtop.so.1", "a library of the upper layer"))
	for name, tc := range map[string]struct {
		base, upper v1.Layer
		want        map[string][]string
	}{
		"a whiteout": {
			mergedUsrBase(t, usrLibDir), whiteouts, map[string][]string{libDir: {baseLib, bottomLib}},
		},
		"an opaque whiteout": {
			mergedUsrBase(t, usrLibDir), opaque, map[string][]string{libDir: {baseLib, bottomLib, upperLib}},
		},
		"an opaque whiteout of lib itself": {
			mergedUsrBase(t, usrLibDir), opaqueLib, map[string][]string{
				usrLibDir: {"libtop.so.1", "x86_64-linux-gnu"},
				libDir:    {baseLib, bottomLib},
			},
		},
		"a whiteout, the link after usr/lib": {
			linkedLast(t), whiteouts, map[string][]string{libDir: {baseLib, bottomLib}},
		},
		"an opaque whiteout, the link after usr/lib": {
			linkedLast(t), opaque, map[string][]string{libDir: {baseLib, bottomLib, upperLib}},
		},
		"an opaque whiteout of lib itself, the link after usr/lib": {
			linkedLast(t), opaqueLib, map[string][]string{
				usrLibDir: {"libtop.so.1", "x86_64-linux-gnu"},
				libDir:    {baseLib, bottomLib},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, root, err := unpack(t, imageOf(t, bottom, tc.base, tc.upper), plenty)
			require.NoError(t, err)

			requireLink(t, filepath.Join(root, "lib"), usrLibDir)
			for dir, want := range tc.want {
				requireEntries(t, filepath.Join(root, dir), want...)
			}
		})
	}

	// Between the layers above the link, a whiteout below lib still deletes: both appliers agree there.
	t.Run("a whiteout of what a layer between holds below lib", func(t *testing.T) {
		middle := layerOf(t, file("lib/x86_64-linux-gnu/libmid.so.1", "deleted by the layer above"))
		top := layerOf(t, file("lib/x86_64-linux-gnu/.wh.libmid.so.1", ""))

		_, root, err := unpack(t, imageOf(t, mergedUsrBase(t, usrLibDir), middle, top), plenty)
		require.NoError(t, err)

		requireEntries(t, filepath.Join(root, libDir), baseLib)
	})
}

// chain returns the entries of n links, from lib through l1, l2 and so on, the last of them to usr/lib.
// They come after usr/lib and before lib, so that lib leads through all of them.
func chain(n int) []tarEntry {
	entries := []tarEntry{directory("usr", 0o755), directory(usrLibDir, 0o755)}
	for i := n - 1; i >= 1; i-- {
		target := usrLibDir
		if i < n-1 {
			target = "l" + strconv.Itoa(i+1)
		}
		entries = append(entries, symlink("l"+strconv.Itoa(i), target))
	}
	link := usrLibDir
	if n > 1 {
		link = "l1"
	}
	return append(entries, symlink("lib", link))
}

func TestExtractFollowsAsManyLinksAsLinux(t *testing.T) {
	// Linux follows 40 links in one path. The link of lib counts as the first.
	_, root, err := unpack(t, imageOf(t, layerOf(t, chain(40)...), assembled(t)), plenty)
	require.NoError(t, err)
	requireContent(t, filepath.Join(root, "usr", "lib", "x86_64-linux-gnu", upperLib), "a library of the upper layer")

	_, _, err = unpack(t, imageOf(t, layerOf(t, chain(41)...), assembled(t)), plenty)
	require.ErrorIs(t, err, pull.ErrBadLink)
}

func TestExtractStopsALinkThatClimbsAboveTheRootAtTheRoot(t *testing.T) {
	// A .. at the root stays at the root, as in Linux and in containerd's applier: a link that climbs above
	// the root leads to a path inside it.
	for target, lands := range map[string]string{
		"../../../usr/lib":            libDir,
		"/../usr/lib":                 libDir,
		"../outside":                  "outside/x86_64-linux-gnu",
		"../../../../../../../../tmp": "tmp/x86_64-linux-gnu",
	} {
		t.Run(target, func(t *testing.T) {
			base, root, err := unpack(t, imageOf(t, mergedUsrBase(t, target), assembled(t)), plenty)
			require.NoError(t, err)

			requireEntries(t, base, "root")
			requireLink(t, filepath.Join(root, "lib"), target)
			requireContent(t, filepath.Join(root, lands, upperLib), "a library of the upper layer")
		})
	}
}

func TestExtractRefusesALinkOfALowerLayerThatTheEntriesAboveCantGoThrough(t *testing.T) {
	// The upper layer of each case holds lib/x86_64-linux-gnu/libfoo.so.1, and the lower layers hold lib as a
	// link that leads into a loop or to something that isn't a directory, or to an entry for the path of the
	// file or of its directory. Extract fails on each rather than guess, and writes nothing outside the root.
	cases := map[string][]v1.Layer{
		"into a loop":              {layerOf(t, symlink("lib", "lib"))},
		"into a loop of two links": {layerOf(t, symlink("lib", "a"), symlink("a", "lib"))},
		"to a file":                {layerOf(t, file("etc/os-release", "ID=example"), symlink("lib", "etc/os-release"))},
		"to a file that comes after it": {
			layerOf(t, symlink("lib", "etc/os-release"), file("etc/os-release", "ID=example")),
		},
		"to a file that comes after it, in a directory that is there": {
			layerOf(t, directory("etc", 0o755), symlink("lib", "etc/os-release"), file("etc/os-release", "ID=example")),
		},
		"to a file that comes after it, below the directory that it leads to": {
			layerOf(t, directory("usr", 0o755), directory(usrLibDir, 0o755), symlink("lib", usrLibDir),
				file(libDir, "a file where the file above needs a directory")),
		},
		"through a file that comes after it": {
			layerOf(t, symlink("lib", usrLibDir), file("usr", "a file where usr/lib needs a directory")),
		},
		"through a file": {layerOf(t, file("etc/os-release", "ID=example"), symlink("lib", "etc/os-release/lib"))},
		"to a file of a layer between": {
			mergedUsrBase(t, usrLibDir),
			layerOf(t, file(libDir+"/libfoo.so.1", "written to usr/lib itself")),
		},
		"to a file where a directory is needed": {
			layerOf(t, symlink("lib", usrLibDir)),
			layerOf(t, file(libDir, "a file where the file above needs a directory")),
		},
		"to a file of a layer below where a directory is needed": {
			layerOf(t, file(libDir, "a file where the file above needs a directory")),
			layerOf(t, symlink("lib", usrLibDir)),
		},
		"to a file of its own layer": {
			layerOf(t, file(libDir+"/libfoo.so.1", "of the base"), symlink("lib", usrLibDir)),
		},
		"to a link of its own layer": {
			layerOf(t, symlink(libDir+"/libfoo.so.1", "../../../../outside/libfoo.so.1"), symlink("lib", usrLibDir)),
		},
	}
	for name, lower := range cases {
		t.Run(name, func(t *testing.T) {
			base, _, err := unpack(t, imageOf(t, append(lower, assembled(t))...), plenty)

			require.ErrorIs(t, err, pull.ErrBadLink)
			require.NotErrorIs(t, err, pull.ErrImageRead, "the image was read: it is no read error")
			requireEntries(t, base, "root")
		})
	}
}

// libc is a library below lib, as a package of a layer that a tool flattened from packages lists it.
const libc = "lib/x86_64-linux-gnu/libc.so.6"

func TestExtractPutsAnEntryBelowALinkOfItsOwnLayerWhereTheLinkLeads(t *testing.T) {
	// A layer that a tool flattened from packages can hold lib -> usr/lib, as a merged-usr base does, and then
	// files below lib. Tar extraction resolves lib through the layer's own link, inside the root: the files land
	// in usr/lib, and the link stays. A layer above that holds lib as a directory replaces the link, but the
	// files stay where the link led.
	for name, tc := range map[string]struct {
		layers []v1.Layer
		link   string
	}{
		"a relative link": {[]v1.Layer{layerOf(t, symlink("lib", usrLibDir),
			directory("usr", 0o755), directory(usrLibDir, 0o755), file(libc, "the C library"))}, usrLibDir},
		"an absolute link": {[]v1.Layer{layerOf(t, symlink("lib", absUsrLibDir),
			directory("usr", 0o755), directory(usrLibDir, 0o755), file(libc, "the C library"))}, absUsrLibDir},
		"a link before the directory that it leads to": {[]v1.Layer{layerOf(t, symlink("lib", usrLibDir),
			file(libc, "the C library"), directory("usr", 0o755), directory(usrLibDir, 0o755))}, usrLibDir},
		"a link that a layer above replaces with a directory": {[]v1.Layer{
			layerOf(t, symlink("lib", usrLibDir), file(libc, "the C library")),
			layerOf(t, directory("lib", 0o755), file("lib/libtop.so.1", "a library of the layer above")),
		}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			base, root, err := unpack(t, imageOf(t, tc.layers...), plenty)
			require.NoError(t, err)

			requireEntries(t, base, "root")
			requireContent(t, filepath.Join(root, libDir, "libc.so.6"), "the C library")
			if tc.link == "" {
				requireEntries(t, filepath.Join(root, "lib"), "libtop.so.1")
				return
			}
			requireLink(t, filepath.Join(root, "lib"), tc.link)
			requireEntries(t, root, "lib", "usr")
		})
	}

	// A whiteout below the link deletes nothing where it leads.
	for name, whiteout := range map[string]string{
		"a whiteout below it":         "lib/x86_64-linux-gnu/.wh." + baseLib,
		"an opaque whiteout below it": "lib/x86_64-linux-gnu/.wh..wh..opq",
	} {
		t.Run(name, func(t *testing.T) {
			lower := layerOf(t, file(libDir+"/"+baseLib, "a library of the layer below"))
			upper := layerOf(t, symlink("lib", usrLibDir), file(whiteout, ""))

			_, root, err := unpack(t, imageOf(t, lower, upper), plenty)
			require.NoError(t, err)

			requireLink(t, filepath.Join(root, "lib"), usrLibDir)
			requireContent(t, filepath.Join(root, libDir, baseLib), "a library of the layer below")
		})
	}
}

func TestExtractFollowsALinkOfTheEntrysOwnLayerThatALayerAboveHides(t *testing.T) {
	// The lower layer holds x/y/lnk, a link, and a file below it. Tar extraction puts the file where the link
	// leads. The layer above hides the link, its directory or an ancestor, and what is below them, but not
	// where the link leads: the file stays there in every runtime, so Extract keeps it.
	lower := func(t *testing.T, target string) v1.Layer {
		t.Helper()
		return layerOf(t, symlink("x/y/lnk", target), file("x/y/lnk/libvuln.so.1", "a library below the link"))
	}
	for name, upper := range map[string][]tarEntry{
		"a whiteout of the link":            {file("x/y/.wh.lnk", "")},
		"a whiteout of its directory":       {file("x/.wh.y", "")},
		"a whiteout of an ancestor":         {file(".wh.x", "")},
		"a file at its directory":           {file("x/y", "a file")},
		"a link at its directory":           {symlink("x/y", "elsewhere")},
		"an opaque whiteout of an ancestor": {directory("x", 0o755), file("x/.wh..wh..opq", "")},
		// The root holds where the link leads too, so the layer above hides the file, and holds its own.
		"an opaque whiteout of the root": {file(".wh..wh..opq", ""), file("usr/lib/libvuln.so.1", "replaced")},
	} {
		t.Run(name, func(t *testing.T) {
			want := "a library below the link"
			if name == "an opaque whiteout of the root" {
				want = "replaced"
			}
			for _, target := range []string{absUsrLibDir, "../../usr/lib"} {
				_, root, err := unpack(t, imageOf(t, lower(t, target), layerOf(t, upper...)), plenty)
				require.NoError(t, err)

				requireContent(t, filepath.Join(root, usrLibDir, "libvuln.so.1"), want)
				_, err = os.Readlink(filepath.Join(root, "x", "y", "lnk"))
				require.Error(t, err, "the layer above hides the link")
			}
		})
	}

	// Where the link leads into what the layer above hides, the file is hidden with it.
	t.Run("a link into the directory that the layer above deletes", func(t *testing.T) {
		_, root, err := unpack(t, imageOf(t, lower(t, "sub"), layerOf(t, file(".wh.x", ""))), plenty)
		require.NoError(t, err)

		requireAbsent(t, filepath.Join(root, "x"))
	})
}

func TestExtractRefusesALinkOfAnEntrysOwnLayerThatTheEntryCantGoThrough(t *testing.T) {
	for name, entries := range map[string][]tarEntry{
		"to a file": {file("etc/os-release", "ID=example"), symlink("lib", "etc/os-release"), file(libc, "x")},
		"through a file": {
			file("etc/os-release", "ID=example"), symlink("lib", "etc/os-release/lib"), file(libc, "x"),
		},
		"into a loop": {symlink("lib", "a"), symlink("a", "lib"), file(libc, "x")},
	} {
		t.Run(name, func(t *testing.T) {
			base, _, err := unpack(t, imageOf(t, layerOf(t, entries...)), plenty)

			require.ErrorIs(t, err, pull.ErrBadLink)
			requireEntries(t, base, "root")
		})
	}
}

func TestExtractRefusesAnEntryThatALinkOfALowerLayerLeadsOntoADirectoryOfALayerBelow(t *testing.T) {
	// The layer above holds lib/x86_64-linux-gnu as a link or a file, which the base's lib -> usr/lib leads
	// onto the base's directory usr/lib/x86_64-linux-gnu. An applier that unpacks a layer onto the layers below
	// replaces the directory, and the base's libbar.so.1 with it. containerd's overlayfs snapshotter keeps both:
	// the layer above holds lib as a directory of its own, which hides the base's link. One tree can't hold
	// both, so Extract fails rather than drop the file.
	bases := map[string]func(*testing.T) v1.Layer{
		"a link before the directory": func(t *testing.T) v1.Layer { return mergedUsrBase(t, usrLibDir) },
		"a link after the directory":  linkedLast,
		// The base holds the directory above its file, with no entry of its own.
		"a link before an implied directory": func(t *testing.T) v1.Layer {
			return layerOf(t, symlink("lib", usrLibDir), file(libDir+"/"+baseLib, "a library of the base"))
		},
		// The base holds the directory, and nothing in it.
		"a link before an empty directory": func(t *testing.T) v1.Layer {
			return layerOf(t, symlink("lib", usrLibDir),
				directory("usr", 0o755), directory(usrLibDir, 0o755), directory(libDir, 0o755))
		},
	}
	for name, upper := range map[string]tarEntry{
		"a link": symlink("lib/x86_64-linux-gnu", "/opt/libs"),
		"a file": file("lib/x86_64-linux-gnu", "a file"),
	} {
		for baseName, base := range bases {
			t.Run(name+", "+baseName, func(t *testing.T) {
				_, _, err := unpack(t, imageOf(t, base(t), layerOf(t, upper)), plenty)

				require.ErrorIs(t, err, pull.ErrBadLink)
				require.NotErrorIs(t, err, pull.ErrImageRead, "the image was read: it is no read error")
			})
		}
	}

	// A layer between that deletes the directory, or one above it, deletes it in every runtime.
	for name, between := range map[string]tarEntry{
		"where a layer between deletes the directory":     file(usrLibDir+"/.wh.x86_64-linux-gnu", ""),
		"where a layer between deletes a directory above": file("usr/.wh.lib", ""),
	} {
		t.Run(name, func(t *testing.T) {
			upper := layerOf(t, symlink("lib/x86_64-linux-gnu", "/opt/libs"))

			_, root, err := unpack(t, imageOf(t, mergedUsrBase(t, usrLibDir), layerOf(t, between), upper), plenty)
			require.NoError(t, err)

			requireLink(t, filepath.Join(root, libDir), "/opt/libs")
		})
	}

	t.Run("a directory, which merges with the base's", func(t *testing.T) {
		upper := layerOf(t, directory("lib/x86_64-linux-gnu", 0o755), file("lib/x86_64-linux-gnu/"+upperLib, "x"))

		_, root, err := unpack(t, imageOf(t, mergedUsrBase(t, usrLibDir), upper), plenty)
		require.NoError(t, err)

		requireEntries(t, filepath.Join(root, libDir), baseLib, upperLib)
	})

	// Where the link's own layer writes a file there itself, or a link of the entry's own layer leads it there,
	// every runtime replaces the directory below.
	t.Run("a file of the link's own layer over a directory below", func(t *testing.T) {
		below := layerOf(t, directory(usrLibDir+"/x", 0o755), file(usrLibDir+"/x/y", "hidden by the file above"))
		base := layerOf(t, symlink("lib", usrLibDir), file(usrLibDir+"/x", "written by the base itself"))
		upper := layerOf(t, file("lib/foo", "makes lib a directory above the base's link"))

		_, root, err := unpack(t, imageOf(t, below, base, upper), plenty)
		require.NoError(t, err)

		requireContent(t, filepath.Join(root, usrLibDir, "x"), "written by the base itself")
	})
	t.Run("a file through a link of its own layer", func(t *testing.T) {
		upper := layerOf(t, symlink("lib", usrLibDir), file("lib/x86_64-linux-gnu", "a file"))

		_, root, err := unpack(t, imageOf(t, mergedUsrBase(t, usrLibDir), upper), plenty)
		require.NoError(t, err)

		requireContent(t, filepath.Join(root, libDir), "a file")
	})
}

func TestExtractNeverWritesThroughALinkOfALowerLayer(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.Mkdir(outside, 0o755))
	lower := layerOf(t,
		symlink("lib", usrLibDir),
		// A link where the file of the upper layer lands, which the file hides.
		symlink(libDir+"/libfoo.so.1", filepath.Join(outside, upperLib)),
		// A link where a directory of the upper layer lands. Its target is outside the root on this host, and
		// inside it in the image: the entries below it land there.
		symlink(libDir+"/plugins", outside),
	)
	upper := layerOf(t,
		file("lib/x86_64-linux-gnu/libfoo.so.1", "a library of the upper layer"),
		file("lib/x86_64-linux-gnu/plugins/libplug.so", "a plug-in"),
	)
	root := filepath.Join(base, "root")
	require.NoError(t, os.Mkdir(root, 0o755))

	require.NoError(t, pull.Extract(imageOf(t, lower, upper), root, plenty))

	requireEntries(t, base, "root", "outside")
	requireEntries(t, outside)
	requireContent(t, filepath.Join(root, libDir, upperLib), "a library of the upper layer")
	requireLink(t, filepath.Join(root, libDir, "plugins"), outside)
	requireContent(t, filepath.Join(root, outside, "libplug.so"), "a plug-in")
}

func TestExtractCopiesHardLinks(t *testing.T) {
	img := imageOf(t, layerOf(t,
		directory("bin", 0o755),
		fileMode("bin/tool", "the tool", 0o755),
		hardLink("bin/alias", "bin/tool"),
		hardLink("bin/absolute", "/bin/tool"),
		hardLink("bin/dotted", "./bin/../bin/tool"),
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
}

func TestExtractRefusesHardLinks(t *testing.T) {
	// Build tools write a hard link to an earlier regular file of its own layer, and nothing else.
	// Anything else fails Extract, rather than give another filesystem than a container sees.
	cases := map[string][]v1.Layer{
		"out of the root":             {layerOf(t, file("x", "a file"), hardLink("y", "../x"))},
		"to a link":                   {layerOf(t, file("x", "a file"), symlink("l", "x"), hardLink("y", "l"))},
		"to a hard link":              {layerOf(t, file("x", "a file"), hardLink("y", "x"), hardLink("z", "y"))},
		"to a directory":              {layerOf(t, directory("d", 0o755), hardLink("y", "d"))},
		"to nothing":                  {layerOf(t, hardLink("y", "missing"))},
		"to a later entry":            {layerOf(t, hardLink("y", "x"), file("x", "after its hard link"))},
		"to a file of a lower layer":  {layerOf(t, file("x", "lower")), layerOf(t, hardLink("y", "x"))},
		"to a file of an upper layer": {layerOf(t, hardLink("y", "x")), layerOf(t, file("x", "upper"))},
	}
	for name, layers := range cases {
		t.Run(name, func(t *testing.T) {
			base, _, err := unpack(t, imageOf(t, layers...), plenty)
			require.ErrorIs(t, err, pull.ErrBadHardLink)
			require.NotErrorIs(t, err, pull.ErrImageRead)
			requireEntries(t, base, "root")
		})
	}
}

func TestExtractRefusesTwoEntriesForOnePathInALayer(t *testing.T) {
	// Of two entries for one path in one layer, Extract would keep the first, where containerd keeps the
	// last, so stale content could win. It fails instead: only two directories for one path are one. A
	// directory that Extract makes above an entry counts as an entry of the layer, since containerd replaces
	// it with a later entry of another kind.
	cases := map[string][]v1.Layer{
		"two files":                 {layerOf(t, file("x", "first"), file("x", "second"))},
		"a file and a link":         {layerOf(t, file("x", "a file"), symlink("x", "target"))},
		"a directory and a file":    {layerOf(t, directory("d", 0o755), file("d", "a file"))},
		"a file and a directory":    {layerOf(t, file("d", "a file"), directory("d", 0o755))},
		"two whiteouts":             {layerOf(t, file(".wh.x", ""), file(".wh.x", ""))},
		"one path in two spellings": {layerOf(t, file("a/b", "first"), file("./a//b", "second"))},
		"two files that a layer above hides": {
			layerOf(t, file("x", "first"), file("x", "second")),
			layerOf(t, file("x", "from the layer above")),
		},
		"a file where an entry made a directory": {layerOf(t, file("a/x", "below a"), file("a", "a file"))},
		"a link where an entry made a directory": {layerOf(t, file("a/b/x", "below a/b"), symlink("a/b", "target"))},
		"a hard link where an entry made a directory": {
			layerOf(t, file("x", "a file"), file("a/y", "below a"), hardLink("a", "x")),
		},
		"a device where an entry made a directory": {layerOf(t, file("a/x", "below a"), device("a"))},
		// A layer above made lib, and this layer holds an entry below lib, which needs a directory, and a link
		// at lib.
		"a link where the layer holds an entry below it": {
			layerOf(t, file("lib/x", "below lib"), symlink("lib", "usr/lib")),
			layerOf(t, file("lib/foo", "from the layer above")),
		},
		// Through a link of their layer, two entries can land on one path.
		"a file, and one that lands on it through a link of the layer": {
			layerOf(t, file(libDir+"/libc.so.6", "first"), symlink("lib", usrLibDir), file(libc, "second")),
		},
		"a file that lands on a path through a link of the layer, and one at the path": {
			layerOf(t, symlink("lib", usrLibDir), file(libc, "first"), file(libDir+"/libc.so.6", "second")),
		},
		// The layer holds something that isn't a directory where an entry of it needs one.
		"an entry below a file of the layer":   {layerOf(t, file("f", "a file"), file("f/w", "below the file"))},
		"an entry below a device of the layer": {layerOf(t, device("d"), file("d/w", "below the device"))},
	}
	for name, layers := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := unpack(t, imageOf(t, layers...), plenty)
			require.ErrorIs(t, err, pull.ErrDuplicateEntry)
			require.NotErrorIs(t, err, pull.ErrImageRead, "the image was read: it is no read error")
		})
	}

	t.Run("two directories", func(t *testing.T) {
		img := imageOf(t, layerOf(t, directory("d", 0o755), file("d/x", "a file"), directory("d/", 0o755)))

		_, root, err := unpack(t, img, plenty)

		require.NoError(t, err)
		requireContent(t, filepath.Join(root, "d", "x"), "a file")
	})

	t.Run("two directories, one through a link of the layer", func(t *testing.T) {
		img := imageOf(t, layerOf(t, directory(libDir, 0o755), symlink("lib", usrLibDir),
			directory("lib/x86_64-linux-gnu", 0o755), file(libc, "the C library")))

		_, root, err := unpack(t, img, plenty)

		require.NoError(t, err)
		requireContent(t, filepath.Join(root, libDir, "libc.so.6"), "the C library")
	})

	t.Run("a directory where an entry made one", func(t *testing.T) {
		img := imageOf(t, layerOf(t, file("d/x", "a file"), directory("d", 0o755)))

		_, root, err := unpack(t, img, plenty)

		require.NoError(t, err)
		requireContent(t, filepath.Join(root, "d", "x"), "a file")
	})

	t.Run("one path in two layers", func(t *testing.T) {
		img := imageOf(t, layerOf(t, file("x", "below")), layerOf(t, file("x", "above")))

		_, root, err := unpack(t, img, plenty)

		require.NoError(t, err)
		requireContent(t, filepath.Join(root, "x"), "above")
	})
}

func TestExtractGivesHardLinksTheContentOfTheirOwnLayer(t *testing.T) {
	// The lower layer of each case: x, and y, a hard link to it.
	linked := func() v1.Layer { return layerOf(t, file("x", "old"), hardLink("y", "x")) }

	t.Run("the target is replaced above", func(t *testing.T) {
		_, root, err := unpack(t, imageOf(t, linked(), layerOf(t, file("x", "new"))), plenty)
		require.NoError(t, err)
		requireContent(t, filepath.Join(root, "x"), "new")
		requireContent(t, filepath.Join(root, "y"), "old")
	})
	t.Run("the target is deleted above", func(t *testing.T) {
		_, root, err := unpack(t, imageOf(t, linked(), layerOf(t, file(".wh.x", ""))), plenty)
		require.NoError(t, err)
		requireAbsent(t, filepath.Join(root, "x"))
		requireContent(t, filepath.Join(root, "y"), "old")
	})
	t.Run("several links to one deleted target", func(t *testing.T) {
		lower := layerOf(t, file("x", "old"), hardLink("y", "x"), hardLink("bin/z", "x"))
		_, root, err := unpack(t, imageOf(t, lower, layerOf(t, file(".wh.x", ""))), plenty)
		require.NoError(t, err)
		requireContent(t, filepath.Join(root, "y"), "old")
		requireContent(t, filepath.Join(root, "bin", "z"), "old")
	})
	t.Run("the target is below a link of its own layer", func(t *testing.T) {
		base := t.TempDir()
		outside := filepath.Join(base, "outside")
		require.NoError(t, os.Mkdir(outside, 0o755))
		root := filepath.Join(base, "root")
		require.NoError(t, os.Mkdir(root, 0o755))
		layer := layerOf(t, symlink("a", outside), file("a/x", "below the link"), hardLink("y", "a/x"))

		require.NoError(t, pull.Extract(imageOf(t, layer), root, plenty))
		requireEntries(t, outside)
		requireContent(t, filepath.Join(root, "y"), "below the link")
	})
	t.Run("the link is replaced above", func(t *testing.T) {
		_, root, err := unpack(t, imageOf(t, linked(), layerOf(t, file("y", "new"))), plenty)
		require.NoError(t, err)
		requireContent(t, filepath.Join(root, "x"), "old")
		requireContent(t, filepath.Join(root, "y"), "new")
	})
	t.Run("the link is deleted above", func(t *testing.T) {
		_, root, err := unpack(t, imageOf(t, linked(), layerOf(t, file(".wh.y", ""))), plenty)
		require.NoError(t, err)
		requireContent(t, filepath.Join(root, "x"), "old")
		requireAbsent(t, filepath.Join(root, "y"))
	})
}

// countedLayer is a layer that counts how often it is read. From its second read on, it gives what
// again returns, when again isn't nil.
type countedLayer struct {
	v1.Layer
	reads *int
	again func() (io.ReadCloser, error)
}

func (l countedLayer) Uncompressed() (io.ReadCloser, error) {
	*l.reads++
	if *l.reads > 1 && l.again != nil {
		return l.again()
	}
	return l.Layer.Uncompressed()
}

func TestExtractReadsALayerAgainOnlyForAHiddenTarget(t *testing.T) {
	var lowerReads, middleReads, upperReads int
	lower := countedLayer{Layer: layerOf(t, file("x", "old"), hardLink("y", "x")), reads: &lowerReads}
	middle := countedLayer{Layer: layerOf(t, file("a", "a file"), hardLink("b", "a")), reads: &middleReads}
	upper := countedLayer{Layer: layerOf(t, file("x", "new")), reads: &upperReads}

	_, root, err := unpack(t, imageOf(t, lower, middle, upper), plenty)

	require.NoError(t, err)
	require.Equal(t, 2, lowerReads, "y's target is hidden, so the layer is read again for it")
	require.Equal(t, 1, middleReads, "b's target was written, so b is copied from it")
	require.Equal(t, 1, upperReads)
	requireContent(t, filepath.Join(root, "y"), "old")
	requireContent(t, filepath.Join(root, "b"), "a file")
}

func TestExtractFailsWhenTheSecondReadFails(t *testing.T) {
	cause := errors.New("the registry failed")
	for name, second := range map[string]struct {
		data []byte
		err  error
	}{
		"it can't be opened": {err: cause},
		// x has another size than in the first read.
		"it gives another layer": {data: tarOf(t, file("x", "another size"), hardLink("y", "x"))},
		// x isn't there at all.
		"it ends early": {data: tarOf(t)},
		// The read breaks off in the content of x: its header and one byte of it.
		"it breaks off in the file": {data: tarOf(t, file("x", "old"), hardLink("y", "x"))[:513]},
	} {
		t.Run(name, func(t *testing.T) {
			var reads int
			again := func() (io.ReadCloser, error) {
				if second.err != nil {
					return nil, second.err
				}
				return io.NopCloser(bytes.NewReader(second.data)), nil
			}
			lower := countedLayer{Layer: layerOf(t, file("x", "old"), hardLink("y", "x")), reads: &reads, again: again}

			_, _, err := unpack(t, imageOf(t, lower, layerOf(t, file(".wh.x", ""))), plenty)

			require.ErrorIs(t, err, pull.ErrImageRead)
			require.Equal(t, 2, reads)
		})
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

func TestExtractCountsTheCopiesOfASecondRead(t *testing.T) {
	const kib = 1 << 10
	lower := layerOf(t, file("big", strings.Repeat("x", 600*kib)), hardLink("y", "big"), hardLink("z", "big"))
	upper := layerOf(t, file(".wh.big", ""))

	_, root, err := unpack(t, imageOf(t, lower, upper), kib*kib)

	require.ErrorIs(t, err, pull.ErrTooLarge)
	requireAbsent(t, filepath.Join(root, "z"))
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

func TestExtractSkipsPAXGlobalHeaders(t *testing.T) {
	// A container runtime ignores a PAX global header. So does Extract: it neither hides the path that the
	// header names, nor makes the directories above it, which would hide what a lower layer holds there.
	t.Run("a header that names a path", func(t *testing.T) {
		img := imageOf(t, layerOf(t,
			globalHeader("etc", map[string]string{"comment": "a global header named etc"}),
			file("etc/passwd", "root:x:0:0:root:/root:/bin/sh"),
			file("etc/group", "root:x:0:"),
		))

		_, root, err := unpack(t, img, plenty)
		require.NoError(t, err)

		requireEntries(t, root, "etc")
		requireContent(t, filepath.Join(root, "etc", "passwd"), "root:x:0:0:root:/root:/bin/sh")
		requireContent(t, filepath.Join(root, "etc", "group"), "root:x:0:")
	})

	t.Run("a header whose path is below a link of a lower layer", func(t *testing.T) {
		lower := layerOf(t,
			directory("usr/lib", 0o755),
			file("usr/lib/libz.so.1", "the library"),
			symlink("lib", "usr/lib"),
		)
		upper := layerOf(t,
			globalHeader("pax_global_header", map[string]string{"path": "lib/pax"}),
			file("etc/os-release", "ID=example"),
		)

		_, root, err := unpack(t, imageOf(t, lower, upper), plenty)
		require.NoError(t, err)

		requireEntries(t, root, "etc", "lib", "usr")
		target, err := os.Readlink(filepath.Join(root, "lib"))
		require.NoError(t, err, "the link of the lower layer is kept")
		require.Equal(t, "usr/lib", target)
		requireContent(t, filepath.Join(root, "usr", "lib", "libz.so.1"), "the library")
	})
}
