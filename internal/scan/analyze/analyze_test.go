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

package analyze

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/scan/result"
)

// The paths of the apk root, which testdata/gen.sh builds for Syft and apkRoot builds for the tests.
const (
	libCommon = "/usr/lib/libbrotlicommon.so.1.0.9"
	libDec    = "/usr/lib/libbrotlidec.so.1.0.9"
	userBin   = "/usr/bin/user"
	otherBin  = "/usr/bin/other"
	busyBox   = "/bin/busybox"
	loadPy    = "/app/load.py"
)

// testRoot is a root filesystem that a test builds in a temporary directory.
type testRoot struct {
	t   *testing.T
	dir string
}

func newRoot(t *testing.T) *testRoot {
	return &testRoot{t: t, dir: t.TempDir()}
}

// host returns the host path of the image path p.
func (r *testRoot) host(p string) string {
	return filepath.Join(r.dir, filepath.FromSlash(p))
}

// write creates the file at the image path p.
func (r *testRoot) write(p, content string) *testRoot {
	r.t.Helper()
	require.NoError(r.t, os.MkdirAll(filepath.Dir(r.host(p)), 0o755))
	require.NoError(r.t, os.WriteFile(r.host(p), []byte(content), 0o644))
	return r
}

// copyFixture copies testdata/name to the image path p.
func (r *testRoot) copyFixture(p, name string) *testRoot {
	r.t.Helper()
	return r.write(p, string(fixture(r.t, name)))
}

// link creates a symlink at the image path p that points to target, as given.
func (r *testRoot) link(p, target string) *testRoot {
	r.t.Helper()
	require.NoError(r.t, os.MkdirAll(filepath.Dir(r.host(p)), 0o755))
	require.NoError(r.t, os.Symlink(target, r.host(p)))
	return r
}

// remove deletes the entry at the image path p.
func (r *testRoot) remove(p string) *testRoot {
	r.t.Helper()
	require.NoError(r.t, os.Remove(r.host(p)))
	return r
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

// apkRoot builds the apk root of testdata/gen.sh:
//   - brotli-libs owns the two libraries and their links
//   - app-tools lists /usr/bin/other and two files that are gone
//   - nothing owns /usr/bin/user, which needs libbrotlidec.so.1
//   - Syft's binary classifier reports /bin/busybox as a package of its own
//   - /app/load.py loads libbrotlidec by its bare name
//   - the apk database and the linker cache name both libraries
func apkRoot(t *testing.T) *testRoot {
	return newRoot(t).
		write("/etc/os-release", "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.22.2\nPRETTY_NAME=\"Alpine Linux v3.22\"\n").
		write("/etc/ld.so.cache", "libbrotlicommon.so.1\x00/usr/lib/libbrotlicommon.so.1\x00libbrotlidec.so.1\x00/usr/lib/libbrotlidec.so.1\x00").
		copyFixture("/lib/apk/db/installed", "apk-installed").
		copyFixture(libCommon, "elf/libbrotlicommon.so.1.0.9").
		link("/usr/lib/libbrotlicommon.so.1", "libbrotlicommon.so.1.0.9").
		copyFixture(libDec, "elf/libbrotlidec.so.1.0.9").
		link("/usr/lib/libbrotlidec.so.1", "libbrotlidec.so.1.0.9").
		copyFixture(userBin, "elf/user").
		copyFixture(otherBin, "elf/other").
		copyFixture(busyBox, "elf/busybox").
		write(loadPy, "import ctypes.util\nctypes.util.find_library(\"brotlidec\")\n")
}

// dpkgRoot builds the dpkg root of testdata/gen.sh without its package database, which the analysis
// reads only through Syft's JSON. /lib links to usr/lib, and libbrotli1 lists libbrotlidec under /lib.
func dpkgRoot(t *testing.T) *testRoot {
	const dir = "/usr/lib/x86_64-linux-gnu"
	return newRoot(t).
		link("/lib", "usr/lib").
		copyFixture(dir+"/libbrotlicommon.so.1.0.9", "elf/libbrotlicommon.so.1.0.9").
		link(dir+"/libbrotlicommon.so.1", "libbrotlicommon.so.1.0.9").
		copyFixture(dir+"/libbrotlidec.so.1.0.9", "elf/libbrotlidec.so.1.0.9").
		link(dir+"/libbrotlidec.so.1", "libbrotlidec.so.1.0.9")
}

// rpmRoot builds the rpm root of testdata/gen.sh without its package database: the files that
// libbrotli lists.
func rpmRoot(t *testing.T) *testRoot {
	return newRoot(t).
		copyFixture("/usr/lib64/libbrotlicommon.so.1.0.9", "elf/libbrotlicommon.so.1.0.9").
		link("/usr/lib64/libbrotlicommon.so.1", "libbrotlicommon.so.1.0.9").
		copyFixture("/usr/lib64/libbrotlidec.so.1.0.9", "elf/libbrotlidec.so.1.0.9").
		link("/usr/lib64/libbrotlidec.so.1", "libbrotlidec.so.1.0.9")
}

func analyzeRoot(t *testing.T, r *testRoot, sbom string, env ...string) result.Manifest {
	t.Helper()
	m, err := Analyze(r.dir, fixture(t, sbom), env)
	require.NoError(t, err)
	return m
}

// packageID returns the ID of the package called name in an SBOM fixture.
func packageID(t *testing.T, sbom, name string) string {
	t.Helper()
	var doc struct {
		Artifacts []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"artifacts"`
	}
	require.NoError(t, json.Unmarshal(fixture(t, sbom), &doc))
	for _, a := range doc.Artifacts {
		if a.Name == name {
			return a.ID
		}
	}
	require.Failf(t, "no such package", "%s has no package %s", sbom, name)
	return ""
}

// libraryAt returns the one library entry for the file at p.
func libraryAt(t *testing.T, m result.Manifest, p string) result.Library {
	t.Helper()
	var found []result.Library
	for _, l := range m.Libraries {
		if l.Path == p {
			found = append(found, l)
		}
	}
	require.Len(t, found, 1, "the library entries for %s", p)
	return found[0]
}

func factsOf(t *testing.T, m result.Manifest, id string) result.PackageFacts {
	t.Helper()
	for _, f := range m.Packages {
		if f.ID == id {
			return f
		}
	}
	require.Failf(t, "no facts", "no facts for package %s", id)
	return result.PackageFacts{}
}

func TestOwnershipFromPackageFileLists(t *testing.T) {
	t.Run("apk", func(t *testing.T) {
		m := analyzeRoot(t, apkRoot(t), "syft-apk.json")
		brotli := packageID(t, "syft-apk.json", "brotli-libs")

		require.Equal(t, brotli, libraryAt(t, m, libCommon).PackageID)
		require.Equal(t, brotli, libraryAt(t, m, libDec).PackageID)
		require.Equal(t, 2, factsOf(t, m, brotli).SharedLibraries)
		require.Zero(t, factsOf(t, m, brotli).OtherELFFiles)
		require.Equal(t, 1, factsOf(t, m, packageID(t, "syft-apk.json", "app-tools")).OtherELFFiles)
		// The ELF files are the two libraries, user, other and busybox. No package owns user.
		require.Equal(t, result.ELFSummary{Total: 5, Owned: 4, Unowned: []string{userBin}}, m.ELF)
	})

	t.Run("dpkg, through a linked directory", func(t *testing.T) {
		m := analyzeRoot(t, dpkgRoot(t), "syft-dpkg.json")
		id := packageID(t, "syft-dpkg.json", "libbrotli1")

		// libbrotli1 lists libbrotlidec as /lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9, and /lib links
		// to usr/lib.
		require.Equal(t, id, libraryAt(t, m, "/usr/lib/x86_64-linux-gnu/libbrotlicommon.so.1.0.9").PackageID)
		require.Equal(t, id, libraryAt(t, m, "/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9").PackageID)
		require.Equal(t, 2, factsOf(t, m, id).SharedLibraries)
		require.Equal(t, result.ELFSummary{Total: 2, Owned: 2}, m.ELF)
	})

	t.Run("rpm", func(t *testing.T) {
		m := analyzeRoot(t, rpmRoot(t), "syft-rpm.json")
		id := packageID(t, "syft-rpm.json", "libbrotli")

		require.Equal(t, id, libraryAt(t, m, "/usr/lib64/libbrotlicommon.so.1.0.9").PackageID)
		require.Equal(t, id, libraryAt(t, m, "/usr/lib64/libbrotlidec.so.1.0.9").PackageID)
		require.Equal(t, 2, factsOf(t, m, id).SharedLibraries)
		require.Equal(t, result.ELFSummary{Total: 2, Owned: 2}, m.ELF)
	})

	t.Run("a listed link owns itself, not its target", func(t *testing.T) {
		const copied = "/opt/copy/libdec.so"
		r := apkRoot(t).remove("/usr/lib/libbrotlidec.so.1").
			link("/usr/lib/libbrotlidec.so.1", "../../opt/copy/libdec.so").
			copyFixture(copied, "elf/libbrotlidec.so.1.0.9")
		m := analyzeRoot(t, r, "syft-apk.json")

		require.Empty(t, libraryAt(t, m, copied).PackageID)
		require.Equal(t, []string{copied, userBin}, m.ELF.Unowned)
	})
}

func TestALibraryOwnedByTwoPackagesHasAnEntryForEach(t *testing.T) {
	// Syft's JSON for the apk root, and a second apk package that lists libbrotlicommon only.
	var doc map[string]any
	require.NoError(t, json.Unmarshal(fixture(t, "syft-apk.json"), &doc))
	var second map[string]any
	for _, a := range doc["artifacts"].([]any) {
		if a.(map[string]any)["name"] == "brotli-libs" {
			raw, err := json.Marshal(a)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw, &second))
		}
	}
	second["id"], second["name"] = "second-owner", "brotli-common"
	second["metadata"].(map[string]any)["files"] = []any{map[string]any{"path": libCommon}}
	doc["artifacts"] = append(doc["artifacts"].([]any), second)
	sbom, err := json.Marshal(doc)
	require.NoError(t, err)

	m, err := Analyze(apkRoot(t).dir, sbom, nil)
	require.NoError(t, err)

	// Each package finds the library. libbrotlidec is outside the second package, so it reaches the
	// library and names it there.
	brotli := packageID(t, "syft-apk.json", "brotli-libs")
	var entries []result.Library
	for _, l := range m.Libraries {
		if l.Path == libCommon {
			entries = append(entries, l)
		}
	}
	require.Equal(t, []result.Library{
		{Path: libCommon, Soname: "libbrotlicommon.so.1", PackageID: brotli, ReachedBy: []string{userBin}, ReachedCount: 1},
		{Path: libCommon, Soname: "libbrotlicommon.so.1", PackageID: "second-owner",
			ReachedBy: []string{userBin, libDec}, ReachedCount: 2, NameHits: []string{libDec}, NameHitCount: 1},
	}, entries)
	require.Equal(t, 1, factsOf(t, m, "second-owner").SharedLibraries)
	require.Equal(t, 2, factsOf(t, m, brotli).SharedLibraries)
	require.Equal(t, 4, m.ELF.Owned)
}

func TestOwnershipFromPackageLocations(t *testing.T) {
	m := analyzeRoot(t, apkRoot(t), "syft-apk.json")

	// Syft's binary classifier reports busybox with the location /bin/busybox, and no file list.
	require.Equal(t, 1, factsOf(t, m, packageID(t, "syft-apk.json", "busybox")).OtherELFFiles)
	require.NotContains(t, m.ELF.Unowned, busyBox)
}

func TestReachThroughDTNeeded(t *testing.T) {
	m := analyzeRoot(t, apkRoot(t), "syft-apk.json")

	dec := libraryAt(t, m, libDec)
	require.Equal(t, []string{userBin}, dec.ReachedBy)
	require.Equal(t, 1, dec.ReachedCount)

	// user reaches libbrotlicommon through libbrotlidec. libbrotlidec needs libbrotlicommon itself,
	// but doesn't count, because it is in the same package.
	common := libraryAt(t, m, libCommon)
	require.Equal(t, []string{userBin}, common.ReachedBy)
	require.Equal(t, 1, common.ReachedCount)
}

func TestNeededNamesAlsoMatchFileNamesThroughLinks(t *testing.T) {
	// Two more copies of libbrotlicommon, whose soname is libbrotlicommon.so.1: one in a file named
	// like the library that user needs, one behind a link of that name.
	r := apkRoot(t).
		copyFixture("/opt/a/libbrotlidec.so.1", "elf/libbrotlicommon.so.1.0.9").
		copyFixture("/opt/c/libcopy.so", "elf/libbrotlicommon.so.1.0.9").
		link("/opt/b/libbrotlidec.so.1", "../c/libcopy.so")
	m := analyzeRoot(t, r, "syft-apk.json")

	// user needs libbrotlidec.so.1, which names both by their file names. libbrotlidec needs
	// libbrotlicommon.so.1, which is their soname. Nothing owns them, so every reacher counts, and
	// every file that names libbrotlicommon.so.1 but the library's own.
	copies := map[string]string{ // each copy, and the other one
		"/opt/a/libbrotlidec.so.1": "/opt/c/libcopy.so",
		"/opt/c/libcopy.so":        "/opt/a/libbrotlidec.so.1",
	}
	for p, other := range copies {
		lib := libraryAt(t, m, p)
		require.Empty(t, lib.PackageID)
		require.Equal(t, []string{userBin, libDec}, lib.ReachedBy, p)
		require.Equal(t, 2, lib.ReachedCount, p)
		require.Equal(t, []string{other, libCommon, libDec}, lib.NameHits, p)
	}

	t.Run("a needed name that only a link has", func(t *testing.T) {
		// A copy of user that needs libalias.so.1, which no library has as its soname. Only the link
		// of that name leads to libbrotlidec, and through it to libbrotlicommon.
		original := fixture(t, "elf/user")
		patched := bytes.Replace(original, []byte("libbrotlidec.so.1\x00"), []byte("libalias.so.1\x00\x00\x00\x00\x00"), 1)
		require.NotEqual(t, original, patched)
		r := apkRoot(t).write("/opt/app/alias-user", string(patched)).link("/usr/lib/libalias.so.1", "libbrotlidec.so.1.0.9")
		m := analyzeRoot(t, r, "syft-apk.json")

		require.Equal(t, []string{"/opt/app/alias-user", userBin}, libraryAt(t, m, libDec).ReachedBy)
		require.Equal(t, []string{"/opt/app/alias-user", userBin}, libraryAt(t, m, libCommon).ReachedBy)
	})
}

func TestELFFilesWithoutAUsableDynamicSection(t *testing.T) {
	t.Run("headers that don't parse", func(t *testing.T) {
		m := analyzeRoot(t, apkRoot(t).write("/opt/fake.so", "\x7fELF\x09"+strings.Repeat("\x00", 60)), "syft-apk.json")
		require.Equal(t, 5, m.ELF.Total)
	})

	// libbrotlidec, patched: it still counts as an ELF file, but not as a shared library. Its package
	// then owns an ELF file that isn't a shared library, which keeps the load check from settling the
	// package.
	patches := map[string]func(t *testing.T, f *elf.File, data []byte){
		"a dynamic section whose strings can't be read": func(t *testing.T, f *elf.File, data []byte) {
			// sh_link of the dynamic section's header names a section that doesn't exist.
			dynamic := slices.IndexFunc(f.Sections, func(s *elf.Section) bool { return s.Type == elf.SHT_DYNAMIC })
			require.Positive(t, dynamic)
			headers := binary.LittleEndian.Uint64(data[0x28:])
			size := uint64(binary.LittleEndian.Uint16(data[0x3a:]))
			binary.LittleEndian.PutUint32(data[headers+uint64(dynamic)*size+40:], 0xffff)
		},
		"an empty soname": func(_ *testing.T, f *elf.File, data []byte) {
			// DT_SONAME points to the start of the string table, which is an empty string.
			dynamic := f.SectionByType(elf.SHT_DYNAMIC)
			for at := dynamic.Offset; at < dynamic.Offset+dynamic.Size; at += 16 {
				if elf.DynTag(binary.LittleEndian.Uint64(data[at:])) == elf.DT_SONAME {
					binary.LittleEndian.PutUint64(data[at+8:], 0)
				}
			}
		},
	}
	brotli := packageID(t, "syft-apk.json", "brotli-libs")
	for name, patch := range patches {
		t.Run(name, func(t *testing.T) {
			data := fixture(t, "elf/libbrotlidec.so.1.0.9")
			f, err := elf.NewFile(bytes.NewReader(data))
			require.NoError(t, err)
			require.Equal(t, elf.ELFCLASS64, f.Class)
			require.Equal(t, binary.LittleEndian, f.ByteOrder)
			patch(t, f, data)
			m := analyzeRoot(t, apkRoot(t).write(libDec, string(data)), "syft-apk.json")

			require.Equal(t, 5, m.ELF.Total)
			require.Equal(t, 1, factsOf(t, m, brotli).SharedLibraries)
			require.Equal(t, 1, factsOf(t, m, brotli).OtherELFFiles)
			for _, l := range m.Libraries {
				require.NotEqual(t, libDec, l.Path)
			}
		})
	}
}

func TestNeededPathsMatchByBaseName(t *testing.T) {
	// A DT_NEEDED entry can be a path. It matches the files of its base name, here through a linked
	// directory.
	r := newRoot(t).write("/usr/bin/app", "").write("/opt/real/libfoo.so.1", "").link("/opt/lib", "real")
	tr, err := walk(r.dir)
	require.NoError(t, err)
	elfs := []elfFile{
		{path: "/usr/bin/app", elfInfo: elfInfo{needed: []string{"/opt/lib/libfoo.so.1"}}},
		{path: "/opt/real/libfoo.so.1", elfInfo: elfInfo{soname: "libfoo.so.2"}},
	}
	require.Equal(t, linkGraph{nil, {0}}, buildLinkGraph(tr, elfs))
}

func TestNamesOfASoname(t *testing.T) {
	require.Equal(t, []libraryName{
		{text: "libbrotlidec.so.1"},
		{text: "libbrotlidec.so"},
		{text: "brotlidec", bounded: true},
	}, namesOf("libbrotlidec.so.1"))

	for _, tc := range []struct {
		soname string
		want   []libraryName
	}{
		{"libfoo.so", []libraryName{{text: "libfoo.so"}, {text: "foo", bounded: true}}},
		{"libc.so.6", []libraryName{{text: "libc.so.6"}, {text: "libc.so"}, {text: "c", bounded: true}}},
		{"libpython3.12.so.1.0", []libraryName{
			{text: "libpython3.12.so.1.0"}, {text: "libpython3.12.so"}, {text: "python3.12", bounded: true}}},
		// The unversioned name ends at the ".so" that a dot or the end follows.
		{"libfoo.socket.so.2", []libraryName{
			{text: "libfoo.socket.so.2"}, {text: "libfoo.socket.so"}, {text: "foo.socket", bounded: true}}},
		{"ld-linux-x86-64.so.2", []libraryName{
			{text: "ld-linux-x86-64.so.2"}, {text: "ld-linux-x86-64.so"}, {text: "ld-linux-x86-64", bounded: true}}},
		// Without "lib" and ".so", the soname is its only name, and it matches as a plain substring.
		{"plugin", []libraryName{{text: "plugin"}}},
	} {
		require.Equal(t, tc.want, namesOf(tc.soname), tc.soname)
	}
}

func TestNameHitsSkipOwnFilesPackageDatabasesAndLinkerCache(t *testing.T) {
	// user names libbrotlidec too, in its dynamic section; the root leaves it out, so that only the
	// exclusions are left to show. The first subtest shows it.
	r := apkRoot(t).remove(userBin).
		write("/var/lib/dpkg/info/libbrotli1:amd64.list", "/usr/lib/libbrotlidec.so.1\n").
		write("/var/lib/rpm/Packages", "libbrotlidec.so.1 libbrotlicommon.so.1").
		write("/usr/lib/sysimage/rpm/rpmdb.sqlite", "libbrotlidec.so.1 libbrotlicommon.so.1")
	m := analyzeRoot(t, r, "syft-apk.json")

	// libbrotlidec names libbrotlicommon, the libraries name themselves, and the apk database and the
	// linker cache name both. None of them counts.
	dec := libraryAt(t, m, libDec)
	require.Equal(t, []string{loadPy}, dec.NameHits)
	require.Equal(t, 1, dec.NameHitCount)
	common := libraryAt(t, m, libCommon)
	require.Empty(t, common.NameHits)
	require.Zero(t, common.NameHitCount)

	t.Run("a binary that needs the library names it", func(t *testing.T) {
		m := analyzeRoot(t, apkRoot(t), "syft-apk.json")
		require.Equal(t, []string{loadPy, userBin}, libraryAt(t, m, libDec).NameHits)
	})

	t.Run("a directory that only starts like a package database", func(t *testing.T) {
		r := apkRoot(t).write("/var/lib/dpkg-old/status", "libbrotlicommon.so.1")
		m := analyzeRoot(t, r, "syft-apk.json")
		require.Equal(t, []string{"/var/lib/dpkg-old/status"}, libraryAt(t, m, libCommon).NameHits)
	})
}

func TestBareNameNeedsBoundaries(t *testing.T) {
	r := apkRoot(t).
		write("/data/inside-a-word", "xbrotlidecx").
		write("/data/after-an-underscore", "_brotlidec").
		write("/data/before-a-digit", "brotlidec2").
		write("/data/quoted", `find_library("brotlidec")`).
		write("/data/whole-file", "brotlidec").
		write("/data/unversioned-in-a-word", "xlibbrotlidec.sox").
		write("/data/versioned-in-a-word", "xlibbrotlidec.so.1x")
	m := analyzeRoot(t, r, "syft-apk.json")

	var hits []string
	for _, p := range libraryAt(t, m, libDec).NameHits {
		if strings.HasPrefix(p, "/data/") {
			hits = append(hits, p)
		}
	}
	require.Equal(t, []string{
		"/data/quoted", "/data/unversioned-in-a-word", "/data/versioned-in-a-word", "/data/whole-file",
	}, hits)
}

func TestFilesPresentPerPackage(t *testing.T) {
	m := analyzeRoot(t, apkRoot(t), "syft-apk.json")

	// app-tools lists /usr/bin/other, /usr/bin/gone-a and /usr/bin/gone-b, and the directories /usr
	// and /usr/bin, which aren't files.
	tools := factsOf(t, m, packageID(t, "syft-apk.json", "app-tools"))
	require.Equal(t, 3, tools.FilesListed)
	require.Equal(t, 1, tools.FilesPresent)
	// brotli-libs lists the libraries and their links.
	brotli := factsOf(t, m, packageID(t, "syft-apk.json", "brotli-libs"))
	require.Equal(t, 4, brotli.FilesListed)
	require.Equal(t, 4, brotli.FilesPresent)
	// busybox comes from the binary classifier, not from a package database: it lists nothing.
	busybox := factsOf(t, m, packageID(t, "syft-apk.json", "busybox"))
	require.Zero(t, busybox.FilesListed)
	require.Zero(t, busybox.FilesPresent)

	t.Run("a link counts as present, even when its target is missing", func(t *testing.T) {
		r := apkRoot(t).remove("/usr/lib/libbrotlidec.so.1").link("/usr/lib/libbrotlidec.so.1", "missing.so")
		m := analyzeRoot(t, r, "syft-apk.json")
		require.Equal(t, 4, factsOf(t, m, packageID(t, "syft-apk.json", "brotli-libs")).FilesPresent)
	})

	t.Run("through a linked directory", func(t *testing.T) {
		m := analyzeRoot(t, dpkgRoot(t), "syft-dpkg.json")
		facts := factsOf(t, m, packageID(t, "syft-dpkg.json", "libbrotli1"))
		require.Equal(t, 2, facts.FilesListed)
		require.Equal(t, 2, facts.FilesPresent)
	})

	t.Run("a file gone from a linked directory", func(t *testing.T) {
		m := analyzeRoot(t, dpkgRoot(t).remove("/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9"), "syft-dpkg.json")
		facts := factsOf(t, m, packageID(t, "syft-dpkg.json", "libbrotli1"))
		require.Equal(t, 2, facts.FilesListed)
		require.Equal(t, 1, facts.FilesPresent)
	})

	// Only an absent file may move a finding towards "removed in a later layer". A path that can't be
	// resolved counts as present.
	for name, target := range map[string]string{"leaves the root": "../../../../../../outside", "loops": "bin"} {
		t.Run("a path through a link that "+name, func(t *testing.T) {
			r := apkRoot(t)
			require.NoError(t, os.RemoveAll(r.host("/usr/bin")))
			m := analyzeRoot(t, r.link("/usr/bin", target), "syft-apk.json")

			// /usr/bin is now a link, which counts, and other, gone-a and gone-b can't be resolved.
			tools := factsOf(t, m, packageID(t, "syft-apk.json", "app-tools"))
			require.Equal(t, 4, tools.FilesListed)
			require.Equal(t, 4, tools.FilesPresent)
		})
	}
}

func TestLargeFilesAreSearchedInChunks(t *testing.T) {
	// The first read takes readChunk bytes and 21 more: the longest name, libbrotlicommon.so.1, and one
	// byte. The bare name crosses that border, and a soname ends the file.
	filler := strings.Repeat(" ", readChunk+5)
	r := apkRoot(t).
		write("/data/large", filler+`find_library("brotlidec")`+filler+filler+"libbrotlicommon.so.1").
		write("/data/large-miss", filler+`find_library("brotlidecx")`+filler)
	m := analyzeRoot(t, r, "syft-apk.json")

	require.Contains(t, libraryAt(t, m, libDec).NameHits, "/data/large")
	require.NotContains(t, libraryAt(t, m, libDec).NameHits, "/data/large-miss")
	require.Equal(t, []string{"/data/large"}, libraryAt(t, m, libCommon).NameHits)
}

func TestPreloadFromImageEnvAndEtc(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		r := apkRoot(t).write("/etc/ld.so.preload", "/opt/preload-marker.so\n")
		m := analyzeRoot(t, r, "syft-apk.json", "PATH=/usr/bin", "LD_PRELOAD=/x", "LD_AUDIT=/opt/audit-marker.so")
		require.Equal(t, result.Preload{LDPreload: true, LDAudit: true, EtcLdSoPreload: true}, m.Preload)

		// Only that they are set travels, never what they are set to.
		line, err := result.Encode(result.Result{Image: "registry.example/team-a/app@sha256:1111", Manifests: []result.Manifest{m}})
		require.NoError(t, err)
		decoded := decodeLine(t, line)
		for _, value := range []string{"/x", "/opt/audit-marker.so", "/opt/preload-marker.so"} {
			require.NotContains(t, decoded, value)
		}
	})

	t.Run("unset", func(t *testing.T) {
		r := apkRoot(t).write("/etc/ld.so.preload", "")
		m := analyzeRoot(t, r, "syft-apk.json", "LD_PRELOAD_PATH=/x", "ld_preload=/x", "X=LD_AUDIT=/x")
		require.Equal(t, result.Preload{}, m.Preload)
	})

	t.Run("a name without a value", func(t *testing.T) {
		m := analyzeRoot(t, apkRoot(t), "syft-apk.json", "LD_AUDIT", "LD_PRELOAD=")
		require.Equal(t, result.Preload{LDPreload: true, LDAudit: true}, m.Preload)
	})

	t.Run("/etc/ld.so.preload through a link", func(t *testing.T) {
		r := apkRoot(t).write("/opt/preload.conf", "/opt/x.so\n").link("/etc/ld.so.preload", "/opt/preload.conf")
		require.True(t, analyzeRoot(t, r, "syft-apk.json").Preload.EtcLdSoPreload)
	})

	t.Run("/etc/ld.so.preload through a link that leaves the root", func(t *testing.T) {
		r := apkRoot(t).link("/etc/ld.so.preload", "../../../../../../preload.conf")
		require.True(t, analyzeRoot(t, r, "syft-apk.json").Preload.EtcLdSoPreload)
	})
}

// decodeLine returns the JSON in a result line.
func decodeLine(t *testing.T, line string) string {
	t.Helper()
	compressed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, result.ResultPrefix))
	require.NoError(t, err)
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	require.NoError(t, err)
	raw, err := io.ReadAll(zr)
	require.NoError(t, err)
	return string(raw)
}

func TestReducedSBOMKeepsMatchingFieldsAndDropsFileLists(t *testing.T) {
	for _, tc := range []struct {
		sbom string
		// The fields of the package's metadata that Grype matches on, with their values.
		pkg    string
		fields map[string]any
	}{
		{"syft-apk.json", "brotli-libs", map[string]any{"originPackage": "brotli"}},
		{"syft-dpkg.json", "libbrotli1", map[string]any{"source": "brotli", "sourceVersion": "1.0.9-2"}},
		{"syft-rpm.json", "libbrotli", map[string]any{"sourceRpm": "brotli-1.0.9-1.src.rpm"}},
	} {
		t.Run(tc.sbom, func(t *testing.T) {
			m, err := Analyze(t.TempDir(), fixture(t, tc.sbom), nil)
			require.NoError(t, err)

			// Syft's JSON, with the three parts removed by hand.
			var want map[string]any
			require.NoError(t, json.Unmarshal(fixture(t, tc.sbom), &want))
			require.Contains(t, want, "artifactRelationships")
			require.Contains(t, want, "files")
			delete(want, "artifactRelationships")
			delete(want, "files")
			lists := 0
			for _, a := range want["artifacts"].([]any) {
				if md, ok := a.(map[string]any)["metadata"].(map[string]any); ok {
					if _, ok := md["files"]; ok {
						lists++
						delete(md, "files")
					}
				}
			}
			require.Positive(t, lists)

			var got map[string]any
			require.NoError(t, json.Unmarshal(m.SBOM, &got))
			require.Equal(t, want, got)

			for _, a := range got["artifacts"].([]any) {
				if a.(map[string]any)["name"] == tc.pkg {
					md := a.(map[string]any)["metadata"].(map[string]any)
					for field, value := range tc.fields {
						require.Equal(t, value, md[field], field)
					}
				}
			}
		})
	}
}

func TestListsAreCappedAndCounted(t *testing.T) {
	r := apkRoot(t).remove(userBin).remove(loadPy)
	reachers := make([]string, 0, 25)
	unowned := make([]string, 0, 105)
	for i := range 25 {
		p := fmt.Sprintf("/opt/reach/user%02d", i)
		r.copyFixture(p, "elf/user")
		reachers = append(reachers, p)
	}
	unowned = append(unowned, reachers...)
	for i := range 80 {
		p := fmt.Sprintf("/opt/static/other%02d", i)
		r.copyFixture(p, "elf/other")
		unowned = append(unowned, p)
	}
	slices.Sort(reachers)
	slices.Sort(unowned)
	m := analyzeRoot(t, r, "syft-apk.json")

	// The 25 copies of user reach libbrotlidec, and name it in their dynamic sections.
	dec := libraryAt(t, m, libDec)
	require.Equal(t, reachers[:20], dec.ReachedBy)
	require.Equal(t, 25, dec.ReachedCount)
	require.Equal(t, reachers[:20], dec.NameHits)
	require.Equal(t, 25, dec.NameHitCount)
	// 105 ELF files are unowned.
	require.Equal(t, 109, m.ELF.Total)
	require.Equal(t, 4, m.ELF.Owned)
	require.Equal(t, unowned[:100], m.ELF.Unowned)
}

func TestSymlinksAreNeverReadForContent(t *testing.T) {
	// Outside the root: a file that names both libraries, an ELF file that needs libbrotlidec, and a
	// library named like the one user needs.
	outside := t.TempDir()
	names := filepath.Join(outside, "names.txt")
	require.NoError(t, os.WriteFile(names, []byte(`find_library("brotlidec") libbrotlicommon.so.1`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "user"), fixture(t, "elf/user"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "libbrotlidec.so.1"), fixture(t, "elf/libbrotlicommon.so.1.0.9"), 0o755))
	// Opening the file would fail, unless the tests run as root.
	require.NoError(t, os.Chmod(names, 0))

	// Links to them: a host path, which the root resolves inside itself, a path that climbs out of the
	// root, a link to the directory, and a link named like the library that user needs.
	r := apkRoot(t)
	escape, err := filepath.Rel(r.host("/app"), names)
	require.NoError(t, err)
	r.link("/app/absolute", names)
	r.link("/app/relative", escape)
	r.link("/opt/outside", outside)
	r.link("/opt/lib/libbrotlidec.so.1", filepath.Join(outside, "libbrotlidec.so.1"))
	m := analyzeRoot(t, r, "syft-apk.json")

	// The links change nothing: the root analyses like the plain apk root, which has these hits and
	// reachers.
	plain := analyzeRoot(t, apkRoot(t), "syft-apk.json")
	require.Equal(t, []string{loadPy, userBin}, libraryAt(t, plain, libDec).NameHits)
	require.Equal(t, []string{userBin}, libraryAt(t, plain, libCommon).ReachedBy)
	require.Equal(t, withoutSBOM(plain), withoutSBOM(m))
}

func TestFIFOsAreNeverOpened(t *testing.T) {
	// Opening a FIFO for reading waits for a writer, which never comes: the scan would hang. One is
	// named like a library that user needs, too.
	r := apkRoot(t)
	require.NoError(t, os.MkdirAll(r.host("/opt/lib"), 0o755))
	for _, p := range []string{"/app/fifo", "/opt/lib/libbrotlidec.so.1"} {
		require.NoError(t, syscall.Mkfifo(r.host(p), 0o644))
	}
	m := analyzeRoot(t, r, "syft-apk.json")

	require.Equal(t, withoutSBOM(analyzeRoot(t, apkRoot(t), "syft-apk.json")), withoutSBOM(m))
}

func withoutSBOM(m result.Manifest) result.Manifest {
	m.SBOM = nil
	return m
}

func TestNameSearchFindsNamesAcrossChunkBorders(t *testing.T) {
	// Sonames whose names overlap each other. The contents are made of pieces of those names and of
	// bytes on both sides of the identifier boundary, so that names, whole or cut, often meet chunk
	// borders.
	// The longest name is that of a soname with no other name, so that no shorter name inside it can
	// stand in for it when it is missed.
	sonames := []string{"liba.so.1", "libab.so.1", "libba.so.2", "libabab.so", "plugin-abcdefgh"}
	tokens := []string{"lib", "a", "b", "ab", ".so", ".1", ".2", ".", "x", "_", "1", `"`, " "}
	chunks := map[int]*nameSearch{}
	for _, size := range []int{1, 2, 3, 5, 8, 64} {
		chunks[size] = newNameSearch(sonames, size)
	}
	check := func(content []byte) map[int]bool {
		want := naiveHits(sonames, content)
		for size, search := range chunks {
			got := map[int]bool{}
			require.NoError(t, search.scan(bytes.NewReader(content), func(soname int) { got[soname] = true }))
			require.Equal(t, want, got, "content %q, chunks of %d", content, size)
		}
		return want
	}

	// Every name at every offset, between bytes that are or aren't part of an identifier.
	for _, soname := range sonames {
		for _, n := range namesOf(soname) {
			for offset := range 70 {
				for _, side := range []string{`"`, "x"} {
					check([]byte(strings.Repeat(side, offset) + n.text + strings.Repeat(side, 3)))
				}
			}
		}
	}

	// Contents made of pieces of the names.
	rng := rand.New(rand.NewPCG(1, 2))
	contentsWithHits := 0
	for range 3000 {
		content := make([]byte, 0, 160)
		for range rng.IntN(40) {
			content = append(content, tokens[rng.IntN(len(tokens))]...)
		}
		if len(check(content)) > 0 {
			contentsWithHits++
		}
	}
	// Many contents name a library, and many don't: both sides are tried.
	require.Greater(t, contentsWithHits, 500)
	require.Less(t, contentsWithHits, 2500)

	// A read that fails ends the search with its error.
	require.ErrorIs(t, chunks[8].scan(iotest.ErrReader(io.ErrClosedPipe), func(int) {}), io.ErrClosedPipe)
}

// naiveHits finds which sonames content names by checking every position of every name.
func naiveHits(sonames []string, content []byte) map[int]bool {
	hits := map[int]bool{}
	for i, soname := range sonames {
		for _, n := range namesOf(soname) {
			for at := 0; at+len(n.text) <= len(content); at++ {
				if string(content[at:at+len(n.text)]) != n.text {
					continue
				}
				end := at + len(n.text)
				if n.bounded && (at > 0 && identifierByte(content[at-1]) || end < len(content) && identifierByte(content[end])) {
					continue
				}
				hits[i] = true
			}
		}
	}
	return hits
}

func identifierByte(b byte) bool {
	return b == '_' || '0' <= b && b <= '9' || 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z'
}

func TestResolveStaysInsideTheRoot(t *testing.T) {
	const (
		libz     = "/usr/lib/libz.so.1.3"
		escape   = "/escape"
		dangling = "/dangling"
	)
	r := newRoot(t).
		write(libz, "z").
		link("/usr/lib/libz.so.1", "libz.so.1.3").
		link("/lib", "usr/lib").
		link("/absolute", "/usr/lib/libz.so.1").
		link(escape, "../../etc/passwd").
		link("/loop-a", "loop-b").
		link("/loop-b", "loop-a").
		link(dangling, "nowhere")
	// A chain of 40 links resolves, and one of 41 doesn't.
	r.link("/chain/0", libz)
	for i := 1; i <= 41; i++ {
		r.link(fmt.Sprintf("/chain/%d", i), fmt.Sprintf("%d", i-1))
	}
	tr, err := walk(r.dir)
	require.NoError(t, err)

	for _, tc := range []struct {
		path       string
		followLast bool
		want       string
		status     resolveStatus
	}{
		{"/lib/libz.so.1", true, libz, resolved},
		{"/lib/libz.so.1", false, "/usr/lib/libz.so.1", resolved},
		{"/absolute", true, libz, resolved},
		{escape, true, "", broken},
		{escape, false, escape, resolved},
		{"/loop-a", true, "", broken},
		{dangling, true, "", missing},
		{dangling, false, dangling, resolved},
		{libz + "/x", true, "", missing},
		{"/chain/39", true, libz, resolved},
		{"/chain/40", true, "", broken},
	} {
		got, status := tr.resolve(tc.path, tc.followLast)
		require.Equal(t, tc.status, status, tc.path)
		require.Equal(t, tc.want, got, tc.path)
	}
}

func TestErrorsCarryNoImageText(t *testing.T) {
	const marker = "secret-marker"
	sbom := fixture(t, "syft-apk.json")

	for _, tc := range []struct {
		name string
		sbom string
		want error
	}{
		{"not JSON", `{"artifacts": [{"id": "` + marker, ErrSBOM},
		{"not an object", `["` + marker + `"]`, ErrSBOM},
		{"without a schema", `{"artifacts": [{"id": "` + marker + `"}]}`, ErrSBOM},
		{"the wrong shape", `{"schema": {"version": "16.1.11"}, "artifacts": "` + marker + `"}`, ErrSBOM},
		{"a package without an ID", `{"schema": {"version": "16.1.11"}, "artifacts": [{"name": "` + marker + `"}]}`, ErrSBOM},
		{"two packages with one ID", `{"schema": {"version": "16.1.11"}, "artifacts": [{"id": "` + marker + `"}, {"id": "` + marker + `"}]}`, ErrSBOM},
		{"a file list of the wrong shape", `{"schema": {"version": "16.1.11"}, "artifacts": [{"id": "a", "metadataType": "apk-db-entry", "metadata": {"files": "` + marker + `"}}]}`, ErrSBOM},
		{"another schema", `{"schema": {"version": "17.0.0", "url": "` + marker + `"}, "artifacts": []}`, ErrUnsupportedSBOM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Analyze(t.TempDir(), []byte(tc.sbom), nil)
			require.ErrorIs(t, err, tc.want)
			require.NotContains(t, err.Error(), marker)
		})
	}

	t.Run("a root that doesn't exist", func(t *testing.T) {
		_, err := Analyze(filepath.Join(t.TempDir(), marker), sbom, nil)
		require.ErrorIs(t, err, ErrRootUnreadable)
		require.NotContains(t, err.Error(), marker)
	})

	t.Run("a root that isn't a directory", func(t *testing.T) {
		r := newRoot(t).write("/"+marker, marker)
		_, err := Analyze(r.host("/"+marker), sbom, nil)
		require.ErrorIs(t, err, ErrRootUnreadable)
		require.NotContains(t, err.Error(), marker)
	})

	t.Run("a file that can't be read", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads every file")
		}
		r := apkRoot(t).write("/app/"+marker, marker)
		require.NoError(t, os.Chmod(r.host("/app/"+marker), 0))
		_, err := Analyze(r.dir, sbom, nil)
		require.ErrorIs(t, err, ErrRootUnreadable)
		require.NotContains(t, err.Error(), marker)
	})
}
