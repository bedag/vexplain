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

// Package analyze reads the evidence of one platform manifest from its unpacked root filesystem and
// from Syft's JSON for it:
//   - which package owns each file, and which files of each OS package are present
//   - how the ELF files reach the shared libraries through DT_NEEDED
//   - which files name a shared library (0026)
//   - whether the image preloads libraries
//   - Syft's JSON without its file lists, which the hub matches
//
// The rules at the hub settle findings as "not affected" from this evidence. So every doubt here
// resolves towards more evidence of use: more reachers, more files that name a library, fewer owned
// files.
//
// The scanner calls it, and the operator never imports it. The root filesystem comes from an image,
// so it is hostile: the analysis never lets the operating system follow a link. It walks the tree
// without following links, reads content only from the regular files that the walk finds, and
// resolves links itself, inside the root.
package analyze

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/bedag/vexplain/internal/scan/result"
)

// The errors of Analyze are fixed texts, because the scan log carries them and no text from an image
// may reach it. They never hold a path, a file name or file content.
var (
	// ErrSBOM means that Syft's JSON can't be read: it isn't JSON, or not of the shape that Syft
	// writes.
	ErrSBOM = errors.New("the SBOM is not valid Syft JSON")
	// ErrUnsupportedSBOM means that Syft's JSON is of another major version of its schema than the
	// one the analysis reads.
	ErrUnsupportedSBOM = errors.New("the SBOM is of an unsupported Syft JSON schema")
	// ErrRootUnreadable means that the root filesystem, or a directory or file in it, can't be read.
	// The analysis stops rather than skip what it can't read, because a skipped file could hide a
	// reference to a library.
	ErrRootUnreadable = errors.New("the root filesystem can't be read")
)

const (
	// maxPaths is how many paths Library.ReachedBy and Library.NameHits keep.
	maxPaths = 20
	// maxUnownedPaths is how many paths ELFSummary.Unowned keeps.
	maxUnownedPaths = 100
	// maxLinkHops is how many links one path may pass through, as in Linux.
	maxLinkHops = 40
	// noPackage stands for the package of a library that no package owns.
	noPackage = -1
)

// Analyze reads the evidence of the root filesystem at rootfs, an image that the scanner unpacked.
// syftJSON is Syft's JSON for that filesystem, and imageEnv the Env of the image's configuration. It
// fills every field of the manifest but Platform and Digest, which the caller sets. The paths in the
// manifest are absolute and clean paths inside the image.
func Analyze(rootfs string, syftJSON []byte, imageEnv []string) (result.Manifest, error) {
	pkgs, err := parseSBOM(syftJSON)
	if err != nil {
		return result.Manifest{}, err
	}
	sbom, err := reduceSBOM(syftJSON)
	if err != nil {
		return result.Manifest{}, err
	}
	t, err := walk(rootfs)
	if err != nil {
		return result.Manifest{}, err
	}

	elfs, err := t.readELFFiles()
	if err != nil {
		return result.Manifest{}, err
	}
	owners := t.owners(pkgs)
	for i := range elfs {
		elfs[i].owners = owners[elfs[i].path]
	}
	namedBy, err := t.nameHits(sonamesOf(elfs))
	if err != nil {
		return result.Manifest{}, err
	}
	preload, err := t.preload(imageEnv)
	if err != nil {
		return result.Manifest{}, err
	}

	return result.Manifest{
		SBOM:      sbom,
		Packages:  t.packageFacts(pkgs, elfs),
		ELF:       elfSummary(elfs),
		Libraries: libraries(pkgs, elfs, buildLinkGraph(t, elfs), namedBy, owners),
		Preload:   preload,
	}, nil
}

// elfFile is an ELF file of the root, with what the analysis read from it.
type elfFile struct {
	path string
	elfInfo
	// owners are the packages that own the file, as indices into the SBOM's packages.
	owners []int
}

// entryKind is what an entry of the root filesystem is.
type entryKind uint8

const (
	kindDir entryKind = iota + 1
	kindFile
	kindSymlink
	// kindOther is a device, a FIFO or a socket.
	kindOther
)

// tree is the root filesystem as the walk found it, held in memory, so that the analysis resolves
// links itself. All its paths are clean, absolute paths inside the image.
type tree struct {
	root  string
	kinds map[string]entryKind
	// links holds the target of each link, as the link holds it.
	links map[string]string
	// files holds the regular files, in the order of the walk.
	files []string
	// byBase holds the regular files and the links by their base names.
	byBase map[string][]string
}

// walk reads the tree of the root filesystem at rootfs, without following links.
func walk(rootfs string) (*tree, error) {
	t := &tree{root: rootfs, kinds: map[string]entryKind{}, links: map[string]string{}, byBase: map[string][]string{}}
	err := filepath.WalkDir(rootfs, func(host string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(rootfs, host)
		if err != nil {
			return err
		}
		p := cleanPath(filepath.ToSlash(rel))
		switch mode := d.Type(); {
		case p == "/" && !mode.IsDir():
			return ErrRootUnreadable
		case mode.IsDir():
			t.kinds[p] = kindDir
		case mode.IsRegular():
			t.kinds[p] = kindFile
			t.files = append(t.files, p)
			t.byBase[path.Base(p)] = append(t.byBase[path.Base(p)], p)
		case mode&fs.ModeSymlink != 0:
			target, err := os.Readlink(host)
			if err != nil {
				return err
			}
			t.kinds[p] = kindSymlink
			t.links[p] = target
			t.byBase[path.Base(p)] = append(t.byBase[path.Base(p)], p)
		default:
			t.kinds[p] = kindOther
		}
		return nil
	})
	if err != nil {
		return nil, ErrRootUnreadable
	}
	return t, nil
}

// resolveStatus says what a path resolved to.
type resolveStatus uint8

const (
	// resolved means the path names an entry of the root.
	resolved resolveStatus = iota
	// missing means that the path names nothing: an entry on the way is absent, or isn't a directory
	// where the path needs one.
	missing
	// broken means that a link on the way leaves the root, or that the path passes through more than
	// maxLinkHops links, which a loop does.
	broken
)

// resolve returns the entry that p names inside the root, with the links on the way followed. When
// followLast is false, a link in the last component is the entry itself, as for lstat. Absolute link
// targets start again at the root, as they do in the image's container, never at the host's own
// root. A ".." above the root leaves it.
func (t *tree) resolve(p string, followLast bool) (string, resolveStatus) {
	current := "/"
	pending := strings.Split(p, "/")
	hops := 0
	for len(pending) > 0 {
		component := pending[0]
		pending = pending[1:]
		switch component {
		case "", ".":
			continue
		case "..":
			if current == "/" {
				return "", broken
			}
			current = path.Dir(current)
			continue
		}
		next := path.Join(current, component)
		kind, ok := t.kinds[next]
		switch {
		case !ok:
			return "", missing
		case kind == kindSymlink && (len(pending) > 0 || followLast):
			if hops++; hops > maxLinkHops {
				return "", broken
			}
			target := t.links[next]
			if strings.HasPrefix(target, "/") {
				current = "/"
			}
			pending = append(strings.Split(target, "/"), pending...)
		case len(pending) > 0 && kind != kindDir:
			return "", missing
		default:
			current = next
		}
	}
	return current, resolved
}

// host returns the host path of the image path p.
func (t *tree) host(p string) string {
	return filepath.Join(t.root, filepath.FromSlash(p))
}

// open opens the regular file at p, which the walk found. The directories above it are directories,
// and a link in the last component, or anything but a regular file, is refused, should the tree have
// changed since.
func (t *tree) open(p string) (*os.File, error) {
	f, err := os.OpenFile(t.host(p), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrRootUnreadable
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, ErrRootUnreadable
	}
	return f, nil
}

// owners maps the entries of the root to the packages that own them, as indices into pkgs. A package
// owns the files of its file list when it is an OS package, and its locations whatever it is. A path
// names the entry that lstat would find: the links in its directories are followed inside the root,
// and a link in its last component is owned itself. A path that names nothing owns nothing.
func (t *tree) owners(pkgs []sbomPackage) map[string][]int {
	owners := map[string][]int{}
	for i, pkg := range pkgs {
		for _, p := range slices.Concat(pkg.files, pkg.locations) {
			entry, status := t.resolve(p, false)
			if status != resolved {
				continue
			}
			if known := owners[entry]; len(known) > 0 && known[len(known)-1] == i {
				continue
			}
			owners[entry] = append(owners[entry], i)
		}
	}
	return owners
}

// filesPresent counts the files of an OS package's file list, and those of them present in the root.
//   - A link counts as present, even when its target is missing.
//   - A directory counts as neither. apk lists the directories that hold a package's files, and they
//     stay when a later layer deletes the files.
//   - A path that passes through a link that leaves the root, or loops, counts as present. Only an
//     absent file may move a finding towards "removed in a later layer".
func (t *tree) filesPresent(files []string) (listed, present int) {
	seen := make(map[string]bool, len(files))
	for _, p := range files {
		if seen[p] {
			continue
		}
		seen[p] = true
		entry, status := t.resolve(p, false)
		switch {
		case status == resolved && t.kinds[entry] == kindDir:
			// A directory, which counts as neither.
		case status == missing:
			listed++
		default:
			listed++
			present++
		}
	}
	return listed, present
}

// packageFacts returns the facts of every package of the SBOM, sorted by ID.
func (t *tree) packageFacts(pkgs []sbomPackage, elfs []elfFile) []result.PackageFacts {
	facts := make([]result.PackageFacts, len(pkgs))
	for i, pkg := range pkgs {
		facts[i].ID = pkg.id
		if pkg.os {
			facts[i].FilesListed, facts[i].FilesPresent = t.filesPresent(pkg.files)
		}
	}
	for _, e := range elfs {
		for _, o := range e.owners {
			if e.soname != "" {
				facts[o].SharedLibraries++
			} else {
				facts[o].OtherELFFiles++
			}
		}
	}
	slices.SortFunc(facts, func(a, b result.PackageFacts) int { return strings.Compare(a.ID, b.ID) })
	return facts
}

// elfSummary counts the ELF files, and those that a package owns.
func elfSummary(elfs []elfFile) result.ELFSummary {
	summary := result.ELFSummary{Total: len(elfs)}
	var unowned []string
	for _, e := range elfs {
		if len(e.owners) > 0 {
			summary.Owned++
		} else {
			unowned = append(unowned, e.path)
		}
	}
	slices.Sort(unowned)
	summary.Unowned = unowned[:min(len(unowned), maxUnownedPaths)]
	return summary
}

// libraries returns the shared libraries, sorted by path, with what reaches them and what names them.
// A library has an entry for each package that owns it, so that each package finds every library it
// owns, and one entry without a package ID when no package owns it. An entry counts the reachers and
// the files that name the library outside its package, and never the library's own file.
func libraries(pkgs []sbomPackage, elfs []elfFile, g linkGraph, namedBy map[string][]string, owners map[string][]int) []result.Library {
	walker := newReachWalker(g)
	var libs []result.Library
	for i, e := range elfs {
		if e.soname == "" {
			continue
		}
		var reachers []string
		for _, j := range walker.reachers(i) {
			reachers = append(reachers, elfs[j].path)
		}
		libOwners := e.owners
		if len(libOwners) == 0 {
			libOwners = []int{noPackage}
		}
		for _, o := range libOwners {
			outside := func(p string) bool {
				return p != e.path && (o == noPackage || !slices.Contains(owners[p], o))
			}
			lib := result.Library{Path: e.path, Soname: e.soname}
			if o != noPackage {
				lib.PackageID = pkgs[o].id
			}
			lib.ReachedBy, lib.ReachedCount = firstSorted(reachers, outside)
			lib.NameHits, lib.NameHitCount = firstSorted(namedBy[e.soname], outside)
			libs = append(libs, lib)
		}
	}
	slices.SortFunc(libs, func(a, b result.Library) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), strings.Compare(a.PackageID, b.PackageID))
	})
	return libs
}

// firstSorted returns the paths that keep accepts, sorted and cut to maxPaths, and how many there are.
func firstSorted(paths []string, keep func(string) bool) ([]string, int) {
	var kept []string
	for _, p := range paths {
		if keep(p) {
			kept = append(kept, p)
		}
	}
	slices.Sort(kept)
	return kept[:min(len(kept), maxPaths)], len(kept)
}

// preload reads whether the image preloads libraries: whether its configuration sets LD_PRELOAD or
// LD_AUDIT, whatever the value, and whether /etc/ld.so.preload names any. It keeps no value.
func (t *tree) preload(imageEnv []string) (result.Preload, error) {
	var p result.Preload
	for _, entry := range imageEnv {
		switch variable, _, _ := strings.Cut(entry, "="); variable {
		case "LD_PRELOAD":
			p.LDPreload = true
		case "LD_AUDIT":
			p.LDAudit = true
		}
	}
	var err error
	p.EtcLdSoPreload, err = t.etcLdSoPreload()
	return p, err
}

// etcLdSoPreload reports whether /etc/ld.so.preload exists, with links followed inside the root, and
// isn't an empty file. It never reads the content. A link that leaves the root or loops counts as
// set, and so does an entry that isn't a regular file.
func (t *tree) etcLdSoPreload() (bool, error) {
	target, status := t.resolve("/etc/ld.so.preload", true)
	switch {
	case status == missing:
		return false, nil
	case status == broken || t.kinds[target] != kindFile:
		return true, nil
	}
	info, err := os.Lstat(t.host(target))
	if err != nil {
		return false, ErrRootUnreadable
	}
	return info.Size() > 0, nil
}
