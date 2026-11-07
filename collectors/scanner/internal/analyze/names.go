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
	"errors"
	"io"
	"path"
	"slices"
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
)

// readChunk is how much of a file the name search reads at once. It never reads a whole file.
const readChunk = 1 << 20

// packageDatabase is a directory in which a package manager keeps its database, with the files in
// it that list the installed packages.
type packageDatabase struct {
	// dir is the directory, with a trailing slash.
	dir string
	// files are the files of the database in dir.
	files []string
	// fileDirs are the directories in dir of which every file belongs to the database.
	fileDirs []string
}

// rpmDatabaseFiles are the files of an rpm database, in its three formats: Berkeley DB, NDB and
// SQLite.
var rpmDatabaseFiles = []string{"Packages", "Packages.db", "rpmdb.sqlite"}

// packageDatabases are the package databases that Syft reads. They name every library of every
// package they know (0026), so hits in the files of their directories don't count. And each of
// their files that isn't empty must be where Syft found a package (catalogComplete). Distroless
// images keep the dpkg database in status.d: a status file and an md5sums file for each package.
var packageDatabases = []packageDatabase{
	{dir: "/var/lib/dpkg/", files: []string{"status"}, fileDirs: []string{"status.d"}},
	{dir: "/lib/apk/db/", files: []string{"installed"}},
	{dir: "/var/lib/rpm/", files: rpmDatabaseFiles},
	{dir: "/usr/lib/sysimage/rpm/", files: rpmDatabaseFiles},
}

// linkerCaches are the linker cache of 0026: the dynamic linker's ld.so.cache, and the aux-cache in
// which ldconfig keeps the sonames it found. Both name every library they know, so hits in them don't
// count.
var linkerCaches = []string{"/etc/ld.so.cache", "/var/cache/ldconfig/aux-cache"}

// excludedFromNames reports whether the hits in the file at p don't count for any library. The paths
// are those that the walk found, so a package database or a cache that a link puts elsewhere counts.
func excludedFromNames(p string) bool {
	inDatabase := slices.ContainsFunc(packageDatabases, func(db packageDatabase) bool {
		return strings.HasPrefix(p, db.dir)
	})
	return inDatabase || slices.Contains(linkerCaches, p)
}

// sonamesOf returns the sonames of the shared libraries, each once.
func sonamesOf(elfs []elfFile) []string {
	var sonames []string
	seen := map[string]bool{}
	for _, e := range elfs {
		if e.soname != "" && !seen[e.soname] {
			seen[e.soname] = true
			sonames = append(sonames, e.soname)
		}
	}
	return sonames
}

// nameHits returns, for each soname, the paths of the files that name the library: a file names it
// when it holds one of its names (namesOf). It reads every regular file once, in chunks, but for the
// files whose hits never count.
func (t *tree) nameHits(sonames []string) (map[string][]string, error) {
	namedBy := make(map[string][]string, len(sonames))
	if len(sonames) == 0 {
		return namedBy, nil
	}
	search := newNameSearch(sonames, readChunk)
	// lastFile holds, for each soname, the number of the file that named it last, counted from one,
	// so that a file is listed once however often it names the library.
	lastFile := make([]int, len(sonames))
	for i, p := range t.files {
		if excludedFromNames(p) {
			continue
		}
		f, err := t.open(p)
		if err != nil {
			return nil, err
		}
		err = search.scan(f, func(s int) {
			if lastFile[s] != i+1 {
				lastFile[s] = i + 1
				namedBy[sonames[s]] = append(namedBy[sonames[s]], p)
			}
		})
		_ = f.Close()
		if err != nil {
			return nil, ErrRootUnreadable
		}
	}
	return namedBy, nil
}

// libraryName is a name under which a library can be loaded (0026, plan decision 8).
type libraryName struct {
	text string
	// bounded means that the name counts only with a byte that can't be part of an identifier, or
	// the start or end of the file, on each side. Only the bare name is bounded.
	bounded bool
}

// namesOf returns the names of the library with the given soname. For libbrotlidec.so.1 they are:
//   - the soname itself, libbrotlidec.so.1, which DT_NEEDED and dlopen use
//   - the unversioned name, libbrotlidec.so, which ends at the first ".so" that a dot or the end
//     of the soname follows
//   - the bare name, brotlidec, without "lib" and ".so", which Python's ctypes.util.find_library and
//     Java's System.loadLibrary take
//
// A soname can hold a path, such as /usr/lib/libfoo.so.1. A program loads such a library by its base
// name too, as dlopen("libfoo.so.1") and find_library("foo") do, so the three names of the base name,
// libfoo.so.1, follow those of the soname.
//
// The first two names of each match as plain substrings. A name equal to an earlier one isn't
// repeated: the earlier one already matches wherever it does.
func namesOf(soname string) []libraryName {
	names := threeNames(nil, soname)
	if strings.Contains(soname, "/") {
		names = threeNames(names, path.Base(soname))
	}
	return names
}

// threeNames appends to names the soname, the unversioned name and the bare name of soname, but for
// a name that is in names already, and returns the result.
func threeNames(names []libraryName, soname string) []libraryName {
	unversioned := soname
	for from := 0; ; {
		at := strings.Index(soname[from:], ".so")
		if at < 0 {
			break
		}
		end := from + at + len(".so")
		if end == len(soname) || soname[end] == '.' {
			unversioned = soname[:end]
			break
		}
		from = end
	}
	bare := strings.TrimSuffix(unversioned, ".so")
	if rest, ok := strings.CutPrefix(bare, "lib"); ok && rest != "" {
		bare = rest
	}

	for _, n := range []libraryName{{text: soname}, {text: unversioned}, {text: bare, bounded: true}} {
		known := slices.ContainsFunc(names, func(earlier libraryName) bool { return earlier.text == n.text })
		if n.text != "" && !known {
			names = append(names, n)
		}
	}
	return names
}

// nameSearch finds which libraries a file names, for all names of all libraries in one pass over the
// file. It matches with an Aho–Corasick automaton that reports overlapping matches, so a name inside
// a longer one, such as libssl.so inside libssl.so.3, is found too.
type nameSearch struct {
	matcher ahocorasick.AhoCorasick
	// refs holds, for each pattern of the matcher, the sonames whose name it is.
	refs [][]nameRef
	// carry is how many bytes a chunk passes on to the next one: the longest name and one byte more.
	// A name that crosses the border needs the longest name less one; the two bytes more give a bare
	// name its byte on each side. So every name is whole, with both its neighbours, in some chunk.
	carry int
	buf   []byte
}

type nameRef struct {
	soname  int
	bounded bool
}

// newNameSearch prepares a search for the names of the given sonames, which reads files in chunks of
// chunkSize bytes.
func newNameSearch(sonames []string, chunkSize int) *nameSearch {
	s := &nameSearch{}
	patterns := map[string]int{}
	var texts []string
	longest := 0
	for i, soname := range sonames {
		for _, n := range namesOf(soname) {
			p, ok := patterns[n.text]
			if !ok {
				p = len(texts)
				patterns[n.text] = p
				texts = append(texts, n.text)
				s.refs = append(s.refs, nil)
				longest = max(longest, len(n.text))
			}
			s.refs[p] = append(s.refs[p], nameRef{soname: i, bounded: n.bounded})
		}
	}
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{MatchKind: ahocorasick.StandardMatch, DFA: true})
	s.matcher = builder.Build(texts)
	s.carry = longest + 1
	s.buf = make([]byte, 0, chunkSize+s.carry)
	return s
}

// scan reads r to its end and calls hit with the index of every soname that one of the names in it
// belongs to, possibly more than once for one soname.
func (s *nameSearch) scan(r io.Reader, hit func(soname int)) error {
	buf := s.buf[:0]
	atStart := true
	for {
		n, err := io.ReadFull(r, buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		atEnd := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		if err != nil && !atEnd {
			return err
		}
		s.match(buf, atStart, atEnd, hit)
		if atEnd {
			return nil
		}
		buf = buf[:copy(buf, buf[len(buf)-s.carry:])]
		atStart = false
	}
}

// match reports the names in one chunk. atStart and atEnd say whether the chunk starts at the start
// of the file and ends at its end.
func (s *nameSearch) match(chunk []byte, atStart, atEnd bool, hit func(soname int)) {
	matches := s.matcher.IterOverlappingByte(chunk)
	for m := matches.Next(); m != nil; m = matches.Next() {
		for _, ref := range s.refs[m.Pattern()] {
			if !ref.bounded || bounded(chunk, m.Start(), m.End(), atStart, atEnd) {
				hit(ref.soname)
			}
		}
	}
}

// bounded reports whether the name at chunk[start:end] has a byte that can't be part of an
// identifier, or the start or end of the file, on each side. A side whose byte lies in the chunk
// before or after doesn't count here: the carried bytes put the name and that byte into that chunk.
func bounded(chunk []byte, start, end int, atStart, atEnd bool) bool {
	before := start == 0 && atStart || start > 0 && !isIdentifierByte(chunk[start-1])
	after := end == len(chunk) && atEnd || end < len(chunk) && !isIdentifierByte(chunk[end])
	return before && after
}

// isIdentifierByte reports whether b can be part of an identifier: an ASCII letter or digit, or an
// underscore.
func isIdentifierByte(b byte) bool {
	return b == '_' || '0' <= b && b <= '9' || 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z'
}
