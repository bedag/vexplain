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
	"debug/elf"
	"errors"
	"io"
)

// elfInfo is what the analysis reads from an ELF file.
type elfInfo struct {
	// soname is the file's DT_SONAME. It is empty for a file that isn't a shared library, such as an
	// executable or a plugin.
	soname string
	// needed holds the file's DT_NEEDED entries: the names of the libraries that it links.
	needed []string
}

// readELFFiles finds the ELF files among the regular files of the root.
func (t *tree) readELFFiles() ([]elfFile, error) {
	var elfs []elfFile
	for _, p := range t.files {
		f, err := t.open(p)
		if err != nil {
			return nil, err
		}
		info, isELF := readELF(f)
		_ = f.Close()
		if isELF {
			elfs = append(elfs, elfFile{path: p, elfInfo: info})
		}
	}
	return elfs, nil
}

// errELFPanic stands for a panic of debug/elf.
var errELFPanic = errors.New("debug/elf panicked")

// readELF reports whether f is an ELF file, and reads its soname and the libraries that it needs. An
// ELF file is a file that starts with the ELF magic.
//
// Some ELF files count without a soname and without dependencies, so that their package owns an ELF
// file that isn't a shared library, which keeps the load check from settling that package:
//   - a file that debug/elf rejects or panics on. The dynamic linker reads only the program headers,
//     so it may load a file whose section headers debug/elf refuses. The name search still finds the
//     file's DT_NEEDED strings in its bytes.
//   - a file whose dynamic section can't be read
//   - a file whose soname is empty, which no DT_NEEDED entry can name
func readELF(f io.ReaderAt) (elfInfo, bool) {
	var magic [len(elf.ELFMAG)]byte
	if _, err := f.ReadAt(magic[:], 0); err != nil || string(magic[:]) != elf.ELFMAG {
		return elfInfo{}, false
	}
	info, err := dynamicEntries(f)
	if err != nil {
		return elfInfo{}, true
	}
	return info, true
}

// dynamicEntries reads the soname and the needed libraries of an ELF file. debug/elf reads through
// ReaderAt only what it needs: the headers, and then the dynamic section and its strings. It returns
// errors for malformed files, but the content is hostile, so a panic becomes an error too, rather than
// ending the scan without a result line.
func dynamicEntries(f io.ReaderAt) (info elfInfo, err error) {
	defer func() {
		if recover() != nil {
			info, err = elfInfo{}, errELFPanic
		}
	}()
	ef, err := elf.NewFile(f)
	if err != nil {
		return elfInfo{}, err
	}
	sonames, err := ef.DynString(elf.DT_SONAME)
	if err != nil {
		return elfInfo{}, err
	}
	needed, err := ef.DynString(elf.DT_NEEDED)
	if err != nil {
		return elfInfo{}, err
	}
	if len(sonames) > 0 {
		info.soname = sonames[0]
	}
	info.needed = needed
	return info, nil
}
