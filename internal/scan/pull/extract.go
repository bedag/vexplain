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

package pull

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

var (
	// ErrTooLarge means that the image unpacks to more than the limit.
	ErrTooLarge = errors.New("the image unpacks to more than the limit")
	// ErrImageRead marks the errors of reading the image: fetching a layer, decompressing it, or
	// reading its tar. Such an error wraps its cause too, so that errors.As finds a registry's answer
	// in it. Every other error of Extract comes from writing to the directory, or is ErrTooLarge or
	// ErrBadHardLink.
	ErrImageRead = errors.New("the image can't be read")
	// ErrBadHardLink means that a hard link of the image names no earlier regular file of its own
	// layer, which is the only hard link that build tools write. Extract fails on it, rather than
	// unpack another filesystem than a container sees.
	ErrBadHardLink = errors.New("a hard link of the image names no earlier regular file of its layer")
	// ErrDuplicateEntry means that a layer of the image holds two entries for one path, other than two
	// directories. Which of them a container sees depends on the runtime, so Extract fails on it, rather
	// than guess.
	ErrDuplicateEntry = errors.New("a layer of the image holds two entries for one path")
	// errLayerChanged means that a second read of a layer didn't give the entries of the first.
	errLayerChanged = errors.New("the layer changed between two reads")
)

const (
	// whiteoutPrefix starts the name of a whiteout, which deletes the entry of the rest of its name
	// from the layers below.
	whiteoutPrefix = ".wh."
	// opaqueWhiteout is the name of a whiteout that hides everything that the layers below hold in
	// its directory.
	opaqueWhiteout = ".wh..wh..opq"
	// blockSize is the unit of the limit: a filesystem stores a file in whole blocks of it.
	blockSize = 4096
	// dirMode and fileMode are the modes of what Extract creates. A file keeps the execute bits of its
	// entry.
	dirMode  = 0o755
	fileMode = 0o644
)

// Extract unpacks img's flattened filesystem, what a container of the image sees, into dir, which
// must be an empty directory.
//
// It reads the layers from the top down, so the entry of a path in the highest layer is the one that
// counts, and it hides those below it:
//   - A whiteout deletes its entry from the layers below, and an opaque whiteout everything that
//     they hold in its directory. Neither touches its own layer.
//   - An entry that isn't a directory hides what the layers below hold at its path and under it.
//   - A layer that holds two entries for one path, other than two directories, fails Extract with
//     ErrDuplicateEntry. A container runtime would show one of them, and containerd the last, so
//     Extract fails rather than guess.
//
// The image is untrusted, so:
//   - Every path stays inside dir. Names are taken inside the image's root, as a container runtime
//     takes them, so ../escape and /abs/path land at /escape and /abs/path.
//   - It never follows a link: a link is created as it is. An entry below a link, or below anything
//     else that isn't a directory, is skipped, which is also the overlay's rule, and nothing is
//     created where an entry is already.
//   - A hard link becomes a copy of the earlier regular file of its own layer that it names, the
//     only hard link that build tools write. The copy has that file's content in its own layer, as
//     in a container: when an entry above hid the file, such as one that replaced or deleted it in
//     a layer above, the copy comes from a second read of the layer. Only a layer with such a copy
//     is read twice. A hard link to anything else, such as a file of another layer, a link, an
//     entry that comes after it, or a path out of the root, fails Extract with ErrBadHardLink.
//   - Devices, FIFOs and entries of other types are skipped, and hide their paths. A PAX global header,
//     which holds records and no file, is ignored, as a container runtime ignores it: it hides nothing.
//   - Directories get mode 0755, and files 0644 with the execute bits of their entry, so that the
//     user who runs Extract, who isn't root, can read, walk and remove all of it.
//
// maxBytes limits the space that the filesystem takes. A file counts its size in whole blocks of
// 4 KiB, as a filesystem stores it, a copy of a hard link counts as a file, and a directory or a link
// counts one block. Extract stops with ErrTooLarge before it writes past the limit, and leaves what it
// unpacked so far.
func Extract(img v1.Image, dir string, maxBytes int64) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	layers, err := img.Layers()
	if err != nil {
		return imageReadError(err)
	}
	u := &unpacker{root: root, left: maxBytes, paths: map[string]pathKind{}, opaque: map[string]bool{}}
	for _, layer := range slices.Backward(layers) {
		if err := u.layer(layer); err != nil {
			return err
		}
	}
	return nil
}

// unpacker writes the flattened filesystem of the layers, from the top layer down. Its paths are
// clean and relative to the root, and "" is the root itself.
type unpacker struct {
	root *os.Root
	// left is how many bytes the limit still allows.
	left int64
	// paths holds every path that an entry of a layer above, or an earlier entry of the same layer,
	// decided.
	paths map[string]pathKind
	// opaque holds the directories whose entries in the layers below are hidden.
	opaque map[string]bool
}

// pathKind is what a path holds.
type pathKind uint8

const (
	// kindDir is a directory that Extract created.
	kindDir pathKind = iota + 1
	// kindHiding is anything else: a file or a link that Extract created or is to create, an entry
	// that it skipped, or what a whiteout deleted. It hides its path and everything under it.
	kindHiding
)

// layerFile is a regular file of the layer that is being unpacked.
type layerFile struct {
	// index is the position of the file's entry in the layer.
	index int
	path  string
	size  int64
	mode  fs.FileMode
	// written is true when Extract wrote the entry, and false when an entry before it hid it.
	written bool
}

// pendingCopy is a file of the layer that an entry before it hid, and the hard links to it, which are
// written from a second read of the layer.
type pendingCopy struct {
	file  layerFile
	links []string
}

// layerPass is what unpacking one layer collects as it reads the layer.
type layerPass struct {
	// files holds the regular files of the layer so far, the last entry of each path, for the hard
	// links to them.
	files map[string]layerFile
	// pending holds the copies that wait for the second read, by the position of their file's entry.
	pending map[int]*pendingCopy
	// deleted and opaqueDirs hold the layer's whiteouts, which delete only what the layers below hold,
	// and so take effect at the end of the layer.
	deleted, opaqueDirs []string
	// entries holds the path of every entry of the layer so far, and whether the entry is a directory,
	// to find two entries for one path.
	entries map[string]bool
}

// layer unpacks one layer, and reads it a second time when it has pending copies.
func (u *unpacker) layer(l v1.Layer) error {
	pass := &layerPass{files: map[string]layerFile{}, pending: map[int]*pendingCopy{}, entries: map[string]bool{}}
	err := readLayer(l, func(index int, header *tar.Header, content io.Reader) error {
		return u.entry(pass, index, header, content)
	})
	if err != nil {
		return err
	}
	if len(pass.pending) > 0 {
		if err := u.writePending(l, pass.pending); err != nil {
			return err
		}
	}

	for _, p := range pass.deleted {
		switch u.paths[p] {
		case kindDir:
			// A directory of this layer, or of one above, stays, but what the layers below hold in it is
			// gone.
			u.opaque[p] = true
		case 0:
			u.paths[p] = kindHiding
		}
	}
	for _, dir := range pass.opaqueDirs {
		u.opaque[dir] = true
	}
	return nil
}

// readLayer calls entry for each entry of the layer, with the entry's position, and then reads the
// layer to its end, so that the registry client's check of its digest runs.
func readLayer(l v1.Layer, entry func(index int, header *tar.Header, content io.Reader) error) error {
	rc, err := l.Uncompressed()
	if err != nil {
		return imageReadError(err)
	}
	// The reads report every error, so Close has nothing to add.
	defer func() { _ = rc.Close() }()

	tr := tar.NewReader(rc)
	for index := 0; ; index++ {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		// With GODEBUG=tarinsecurepath=0, tar reports names such as ../escape as insecure. Extract takes
		// them inside the root, as it takes every name.
		if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
			return imageReadError(err)
		}
		if err := entry(index, header, tr); err != nil {
			return err
		}
	}
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return imageReadError(err)
	}
	return nil
}

// entry unpacks the entry at index of the layer, which header describes and content holds.
func (u *unpacker) entry(pass *layerPass, index int, header *tar.Header, content io.Reader) error {
	// A PAX global header holds records for the entries after it, and no file. The tar reader returns it
	// with the name of its path record, if it has one. A container runtime ignores it, so it takes no
	// path, and makes no directory above one, which would hide what a lower layer holds there.
	if header.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}
	p := imagePath(header.Name)
	if p == "" {
		return nil
	}
	// Two directories for one path are one. Of any other two entries for one path, which no build tool
	// writes, either could be the one that a container sees, and the one that a hard link of this layer
	// names. So Extract fails on them, even where a layer above hides the path.
	dir := header.Typeflag == tar.TypeDir
	if wasDir, seen := pass.entries[p]; seen && (!wasDir || !dir) {
		return ErrDuplicateEntry
	}
	pass.entries[p] = dir
	base := path.Base(p)
	whiteout := strings.HasPrefix(base, whiteoutPrefix)
	hidden := u.hidden(p)
	if !whiteout && regular(header) {
		pass.files[p] = layerFile{index: index, path: p, size: header.Size, mode: modeOf(header), written: !hidden}
	}
	if hidden {
		return nil
	}
	// The layer holds the directories above every entry, whiteouts included.
	if err := u.makeParents(p); err != nil {
		return err
	}
	switch {
	case base == opaqueWhiteout:
		pass.opaqueDirs = append(pass.opaqueDirs, parent(p))
	case whiteout:
		// A name of "." or ".." would delete a directory above the whiteout.
		if name := strings.TrimPrefix(base, whiteoutPrefix); name != "" && name != "." && name != ".." {
			pass.deleted = append(pass.deleted, path.Join(parent(p), name))
		}
	case header.Typeflag == tar.TypeDir:
		return u.mkdir(p)
	case regular(header):
		return u.writeFile(p, header.Size, modeOf(header), imageReader{content})
	case header.Typeflag == tar.TypeSymlink:
		return u.symlink(p, header.Linkname)
	case header.Typeflag == tar.TypeLink:
		return u.hardLink(pass, p, header.Linkname)
	default:
		// A device, a FIFO, or an entry of another type, which is skipped.
		u.paths[p] = kindHiding
	}
	return nil
}

// regular reports whether header is the entry of a regular file.
func regular(header *tar.Header) bool {
	return header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeGNUSparse
}

// modeOf returns the mode of the file of header: fileMode with the entry's execute bits.
func modeOf(header *tar.Header) fs.FileMode {
	return fileMode | fs.FileMode(header.Mode)&0o111
}

// hidden reports whether an entry at p is hidden by what came before it: an entry at p itself, or
// above p an entry that isn't a directory, or an opaque directory.
func (u *unpacker) hidden(p string) bool {
	if _, ok := u.paths[p]; ok || u.opaque[""] {
		return true
	}
	for i := range len(p) {
		if p[i] == '/' && (u.paths[p[:i]] == kindHiding || u.opaque[p[:i]]) {
			return true
		}
	}
	return false
}

// makeParents creates the directories above p that aren't there yet. p isn't hidden, so each of
// them is a directory already, or nothing.
func (u *unpacker) makeParents(p string) error {
	for i := range len(p) {
		if p[i] != '/' {
			continue
		}
		if _, ok := u.paths[p[:i]]; ok {
			continue
		}
		if err := u.mkdir(p[:i]); err != nil {
			return err
		}
	}
	return nil
}

// mkdir creates the directory p.
func (u *unpacker) mkdir(p string) error {
	if err := u.charge(blockSize); err != nil {
		return err
	}
	if err := u.root.Mkdir(p, dirMode); err != nil {
		return err
	}
	u.paths[p] = kindDir
	return nil
}

// writeFile creates the regular file p with the size bytes of content.
func (u *unpacker) writeFile(p string, size int64, mode fs.FileMode, content io.Reader) error {
	if err := u.charge(size); err != nil {
		return err
	}
	// O_EXCL never opens what is there already, and so never follows a link at p.
	f, err := u.root.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, content)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	u.paths[p] = kindHiding
	return nil
}

// symlink creates p as a link to target, as it is.
func (u *unpacker) symlink(p, target string) error {
	if err := u.charge(blockSize); err != nil {
		return err
	}
	if err := u.root.Symlink(target, p); err != nil {
		return err
	}
	u.paths[p] = kindHiding
	return nil
}

// hardLink unpacks the hard link at p to target, which must name an earlier regular file of the same
// layer. It copies the file when the layer wrote it, and leaves the copy pending when an entry before
// the file hid it.
func (u *unpacker) hardLink(pass *layerPass, p, target string) error {
	source, ok := linkTarget(target)
	file, isFile := pass.files[source]
	if !ok || !isFile {
		return ErrBadHardLink
	}
	if file.written {
		return u.copyFile(source, p, file)
	}
	// p is decided now, and written after the layer.
	u.paths[p] = kindHiding
	c := pass.pending[file.index]
	if c == nil {
		c = &pendingCopy{file: file}
		pass.pending[file.index] = c
	}
	c.links = append(c.links, p)
	return nil
}

// writePending writes the pending copies of the layer from a second read of it. The second read must
// give the entries of the first.
func (u *unpacker) writePending(l v1.Layer, pending map[int]*pendingCopy) error {
	written := 0
	err := readLayer(l, func(index int, header *tar.Header, content io.Reader) error {
		c, ok := pending[index]
		if !ok {
			return nil
		}
		if !regular(header) || imagePath(header.Name) != c.file.path || header.Size != c.file.size {
			return imageReadError(errLayerChanged)
		}
		first := c.links[0]
		if err := u.writeFile(first, c.file.size, c.file.mode, imageReader{content}); err != nil {
			return err
		}
		for _, p := range c.links[1:] {
			if err := u.copyFile(first, p, c.file); err != nil {
				return err
			}
		}
		written++
		return nil
	})
	if err == nil && written != len(pending) {
		err = imageReadError(errLayerChanged)
	}
	return err
}

// copyFile creates p as a copy of the regular file at source, which Extract wrote from file.
func (u *unpacker) copyFile(source, p string, file layerFile) error {
	f, err := u.root.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return u.writeFile(p, file.size, file.mode, f)
}

// charge takes the space of a file of size bytes from what the limit allows, or fails with
// ErrTooLarge when that would go past the limit.
func (u *unpacker) charge(size int64) error {
	space := size / blockSize * blockSize
	if size%blockSize != 0 {
		space += blockSize
	}
	// A space below the size is one that overflowed.
	if size < 0 || space < size || space > u.left {
		return ErrTooLarge
	}
	u.left -= space
	return nil
}

// imagePath returns the path of the entry name inside the image, relative to its root, or "" for the
// root itself. A container runtime takes an absolute name, and one that climbs out with .., from the
// root, and so does imagePath.
func imagePath(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

// parent returns the directory that holds p, or "" for the root.
func parent(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}

// linkTarget returns the path that the target of a hard link names, relative to the root. A tar names
// it as an entry of the archive, so a leading slash doesn't make it absolute. It returns false for a
// target that climbs out of the root.
func linkTarget(target string) (string, bool) {
	rel := strings.TrimLeft(target, "/")
	if !filepath.IsLocal(rel) {
		return "", false
	}
	return path.Clean(rel), true
}

// imageReader marks the errors of reading a layer's content, to tell them from the errors of writing
// it.
type imageReader struct {
	r io.Reader
}

func (r imageReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		err = imageReadError(err)
	}
	return n, err
}

// imageReadError marks err as an error of reading the image.
func imageReadError(err error) error {
	return fmt.Errorf("%w: %w", ErrImageRead, err)
}
