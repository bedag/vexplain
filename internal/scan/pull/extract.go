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
	// in it. Every other error of Extract comes from writing to the directory.
	ErrImageRead = errors.New("the image can't be read")
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
// It reads the layers from the top down, so the first entry of a path is the one that counts, and
// it hides those below it:
//   - A whiteout deletes its entry from the layers below, and an opaque whiteout everything that
//     they hold in its directory. Neither touches its own layer.
//   - An entry that isn't a directory hides what the layers below hold at its path and under it.
//
// The image is untrusted, so:
//   - Every path stays inside dir. Names are taken inside the image's root, as a container runtime
//     takes them, so ../escape and /abs/path land at /escape and /abs/path.
//   - It never follows a link: a link is created as it is. An entry below a link, or below anything
//     else that isn't a directory, is skipped, which is also the overlay's rule, and nothing is
//     created where an entry is already.
//   - A hard link becomes a copy of an earlier regular file inside dir. One to anything else, to a
//     file that isn't there yet, or out of the root, is skipped.
//   - Devices, FIFOs and entries of other types are skipped.
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
	u := &unpacker{
		root:   root,
		left:   maxBytes,
		paths:  map[string]pathKind{},
		files:  map[string]fileInfo{},
		opaque: map[string]bool{},
	}
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
	// files holds the regular files written, for the hard links to them.
	files map[string]fileInfo
	// opaque holds the directories whose entries in the layers below are hidden.
	opaque map[string]bool
}

// pathKind is what a path holds.
type pathKind uint8

const (
	// kindDir is a directory that Extract created.
	kindDir pathKind = iota + 1
	// kindHiding is anything else: a file or a link that Extract created, an entry that it skipped,
	// or what a whiteout deleted. It hides its path and everything under it.
	kindHiding
)

// fileInfo is what a copy of a regular file takes from it.
type fileInfo struct {
	size int64
	mode fs.FileMode
}

// layer unpacks one layer.
func (u *unpacker) layer(l v1.Layer) error {
	rc, err := l.Uncompressed()
	if err != nil {
		return imageReadError(err)
	}
	// The reads report every error, so Close has nothing to add.
	defer func() { _ = rc.Close() }()

	// A whiteout deletes only what the layers below hold, so it takes effect at the end of its layer.
	var deleted, opaqueDirs []string
	tr := tar.NewReader(rc)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		// With GODEBUG=tarinsecurepath=0, tar reports names such as ../escape as insecure. Extract takes
		// them inside the root, as it takes every name.
		if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
			return imageReadError(err)
		}
		p := imagePath(header.Name)
		if p == "" || u.hidden(p) {
			continue
		}
		// The layer holds the directories above every entry, whiteouts included.
		if err := u.makeParents(p); err != nil {
			return err
		}
		switch base := path.Base(p); {
		case base == opaqueWhiteout:
			opaqueDirs = append(opaqueDirs, parent(p))
		case strings.HasPrefix(base, whiteoutPrefix):
			// A name of "." or ".." would delete a directory above the whiteout.
			if name := strings.TrimPrefix(base, whiteoutPrefix); name != "" && name != "." && name != ".." {
				deleted = append(deleted, path.Join(parent(p), name))
			}
		default:
			if err := u.entry(p, header, tr); err != nil {
				return err
			}
		}
	}
	// Read the layer to its end, so that the registry client's check of its digest runs.
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return imageReadError(err)
	}

	for _, p := range deleted {
		switch u.paths[p] {
		case kindDir:
			// A directory of this layer, or of one above, stays, but what the layers below hold in it is
			// gone.
			u.opaque[p] = true
		case 0:
			u.paths[p] = kindHiding
		}
	}
	for _, dir := range opaqueDirs {
		u.opaque[dir] = true
	}
	return nil
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

// entry unpacks the entry at p, which header describes and content holds.
func (u *unpacker) entry(p string, header *tar.Header, content io.Reader) error {
	switch header.Typeflag {
	case tar.TypeDir:
		return u.mkdir(p)
	case tar.TypeReg, tar.TypeGNUSparse:
		mode := fileMode | fs.FileMode(header.Mode)&0o111
		return u.writeFile(p, header.Size, mode, imageReader{content})
	case tar.TypeSymlink:
		return u.symlink(p, header.Linkname)
	case tar.TypeLink:
		return u.copyFile(p, header.Linkname)
	default:
		// A device, a FIFO, or an entry of another type, which is skipped.
		u.paths[p] = kindHiding
		return nil
	}
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
	u.files[p] = fileInfo{size: size, mode: mode}
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

// copyFile creates p as a copy of the regular file that the hard link target names. When there is
// none, it skips the link.
func (u *unpacker) copyFile(p, target string) error {
	source, ok := linkTarget(target)
	info, isFile := u.files[source]
	if !ok || !isFile {
		u.paths[p] = kindHiding
		return nil
	}
	f, err := u.root.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return u.writeFile(p, info.size, info.mode, f)
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
