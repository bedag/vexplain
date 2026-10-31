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
	"maps"
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
	// in it. Every other error of Extract comes from writing to the directory, or is ErrTooLarge,
	// ErrBadHardLink, ErrDuplicateEntry or ErrBadLink.
	ErrImageRead = errors.New("the image can't be read")
	// ErrBadHardLink means that a hard link of the image names no earlier regular file of its own
	// layer, which is the only hard link that build tools write. Extract fails on it, rather than
	// unpack another filesystem than a container sees.
	ErrBadHardLink = errors.New("a hard link of the image names no earlier regular file of its layer")
	// ErrDuplicateEntry means that a layer of the image holds two entries for one path, other than two
	// directories. Which of them a container sees depends on the runtime, so Extract fails on it, rather
	// than guess. A directory that Extract makes above an entry counts as an entry of its layer, and so
	// does the directory above an entry where its layer holds a link.
	ErrDuplicateEntry = errors.New("a layer of the image holds two entries for one path")
	// ErrBadLink means that a link of the image, which the paths of entries of the layers above it go
	// through, passes through more than 40 links, which a loop does, or meets something that isn't a
	// directory, or that one of those entries meets another entry for its path where the link leads,
	// other than two directories. Extract fails on it, rather than guess where a container finds the
	// entries. A link that climbs above the root stops at the root, as in Linux.
	ErrBadLink = errors.New("a link of the image doesn't lead to where the entries above it can go")
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
	// maxLinks is how many links one path may pass through, as in Linux.
	maxLinks = 40
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
//     Extract fails rather than guess. A directory that Extract makes above an entry is an entry of
//     the layer too, which containerd replaces with a later entry of another kind for its path.
//   - An entry below a link of a layer below it goes where the link leads, and the link stays, as
//     containerd's applier puts it when it unpacks a layer onto the layers below: it resolves the
//     directories above an entry through their links, inside the root. A whiteout below the link
//     deletes what the layers below the link hold where it leads, and an opaque whiteout hides it.
//     So a layer that a tool assembled from files can hold lib/... over a base where lib links to
//     usr/lib, and the files that the base's packages list below /lib stay present. A layer between
//     that holds a directory at the link's path, or deletes the link, replaces it for the layers
//     above, as in a container.
//   - A link that such entries go through stops at the root where it climbs above it, as in Linux. One
//     that passes through more than 40 links, or meets something that isn't a directory, fails Extract
//     with ErrBadLink, and so does an entry that meets another one where the link leads, other than two
//     directories.
//
// The image is untrusted, so:
//   - Every path stays inside dir. Names are taken inside the image's root, as a container runtime
//     takes them, so ../escape and /abs/path land at /escape and /abs/path.
//   - It never writes through a link: a link is created as it is, and Extract follows a link of a
//     layer below only in its own record of the paths that the layers decided, never on disk. An
//     entry below a link of a layer above, or below anything else that isn't a directory, is skipped,
//     as an overlay hides it, and so is an entry below a link of its own layer. Nothing is created
//     where an entry is already.
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
	u := &unpacker{root: root, left: maxBytes, tree: &node{kind: kindDir}}
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
	// tree holds every path that an entry of a layer above, or an earlier entry of the same layer,
	// decided, from the root down. A directory that moves takes the paths below it along.
	tree *node
	// current numbers the layer that is being unpacked: the top layer is 1, the one below it 2.
	current int
}

// node is a path that an entry decided.
type node struct {
	kind pathKind
	// opaque is true for a directory whose entries in the layers below are hidden.
	opaque bool
	// target is the target of a link, as its entry names it.
	target string
	// below is the number of the last layer with an entry below a directory.
	below int
	// placed is true for a directory that a link placed where it leads, for the entries of the layers
	// above the link.
	placed bool
	// children holds the decided paths in a directory, by name.
	children map[string]*node
}

// pathKind is what a path holds.
type pathKind uint8

const (
	// kindDir is a directory that an entry holds.
	kindDir pathKind = iota + 1
	// kindMadeDir is a directory that Extract made above an entry, where no entry holds one. The
	// entries below it go elsewhere when a layer below holds a link at its path.
	kindMadeDir
	// kindLink is a link that Extract created.
	kindLink
	// kindFile is a regular file that Extract created, or is to create.
	kindFile
	// kindHidden is an entry that Extract skipped, or what a whiteout deleted.
	kindHidden
)

// isDir reports whether n is a directory. Any other node hides its path and everything below it.
func (n *node) isDir() bool {
	return n.kind == kindDir || n.kind == kindMadeDir
}

// add decides the path name in the directory n as child, and returns child.
func (n *node) add(name string, child *node) *node {
	if n.children == nil {
		n.children = map[string]*node{}
	}
	n.children[name] = child
	return child
}

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
	// entries holds the path of every entry of the layer so far, and of every directory that Extract
	// made above one, and whether the entry is a directory, to find two entries for one path.
	entries map[string]bool
}

// layer unpacks one layer, and reads it a second time when it has pending copies.
func (u *unpacker) layer(l v1.Layer) error {
	u.current++
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

	// The directory of each whiteout is still one: the layer decided it when it read the whiteout, and
	// a link of the layer neither replaces nor moves a directory that the layer has an entry below.
	for _, p := range pass.deleted {
		dir, name := u.find(parent(p)), path.Base(p)
		if dir == nil || !dir.isDir() {
			continue
		}
		switch n := dir.children[name]; {
		case n == nil:
			dir.add(name, &node{kind: kindHidden})
		case n.isDir():
			// A directory of this layer, or of one above, stays, but what the layers below hold at its
			// path is gone, a link included, and so is what they hold in it.
			n.kind, n.opaque = kindDir, true
		}
	}
	for _, p := range pass.opaqueDirs {
		if dir := u.find(p); dir != nil && dir.isDir() {
			dir.opaque = true
		}
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
	n, hiddenAbove, placed := u.lookup(p)
	if !whiteout && regular(header) {
		written := !hiddenAbove && n == nil
		pass.files[p] = layerFile{index: index, path: p, size: header.Size, mode: modeOf(header), written: written}
	}
	switch {
	case hiddenAbove:
		return nil
	case n != nil:
		return u.decided(pass, p, n, placed, header)
	}
	// The layer holds the directories above every entry, whiteouts included.
	dirNode, err := u.makeParents(pass, p)
	if err != nil {
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
	case dir:
		if err := u.mkdir(p); err != nil {
			return err
		}
		dirNode.add(base, &node{kind: kindDir})
	case regular(header):
		if err := u.writeFile(p, header.Size, modeOf(header), imageReader{content}); err != nil {
			return err
		}
		dirNode.add(base, &node{kind: kindFile})
	case header.Typeflag == tar.TypeSymlink:
		if err := u.symlink(p, header.Linkname); err != nil {
			return err
		}
		dirNode.add(base, &node{kind: kindLink, target: header.Linkname})
	case header.Typeflag == tar.TypeLink:
		return u.hardLink(pass, dirNode, p, header.Linkname)
	default:
		// A device, a FIFO, or an entry of another type, which is skipped.
		dirNode.add(base, &node{kind: kindHidden})
	}
	return nil
}

// decided unpacks the entry that header describes at p, which an entry of a layer above, or an earlier
// entry of the same layer, decided as n. That entry hides it, but where Extract made a directory for
// the entries of the layers above:
//   - An entry that holds a directory there is that directory, so that a link of a layer below doesn't
//     lead them elsewhere.
//   - A link there was below them, so they go where it leads (adopt).
//   - Anything else there is hidden, as an overlay hides it below the directory, unless a link placed
//     p, or a directory above it, where the link leads: then the entries above would go through the
//     link to something that isn't a directory, which fails with ErrBadLink.
func (u *unpacker) decided(pass *layerPass, p string, n *node, placed bool, header *tar.Header) error {
	if n.kind != kindMadeDir {
		return nil
	}
	switch {
	case header.Typeflag == tar.TypeDir:
		// Like any entry of the layer, it is below the directories above p.
		if _, err := u.makeParents(pass, p); err != nil {
			return err
		}
		n.kind = kindDir
		return nil
	case header.Typeflag == tar.TypeSymlink:
		return u.adopt(pass, p, n, header.Linkname)
	case placed:
		return ErrBadLink
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

// lookup returns the node of p, or nil when nothing decided p, and whether something above p hides an
// entry at p: an entry that isn't a directory, or an opaque directory. placed reports whether a link
// placed p, or a directory above it, where the link leads.
func (u *unpacker) lookup(p string) (n *node, hiddenAbove, placed bool) {
	dir := u.tree
	for rest := p; ; {
		if dir.opaque {
			return nil, true, false
		}
		name, next, more := strings.Cut(rest, "/")
		if n = dir.children[name]; n == nil {
			return nil, false, placed
		}
		placed = placed || n.placed
		if !more {
			return n, false, placed
		}
		if !n.isDir() {
			return nil, true, false
		}
		dir, rest = n, next
	}
}

// find returns the node of p, or nil when nothing decided p.
func (u *unpacker) find(p string) *node {
	n := u.tree
	if p == "" {
		return n
	}
	for name := range strings.SplitSeq(p, "/") {
		if n = n.children[name]; n == nil {
			return nil
		}
	}
	return n
}

// makeParents creates the directories above p that aren't there yet, and returns the node of the
// directory that holds p. Each directory above p must be one already, or nothing.
//
// For an entry of the layer, pass is the layer's. A directory that makeParents creates then counts as
// an entry of the layer, so that a later entry of another kind for its path is a second entry for one
// path: containerd would replace the directory with it. And each directory above p gets the layer as
// the last one with an entry below it.
//
// For the entries of the layers above, which a link of the layer places at p, pass is nil, and a
// directory that makeParents creates is one that the link placed.
func (u *unpacker) makeParents(pass *layerPass, p string) (*node, error) {
	dir := u.tree
	for i := 0; ; {
		j := strings.IndexByte(p[i:], '/')
		if j < 0 {
			return dir, nil
		}
		name, sub := p[i:i+j], p[:i+j]
		child := dir.children[name]
		if child == nil {
			if err := u.mkdir(sub); err != nil {
				return nil, err
			}
			child = dir.add(name, &node{kind: kindMadeDir, placed: pass == nil})
			if pass != nil {
				pass.entries[sub] = true
			}
		}
		if pass != nil {
			child.below = u.current
		}
		dir, i = child, i+j+1
	}
}

// adopt unpacks the link at p, where Extract made the directory made for the entries of the layers
// above. The link was there below them, so they go where it leads, inside the root, and the link
// stays, as containerd's applier places them: the directory moves there, or merges into the one that
// is there. Their whiteouts move along, and so delete what the layers below hold where the link leads.
//
// It fails with ErrDuplicateEntry when the layer has an entry below p as well, which needs a directory
// at p, and with ErrBadLink as resolve and merge do.
func (u *unpacker) adopt(pass *layerPass, p string, made *node, target string) error {
	dirNode, err := u.makeParents(pass, p)
	if err != nil {
		return err
	}
	if made.below == u.current {
		return ErrDuplicateEntry
	}
	// The link is at p for resolve, so that a path through p leads on through the link.
	dirNode.add(path.Base(p), &node{kind: kindLink, target: target})
	dest, destNode, err := u.resolve(parent(p), target)
	if err != nil {
		return err
	}
	if destNode == nil {
		// Nothing is decided where the link leads, so the directory moves there as a whole.
		destDir, err := u.makeParents(nil, dest)
		if err != nil {
			return err
		}
		made.placed = true
		destDir.add(path.Base(dest), made)
		if err := u.root.Rename(p, dest); err != nil {
			return err
		}
	} else {
		destNode.opaque = destNode.opaque || made.opaque
		if err := u.merge(made, destNode, p, dest); err != nil {
			return err
		}
		if err := u.root.Remove(p); err != nil {
			return err
		}
	}
	return u.symlink(p, target)
}

// resolve returns the path where a link in the directory dir to target leads, and its node, or nil
// when nothing decided that path. It resolves as Linux does inside a container's root, in what the
// layers decided so far: an absolute target starts at the root, .. goes up one directory and stays
// at the root, and each link on the way leads on, the link itself the first. It fails with ErrBadLink
// when the path passes through more than maxLinks links, or meets anything but a directory.
func (u *unpacker) resolve(dir, target string) (string, *node, error) {
	// names is the path so far, and nodes the node of each of its names, nil where nothing is decided.
	var names []string
	var nodes []*node
	if !strings.HasPrefix(target, "/") && dir != "" {
		n := u.tree
		for name := range strings.SplitSeq(dir, "/") {
			if n != nil {
				n = n.children[name]
			}
			names, nodes = append(names, name), append(nodes, n)
		}
	}
	pending := strings.Split(target, "/")
	for links := 1; len(pending) > 0; {
		name := pending[0]
		pending = pending[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			if len(names) > 0 {
				names, nodes = names[:len(names)-1], nodes[:len(nodes)-1]
			}
			continue
		}
		var n *node
		if len(nodes) == 0 {
			n = u.tree.children[name]
		} else if last := nodes[len(nodes)-1]; last != nil {
			n = last.children[name]
		}
		switch {
		case n == nil || n.isDir():
			names, nodes = append(names, name), append(nodes, n)
		case n.kind == kindLink:
			if links++; links > maxLinks {
				return "", nil, ErrBadLink
			}
			if strings.HasPrefix(n.target, "/") {
				names, nodes = names[:0], nodes[:0]
			}
			pending = append(strings.Split(n.target, "/"), pending...)
		default:
			return "", nil, ErrBadLink
		}
	}
	if len(nodes) == 0 {
		return "", u.tree, nil
	}
	return strings.Join(names, "/"), nodes[len(nodes)-1], nil
}

// merge moves what the directory src at the path from holds into the directory dst at the path to,
// where a link of the layer places it. What dst holds is of a layer above, or of an earlier entry of
// the link's own layer, which unpacked it already:
//   - Two directories for one path are one. An opaque one hides what the layers below hold in it, and
//     keeps what dst holds.
//   - A whiteout, or a skipped entry, keeps what dst holds for its path. In a container it deletes
//     that when it is of a layer below the whiteout's, but Extract doesn't remove what it unpacked:
//     it errs towards a file that is present.
//   - Anything else that both hold for one path fails with ErrBadLink: which of them a container sees
//     depends on the order of the layers and on the runtime.
//
// It removes the directories below from that it emptied, and leaves from itself. It works through the
// directories with a list rather than with recursion, so that a deep tree of an image can't exhaust the
// stack.
func (u *unpacker) merge(src, dst *node, from, to string) error {
	type dirs struct {
		src, dst *node
		from, to string
	}
	work := []dirs{{src, dst, from, to}}
	// emptied lists the directories that were merged, each after the directories above it.
	var emptied []string
	for len(work) > 0 {
		m := work[len(work)-1]
		work = work[:len(work)-1]
		for _, name := range slices.Sorted(maps.Keys(m.src.children)) {
			s, d := m.src.children[name], m.dst.children[name]
			fromChild, toChild := path.Join(m.from, name), path.Join(m.to, name)
			switch {
			case d == nil:
				s.placed = true
				m.dst.add(name, s)
				// A deleted or skipped entry is nowhere on disk.
				if s.kind != kindHidden {
					if err := u.root.Rename(fromChild, toChild); err != nil {
						return err
					}
				}
			case s.kind == kindHidden:
				// d stays.
			case s.isDir() && d.isDir():
				if s.kind == kindDir {
					d.kind = kindDir
				}
				d.opaque = d.opaque || s.opaque
				work = append(work, dirs{s, d, fromChild, toChild})
				emptied = append(emptied, fromChild)
			default:
				return ErrBadLink
			}
		}
	}
	for _, dir := range slices.Backward(emptied) {
		if err := u.root.Remove(dir); err != nil {
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
	return u.root.Mkdir(p, dirMode)
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
	return err
}

// symlink creates p as a link to target, as it is.
func (u *unpacker) symlink(p, target string) error {
	if err := u.charge(blockSize); err != nil {
		return err
	}
	return u.root.Symlink(target, p)
}

// hardLink unpacks the hard link at p to target, which must name an earlier regular file of the same
// layer, and decides p in the directory dir. It copies the file when the layer wrote it, and leaves the
// copy pending when an entry before the file hid it.
func (u *unpacker) hardLink(pass *layerPass, dir *node, p, target string) error {
	source, ok := linkTarget(target)
	file, isFile := pass.files[source]
	if !ok || !isFile {
		return ErrBadHardLink
	}
	if file.written {
		if err := u.copyFile(source, p, file); err != nil {
			return err
		}
		dir.add(path.Base(p), &node{kind: kindFile})
		return nil
	}
	// p is decided now, and written after the layer.
	dir.add(path.Base(p), &node{kind: kindFile})
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
