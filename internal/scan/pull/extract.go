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
	// than guess. Two entries that land on one path through a link of their layer are two entries for it
	// too. A directory that an entry needs above it counts as an entry of its layer: where Extract makes
	// it, where the layer holds a link at its path, and where the layer holds something else there that
	// isn't a directory.
	ErrDuplicateEntry = errors.New("a layer of the image holds two entries for one path")
	// ErrBadLink means that a link that the path of an entry goes through passes through more than 40
	// links, which a loop does, or meets something that isn't a directory, or that an entry of a layer
	// above a link meets another entry for its path where the link leads, other than two directories.
	// Extract fails on it, rather than guess where a container finds the entry. A link that climbs
	// above the root stops at the root, as in Linux.
	ErrBadLink = errors.New("a link of the image doesn't lead to where the entries below it can go")
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
//
// The directories above an entry resolve through links, inside the root, and a .. at the root stays
// there, as in Linux:
//   - An entry below a link of its own layer goes where the link leads, as tar extraction puts it,
//     also where a layer above hides the link or a directory above it: that hides the link's path and
//     what is below it, not where the link leads. So a layer that a tool flattened from packages can
//     hold lib -> usr/lib and then lib/... files, which land in usr/lib.
//   - An entry below a link of a layer below it goes where the link leads, and the link stays, as
//     containerd's applier puts it when it unpacks a layer onto the layers below. So a layer that a
//     tool assembled from files can hold lib/... over a base where lib links to usr/lib, and the files
//     that the base's packages list below /lib stay present. A layer between that holds a directory
//     at the link's path, or deletes the link, replaces it for the layers above, as in a container.
//   - An entry below a link of a layer above it, or below anything else of a layer above that isn't a
//     directory, is hidden, as an overlay hides it.
//   - A whiteout or an opaque whiteout below a link deletes nothing where the link leads. Runtimes
//     differ there: containerd's overlayfs snapshotter unpacks each layer on its own, where a
//     directory above an entry hides a link of a layer below, and which runtime a cluster uses can't
//     be told. Where runtimes differ, Extract keeps a file present.
//   - A path that passes through more than 40 links, which a loop does, fails Extract with ErrBadLink,
//     and so does one that meets something that isn't a directory: where a link of a layer below leads
//     the entries of the layers above, and where a link of the entry's own layer leads it to something
//     of that layer. Without a link on the way, an entry below something of its own layer that isn't a
//     directory fails with ErrDuplicateEntry.
//   - Entries that land on one path through a link fail too, other than two directories: of one layer
//     with ErrDuplicateEntry, and of two layers, where a link of a layer below leads, with ErrBadLink.
//
// The image is untrusted, so:
//   - Every path stays inside dir. Names are taken inside the image's root, as a container runtime
//     takes them, so ../escape and /abs/path land at /escape and /abs/path, and links resolve inside
//     it too.
//   - It never writes through a link. Extract follows links only in its own record of the paths that
//     the layers decided, never on disk, and creates a link as it is. An entry never writes through a
//     link at its own path: where a layer below holds one there, the entry replaces it, as tar
//     extraction does, since Extract never makes that link. Nothing is created where an entry is
//     already.
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
	u := &unpacker{root: root, left: maxBytes, tree: &node{kind: kindDir}, marks: &mark{}}
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
	// tree holds what the entries of the layers above, and the earlier entries of the same layer, put
	// on disk or are to put there, from the root down. A directory that moves takes what is below it
	// along.
	tree *node
	// marks holds where whiteouts and skipped entries of those layers hide what the layers below them
	// hold. Marks never move with a directory: a whiteout below a link of a layer below deletes nothing
	// where the link leads.
	marks *mark
	// current numbers the layer that is being unpacked: the top layer is 1, the one below it 2.
	current int
}

// node is a path where an entry put a directory, a file or a link.
type node struct {
	kind pathKind
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
)

// mark is a path where a whiteout or a skipped entry of a layer hides what the layers below it hold.
type mark struct {
	// hidden is true at a path that a whiteout deleted, or where an entry was skipped: the layers below
	// hold nothing there, nor below it.
	hidden bool
	// opaque is true for a directory that the layers below hold nothing in.
	opaque bool
	// children holds the marks below the path, by name.
	children map[string]*mark
}

// markAt returns the mark of p, which it adds, with the marks above it, where there is none.
func (u *unpacker) markAt(p string) *mark {
	m := u.marks
	if p == "" {
		return m
	}
	for name := range strings.SplitSeq(p, "/") {
		child := m.children[name]
		if child == nil {
			if m.children == nil {
				m.children = map[string]*mark{}
			}
			child = &mark{}
			m.children[name] = child
		}
		m = child
	}
	return m
}

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
	// path is the name of the entry, and at the path where Extract wrote it, through the links of the
	// layer.
	path, at string
	size     int64
	mode     fs.FileMode
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
	// entries holds the path of every entry of the layer so far, as its name has it and through the links
	// of the layer, and of every directory that Extract made above one, and whether the entry is a
	// directory, to find two entries for one path.
	entries map[string]bool
	// links holds the target of every link of the layer so far, by its path through the links of the
	// layer, whether or not a layer above hides it, or a directory above it: the layer's own entries go
	// through it.
	links map[string]string
}

// claim records an entry of the layer at p, a directory when dir is true, and fails with
// ErrDuplicateEntry when the layer holds another entry there, but for two directories.
func (pass *layerPass) claim(p string, dir bool) error {
	if wasDir, seen := pass.entries[p]; seen && (!wasDir || !dir) {
		return ErrDuplicateEntry
	}
	pass.entries[p] = dir
	return nil
}

// layer unpacks one layer, and reads it a second time when it has pending copies.
func (u *unpacker) layer(l v1.Layer) error {
	u.current++
	pass := &layerPass{
		files:   map[string]layerFile{},
		pending: map[int]*pendingCopy{},
		entries: map[string]bool{},
		links:   map[string]string{},
	}
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

	// What the layer and the layers above put at a deleted path stays. What the layers below hold there
	// is gone, a link included, and so is what they hold below it.
	for _, p := range pass.deleted {
		u.markAt(p).hidden = true
	}
	for _, p := range pass.opaqueDirs {
		u.markAt(p).opaque = true
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
	// names. So Extract fails on them, even where a layer above hides the path, and also where a link of
	// the layer leads an entry to the path of another.
	dir := header.Typeflag == tar.TypeDir
	if err := pass.claim(p, dir); err != nil {
		return err
	}
	w, err := u.place(pass, p)
	if err != nil {
		return err
	}
	if w.path != p {
		if err := pass.claim(w.path, dir); err != nil {
			return err
		}
	}
	// The layer's own entries go through its link, wherever a layer above hides it.
	if header.Typeflag == tar.TypeSymlink {
		pass.links[w.path] = header.Linkname
	}
	base := path.Base(p)
	whiteout := strings.HasPrefix(base, whiteoutPrefix)
	if !whiteout && regular(header) {
		pass.files[p] = layerFile{index: index, path: p, at: w.path, size: header.Size, mode: modeOf(header),
			written: !w.hidden && w.node == nil}
	}
	switch {
	case w.hidden:
		return nil
	case w.node != nil:
		return u.decided(pass, w.path, w.node, w.placed, header)
	}
	p = w.path
	// The layer holds the directories above every entry, whiteouts included.
	dirNode, err := u.makeParents(pass, p)
	if err != nil {
		return err
	}
	switch {
	case whiteout && w.linked:
		// A whiteout below a link deletes nothing where the link leads.
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
		// A device, a FIFO, or an entry of another type, which is skipped, and hides its path.
		u.markAt(p).hidden = true
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

// placement is where an entry of the layer that is being unpacked goes.
type placement struct {
	// path is the path of the entry with the links of its layer followed.
	path string
	// node is what an entry put at path before, or nil.
	node *node
	// hidden is true when the entry is hidden at path: by an entry of a layer above, at path or above it,
	// that isn't a directory, by an opaque directory above it, or by a whiteout or a skipped entry.
	hidden bool
	// placed is true when a link placed path, or a directory above it, where the link leads.
	placed bool
	// linked is true when the path goes through a link of the layer.
	linked bool
}

// place returns where the entry at p of the layer that is being unpacked goes. The directories above it
// resolve through the links of its layer, as tar extraction resolves them: inside the root, with each
// link leading on from its directory, an absolute one from the root, and a .. at the root staying there.
// That holds also where a layer above hides the link, or a directory above it: the layer above hides
// that path and what is below it, not where the link leads. So what the layers above hold on the path
// where the entry lands decides whether it is hidden, and not what they hold on the way there. It fails
// with ErrBadLink when the path passes through more than maxLinks links, or leads through a link of the
// layer to something of the layer that isn't a directory, and with ErrDuplicateEntry when the layer holds
// something that isn't a directory, nor a link, above the entry.
func (u *unpacker) place(pass *layerPass, p string) (placement, error) {
	var w placement
	k := walk{u: u, p: p}
	pending := strings.Split(p, "/")
	last := pending[len(pending)-1]
	pending = pending[:len(pending)-1]
	for links := 0; len(pending) > 0; {
		name := pending[0]
		pending = pending[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			k.up()
			continue
		}
		sub := k.sub(name, w.linked)
		if target, ok := pass.links[sub]; ok {
			if links++; links > maxLinks {
				return w, ErrBadLink
			}
			w.linked = true
			if strings.HasPrefix(target, "/") {
				k.reset()
			}
			pending = append(strings.Split(target, "/"), pending...)
			continue
		}
		if wasDir, seen := pass.entries[sub]; seen && !wasDir {
			if w.linked {
				return w, ErrBadLink
			}
			return w, ErrDuplicateEntry
		}
		n, m, hidden := k.child(name)
		k.down(sub, n, m, hidden || (n != nil && !n.isDir()))
	}
	w.path = k.sub(last, w.linked)
	n, _, hidden := k.child(last)
	if hidden || k.hidden() {
		w.hidden = true
		return w, nil
	}
	w.node, w.placed = n, k.placed() || (n != nil && n.placed)
	return w, nil
}

// walk is the path that place has resolved so far.
type walk struct {
	u *unpacker
	// p is the path that place resolves.
	p string
	// path is the path so far, and nodes and marks hold the node and the mark of each of its names, nil
	// where there is none. hides holds for each name whether the layers above hide an entry there, and
	// below it.
	path  string
	nodes []*node
	marks []*mark
	hides []bool
}

// sub returns the path of name in the directory so far. Without a link on the way, linked is false, and
// the path so far is the start of p.
func (k *walk) sub(name string, linked bool) string {
	switch {
	case k.path == "":
		return name
	case !linked:
		return k.p[:len(k.path)+1+len(name)]
	default:
		return k.path + "/" + name
	}
}

// child returns the node and the mark of name in the directory so far, nil where there is none, and
// whether an opaque directory, a whiteout or a skipped entry of a layer above hides an entry there.
func (k *walk) child(name string) (n *node, m *mark, hidden bool) {
	dirNode, dirMark := k.u.tree, k.u.marks
	if len(k.nodes) > 0 {
		dirNode, dirMark = k.nodes[len(k.nodes)-1], k.marks[len(k.marks)-1]
	}
	if dirNode != nil {
		n = dirNode.children[name]
	}
	if dirMark != nil {
		m = dirMark.children[name]
		hidden = dirMark.opaque
	}
	return n, m, hidden || (m != nil && m.hidden)
}

// down goes into the directory sub, with its node and mark, and whether the layers above hide it.
func (k *walk) down(sub string, n *node, m *mark, hidden bool) {
	k.path, k.nodes, k.marks, k.hides = sub, append(k.nodes, n), append(k.marks, m), append(k.hides, hidden)
}

// up goes up one directory, and stays at the root.
func (k *walk) up() {
	if k.path != "" {
		last := len(k.nodes) - 1
		k.path, k.nodes, k.marks, k.hides = parent(k.path), k.nodes[:last], k.marks[:last], k.hides[:last]
	}
}

// reset goes back to the root.
func (k *walk) reset() {
	k.path, k.nodes, k.marks, k.hides = "", k.nodes[:0], k.marks[:0], k.hides[:0]
}

// placed reports whether a link placed a directory of the path so far where it leads.
func (k *walk) placed() bool {
	return slices.ContainsFunc(k.nodes, func(n *node) bool { return n != nil && n.placed })
}

// hidden reports whether the layers above hide a directory of the path so far, and so what is below it.
func (k *walk) hidden() bool {
	return slices.Contains(k.hides, true)
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
// stays: the directory moves there, or merges into the one that is there. Their whiteouts and skipped
// entries stay at p, below the link, and so hide nothing where it leads: whether they would depends on
// the runtime, and Extract keeps the files.
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
// the link's own layer, which unpacked it already. Two directories for one path are one. Anything else
// that both hold for one path fails with ErrBadLink: which of them a container sees depends on the
// order of the layers and on the runtime.
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
				if err := u.root.Rename(fromChild, toChild); err != nil {
					return err
				}
			case s.isDir() && d.isDir():
				if s.kind == kindDir {
					d.kind = kindDir
				}
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
		if err := u.copyFile(file.at, p, file); err != nil {
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
