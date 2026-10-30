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

import "path"

// linkGraph is the graph of DT_NEEDED, reversed: for each ELF file, by its index, the ELF files whose
// DT_NEEDED entries name it.
type linkGraph [][]int

// buildLinkGraph resolves the DT_NEEDED entries of every ELF file across the whole image, without
// the dynamic linker's search paths (plan decision 7). A needed name matches:
//   - every ELF file whose soname equals it
//   - every path whose base name equals it, with links followed inside the root to their target
//
// All matches count. That reaches more files than the dynamic linker would load, which only makes
// the residual bigger. A needed name that is a path matches the files of its base name, the file at
// that path among them.
func buildLinkGraph(t *tree, elfs []elfFile) linkGraph {
	index := make(map[string]int, len(elfs))
	bySoname := map[string][]int{}
	for i, e := range elfs {
		index[e.path] = i
		if e.soname != "" {
			bySoname[e.soname] = append(bySoname[e.soname], i)
		}
	}

	matches := map[string][]int{}
	match := func(needed string) []int {
		if found, ok := matches[needed]; ok {
			return found
		}
		var found []int
		seen := map[int]bool{}
		add := func(i int) {
			if !seen[i] {
				seen[i] = true
				found = append(found, i)
			}
		}
		for _, i := range bySoname[needed] {
			add(i)
		}
		for _, p := range t.byBase[path.Base(needed)] {
			if target, status := t.resolve(p, true); status == resolved {
				if i, ok := index[target]; ok {
					add(i)
				}
			}
		}
		matches[needed] = found
		return found
	}

	g := make(linkGraph, len(elfs))
	for i, e := range elfs {
		for _, needed := range e.needed {
			if needed == "" {
				continue
			}
			for _, j := range match(needed) {
				g[j] = append(g[j], i)
			}
		}
	}
	return g
}

// reachWalker finds the ELF files from which a file can be reached. It keeps its marks between
// walks, so that a walk costs only what it visits.
type reachWalker struct {
	g     linkGraph
	marks []int // the number of the walk that last visited each file
	walk  int
	queue []int
}

func newReachWalker(g linkGraph) *reachWalker {
	return &reachWalker{g: g, marks: make([]int, len(g))}
}

// reachers returns the ELF files from which file i can be reached through DT_NEEDED, followed
// transitively, without i itself, in the order the walk finds them.
func (w *reachWalker) reachers(i int) []int {
	w.walk++
	w.marks[i] = w.walk
	queue := append(w.queue[:0], i)
	for head := 0; head < len(queue); head++ {
		for _, j := range w.g[queue[head]] {
			if w.marks[j] != w.walk {
				w.marks[j] = w.walk
				queue = append(queue, j)
			}
		}
	}
	w.queue = queue
	return append([]int(nil), queue[1:]...)
}
