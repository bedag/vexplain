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

// Package ledger records the tool calls of one case, as vexplain's MCP server makes them (decision 0053): each call
// with its ID, such as ev-3, its arguments, its whole output and how much of it the model was shown. The claims of a
// verdict cite the IDs, and the validator checks them against the ledger. When the case ends, Object turns it into the
// case's Ledger, which the evidence store's records of the outputs complete.
package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"k8s.io/utils/ptr"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// Trust says how far a tool's output may count as evidence.
type Trust = inventoryv1alpha1.LedgerTrust

const (
	// Known is the output of a tool that declares a known type of evidence.
	Known = inventoryv1alpha1.LedgerTrustKnown
	// External is the output of a foreign source, which never counts towards not affected.
	External = inventoryv1alpha1.LedgerTrustExternal
)

const (
	// maxArguments is how many characters of a call's arguments an entry keeps, and previewCharacters how many of its
	// output's.
	maxArguments      = 4096
	previewCharacters = 512
)

// Entry is one tool call.
type Entry struct {
	ID, Tool string
	// Arguments are the call's arguments as the model gave them: their first 4096 characters.
	Arguments string
	Duration  time.Duration
	Trust     Trust
	// Output is the whole output. It is held while the case runs, for paging and for the validator, and stored in the
	// evidence store: the Ledger keeps only its size, its hash and a preview.
	Output []byte
	// ShownBytes is how much of Output the model was shown with the result of the call: its first page.
	ShownBytes   int
	OutputSHA256 string
}

// Ledger records the tool calls of one case. It is not safe for concurrent use.
type Ledger struct {
	name   string
	labels map[string]string
	// pageBytes is the most of an output that the model sees at once.
	pageBytes int
	entries   []Entry
}

// New returns the empty ledger of the case whose Assessment is named name and labelled with labels. pageBytes is the
// most of an output that the model sees at once: 4 × the profile's toolResultMaxTokens.
func New(name string, labels map[string]string, pageBytes int) *Ledger {
	return &Ledger{name: name, labels: labels, pageBytes: max(pageBytes, 1)}
}

// Subject returns the subject under which the evidence store holds the outputs of the case's calls:
// assessment/<name>. One subject for the case lets whoever deletes the case delete its outputs at once.
func (l *Ledger) Subject() string { return SubjectOf(l.name) }

// SubjectOf returns the subject of the outputs of the calls of the case whose Assessment is named name.
func SubjectOf(name string) string { return "assessment/" + name }

// NextID returns the ID that the next Add gives its entry.
func (l *Ledger) NextID() string { return fmt.Sprintf("ev-%d", len(l.entries)+1) }

// Len returns how many calls the ledger holds.
func (l *Ledger) Len() int { return len(l.entries) }

// Add records a call of tool with its arguments, its whole output, the trust of its output and its duration, and
// returns the entry, with the next ID.
func (l *Ledger) Add(tool string, args json.RawMessage, out []byte, trust Trust, d time.Duration) Entry {
	sum := sha256.Sum256(out)
	e := Entry{
		ID: l.NextID(), Tool: tool, Arguments: characters(args, maxArguments), Duration: d, Trust: trust,
		Output: out, ShownBytes: cut(out, l.pageBytes), OutputSHA256: hex.EncodeToString(sum[:]),
	}
	l.entries = append(l.entries, e)
	return e
}

// Entry returns the entry of an ID, and false when the ledger holds none.
func (l *Ledger) Entry(id string) (Entry, bool) {
	for _, e := range l.entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// Clone returns a copy of the ledger, which later calls don't change.
func (l *Ledger) Clone() *Ledger {
	c := *l
	c.entries = slices.Clone(l.entries)
	return &c
}

// Entries returns every entry, in the order of the calls.
func (l *Ledger) Entries() []Entry { return slices.Clone(l.entries) }

// Page returns page n, from 1, of an entry's output, and how many pages it has. Page 1 is what the model was shown
// with the result of the call. Each page is at most the ledger's page size and ends at the end of a line, but for a
// line longer than a page, which is cut. An empty output is one empty page. It returns false when there is no page n.
func (l *Ledger) Page(e Entry, n int) (page []byte, pages int, ok bool) {
	rest := e.Output
	for {
		size := cut(rest, l.pageBytes)
		pages++
		if pages == n {
			page = rest[:size]
		}
		rest = rest[size:]
		if len(rest) == 0 {
			return page, pages, n >= 1 && n <= pages
		}
	}
}

// Object returns the case's Ledger: every entry, with a reference to its output in the evidence store, the output's
// size and hash, and a preview of it.
func (l *Ledger) Object() *inventoryv1alpha1.Ledger {
	obj := &inventoryv1alpha1.Ledger{}
	obj.Name = l.name
	obj.Labels = maps.Clone(l.labels)
	for _, e := range l.entries {
		entry := inventoryv1alpha1.LedgerEntry{
			ID: e.ID, Tool: e.Tool, DurationMilliseconds: ptr.To(e.Duration.Milliseconds()), Trust: e.Trust,
			OutputRef: inventoryv1alpha1.LedgerOutputReference{Subject: l.Subject(), Type: sdkevidence.TypeToolOutput,
				Source: e.ID},
			OutputBytes: ptr.To(int64(len(e.Output))), ShownBytes: ptr.To(int64(e.ShownBytes)),
			OutputSHA256: e.OutputSHA256,
		}
		if e.Arguments != "" {
			entry.Arguments = ptr.To(e.Arguments)
		}
		if preview := characters(e.Output, previewCharacters); preview != "" {
			entry.Preview = ptr.To(preview)
		}
		obj.Spec.Entries = append(obj.Spec.Entries, entry)
	}
	return obj
}

// cut returns how many of the first bytes of out make one page of at most size bytes: up to the end of the last line
// that fits, or, when not even one line fits, up to the last character that does.
func cut(out []byte, size int) int {
	if len(out) <= size {
		return len(out)
	}
	if i := bytes.LastIndexByte(out[:size], '\n'); i >= 0 {
		return i + 1
	}
	n := size
	for n > 0 && !utf8.RuneStart(out[n]) {
		n--
	}
	if n == 0 {
		// Bytes that are no UTF-8 text are cut where the size says.
		return size
	}
	return n
}

// characters returns the first n characters of b, with what isn't UTF-8 replaced, so that the text fits an API field
// that counts characters. It reads no more than the 4n bytes that n characters take at most.
func characters(b []byte, n int) string {
	s := strings.ToValidUTF8(string(b[:min(len(b), 4*n)]), "\uFFFD")
	for i := range s {
		if n == 0 {
			return s[:i]
		}
		n--
	}
	return s
}
