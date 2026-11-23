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

// Package casefile builds the case file: what the agent gets first on a case (main design 6.6). It holds the findings
// of the case's vulnerability with their packages and aliases and what the rules concluded, the subject, where the
// subject runs, and the names of the evidence that the agent can search. It holds no owner values: they serve the
// people who act on a case, and the model needs none of them.
//
// The evidence itself stays out of the case file. The agent searches it, through vexplain's MCP server, as lines of
// path = value.
package casefile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/cases"
)

// CaseFile is the case file of one case, and the evidence that the agent can search.
type CaseFile struct {
	// JSON is the case file, as the model gets it.
	JSON []byte
	// Cut says what the case file left out to stay within its cap, one note for each list that it cut. JSON holds the
	// same notes, so that the model knows them too.
	Cut []string
	// lines are the lines of each piece of evidence, by its name.
	lines map[string][]string
}

// file is the case file's JSON.
type file struct {
	VulnerabilityID string     `json:"vulnerabilityID"`
	Subject         subject    `json:"subject"`
	Findings        []finding  `json:"findings"`
	RunsIn          runsIn     `json:"runsIn"`
	Evidence        []evidence `json:"evidence"`
	Cut             []string   `json:"cut,omitempty"`
}

// Package is what the SBOM says of a finding's package: its purl, and the distribution that describe reads it in,
// such as debian-12. Either is empty where the SBOM has none.
type Package struct {
	PURL, Distro string
}

// finding is a finding with its package's purl and distribution, so that the agent asks describe about the package as
// the SBOM has it.
type finding struct {
	inventoryv1alpha1.Finding
	PURL   string `json:"purl,omitempty"`
	Distro string `json:"distro,omitempty"`
}

type subject struct {
	ManifestDigest string   `json:"manifestDigest"`
	Repositories   []string `json:"repositories,omitempty"`
	Platform       string   `json:"platform,omitempty"`
}

// runsIn is where the subject runs: the names of the clusters and of the first namespaces, without their owner values,
// and the workloads by exposure, with the groups of the rules that decided it.
type runsIn struct {
	Clusters            []string         `json:"clusters"`
	Namespaces          []namespace      `json:"namespaces"`
	NamespaceCount      int32            `json:"namespaceCount"`
	Workloads           int32            `json:"workloads"`
	UrgentWorkloads     int32            `json:"urgentWorkloads"`
	WorkloadsByExposure map[string]int32 `json:"workloadsByExposure,omitempty"`
	HighestExposure     string           `json:"highestExposure,omitempty"`
	HighestUrgency      string           `json:"highestUrgency,omitempty"`
	Exposure            []exposureGroup  `json:"exposure,omitempty"`
}

type namespace struct {
	Cluster string `json:"cluster"`
	Name    string `json:"name"`
}

// exposureGroup is a group of the workloads by their exposure, which names its first workloads by subject alone, and
// none of their labels.
type exposureGroup struct {
	Exposure  string   `json:"exposure"`
	Rules     []string `json:"rules,omitempty"`
	Missing   []string `json:"missing,omitempty"`
	Workloads int32    `json:"workloads"`
	First     []string `json:"first,omitempty"`
}

// evidence names a piece of evidence that the agent can search, and how many lines it has: none where it is missing.
type evidence struct {
	Name  string `json:"name"`
	Lines int    `json:"lines"`
}

// Build returns the case file of c, each finding with the purl and distribution of its package in packages, keyed by the
// package's ID, and with the evidence that the agent can search: the data of each of its names, one
// document for each producer. Over maxBytes, the case file cuts its lists from their ends, in this order: the
// clusters, the repositories, the namespaces, the groups of the workloads by exposure, the least exposed first, and the
// findings but the first. It keeps the names of the evidence, and says what it cut. It returns an error when even that
// doesn't fit, and when the data of a piece of evidence isn't JSON.
func Build(c cases.Case, data map[string][]json.RawMessage, packages map[string]Package, maxBytes int) (CaseFile, error) {
	cf := CaseFile{lines: map[string][]string{}}
	f := file{
		VulnerabilityID: c.VulnerabilityID,
		Subject: subject{ManifestDigest: c.Subject.ManifestDigest, Repositories: slices.Clone(c.Subject.Repositories),
			Platform: c.Subject.Platform},
		RunsIn: runsIn{
			Clusters: slices.Clone(c.Impact.ClusterNames), Namespaces: []namespace{}, NamespaceCount: c.Impact.Namespaces,
			Workloads: c.Impact.Resources, UrgentWorkloads: c.Impact.UrgentResources,
			HighestExposure: string(c.Impact.HighestExposure), HighestUrgency: string(c.Impact.HighestUrgency),
		},
		Evidence: []evidence{},
	}
	for _, fi := range c.Findings {
		p := packages[fi.Package.ID]
		f.Findings = append(f.Findings, finding{Finding: fi, PURL: p.PURL, Distro: p.Distro})
	}
	for _, o := range c.Impact.Owners {
		f.RunsIn.Namespaces = append(f.RunsIn.Namespaces, namespace{Cluster: o.Cluster, Name: o.Namespace})
	}
	for _, g := range c.Impact.Exposure {
		f.RunsIn.Exposure = append(f.RunsIn.Exposure, exposureGroup{Exposure: string(g.Exposure), Rules: g.Rules,
			Missing: g.Missing, Workloads: g.Workloads, First: g.First})
	}
	for level, n := range c.Impact.WorkloadsByExposure {
		if n > 0 {
			if f.RunsIn.WorkloadsByExposure == nil {
				f.RunsIn.WorkloadsByExposure = map[string]int32{}
			}
			f.RunsIn.WorkloadsByExposure[string(level)] = n
		}
	}
	for _, name := range slices.Sorted(maps.Keys(data)) {
		lines, err := linesOf(data[name])
		if err != nil {
			return CaseFile{}, fmt.Errorf("read the evidence %s: %w", name, err)
		}
		cf.lines[name] = lines
		f.Evidence = append(f.Evidence, evidence{Name: name, Lines: len(lines)})
	}

	lists := []struct {
		path, noun string
		keep       int
		length     func() int
		cut        func(n int)
	}{
		{"runsIn.clusters", "clusters", 0, func() int { return len(f.RunsIn.Clusters) },
			func(n int) { f.RunsIn.Clusters = f.RunsIn.Clusters[:n] }},
		{"subject.repositories", "repositories", 0, func() int { return len(f.Subject.Repositories) },
			func(n int) { f.Subject.Repositories = f.Subject.Repositories[:n] }},
		{"runsIn.namespaces", "namespaces", 0, func() int { return len(f.RunsIn.Namespaces) },
			func(n int) { f.RunsIn.Namespaces = f.RunsIn.Namespaces[:n] }},
		{"runsIn.exposure", "groups", 0, func() int { return len(f.RunsIn.Exposure) },
			func(n int) { f.RunsIn.Exposure = f.RunsIn.Exposure[:n] }},
		{"findings", "findings", 1, func() int { return len(f.Findings) },
			func(n int) { f.Findings = f.Findings[:n] }},
	}
	// Strings, numbers, lists and structs always marshal.
	raw, _ := json.Marshal(f)
	for _, l := range lists {
		total := l.length()
		for cutting := false; len(raw) > maxBytes && l.length() > l.keep; cutting = true {
			l.cut(l.length() - 1)
			note := fmt.Sprintf("%s: the first %d of %d %s are shown", l.path, l.length(), total, l.noun)
			if cutting {
				f.Cut[len(f.Cut)-1] = note
			} else {
				f.Cut = append(f.Cut, note)
			}
			raw, _ = json.Marshal(f)
		}
	}
	if len(raw) > maxBytes {
		return CaseFile{}, fmt.Errorf("the case file takes %d bytes even cut, over its cap of %d", len(raw), maxBytes)
	}
	cf.JSON, cf.Cut = raw, f.Cut
	return cf, nil
}

// Names returns the names of the evidence that the agent can search, sorted.
func (cf CaseFile) Names() []string {
	return slices.Sorted(maps.Keys(cf.lines))
}

// Search returns the first limit lines of the evidence name that contain query, ignoring case, and how many lines
// contain it. A query with | holds several terms, without the spaces around them, and a line that contains any of
// them matches; empty terms are ignored. It returns false for a name that the case file doesn't hold.
func (cf CaseFile) Search(name, query string, limit int) (found []string, total int, ok bool) {
	lines, ok := cf.lines[name]
	if !ok {
		return nil, 0, false
	}
	terms := []string{strings.ToLower(query)}
	if strings.Contains(query, "|") {
		terms = strings.Split(terms[0], "|")
		for i := range terms {
			terms[i] = strings.TrimSpace(terms[i])
		}
		terms = slices.DeleteFunc(terms, func(t string) bool { return t == "" })
	}
	for _, line := range lines {
		lower := strings.ToLower(line)
		if slices.ContainsFunc(terms, func(t string) bool { return strings.Contains(lower, t) }) {
			total++
			if len(found) < limit {
				found = append(found, line)
			}
		}
	}
	return found, total, true
}

// linesOf flattens each document into lines of path = value, such as packages[3].name = "libbrotli1", a document's
// keys sorted. Where several producers deliver the evidence, each line starts with the index of its document.
func linesOf(docs []json.RawMessage) ([]string, error) {
	var lines []string
	for i, doc := range docs {
		dec := json.NewDecoder(bytes.NewReader(doc))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		root := ""
		if len(docs) > 1 {
			root = fmt.Sprintf("[%d]", i)
		}
		lines = flatten(lines, root, v)
	}
	return lines, nil
}

// plainKey is a key that a path names after a dot. Any other key is quoted in brackets.
var plainKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// flatten appends the lines of v under path.
func flatten(lines []string, path string, v any) []string {
	switch v := v.(type) {
	case map[string]any:
		if len(v) == 0 {
			return append(lines, line(path, "{}"))
		}
		for _, k := range slices.Sorted(maps.Keys(v)) {
			name := "." + k
			if !plainKey.MatchString(k) {
				name = "[" + scalar(k) + "]"
			}
			lines = flatten(lines, path+name, v[k])
		}
		return lines
	case []any:
		if len(v) == 0 {
			return append(lines, line(path, "[]"))
		}
		for i, e := range v {
			lines = flatten(lines, fmt.Sprintf("%s[%d]", path, i), e)
		}
		return lines
	default:
		return append(lines, line(path, scalar(v)))
	}
}

func line(path, value string) string {
	return strings.TrimPrefix(path, ".") + " = " + value
}

// scalar returns v as JSON, without escaping the characters that HTML gives a meaning, so that a URL reads as it is.
func scalar(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	// A scalar that json decoded always encodes.
	_ = enc.Encode(v)
	return strings.TrimSuffix(b.String(), "\n")
}
