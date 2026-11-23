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

// Package describe is the vulnerabilities collector's operation describe: what Grype's database holds for one
// vulnerability, from every provider, and for each package that it is asked about, whether the provider of the
// package's distribution or ecosystem has fixed the vulnerability at the installed version. The agent calls it, and
// the validator of the agent's verdicts lets "fixed" and "not affected" rest on its Yes alone, without comparing
// versions itself: compare.go says when the answer is Yes.
//
// It runs Grype's searches of the database, which need no network (parse.go). The design gives the reasons, in
// docs/design/2026-11-16-agent-on-cases.md, section 5.8.
package describe

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"google.golang.org/protobuf/proto"

	"github.com/bedag/vexplain/collectors/vulnerabilities/internal/grype"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
)

// Name is the name of the operation.
const Name = "describe"

const (
	// subjectPrefix starts the subject of describe's event, which is about the vulnerability: vulnerability/<ID>.
	subjectPrefix = "vulnerability/"
	// maxPackages is how many packages describe is asked about at most.
	maxPackages = 16
	// maxAliases is how many aliases describe is given at most.
	maxAliases = 8
	// maxNamed is how many entries that name a package are listed for a package that no entry answers for.
	maxNamed = 8
	// fixedState is the state of a range that names its fix.
	fixedState = "fixed"
	// nvdProvider is NVD, whose description of a CVE comes first.
	nvdProvider = "nvd"
	// cvssScheme is the scheme of a record's CVSS scores.
	cvssScheme = "CVSS"
)

// The reasons of the failures that describe gives.
const (
	reasonNotFound     = "NotFound"
	reasonInvalidInput = "InvalidInput"
	reasonInternal     = "Internal"
	reasonTooLarge     = "TooLarge"
)

// idPattern is what a vulnerability ID looks like, such as CVE-2026-0001, GHSA-xxxx-xxxx-xxxx or RHSA-2026:0001. It
// starts with no dash, so that Grype never takes one for a flag.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// parameterSchema is the schema of describe's parameters, which the agent's tool takes as its input.
const parameterSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "The vulnerability to describe, and the packages of the case to compare with each provider's fix.",
  "type": "object",
  "additionalProperties": false,
  "required": ["vulnerabilityID"],
  "properties": {
    "vulnerabilityID": {
      "description": "A vulnerability ID or an alias, such as CVE-2026-0001 or GHSA-xxxx-xxxx-xxxx.",
      "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
    },
    "aliases": {
      "description": "Other IDs of the same vulnerability, such as the IDs that the case's findings carry. They are searched with vulnerabilityID.",
      "type": "array", "maxItems": 8,
      "items": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"}
    },
    "packages": {
      "description": "The packages of the case, as the SBOM has them. Give the purl: it names the source package that distributions track, and the release.",
      "type": "array", "maxItems": 16,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["name", "type"],
        "properties": {
          "name": {"type": "string", "minLength": 1, "maxLength": 253},
          "version": {"description": "The installed version.", "type": "string", "minLength": 1, "maxLength": 128},
          "type": {"description": "Syft's type, such as deb, rpm, apk or go-module.", "type": "string", "minLength": 1, "maxLength": 64},
          "purl": {"type": "string", "pattern": "^pkg:[^\\s]+$", "maxLength": 2048},
          "distro": {"description": "The distribution and release, such as debian-12, where the purl names none. Where it names one, the same.", "type": "string", "minLength": 1, "maxLength": 64}
        }
      }
    }
  }
}`

// Operation is describe, as the collector declares it.
var Operation = collector.Operation{
	Name: Name,
	Description: "Describes a vulnerability from the vulnerability database, offline: the description, CVSS, known " +
		"exploitation, EPSS and references, and what each provider says of a fix, per distribution release or " +
		"ecosystem. For each package given, fixedForInstalled says whether the provider of the package's own " +
		"distribution or ecosystem has fixed it at the installed version: Yes, No or Unknown. Only the entries " +
		"that answer for a package given are listed, and the entries that name a package that none answers for, " +
		"at most 8 for each; the entries that answer for no package given are counted per provider in " +
		"otherProviders. The advisory of a language package is often listed under the ecosystem's own ID, such as " +
		"a GHSA or GO ID, which the case file may name: give it and the other IDs of the vulnerability in aliases.",
	Role:            collector.RoleHub,
	Produces:        []string{evidence.TypeDescription},
	ParameterSchema: []byte(parameterSchema),
}

// parameters are describe's parameters.
type parameters struct {
	VulnerabilityID string                      `json:"vulnerabilityID"`
	Aliases         []string                    `json:"aliases"`
	Packages        []evidence.DescribedPackage `json:"packages"`
}

// Invoke runs describe on the database of g, which the caller holds for reading, and returns one event about
// vulnerability/<ID>, with the options. Parameters that describe can't take fail with InvalidInput before Grype runs,
// and an ID that the database doesn't hold fails with NotFound, never as an empty answer. An error is for no answer:
// Grype that fails, or an output that isn't what it prints.
func Invoke(ctx context.Context, g grype.Grype, req collector.InvokeRequest, opts ...evidence.Option) (
	[]cloudevents.Event, *collector.Failure, error) {
	params, asked, why := parametersOf(req.Parameters)
	if why != "" {
		return nil, &collector.Failure{Reason: reasonInvalidInput, Message: why}, nil
	}
	records, rows, err := search(ctx, g, params.VulnerabilityID, params.Aliases)
	if err != nil {
		return nil, nil, fmt.Errorf("describe a vulnerability: %w", err)
	}
	if len(records) == 0 {
		return nil, &collector.Failure{Reason: reasonNotFound,
			Message: "the vulnerability database holds no vulnerability of the ID"}, nil
	}
	d := describe(params, asked, records, rows)
	e, err := evidence.New(evidence.TypeDescription, subjectPrefix+params.VulnerabilityID, d, opts...)
	if err == nil {
		err = evidence.Validate(e)
	}
	if err != nil {
		return nil, &collector.Failure{Reason: reasonInternal,
			Message: "what the database holds can't be made into evidence"}, nil
	}
	p, err := evidence.ToProto(e)
	if err != nil {
		return nil, nil, fmt.Errorf("measure the description: %w", err)
	}
	if proto.Size(&collectorv1alpha1.InvokeResponse{Item: &collectorv1alpha1.InvokeResponse_Event{Event: p}}) >
		collector.MaxMessageSize {
		return nil, &collector.Failure{Reason: reasonTooLarge,
			Message: "the description is more than a message of the collector API holds"}, nil
	}
	return []cloudevents.Event{e}, nil, nil
}

// parametersOf reads the parameters, and each package as Grype reads it, or says why it can't in a fixed text: the
// parameters come from a model, and repeat nothing of them.
func parametersOf(raw json.RawMessage) (parameters, []installed, string) {
	var params parameters
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&params) != nil || !idPattern.MatchString(params.VulnerabilityID) {
		return parameters{}, nil, "the parameters are a vulnerability ID, such as CVE-2026-0001, and packages"
	}
	if len(params.Aliases) > maxAliases {
		return parameters{}, nil, fmt.Sprintf("describe takes %d aliases at most", maxAliases)
	}
	for _, a := range params.Aliases {
		if !idPattern.MatchString(a) {
			return parameters{}, nil, "an alias is a vulnerability ID, such as GHSA-xxxx-xxxx-xxxx"
		}
	}
	if len(params.Packages) > maxPackages {
		return parameters{}, nil, fmt.Sprintf("describe takes %d packages at most", maxPackages)
	}
	asked := make([]installed, 0, len(params.Packages))
	for i, p := range params.Packages {
		in, ok := installedOf(p)
		if !ok || p.Name == "" || p.Type == "" {
			return parameters{}, nil, fmt.Sprintf("package %d has no name or type, or its purl names another "+
				"package, or none that Grype reads", i)
		}
		asked = append(asked, in)
	}
	return params, asked, ""
}

// search runs Grype's searches for the ID and the aliases that were given, and again with the aliases that its records
// name, such as the CVE of a GitHub advisory, which the providers of a distribution list it under. The aliases of an
// alias are not searched.
func search(ctx context.Context, g grype.Grype, id string, given []string) ([]record, []row, error) {
	ids := []string{id}
	for _, a := range given {
		if !slices.ContainsFunc(ids, func(i string) bool { return strings.EqualFold(i, a) }) {
			ids = append(ids, a)
		}
	}
	records, rows, err := searchOnce(ctx, g, ids...)
	if err != nil || len(records) == 0 {
		return records, rows, err
	}
	searched := len(ids)
	for _, a := range aliasesOf(id, records) {
		if !strings.HasPrefix(a, "-") && !slices.ContainsFunc(ids, func(i string) bool { return strings.EqualFold(i, a) }) {
			ids = append(ids, a)
		}
	}
	if len(ids) == searched {
		return records, rows, nil
	}
	return searchOnce(ctx, g, ids...)
}

func searchOnce(ctx context.Context, g grype.Grype, ids ...string) ([]record, []row, error) {
	recordsJSON, packagesJSON, err := g.Search(ctx, ids...)
	if err != nil {
		return nil, nil, err
	}
	return parse(recordsJSON, packagesJSON)
}

// aliasesOf returns the IDs that the records name besides id, their own and their aliases, each once, sorted.
func aliasesOf(id string, records []record) []string {
	var aliases []string
	for _, r := range records {
		for _, a := range append([]string{r.ID}, r.Aliases...) {
			if a != "" && !strings.EqualFold(a, id) {
				aliases = append(aliases, a)
			}
		}
	}
	slices.Sort(aliases)
	return slices.Compact(aliases)
}

// describe makes the description of the records and rows, for the packages asked about.
func describe(params parameters, asked []installed, records []record, rows []row) evidence.Description {
	id := params.VulnerabilityID
	// The records of the ID asked about come first, and NVD's first among them: its description of a CVE, and the
	// advisory's own of a GitHub advisory.
	slices.SortStableFunc(records, func(a, b record) int {
		return cmp.Or(compareBool(!strings.EqualFold(a.ID, id), !strings.EqualFold(b.ID, id)),
			compareBool(a.Provider != nvdProvider, b.Provider != nvdProvider),
			cmp.Compare(a.Provider, b.Provider), cmp.Compare(a.ID, b.ID))
	})
	d := evidence.Description{VulnerabilityID: id, Aliases: aliasesOf(id, records), Packages: params.Packages}
	d.Providers, d.OtherProviders = providersOf(asked, rows)
	// The description and the references are those of the asked ID's records and of the listed entries' providers.
	listed := map[string]bool{}
	for _, p := range d.Providers {
		listed[p.Provider] = true
	}
	for _, r := range records {
		if d.Description == "" && listed[r.Provider] {
			d.Description = strings.TrimSpace(r.Description)
		}
	}
	var epss []string
	for _, r := range records {
		if d.Description == "" {
			d.Description = strings.TrimSpace(r.Description)
		}
		d.KnownExploited = d.KnownExploited || len(r.KnownExploited) > 0
		for _, ref := range r.Refs {
			if ref.URL != "" && (strings.EqualFold(r.ID, id) || listed[r.Provider]) && !slices.Contains(d.References, ref.URL) {
				d.References = append(d.References, ref.URL)
			}
		}
		for _, s := range r.Severities {
			var score cvss
			if !strings.EqualFold(s.Scheme, cvssScheme) || json.Unmarshal(s.Value, &score) != nil {
				continue
			}
			v := evidence.CVSS{Version: score.Version, Vector: score.Vector}
			if v.Version != "" && v.Vector != "" && !slices.Contains(d.CVSS, v) {
				d.CVSS = append(d.CVSS, v)
			}
		}
		for _, e := range r.EPSS {
			if e.CVE != "" && !slices.Contains(epss, e.CVE) {
				epss = append(epss, e.CVE)
			}
		}
	}
	setEPSS(&d, records, epss)
	return d
}

// setEPSS sets the EPSS score of the ID's own CVE, or of the one CVE that the records score, such as the CVE of a
// GitHub advisory. Of several CVEs that aren't the ID, none is the vulnerability's.
func setEPSS(d *evidence.Description, records []record, cves []string) {
	cve := d.VulnerabilityID
	if !slices.ContainsFunc(cves, func(c string) bool { return strings.EqualFold(c, cve) }) {
		if len(cves) != 1 {
			return
		}
		cve = cves[0]
	}
	for _, r := range records {
		for _, e := range r.EPSS {
			if strings.EqualFold(e.CVE, cve) && e.Date != "" {
				permille := grype.Permille(e.EPSS)
				d.EPSSPermille, d.EPSSDate = &permille, e.Date
				return
			}
		}
	}
}

// providersOf lists the entries that answer for an asked package, and for each asked package that none answers for,
// at most maxNamed that name it. It counts the rest per provider. An entry that is left out says Unknown for every
// asked package, so no Yes or No is hidden.
func providersOf(asked []installed, rows []row) ([]evidence.ProviderFix, []evidence.ProviderCount) {
	entries := entriesOf(asked, rows)
	keep := map[*entry]bool{}
	for _, e := range entries {
		keep[e] = e.answers
	}
	for i, in := range asked {
		named, answered := 0, false
		for _, e := range entries {
			answered = answered || e.answeredBy[i]
		}
		for _, e := range entries {
			if !answered && named < maxNamed && in.names(e.fix.Package) {
				keep[e] = true
				named++
			}
		}
	}
	providers := make([]evidence.ProviderFix, 0, len(entries))
	counts := map[string]int32{}
	for _, e := range entries {
		if keep[e] {
			providers = append(providers, e.fix)
		} else {
			counts[e.fix.Provider]++
		}
	}
	others := make([]evidence.ProviderCount, 0, len(counts))
	for _, p := range slices.Sorted(maps.Keys(counts)) {
		others = append(others, evidence.ProviderCount{Provider: p, Entries: counts[p]})
	}
	return providers, others
}

// entry is what one provider says of one package in one namespace, in its records of one vulnerability.
type entry struct {
	fix    evidence.ProviderFix
	ranges []versionRange
	// answers is true when the entry speaks for an asked package's distribution or ecosystem and names it.
	answers bool
	// answeredBy are the asked packages that it answers for, by their index.
	answeredBy map[int]bool
}

// entriesOf groups the rows by provider, vulnerability, namespace and package, and answers for each asked package,
// in each entry whose namespace speaks for it and that names it, from all of the provider's rows of the vulnerability
// that do (fixedForInstalled). The rows of one vulnerability say nothing of another's fix, so each entry answers from
// its own vulnerability's rows, which it names. The entries that answer for an asked package come first.
func entriesOf(asked []installed, rows []row) []*entry {
	type key struct{ provider, vulnerability, namespace, name string }
	var entries []*entry
	type source struct{ provider, vulnerability string }
	byKey := map[key]*entry{}
	bySource := map[source][]row{}
	for _, r := range rows {
		k := key{r.provider, r.vulnerability, r.namespace, r.name}
		if byKey[k] == nil {
			byKey[k] = &entry{fix: evidence.ProviderFix{Provider: r.provider, VulnerabilityID: r.vulnerability,
				Namespace: r.namespace, Package: r.name}, answeredBy: map[int]bool{}}
			entries = append(entries, byKey[k])
		}
		byKey[k].ranges = append(byKey[k].ranges, r.ranges...)
		s := source{r.provider, r.vulnerability}
		bySource[s] = append(bySource[s], r)
	}
	// The answer of a provider for a package, in its records of one vulnerability, is one, whichever of its entries
	// that speak for the package shows it.
	answers := make([]map[source]string, len(asked))
	for i, in := range asked {
		answers[i] = map[source]string{}
		for s, sourceRows := range bySource {
			answers[i][s] = in.fixedForInstalled(sourceRows)
		}
	}
	for _, e := range entries {
		e.fix.FixState, e.fix.FixedVersions = fixOf(e.ranges)
		for i, in := range asked {
			answer := evidence.FixedForInstalledUnknown
			if in.names(e.fix.Package) && in.speaksFor(e.fix.Namespace) {
				answer = answers[i][source{e.fix.Provider, e.fix.VulnerabilityID}]
				e.answers = true
				e.answeredBy[i] = true
			}
			e.fix.Packages = append(e.fix.Packages, evidence.PackageFix{Name: in.asked.Name, Version: in.asked.Version,
				FixedForInstalled: answer})
		}
	}
	slices.SortStableFunc(entries, func(a, b *entry) int {
		return cmp.Or(compareBool(!a.answers, !b.answers), cmp.Compare(a.fix.Provider, b.fix.Provider),
			cmp.Compare(a.fix.Namespace, b.fix.Namespace), cmp.Compare(a.fix.Package, b.fix.Package),
			cmp.Compare(a.fix.VulnerabilityID, b.fix.VulnerabilityID))
	})
	return entries
}

// fixOf returns the fix state of the ranges, as Grype states a vulnerability's: fixed when a range names a fix, else
// the state of the last range that has one, and the fixed versions, each once.
func fixOf(ranges []versionRange) (string, []string) {
	state := ""
	var versions []string
	for _, r := range ranges {
		switch {
		case r.Fix == nil:
		case r.Fix.State == fixedState:
			state = fixedState
			if r.Fix.Version != "" && !slices.Contains(versions, r.Fix.Version) {
				versions = append(versions, r.Fix.Version)
			}
		case state != fixedState:
			state = r.Fix.State
		}
	}
	return state, versions
}

// compareBool orders false before true.
func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	}
	return 1
}
