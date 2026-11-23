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

// Package validator checks the agent's verdict on a case before the core records it (main design 6.7; design of the
// agent on image cases, 5.5). It guards against the worst error, a false "not affected": a verdict that silences a
// finding, not_affected or fixed, stands only on describe's answers, of known trust, that every package of the case
// has the fix. Its table is in table.go.
package validator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/bedag/vexplain/internal/agent/core"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/agent/verdict"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

// Case is what the validator knows of a case.
type Case struct {
	// VulnerabilityID is the case's vulnerability, and Aliases are the aliases that its findings name: an answer of
	// describe about any of them is about the case.
	VulnerabilityID string
	Aliases         []string
	// Packages are the packages of the case's findings.
	Packages []Package
	// AgentHolds are the rules that hold a finding of the case against the agent, as the findings' agentHolds name
	// them.
	AgentHolds []string
	// Guidance is the guidance of the investigation that the case was judged with, if any.
	Guidance string
}

// Package is a package of a case, as the SBOM has it.
type Package struct {
	Name, Version, Type string
	// PURL is the package's purl in the SBOM, and Distro the distribution and release that describe reads for it, such
	// as debian-12: the one that its purl names, or the image's for an OS package whose purl names none. It is empty
	// for a package of an ecosystem.
	PURL, Distro string
}

// The checks of the problems, a fixed set that a metric can count by.
const (
	checkStatus            = "Status"
	checkJustification     = "Justification"
	checkCitation          = "Citation"
	checkAgentHold         = "AgentHold"
	checkFixedForInstalled = "FixedForInstalled"
	checkExplainable       = "Explainable"
)

// Checks lists every check, for a metric that starts each of its series at 0.
var Checks = []string{checkStatus, checkJustification, checkCitation, checkAgentHold, checkFixedForInstalled,
	checkExplainable}

// guidanceRun is how many words of the investigation's guidance in a row make a verdict's text a repetition of it.
// Shorter runs would match common phrases.
const guidanceRun = 8

// words returns the words of the text, lowercased: its runs of letters and digits.
func words(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

// explainer checks that a text of a verdict stands on the ledger entries that it cites, without the investigation's
// guidance, which no entry holds and which may be gone with its investigation.
type explainer struct {
	// runs are the guidance's runs of guidanceRun words, joined by a space.
	runs map[string]bool
	l    *ledger.Ledger
	// cited holds the words of each entry looked at, joined by a space and with one around them, by ID.
	cited map[string]string
}

func newExplainer(guidance string, l *ledger.Ledger) *explainer {
	x := &explainer{runs: map[string]bool{}, l: l, cited: map[string]string{}}
	all := words(guidance)
	for i := 0; i+guidanceRun <= len(all); i++ {
		x.runs[strings.Join(all[i:i+guidanceRun], " ")] = true
	}
	return x
}

// held reports whether one of the entries of the IDs holds the words of phrase in a row.
func (x *explainer) held(phrase string, ids []string) bool {
	for _, id := range ids {
		text, ok := x.cited[id]
		if !ok {
			if e, found := x.l.Entry(id); found {
				text = " " + strings.Join(words(string(e.Output)), " ") + " "
			}
			x.cited[id] = text
		}
		if strings.Contains(text, " "+phrase+" ") {
			return true
		}
	}
	return false
}

// why says why the text doesn't stand on the entries of the IDs, and "" when it does: it names a guidance, where the
// words around the name aren't the entries' own, as a tracker's "no guidance for" is; or it repeats a run of the
// investigation's guidance that the entries don't hold.
func (x *explainer) why(text string, ids []string) string {
	all := words(text)
	for i, w := range all {
		if w == "guidance" && !x.held(strings.Join(all[max(0, i-1):min(len(all), i+2)], " "), ids) {
			return "names the guidance"
		}
	}
	for i := 0; i+guidanceRun <= len(all); i++ {
		if run := strings.Join(all[i:i+guidanceRun], " "); x.runs[run] && !x.held(run, ids) {
			return "repeats the investigation's guidance"
		}
	}
	return ""
}

type validator struct{ c Case }

// New returns the validator of the case c.
func New(c Case) core.Validator { return validator{c: c} }

// Validate checks the verdict v against the table and the ledger l, and returns the problems that it finds, each
// saying what the agent can do about it.
func (val validator) Validate(v verdict.Verdict, l *ledger.Ledger) []verdict.Problem {
	req, ok := table[v.Status]
	if !ok {
		return []verdict.Problem{{Check: checkStatus, Message: "the status is none that a verdict takes"}}
	}
	var problems []verdict.Problem
	add := func(check, format string, args ...any) {
		problems = append(problems, verdict.Problem{Check: check, Message: fmt.Sprintf(format, args...)})
	}
	switch {
	case len(req.justifications) == 0 && v.Justification != "":
		add(checkJustification, "only not_affected takes a justification")
	case len(req.justifications) > 0 && !slices.Contains(req.justifications, v.Justification):
		add(checkJustification, "not_affected takes only the justification vulnerable_code_not_present, resting on "+
			"describe's answer that every package of the case has the fix")
	}
	if len(v.Claims) == 0 {
		add(checkCitation, "the verdict makes no claim: each claim cites the ledger IDs that support it")
	}
	var cited []ledger.Entry
	for i, c := range v.Claims {
		if len(c.Evidence) == 0 {
			add(checkCitation, "claim %d cites no ledger ID", i+1)
		}
		for _, id := range c.Evidence {
			e, ok := l.Entry(id)
			if !ok {
				add(checkCitation, "claim %d cites %s, which the ledger doesn't hold", i+1, id)
				continue
			}
			cited = append(cited, e)
		}
	}
	if val.c.Guidance != "" {
		const explain = "a verdict stands on its claims and their evidence alone, so leave the guidance out of the " +
			"summary and the claims; the next step may name its mitigation"
		x := newExplainer(val.c.Guidance, l)
		var all []string
		for _, c := range v.Claims {
			all = append(all, c.Evidence...)
		}
		// The summary rests on what the claims cite.
		if why := x.why(v.Summary, all); why != "" {
			add(checkExplainable, "the summary %s: %s", why, explain)
		}
		for i, c := range v.Claims {
			if why := x.why(c.Text, c.Evidence); why != "" {
				add(checkExplainable, "claim %d %s: %s", i+1, why, explain)
			}
		}
	}
	if !req.silences {
		return problems
	}
	if len(val.c.AgentHolds) > 0 {
		add(checkAgentHold, "the rules %s hold a finding of the case against the agent: the case can't be "+
			"not_affected or fixed", strings.Join(val.c.AgentHolds, ", "))
	}
	if len(val.c.Packages) == 0 {
		add(checkFixedForInstalled, "the case names no package, so no answer of describe can show a fix")
	}
	all := l.Entries()
	for _, p := range val.c.Packages {
		if why := val.fixed(p, cited, all); why != "" {
			add(checkFixedForInstalled, "%s", why)
		}
	}
	return problems
}

// fixed says why the ledger doesn't show that the package p has the fix, and "" when it does: a cited answer of
// describe says Yes for p, and nothing in the ledger in the shape of describe's answer says No. A No counts from any
// entry, cited or not, whatever its trust and whatever vulnerability its records are of, and however describe was
// asked about the package: a provider that says No outweighs one that says Yes, so that a disagreement leaves the case
// open.
func (val validator) fixed(p Package, cited, all []ledger.Entry) string {
	name := fmt.Sprintf("%s %s (%s)", p.Name, p.Version, p.Type)
	for _, e := range all {
		for _, d := range documents(e.Output) {
			if slices.ContainsFunc(answersIn(d, p.matches), func(a sdkevidence.ProviderFix) bool {
				return a.Packages[0].FixedForInstalled == sdkevidence.FixedForInstalledNo
			}) {
				return fmt.Sprintf("an answer in %s says that %s doesn't have the fix", e.ID, name)
			}
		}
	}
	for _, e := range cited {
		// Only describe's own answer, whole and of known trust, can show a fix: never a failed call, a fetched page or
		// a foreign tool's output.
		var d sdkevidence.Description
		if e.Tool != describeTool || e.Trust != ledger.Known || json.Unmarshal(e.Output, &d) != nil {
			continue
		}
		if slices.ContainsFunc(answersIn(d, p.is), func(a sdkevidence.ProviderFix) bool {
			return a.Packages[0].FixedForInstalled == sdkevidence.FixedForInstalledYes && val.about(a.VulnerabilityID)
		}) {
			return ""
		}
	}
	return fmt.Sprintf("no cited answer of describe says that %s has the fix in the records of %s or its aliases: "+
		"describe it with the package as the SBOM has it, by its name, version, type and purl, and its distribution and "+
		"release where the purl names none, and cite the answer",
		name, val.c.VulnerabilityID)
}

// documents returns the JSON documents of an output that have the shape of describe's answer. An output can hold
// several, one after the other, as the events of one collector's answer are written. Reading ends at the first that
// isn't JSON.
func documents(out []byte) []sdkevidence.Description {
	var found []sdkevidence.Description
	decoder := json.NewDecoder(bytes.NewReader(out))
	for {
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return found
		}
		var d sdkevidence.Description
		if json.Unmarshal(raw, &d) == nil {
			found = append(found, d)
		}
	}
}

// answersIn returns the providers' answers in d for the packages asked about that match accepts, each with the one
// answer for its package in Packages.
func answersIn(d sdkevidence.Description, match func(sdkevidence.DescribedPackage) bool) []sdkevidence.ProviderFix {
	var answers []sdkevidence.ProviderFix
	for i, asked := range d.Packages {
		if !match(asked) {
			continue
		}
		for _, provider := range d.Providers {
			// A provider answers for each package asked about, in the order asked.
			if i < len(provider.Packages) && provider.Packages[i].Name == asked.Name &&
				provider.Packages[i].Version == asked.Version {
				provider.Packages = provider.Packages[i : i+1]
				answers = append(answers, provider)
			}
		}
	}
	return answers
}

// about reports whether an ID is the case's vulnerability or one of the aliases that its findings name. An empty ID
// is no vulnerability's.
func (val validator) about(id string) bool {
	same := func(a string) bool { return strings.EqualFold(a, id) }
	return id != "" && (same(val.c.VulnerabilityID) || slices.ContainsFunc(val.c.Aliases, same))
}

// matches reports whether describe was asked about the package p: by its name, version and type, in its distribution
// and release, and by its purl or none. Describe's No about it, asked so, counts.
func (p Package) matches(asked sdkevidence.DescribedPackage) bool {
	return asked.Name == p.Name && asked.Version == p.Version && asked.Type == p.Type &&
		(asked.PURL == "" || asked.PURL == p.PURL) && distroOf(asked) == p.Distro
}

// is reports whether describe was asked about the package p as the case has it, with the purl that the SBOM gives
// it, so that its Yes counts. The model chooses describe's arguments, and describe compares what it is given: the
// version, and the source packages that a purl names. An answer about a version or a purl that the model made up
// shows nothing about the case.
func (p Package) is(asked sdkevidence.DescribedPackage) bool {
	return p.matches(asked) && asked.PURL == p.PURL
}

// distroOf returns the distribution and release that describe read for a package: the one given, or else the one
// that its purl names in the qualifier distro.
func distroOf(p sdkevidence.DescribedPackage) string {
	if p.Distro != "" {
		return p.Distro
	}
	return PURLDistro(p.PURL)
}

// PURLDistro returns the distribution and release that a purl names in its qualifier distro, such as debian-12, and ""
// when it names none.
func PURLDistro(purl string) string {
	_, qualifiers, found := strings.Cut(purl, "?")
	if !found {
		return ""
	}
	qualifiers, _, _ = strings.Cut(qualifiers, "#")
	values, err := url.ParseQuery(qualifiers)
	if err != nil {
		return ""
	}
	return values.Get("distro")
}
