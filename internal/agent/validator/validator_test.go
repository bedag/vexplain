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

package validator_test

import (
	"cmp"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/agent/ledger"
	"github.com/bedag/vexplain/internal/agent/validator"
	"github.com/bedag/vexplain/internal/agent/verdict"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
)

const (
	vulnerability = "CVE-2026-0001"
	alias         = "GHSA-aaaa-bbbb-cccc"
	// sibling is a vulnerability that the case's records name, and which isn't the case's.
	sibling  = "CVE-2026-9999"
	describe = "vulnerabilities__describe"
	debian   = "debian"
	ubuntu   = "ubuntu"
	// The checks that the tests expect.
	checkCitation, checkFixed, checkExplainable = "Citation", "FixedForInstalled", "Explainable"
	yes, no, unk                                = sdkevidence.FixedForInstalledYes, sdkevidence.FixedForInstalledNo, sdkevidence.FixedForInstalledUnknown
)

var (
	notAffected = string(inventoryv1alpha1.VEXStatusNotAffected)
	fixed       = string(inventoryv1alpha1.VEXStatusFixed)
	affected    = string(inventoryv1alpha1.VEXStatusAffected)
	vcnp        = string(inventoryv1alpha1.VEXJustificationVulnerableCodeNotPresent)

	brotli = validator.Package{Name: "libbrotli1", Version: "1.0.9-2", Type: "deb",
		PURL: "pkg:deb/debian/libbrotli1@1.0.9-2?arch=amd64&distro=debian-12&upstream=brotli", Distro: "debian-12"}
	zlib = validator.Package{Name: "zlib1g", Version: "1.2.13-1", Type: "deb",
		PURL: "pkg:deb/debian/zlib1g@1.2.13-1?arch=amd64&distro=debian-12&upstream=zlib", Distro: "debian-12"}
)

// theCase is a case of the vulnerability in two packages.
func theCase(holds ...string) validator.Case {
	return validator.Case{VulnerabilityID: vulnerability, Aliases: []string{alias},
		Packages: []validator.Package{brotli, zlib}, AgentHolds: holds}
}

// asked is a package as the agent asks describe about it: as the SBOM has it, by its purl.
func asked(p validator.Package) sdkevidence.DescribedPackage {
	return sdkevidence.DescribedPackage{Name: p.Name, Version: p.Version, Type: p.Type, PURL: p.PURL}
}

// provider is a provider of describe's answer, and its answer for each package asked about, in order. id is the
// vulnerability whose records the answer rests on, when it isn't the one described.
type provider struct {
	name    string
	answers []string
	id      string
}

// described returns describe's answer about the vulnerability id for the packages, with the providers' answers.
func described(t *testing.T, id string, packages []sdkevidence.DescribedPackage, providers ...provider) []byte {
	t.Helper()
	d := sdkevidence.Description{VulnerabilityID: id, Packages: packages}
	for _, p := range providers {
		fix := sdkevidence.ProviderFix{Provider: p.name, VulnerabilityID: cmp.Or(p.id, id),
			Namespace: p.name + ":distro:debian:12", Package: "brotli", FixState: "fixed", FixedVersions: []string{"1.0.9-1"}}
		for i, answer := range p.answers {
			fix.Packages = append(fix.Packages, sdkevidence.PackageFix{Name: packages[i].Name,
				Version: packages[i].Version, FixedForInstalled: answer})
		}
		d.Providers = append(d.Providers, fix)
	}
	out, err := json.Marshal(d)
	require.NoError(t, err)
	return out
}

// both is describe's answer that the one provider has fixed the vulnerability for both packages of the case.
func both(t *testing.T) []byte {
	return described(t, vulnerability, []sdkevidence.DescribedPackage{asked(brotli), asked(zlib)}, provider{name: debian, answers: []string{yes, yes}})
}

// ledgerOf returns a ledger that holds a call of the tool for each output, of known trust: ev-1, ev-2 and so on.
func ledgerOf(tool string, outputs ...[]byte) *ledger.Ledger {
	l := ledger.New("case", nil, 16000)
	for _, out := range outputs {
		l.Add(tool, json.RawMessage(`{}`), out, ledger.Known, 0)
	}
	return l
}

// verdictOf returns a verdict of the status, with one claim that cites the IDs.
func verdictOf(status, justification string, ids ...string) verdict.Verdict {
	return verdict.Verdict{Status: status, Justification: justification, Step: "nothing to do",
		Summary: "The installed versions hold the fix (ev-1).",
		Claims:  []verdict.Claim{{Text: "the distribution fixed it at the installed versions", Evidence: ids}}}
}

// forBoth are the checks of a verdict that nothing shows the fix for, for either package of the case.
var forBoth = []string{checkFixed, checkFixed}

// checks returns the checks of the problems.
func checks(problems []verdict.Problem) []string {
	out := make([]string, 0, len(problems))
	for _, p := range problems {
		out = append(out, p.Check)
	}
	return out
}

func TestAClaimMustCiteAnEntryThatExists(t *testing.T) {
	v := validator.New(theCase())
	l := ledgerOf("search_evidence", []byte("packages[0].name = \"libbrotli1\"\n"))

	require.Empty(t, v.Validate(verdictOf(affected, "", "ev-1"), l))

	problems := v.Validate(verdictOf(affected, "", "ev-1", "ev-9"), l)
	require.Equal(t, []string{checkCitation}, checks(problems))
	require.Contains(t, problems[0].Message, "ev-9")

	require.Equal(t, []string{checkCitation}, checks(v.Validate(verdictOf(affected, ""), l)), "a claim that cites nothing")
	none := verdictOf(affected, "", "ev-1")
	none.Claims = nil
	require.Equal(t, []string{checkCitation}, checks(v.Validate(none, l)), "a verdict without claims")
}

func TestNotAffectedNeedsDescribeToSayFixedForEveryPackage(t *testing.T) {
	v := validator.New(theCase())
	for _, status := range []string{notAffected, fixed} {
		justification := ""
		if status == notAffected {
			justification = vcnp
		}
		t.Run(status, func(t *testing.T) {
			require.Empty(t, v.Validate(verdictOf(status, justification, "ev-1"), ledgerOf(describe, both(t))))

			oneOfTwo := described(t, vulnerability, []sdkevidence.DescribedPackage{asked(brotli), asked(zlib)},
				provider{name: debian, answers: []string{yes, unk}})
			problems := v.Validate(verdictOf(status, justification, "ev-1"), ledgerOf(describe, oneOfTwo))
			require.Equal(t, []string{checkFixed}, checks(problems), "Yes for one package of two")
			require.Contains(t, problems[0].Message, zlib.Name)
			require.NotContains(t, problems[0].Message, brotli.Name)
			require.Contains(t, problems[0].Message, "distribution", "the message names every argument that counts")

			require.Empty(t, v.Validate(verdictOf(status, justification, "ev-1", "ev-2"), ledgerOf(describe,
				described(t, vulnerability, []sdkevidence.DescribedPackage{asked(brotli)}, provider{name: debian, answers: []string{yes}}),
				described(t, vulnerability, []sdkevidence.DescribedPackage{asked(zlib)}, provider{name: debian, answers: []string{yes}}))),
				"each package in a call of its own")

			disagree := described(t, vulnerability, []sdkevidence.DescribedPackage{asked(brotli), asked(zlib)},
				provider{name: debian, answers: []string{yes, yes}}, provider{name: ubuntu, answers: []string{unk, no}})
			require.Equal(t, []string{checkFixed},
				checks(v.Validate(verdictOf(status, justification, "ev-1"), ledgerOf(describe, disagree))),
				"a provider that says No outweighs one that says Yes")

			uncited := ledgerOf(describe, both(t),
				described(t, vulnerability, []sdkevidence.DescribedPackage{asked(zlib)}, provider{name: ubuntu, answers: []string{no}}))
			require.Equal(t, []string{checkFixed}, checks(v.Validate(verdictOf(status, justification, "ev-1"), uncited)),
				"a No in the ledger counts, cited or not")

			require.Equal(t, forBoth, checks(v.Validate(verdictOf(status, justification, "ev-1"),
				ledgerOf("search_evidence", both(t)))), "only describe's answer counts")
			require.Equal(t, forBoth,
				checks(v.Validate(verdictOf(status, justification, "ev-1"), ledgerOf(describe, []byte("not JSON")))))
		})
	}

	t.Run("the packages asked about are the case's", func(t *testing.T) {
		for name, change := range map[string]func(*sdkevidence.DescribedPackage){
			"another version": func(p *sdkevidence.DescribedPackage) { p.Version = "1.0.9-9"; p.PURL = "" },
			"another name":    func(p *sdkevidence.DescribedPackage) { p.Name = "brotli"; p.PURL = "" },
			"another type":    func(p *sdkevidence.DescribedPackage) { p.Type = "rpm"; p.PURL = "" },
			"another release": func(p *sdkevidence.DescribedPackage) { p.Distro = "debian-13"; p.PURL = "" },
			"another source package": func(p *sdkevidence.DescribedPackage) {
				p.PURL = "pkg:deb/debian/libbrotli1@1.0.9-2?arch=amd64&distro=debian-12&upstream=brotli%409.9"
			},
			"another release in the purl": func(p *sdkevidence.DescribedPackage) {
				p.PURL = "pkg:deb/debian/libbrotli1@1.0.9-2?arch=amd64&distro=debian-13&upstream=brotli"
			},
		} {
			changed := asked(brotli)
			change(&changed)
			out := described(t, vulnerability, []sdkevidence.DescribedPackage{changed, asked(zlib)},
				provider{name: debian, answers: []string{yes, yes}})
			require.Equal(t, []string{checkFixed},
				checks(v.Validate(verdictOf(fixed, "", "ev-1"), ledgerOf(describe, out))), name)
		}

		byName := sdkevidence.DescribedPackage{Name: brotli.Name, Version: brotli.Version, Type: brotli.Type,
			Distro: brotli.Distro}
		out := described(t, vulnerability, []sdkevidence.DescribedPackage{byName, asked(zlib)},
			provider{name: debian, answers: []string{yes, yes}})
		require.Equal(t, []string{checkFixed}, checks(v.Validate(verdictOf(fixed, "", "ev-1"), ledgerOf(describe, out))),
			"without the purl that the SBOM gives the package")

		withoutPURL := brotli
		withoutPURL.PURL = ""
		require.Empty(t, validator.New(validator.Case{VulnerabilityID: vulnerability, Packages: []validator.Package{withoutPURL}}).
			Validate(verdictOf(fixed, "", "ev-1"), ledgerOf(describe, out)),
			"by name, version, type and release, for a package that the SBOM gives no purl")
	})

	t.Run("the answer rests on the case's vulnerability", func(t *testing.T) {
		packages := []sdkevidence.DescribedPackage{asked(brotli), asked(zlib)}
		out := described(t, alias, packages, provider{name: debian, answers: []string{yes, yes}})
		require.Empty(t, v.Validate(verdictOf(fixed, "", "ev-1"), ledgerOf(describe, out)), "an alias of the case")

		out = described(t, sibling, packages, provider{name: debian, answers: []string{yes, yes}})
		require.Equal(t, forBoth, checks(v.Validate(verdictOf(fixed, "", "ev-1"), ledgerOf(describe, out))),
			"another vulnerability")

		out = described(t, vulnerability, packages, provider{name: debian, answers: []string{yes, yes}, id: sibling})
		require.Equal(t, forBoth, checks(v.Validate(verdictOf(fixed, "", "ev-1"), ledgerOf(describe, out))),
			"a Yes from the records of another vulnerability that describe found under the case's")

		out = described(t, sibling, packages, provider{name: debian, answers: []string{yes, yes}, id: vulnerability})
		require.Empty(t, v.Validate(verdictOf(fixed, "", "ev-1"), ledgerOf(describe, out)),
			"a Yes from the case's own records, found under another ID")

		siblingNo := described(t, vulnerability, []sdkevidence.DescribedPackage{asked(zlib)},
			provider{name: ubuntu, answers: []string{no}, id: sibling})
		require.Equal(t, []string{checkFixed},
			checks(v.Validate(verdictOf(fixed, "", "ev-1"), ledgerOf(describe, described(t, vulnerability, packages,
				provider{name: debian, answers: []string{yes, yes}}), siblingNo))),
			"a No holds the case open, whatever vulnerability its records are of")
	})

	t.Run("a case without packages", func(t *testing.T) {
		empty := validator.New(validator.Case{VulnerabilityID: vulnerability})
		require.Equal(t, []string{checkFixed},
			checks(empty.Validate(verdictOf(fixed, "", "ev-1"), ledgerOf(describe, both(t)))))
	})
}

func TestNotAffectedTakesOnlyVulnerableCodeNotPresent(t *testing.T) {
	v := validator.New(theCase())
	l := ledgerOf(describe, both(t))

	require.Empty(t, v.Validate(verdictOf(notAffected, vcnp, "ev-1"), l))
	for _, j := range []string{"", string(inventoryv1alpha1.VEXJustificationComponentNotPresent),
		string(inventoryv1alpha1.VEXJustificationVulnerableCodeNotInExecutePath)} {
		require.Equal(t, []string{"Justification"}, checks(v.Validate(verdictOf(notAffected, j, "ev-1"), l)), j)
	}
	require.Equal(t, []string{"Justification"}, checks(v.Validate(verdictOf(affected, vcnp, "ev-1"), l)),
		"only not affected takes a justification")
	require.Equal(t, []string{"Status"}, checks(v.Validate(verdictOf("Maybe", "", "ev-1"), l)))
}

func TestAFetchedPageNeverSupportsNotAffected(t *testing.T) {
	v := validator.New(theCase())

	page := ledger.New("case", nil, 16000)
	page.Add("advisories__fetch", json.RawMessage(`{}`), both(t), ledger.External, 0)
	require.Equal(t, forBoth, checks(v.Validate(verdictOf(notAffected, vcnp, "ev-1"), page)))

	external := ledger.New("case", nil, 16000)
	external.Add(describe, json.RawMessage(`{}`), both(t), ledger.External, 0)
	require.Equal(t, forBoth, checks(v.Validate(verdictOf(fixed, "", "ev-1"), external)),
		"an output of external trust, such as a failed call's, under describe's name")

	require.Empty(t, v.Validate(verdictOf(affected, "", "ev-1"), page), "it can support affected")

	held := ledgerOf(describe, both(t))
	held.Add("advisories__fetch", json.RawMessage(`{}`), described(t, vulnerability,
		[]sdkevidence.DescribedPackage{asked(zlib)}, provider{name: ubuntu, answers: []string{no}}), ledger.External, 0)
	require.Equal(t, []string{checkFixed}, checks(v.Validate(verdictOf(fixed, "", "ev-1"), held)),
		"a No of external trust in the shape of describe's answer holds the case open")
}

func TestAHoldAgainstAllRejectsNotAffectedAndFixed(t *testing.T) {
	v := validator.New(theCase("completeness-guard"))
	l := ledgerOf(describe, both(t))

	problems := v.Validate(verdictOf(notAffected, vcnp, "ev-1"), l)
	require.Equal(t, []string{"AgentHold"}, checks(problems))
	require.Contains(t, problems[0].Message, "completeness-guard")
	require.Equal(t, []string{"AgentHold"}, checks(v.Validate(verdictOf(fixed, "", "ev-1"), l)))
	require.Empty(t, v.Validate(verdictOf(affected, "", "ev-1"), l))
	require.Empty(t, v.Validate(verdictOf(string(inventoryv1alpha1.VEXStatusUnderInvestigation), "", "ev-1"), l))
}

// A No about the case's package holds the case open however describe was asked about it: by the purl, or by name,
// version, type and release without one, which can't show a fix.
func TestANoAskedWithoutThePURLStillCounts(t *testing.T) {
	v := validator.New(theCase())
	byName := sdkevidence.DescribedPackage{Name: zlib.Name, Version: zlib.Version, Type: zlib.Type, Distro: zlib.Distro}
	l := ledgerOf(describe, both(t),
		described(t, vulnerability, []sdkevidence.DescribedPackage{byName}, provider{name: ubuntu, answers: []string{no}}))

	problems := v.Validate(verdictOf(fixed, "", "ev-1"), l)
	require.Equal(t, []string{checkFixed}, checks(problems))
	require.Contains(t, problems[0].Message, "ev-2")
}

// An output of several JSON documents, as the events of one collector answer are written, is read document by document
// for a No. A Yes needs the one answer of describe, whole.
func TestANoInAnOutputOfSeveralDocumentsCounts(t *testing.T) {
	v := validator.New(theCase())
	zlibNo := described(t, vulnerability, []sdkevidence.DescribedPackage{asked(zlib)}, provider{name: ubuntu, answers: []string{no}})
	several := func(documents ...[]byte) []byte {
		var out []byte
		for _, d := range documents {
			out = append(append(out, d...), '\n')
		}
		return out
	}

	l := ledgerOf(describe, both(t), several(both(t), zlibNo))
	require.Equal(t, []string{checkFixed}, checks(v.Validate(verdictOf(fixed, "", "ev-1"), l)),
		"the second document of ev-2 says No")

	l = ledgerOf(describe, several(both(t), []byte(`{"vulnerabilityID": "`+vulnerability+`", "providers": []}`)))
	require.Equal(t, forBoth, checks(v.Validate(verdictOf(fixed, "", "ev-1"), l)),
		"a Yes in an output that isn't one answer of describe")
}

// An answer that names no vulnerability never counts as the case's, even for a case without an ID.
func TestAYesWithoutAVulnerabilityIDNeverCounts(t *testing.T) {
	v := validator.New(validator.Case{Packages: []validator.Package{brotli, zlib}, Aliases: []string{""}})
	out := described(t, "", []sdkevidence.DescribedPackage{asked(brotli), asked(zlib)},
		provider{name: debian, answers: []string{yes, yes}})
	require.Equal(t, forBoth, checks(v.Validate(verdictOf(fixed, "", "ev-1"), ledgerOf(describe, out))))
}

// guidance is an investigation's guidance, as a person writes it.
const guidance = "Busybox wget is reached only from the entrypoint script, which fetches the configuration at start. " +
	"Check /usr/lib/nginx/modules/ngx_http_v2_module.so in the image."

// explained returns an affected verdict with the summary, and one claim of the text that cites the IDs.
func explained(summary, claim string, ids ...string) verdict.Verdict {
	return verdict.Verdict{Status: affected, Step: "Use curl instead of busybox wget.", Summary: summary,
		Claims: []verdict.Claim{{Text: claim, Evidence: ids}}}
}

// A verdict must be explainable from its claims and their evidence alone: it still holds once its investigation is
// gone, and no ledger entry holds the guidance. So the summary and the claims neither name the guidance nor repeat it,
// except where the evidence that they cite holds the same words.
func TestAVerdictThatUsesTheGuidanceIsRefused(t *testing.T) {
	l := ledger.New("case", nil, 16000)
	l.Add("search_evidence", json.RawMessage(`{}`),
		[]byte("contents[3].path = \"/usr/lib/nginx/modules/ngx_http_v2_module.so\"\n"), ledger.Known, 0) // ev-1
	l.Add("advisories__fetch", json.RawMessage(`{}`), []byte("Debian gives no guidance for bookworm yet."),
		ledger.External, 0) // ev-2
	withGuidance := theCase()
	withGuidance.Guidance = guidance
	v := validator.New(withGuidance)
	const fact = "busybox 1.36.1 is installed"
	const path = "the image's contents hold /usr/lib/nginx/modules/ngx_http_v2_module.so"

	require.Empty(t, v.Validate(explained("Busybox 1.36.1 is affected (ev-1).", fact, "ev-1"), l))
	require.Equal(t, []string{checkExplainable}, checks(v.Validate(explained("Per the GUIDANCE, wget is safe.", fact, "ev-1"), l)),
		"naming the guidance, in any case")
	require.Equal(t, []string{checkExplainable}, checks(v.Validate(explained("Busybox is affected.",
		"the guidance's check found nothing", "ev-1"), l)), "in a claim too")
	require.Equal(t, []string{checkExplainable}, checks(v.Validate(explained("Busybox is affected.",
		"wget is reached ONLY from the entrypoint-script, which fetches the configuration", "ev-1"), l)),
		"a run of 8 of the guidance's words, across case and punctuation")
	require.Empty(t, v.Validate(explained("Busybox is affected.",
		"curl is reached only from the entrypoint script, as ev-1 shows", "ev-1"), l), "a run of 7 words isn't one of 8")

	require.Empty(t, v.Validate(explained("Busybox is affected.", path, "ev-1"), l),
		"a run that the cited evidence holds is the evidence's, which a claim may quote")
	require.Equal(t, []string{checkExplainable}, checks(v.Validate(explained("Busybox is affected.", path, "ev-2"), l)),
		"evidence that the claim doesn't cite doesn't vouch for its words")
	require.Empty(t, v.Validate(explained("The image holds /usr/lib/nginx/modules/ngx_http_v2_module.so.", path, "ev-1"), l),
		"the summary may quote what a claim cites")

	require.Empty(t, v.Validate(explained("Busybox is affected.", "the tracker gives no guidance for bookworm", "ev-2"), l),
		"the cited evidence's own words around the word")
	require.Equal(t, []string{checkExplainable}, checks(v.Validate(explained("Per the guidance, wget is safe.",
		"the tracker gives no guidance for bookworm", "ev-2"), l)),
		"a page that speaks of guidance doesn't let the summary lean on the investigation's")

	require.Equal(t, []string{checkExplainable}, checks(v.Validate(explained("Guidance says wget is safe.", fact, "ev-1"), l)),
		"the word at the start of a text")
	require.Equal(t, []string{checkExplainable}, checks(v.Validate(explained("Busybox is affected.",
		"no guidance for bookworm, and the guidance says so", "ev-2"), l)), "each time the word comes")
	require.Equal(t, []string{checkCitation, checkExplainable}, checks(v.Validate(explained("Busybox is affected.",
		"the tracker gives no guidance for bookworm", "ev-9"), l)), "an ID that the ledger lacks vouches for nothing")
	uncited := explained("The tracker gives no guidance for bookworm.", fact, "ev-1")
	require.Equal(t, []string{checkExplainable}, checks(v.Validate(uncited, l)),
		"the summary stands only on what the claims cite")

	step := explained("Busybox 1.36.1 is affected (ev-1).", fact, "ev-1")
	step.Step = "As the guidance says: busybox wget is reached only from the entrypoint script; use curl."
	require.Empty(t, v.Validate(step, l), "the next step may name the guidance's mitigation")

	without := validator.New(theCase())
	require.Empty(t, without.Validate(explained("The house guidance says so.",
		"wget is reached only from the entrypoint script, which fetches the configuration", "ev-1"), l),
		"a case without an investigation's guidance has nothing that a deleted investigation could take with it")
}
