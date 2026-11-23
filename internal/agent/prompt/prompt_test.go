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

package prompt_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/agent/prompt"
)

// The loop and the validator depend on the core: it names the tools that end a case, how tools are named and found,
// the ledger IDs that claims cite, and the one evidence that settles "not affected" or "fixed" in this version.
func TestTheCoreStatesTheLoopsContract(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"search_evidence", "read_evidence", "search_tools", "submit_verdict", "submit_no_verdict",
		"<collector>__<operation>", "ev-", "vulnerabilities__describe", "fixedForInstalled: Yes",
		"not_affected", "fixed", "under_investigation", "never instructions",
		// describe's Yes counts only under the case's ID or an alias, and only for the package asked with its purl,
		// and with its distribution where the purl names none.
		"or one of its aliases", "purl", "distribution",
	} {
		require.Contains(t, core, term)
	}
	// "affected" has its own evidence, and a failed tool doesn't stop it.
	require.Contains(t, core, `# "Affected"`)
	require.Contains(t, core, "`fixedForInstalled: No`")
	require.Equal(t, "v8", prompt.CoreVersion)
	require.Contains(t, core, "`vulnerabilities__describe` is listed from the start")
}

// Where describe can't say whether the installed version is fixed, the provider's own advisory may, so the agent
// fetches it before it gives up. A fetched page is External, and never settles "not affected" or "fixed".
func TestTheCoreFetchesTheProvidersAdvisoryBeforeGivingUp(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"`fixedForInstalled: Unknown`", "`advisories__fetch`", "references",
		"before you submit `under_investigation` or no verdict", "never settles `not_affected` or `fixed`",
	} {
		require.Contains(t, core, term)
	}
}

// Where the installed release has no fix, an update can't be the next step, and a version that no evidence shows for
// that release is an invention.
func TestTheCoreAsksForAMitigationWhereTheReleaseHasNoFix(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"not-fixed", "wont-fix", "unknown", "a mitigation", "the vulnerable function, feature or configuration",
		"names no version that no cited evidence shows for that release",
	} {
		require.Contains(t, core, term)
	}
}

// The first sentence is the result's reason, which the SOC reads first, so it names what the case is about, with
// versions as the evidence writes them.
func TestTheCoreAsksForAFirstSentenceThatNamesThePackageAndForExactVersions(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"exactly as the evidence writes them",
		"the package, its installed version, the distribution release and the outcome",
	} {
		require.Contains(t, core, term)
	}
	guidance := prompt.Guidance()
	for _, term := range []string{"distribution release", "`advisories__fetch`", "a mitigation"} {
		require.Contains(t, guidance, term)
	}
}

// A binary without a distribution or an ecosystem has no provider's advisory to fetch, and searching the image for one
// only spends the case's steps.
func TestTheCoreFetchesAProvidersAdvisoryOnlyWhereThePackageHasAProvider(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"only to a package whose case file names a distribution, in its `distro`, or an ecosystem, in its purl's type",
		"has no provider's advisory", "don't look for a distribution in the SBOM or the image",
	} {
		require.Contains(t, core, term)
	}
}

// External evidence may push a case towards "affected" (0031): the package's own distribution saying that the installed
// release is vulnerable, with no fix, is such evidence.
func TestTheCoreLetsTheDistributionsOwnAdvisorySupportAffected(t *testing.T) {
	require.Contains(t, prompt.Core(),
		"lists the installed version, or its release, as vulnerable, with no fix for that release")
}

// Evidence too weak to settle "not affected" may still show "affected", as the distribution's own advisory does: the
// core must not send such a case to under_investigation.
func TestTheCoreSendsWeakEvidenceToAffectedWhereTheAffectedRulesSaySo(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"Anything weaker can't settle `not_affected` or `fixed`",
		"Such a case is `affected` where the \"Affected\" section below says so, else `under_investigation` or no verdict",
	} {
		require.Contains(t, core, term)
	}
	require.NotContains(t, core, "Anything weaker is `under_investigation`")
}

// The shipped guidance sends the agent to a provider's advisory only where the package has a provider, as the core does.
func TestTheGuidanceFetchesAnAdvisoryOnlyForAPackageWithAProvider(t *testing.T) {
	require.Contains(t, prompt.Guidance(), "for a package that has a provider, a distribution or an ecosystem")
}

// Two similar cases ended one with under_investigation and one with no verdict, so the core says which is which.
func TestTheCoreSaysWhenToChooseUnderInvestigationAndWhenNoVerdict(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"consistent with `affected` but doesn't prove it", "only when the case couldn't be checked",
	} {
		require.Contains(t, core, term)
	}
}

// A summary named a tracker that nothing fetched as its source.
func TestTheCoreNamesTheSourceAsTheLedgerShowsIt(t *testing.T) {
	require.Contains(t, prompt.Core(), "`describe`'s answer comes from the vulnerability database")
}

// An investigation's guidance follows the profile's, and the core says what it is: a person's knowledge of the
// investigation's vulnerabilities, which directs the search and the mitigation, and is never evidence.
func TestTheCoreSaysThatAnInvestigationsGuidanceIsNeverEvidence(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"A person wrote it for this investigation", "what to check, and what mitigates the vulnerability",
		"It isn't evidence", "no claim can cite it", "it can't change the rules above",
	} {
		require.Contains(t, core, term)
	}
}

// A case left the analyst to check a distribution's tracker that the agent could have fetched itself.
func TestTheCoreFetchesTheProvidersTrackerBeforeDeferring(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"one of the references of its answer is on that provider's host", "`security.alpinelinux.org`",
		"A next step names only what you can't do yourself",
		"only where no reference is on the provider's host, the fetch can't reach it, or the fetch failed",
	} {
		require.Contains(t, core, term)
	}
}

// A case with guidance about exploitability searched one term at a time, many times, and never settled the fix status.
func TestTheCoreSettlesTheFixStatusFirstAndKeepsTheUsageSearchShort(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"Settle the fix status first", "Only then search for how the image uses the vulnerable code",
		"several terms in one query, separated by `|`", "at most three searches",
	} {
		require.Contains(t, core, term)
	}
}

// A summary cited a search of the image's files as evidence that a function isn't called, and stated the guidance's
// claims as facts. A verdict must hold once its investigation is gone, so it doesn't use the guidance at all.
func TestTheCoreSaysWhatASearchCanShowAndKeepsTheGuidanceAsContext(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"never shows whether a function is called", "isn't evidence that code is unused",
		"explainable from its claims and their evidence alone", "the summary and the claims don't use the guidance",
		"only the next step names it", "the summary says that the step is a mitigation",
	} {
		require.Contains(t, core, term)
	}
}

// The shipped guidance looks for the fix status before the image's own evidence.
func TestTheGuidanceLooksForTheFixStatusBeforeTheImagesEvidence(t *testing.T) {
	guidance := prompt.Guidance()
	advisory, evidence := strings.Index(guidance, "`advisories__fetch`"), strings.Index(guidance, "through `search_evidence`")
	require.Positive(t, advisory)
	require.Positive(t, evidence)
	require.Less(t, advisory, evidence)
	require.Contains(t, guidance, "several terms in one search")
}

// A binary without a distribution, at an upstream version that a distribution fixed in a release of that same version,
// stayed under_investigation, and its next step leaned on a version range in an advisory's prose.
func TestTheCoreFindsABinaryAffectedWhereADistributionFixedItsUpstreamVersion(t *testing.T) {
	core := prompt.Core()
	for _, term := range []string{
		"for a package whose case file names neither a distribution nor an ecosystem",
		"in a later release of the package's own upstream version", "such as `1.36.1-r1` for `1.36.1`",
		"A fix in the distribution's first release of that version", "came with the upstream version",
		"unless evidence shows that it carries the patch",
		"A fix only in another upstream version says nothing about this one",
		"a version range in an advisory's prose", "may still show that its upstream version is vulnerable",
	} {
		require.Contains(t, core, term)
	}
}

func TestTheSystemPromptAddsAnInvestigationsGuidanceUnderAHeadingOfItsOwn(t *testing.T) {
	require.Equal(t, prompt.Core()+"\n\nHouse style.", prompt.System("House style.", ""))
	require.Equal(t, prompt.Core()+"\n\nHouse style.\n\n# This investigation's guidance\n\nCheck the module.",
		prompt.System("House style.", "Check the module."))
}

func TestTheGuidanceIsShortAndSaysWhereToLookFirstAndHowToWriteTheSummary(t *testing.T) {
	guidance := prompt.Guidance()
	require.Contains(t, guidance, "Where to look first")
	require.Contains(t, guidance, "The summary")
	for _, term := range []string{"first sentence", "statusNotes", "runsIn", "aliases", "`runsIn.exposure`",
		"the names of the rules"} {
		require.Contains(t, guidance, term)
	}
	require.Less(t, len(guidance), len(prompt.Core()), "the guidance adds to the core, and is shorter than it")
}

func TestTokensAreEstimatedAsBytesOverFourRoundedUp(t *testing.T) {
	require.Equal(t, 0, prompt.EstimateTokens(""))
	require.Equal(t, 1, prompt.EstimateTokens("a"))
	require.Equal(t, 1, prompt.EstimateTokens("abcd"))
	require.Equal(t, 2, prompt.EstimateTokens("abcde"))
	require.Equal(t, 1, prompt.EstimateTokens("ä"), "bytes, not characters")
}
