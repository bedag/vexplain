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

package cases

import (
	"cmp"
	"slices"
	"strings"

	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
)

// Less reports whether case a goes before case b, as Compare orders them.
func Less(a, b Case) bool { return Compare(a, b) < 0 }

// Compare orders cases by tiers, as CompareTiers does. The vulnerability's ID and the manifest's digest order the rest,
// so that no two cases are equal.
func Compare(a, b Case) int {
	return cmp.Or(
		CompareTiers(TiersOf(a), TiersOf(b)),
		strings.Compare(a.VulnerabilityID, b.VulnerabilityID),
		strings.Compare(a.ManifestDigest, b.ManifestDigest),
	)
}

// Tiers are what CompareTiers orders a case by: the place of its most urgent outcome, whether a finding of it is known
// to be exploited, its highest EPSS in per mille, -1 when none has one, and the workloads that run its subject. The
// agent's queue keeps them in each case's Assessment.
type Tiers struct {
	UrgencyRank    int32
	KnownExploited bool
	EPSSPermille   int32
	Resources      int32
}

// TiersOf returns the tiers of a case.
func TiersOf(c Case) Tiers {
	return Tiers{UrgencyRank: urgencyRank(c.Impact.HighestUrgency), KnownExploited: knownExploited(c),
		EPSSPermille: epssOf(c), Resources: c.Impact.Resources}
}

// CompareTiers orders cases by tiers, not by a score (decisions 0024 and 0050): the most urgent first, then those of a
// vulnerability known to be exploited, then the higher EPSS, then the more workloads that run the subject. Cases of
// the same tiers are equal.
func CompareTiers(a, b Tiers) int {
	exploited := func(t Tiers) int {
		if t.KnownExploited {
			return 0
		}
		return 1
	}
	return cmp.Or(
		cmp.Compare(a.UrgencyRank, b.UrgencyRank),
		cmp.Compare(exploited(a), exploited(b)),
		cmp.Compare(b.EPSSPermille, a.EPSSPermille),
		cmp.Compare(b.Resources, a.Resources),
	)
}

// urgencyRank is the place of an outcome in the tiers, the most urgent first. An outcome that this version doesn't
// know comes first, which errs towards urgency, and none, of a subject that no workload is known to run, last.
func urgencyRank(o configv1alpha1.SSVCOutcome) int32 {
	switch o {
	case configv1alpha1.SSVCOutcomeImmediate:
		return 1
	case configv1alpha1.SSVCOutcomeOutOfCycle:
		return 2
	case configv1alpha1.SSVCOutcomeScheduled:
		return 3
	case configv1alpha1.SSVCOutcomeDefer:
		return 4
	case "":
		return 5
	}
	return 0
}

// knownExploited reports whether a finding of the case is known to be exploited. A value that this version doesn't know
// may say that it is, and goes with them.
func knownExploited(c Case) bool {
	return slices.ContainsFunc(c.Findings, func(f inventoryv1alpha1.Finding) bool {
		return f.KnownExploited != inventoryv1alpha1.KnownExploitedNotListed
	})
}

// epssOf returns the highest EPSS of the case's findings, in per mille, and -1 when none has one.
func epssOf(c Case) int32 {
	highest := int32(-1)
	for _, f := range c.Findings {
		highest = max(highest, ptr.Deref(f.EPSSPermille, -1))
	}
	return highest
}
