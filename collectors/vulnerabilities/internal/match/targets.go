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

package match

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	grypepkg "github.com/anchore/grype/grype/pkg"
	grypeversion "github.com/anchore/grype/grype/version"
	syftpkg "github.com/anchore/syft/syft/pkg"

	"github.com/bedag/vexplain/collectors/vulnerabilities/internal/grype"
	"github.com/bedag/vexplain/sdk/evidence"
)

// The limits of the findings schema (sdk/evidence/schemas). A string over its limit is left out, and never cut where
// that would make it another string: an ID, an alias or a version.
const (
	maxIDLength     = 256
	maxTitleLength  = 512
	maxAliasLength  = 64
	maxAliases      = 8
	maxTargetLength = 128
)

// formatOf returns the version scheme that a match's versions are compared in, or the unknown scheme where there is
// none to be sure of. It is the scheme that Grype matched with, which the constraints of its match details name: a
// package type such as npm has no scheme of its own in Grype, and the constraint says what Grype compared in. Where the
// constraints name none, it is the package type's, as Grype maps it. Constraints that name two schemes leave no
// scheme, since neither is more Grype's than the other.
func formatOf(g grype.Match) grypeversion.Format {
	switch len(g.ConstraintFormats) {
	case 0:
		return grypepkg.VersionFormat(grypepkg.Package{Type: syftpkg.Type(g.PackageType)})
	case 1:
		return g.ConstraintFormats[0]
	default:
		return grypeversion.UnknownFormat
	}
}

// fixTarget returns the lowest of the fixed versions that is above the installed one, in the order of the format, or ""
// where there is none: the format is unknown, the installed version doesn't parse in it, no fixed version parses and
// lies above it, or the target is longer than the schema allows, since a version that is cut is another version. Of
// versions that the format orders as equal the one that sorts first as text wins, so that the answer doesn't depend on
// the order of the list.
func fixTarget(format grypeversion.Format, installed string, fixed []string) string {
	if format == grypeversion.UnknownFormat || installed == "" {
		return ""
	}
	current := grypeversion.New(installed, format)
	if current.Validate() != nil {
		return ""
	}
	target := ""
	var lowest *grypeversion.Version
	for _, f := range fixed {
		candidate := grypeversion.New(f, format)
		if candidate.Validate() != nil {
			continue
		}
		above, err := current.Compare(candidate)
		if err != nil || above >= 0 {
			continue
		}
		if lowest != nil {
			order, err := candidate.Compare(lowest)
			if err != nil || order > 0 || order == 0 && f >= target {
				continue
			}
		}
		target, lowest = f, candidate
	}
	if utf8.RuneCountInString(target) > maxTargetLength {
		return ""
	}
	return target
}

// setUpdateTargets sets the update target of each match to the highest fix target among the matches of its package,
// compared in the scheme that the fix targets were made in: formats[i] is that of matches[i]. A package whose targets
// were made in two schemes, or in an unknown one, or that don't compare, has none, since a wrong target is worse than
// none.
func setUpdateTargets(matches []evidence.Match, formats []grypeversion.Format) {
	type best struct {
		target  string
		format  grypeversion.Format
		version *grypeversion.Version
		failed  bool
	}
	byPackage := map[string]*best{}
	for i, m := range matches {
		if m.FixTarget == "" {
			continue
		}
		b := byPackage[m.PackageID]
		if b == nil {
			b = &best{format: formats[i]}
			byPackage[m.PackageID] = b
		}
		v := grypeversion.New(m.FixTarget, formats[i])
		switch {
		case b.failed:
		case formats[i] != b.format || formats[i] == grypeversion.UnknownFormat || v.Validate() != nil:
			b.failed = true
		case b.version == nil:
			b.target, b.version = m.FixTarget, v
		default:
			order, err := v.Compare(b.version)
			switch {
			case err != nil:
				b.failed = true
			case order > 0 || order == 0 && m.FixTarget < b.target:
				b.target, b.version = m.FixTarget, v
			}
		}
	}
	for i := range matches {
		if b := byPackage[matches[i].PackageID]; b != nil && !b.failed {
			matches[i].UpdateTarget = b.target
		}
	}
}

// matchOf maps one of Grype's matches onto the findings' type, and returns the version scheme that its fix target was
// made in.
func matchOf(g grype.Match) (evidence.Match, grypeversion.Format) {
	format := formatOf(g)
	m := evidence.Match{
		VulnerabilityID: g.VulnerabilityID,
		PackageID:       g.PackageID,
		PackageName:     g.PackageName,
		PackageVersion:  g.PackageVersion,
		PackageType:     g.PackageType,
		Severity:        g.Severity,
		FixState:        g.FixState,
		FixedVersions:   g.FixedVersions,
		FixTarget:       fixTarget(format, g.PackageVersion, g.FixedVersions),
		Aliases:         aliasesOf(g),
		KnownExploited:  g.KnownExploited,
	}
	if id := g.VulnerabilityID + "/" + g.PackageID; utf8.RuneCountInString(id) <= maxIDLength {
		m.ID = id
	}
	m.Title = strings.TrimSpace(fmt.Sprintf("%s in %s %s", g.VulnerabilityID, g.PackageName, g.PackageVersion))
	if runes := []rune(m.Title); len(runes) > maxTitleLength {
		m.Title = string(runes[:maxTitleLength])
	}
	for _, score := range g.CVSS {
		m.CVSS = append(m.CVSS, evidence.CVSS{Version: score.Version, Vector: score.Vector})
	}
	return m, format
}

// aliasesOf returns the first 8 of a match's aliases, sorted, without its own ID and without an alias that is empty
// or longer than the schema allows.
func aliasesOf(g grype.Match) []string {
	var aliases []string
	for _, a := range g.Aliases {
		if a != "" && a != g.VulnerabilityID && utf8.RuneCountInString(a) <= maxAliasLength {
			aliases = append(aliases, a)
		}
	}
	slices.Sort(aliases)
	aliases = slices.Compact(aliases)
	return aliases[:min(len(aliases), maxAliases)]
}
