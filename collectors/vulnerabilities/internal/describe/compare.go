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

package describe

import (
	"slices"
	"strings"

	"github.com/anchore/grype/grype/db/v5/namespace"
	distronamespace "github.com/anchore/grype/grype/db/v5/namespace/distro"
	languagenamespace "github.com/anchore/grype/grype/db/v5/namespace/language"
	"github.com/anchore/grype/grype/distro"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	syftpkg "github.com/anchore/syft/syft/pkg"

	"github.com/bedag/vexplain/sdk/evidence"
)

// Whether a package has a provider's fix decides whether the agent may call it fixed or not affected, and the validator
// takes the answer as it is. So the answer is Yes only where Grype's own reading of the package and Grype's own
// comparison of versions leave no doubt, and Unknown wherever they leave some.
//
// A package is compared as Grype matches it: under its own name and those of its source packages, which its purl
// names, each with its version (grype/pkg); against every row of the provider that names one of them, as the rows'
// constraints read in the scheme of their type (grype/version); and with missing epochs read as Grype's matchers read
// them by default (epochsOf).
//
// Every row of the provider counts whose namespace speaks for the package, such as those of SLES 15 and of its
// service pack 15.5 for a package of 15.5, and those of an extended update stream of Red Hat, which share the
// release's namespace. A row's qualifiers, such as a module stream of an RPM or an architecture, narrow the packages
// that it applies to; the SBOM doesn't say what they ask, so every row applies, as Grype applies them to a package
// that doesn't say. The answer is Yes only when none of these rows holds the version, which is stricter than Grype,
// which would read only some of them.

// epochsOf returns how versions of the scheme are compared where one side has no epoch, as Grype's matchers compare
// them by default. An RPM version without an epoch, such as a source RPM's, takes the epoch of the constraint or the
// fix that it is compared with, and a constraint's or a fix's missing epoch is ignored: the binary RPM's own version
// always has one (installedOf). Every other version without an epoch, such as a Debian one, has epoch 0, as dpkg reads
// it, so a caller that drops an epoch gets no Yes for a fix of a higher epoch.
func epochsOf(format version.Format) version.ComparisonConfig {
	if format == version.RpmFormat {
		return version.ComparisonConfig{MissingEpochStrategy: version.MissingEpochStrategyAuto}
	}
	return version.ComparisonConfig{MissingEpochStrategy: version.MissingEpochStrategyZero}
}

// installed is a package that describe was asked about, as Grype reads it.
type installed struct {
	asked    evidence.DescribedPackage
	language syftpkg.Language
	distro   *distro.Distro
	// format is the version scheme of the package's type, or the unknown scheme for a type that has none of its own,
	// such as npm.
	format version.Format
	// listedAs are the names and versions under which a provider may list the package: its own, and its source
	// packages', each with the version to compare.
	listedAs []listed
	// generic is true for a package that a pkg:generic purl names: it names no package type, so it speaks for no
	// distribution or ecosystem.
	generic bool
}

type listed struct{ name, version string }

// installedOf reads a package as Grype reads it: from its purl when it has one, which must name the package of the
// name, version and type, and else from those alone, which names no source package. The distribution that it is
// given is the release where the purl names none, and must be the purl's where it does: the release decides which
// provider answers. It returns false for a purl that names another package or release, or that Grype reads no single
// package from. A Go standard library may have "go" before the purl's version, as Syft writes it.
func installedOf(p evidence.DescribedPackage) (installed, bool) {
	generic := false
	pkg := grypepkg.Package{Name: p.Name, Version: p.Version, Type: syftpkg.Type(p.Type),
		Language: syftpkg.LanguageByName(p.Type)}
	if p.PURL != "" {
		// Grype reads a "pkg:" input as purls alone, and never as a path or an image to scan, and a purl is one line.
		if !strings.HasPrefix(p.PURL, "pkg:") || strings.ContainsAny(p.PURL, " \t\r\n") {
			return installed{}, false
		}
		read, _, _, err := grypepkg.Provide(p.PURL, grypepkg.ProviderConfig{})
		// A generic purl names no type: Syft reads the name as the type, so the asked type is kept.
		generic = strings.HasPrefix(p.PURL, "pkg:generic/")
		if err != nil || len(read) != 1 || read[0].Name != p.Name || (string(read[0].Type) != p.Type && !generic) {
			return installed{}, false
		}
		// Syft writes Go's standard library as stdlib go1.27.1, with the purl version 1.27.1. The asked version is kept:
		// Grype compares a Go version without its "go" prefix, and the validator matches the answer by the SBOM's.
		stdlib := read[0].Type == syftpkg.GoModulePkg && read[0].Name == "stdlib" && p.Version == "go"+read[0].Version
		if read[0].Version != p.Version && !stdlib {
			return installed{}, false
		}
		if !generic {
			pkg = read[0]
		}
		pkg.Version = p.Version
	}
	if p.Distro != "" {
		name, release := distro.ParseDistroString(p.Distro)
		given := distro.NewFromNameVersion(name, release)
		if name == "" || pkg.Distro != nil && (pkg.Distro.Type != given.Type || pkg.Distro.Version != given.Version) {
			return installed{}, false
		}
		pkg.Distro = given
	}
	in := installed{asked: p, language: pkg.Language, distro: pkg.Distro, format: grypepkg.VersionFormat(pkg), generic: generic}
	if p.Version == "" {
		// A package without a version can't be compared: it is listed under no name.
		return in, true
	}
	own := pkg.Version
	if pkg.Type == syftpkg.RpmPkg && !strings.Contains(own, ":") {
		own = "0:" + own
	}
	in.listedAs = append(in.listedAs, listed{name: pkg.Name, version: own})
	for _, source := range grypepkg.UpstreamPackages(pkg) {
		in.listedAs = append(in.listedAs, listed{name: source.Name, version: source.Version})
	}
	return in, true
}

// speaksFor reports whether a provider's namespace is that of the package's distribution and release, for an OS
// package, or of its language, for a package of an ecosystem. A rolling namespace speaks for every release of its
// distribution, which has one stream. NVD's CPEs speak for no package, and a distribution's namespace for no package
// that isn't one of its own kind, with a version scheme of its type: a library that Syft found in a binary of the
// image isn't the distribution's package of that name, and Grype doesn't match it against the distribution's rows.
func (in installed) speaksFor(ns string) bool {
	if in.generic {
		return false
	}
	parsed, err := namespace.FromString(ns)
	if err != nil {
		return false
	}
	switch n := parsed.(type) {
	case *distronamespace.Namespace:
		d := in.distro
		return d != nil && d.Version != "" && n.DistroType() == d.Type &&
			in.language == syftpkg.UnknownLanguage && in.format != version.UnknownFormat &&
			(n.Version() == "rolling" || n.Version() == d.Version || strings.HasPrefix(d.Version, n.Version()+"."))
	case *languagenamespace.Namespace:
		return in.language != syftpkg.UnknownLanguage && n.Language() == in.language
	}
	return false
}

// names reports whether the package is listed under the name, or under the CPE of that product.
func (in installed) names(name string) bool {
	// NVD lists a CPE, cpe:2.3:<part>:<vendor>:<product>:..., whose product is the package's name.
	if fields := strings.Split(name, ":"); strings.HasPrefix(name, "cpe:2.3:") && len(fields) > 4 {
		name = fields[4]
	}
	return slices.ContainsFunc(in.listedAs, func(l listed) bool { return strings.EqualFold(l.name, name) })
}

// The verdicts of one row on one version.
type verdict int

const (
	// unclear: the versions don't compare, or the version is in no range and below every fix.
	unclear verdict = iota
	// affected: a range holds the version.
	affected
	// fixed: no range holds the version, and it is at a fix or above.
	fixed
)

// fixedForInstalled returns what one provider says of the package, where rows are all of the provider's rows: of
// those whose namespace speaks for the package and that name it, No when one holds its version, Yes when there are
// some, none holds it and each has a fix at the version or below, and Unknown otherwise.
func (in installed) fixedForInstalled(rows []row) string {
	var verdicts []verdict
	for _, r := range rows {
		if !in.names(r.name) || !in.speaksFor(r.namespace) {
			continue
		}
		for _, l := range in.listedAs {
			if strings.EqualFold(r.name, l.name) {
				verdicts = append(verdicts, in.judge(r.ranges, l.version))
			}
		}
	}
	switch {
	case slices.Contains(verdicts, affected):
		return evidence.FixedForInstalledNo
	case len(verdicts) > 0 && !slices.Contains(verdicts, unclear):
		return evidence.FixedForInstalledYes
	}
	return evidence.FixedForInstalledUnknown
}

// judge compares the version with one row's ranges as Grype matches it: the constraints of the ranges joined, in the
// scheme of their type, which must be the package type's where that has one. A row without any constraint holds every
// version, as Grype reads it, and so does a range without a constraint that names no fix, such as one that won't be
// fixed, which Grype leaves out when other ranges of the row have a constraint. Any other range without a constraint,
// beside ranges with one, names a fix and holds the versions below it, which Grype doesn't read: the row is unclear.
func (in installed) judge(ranges []versionRange, installedVersion string) verdict {
	constraint, format := constraintOf(ranges)
	unfixedEverywhere := slices.ContainsFunc(ranges, func(r versionRange) bool {
		return r.Version.Constraint == "" && (r.Fix == nil || r.Fix.State != fixedState)
	})
	switch {
	case len(ranges) == 0 || constraint == "" || unfixedEverywhere:
		return affected
	case slices.ContainsFunc(ranges, func(r versionRange) bool { return r.Version.Constraint == "" }):
		return unclear
	}
	if format == version.UnknownFormat || in.format != version.UnknownFormat && in.format != format {
		return unclear
	}
	epochs := epochsOf(format)
	v := version.NewWithConfig(installedVersion, format, epochs)
	c, err := version.GetConstraint(constraint, format)
	if err != nil || v.Validate() != nil {
		return unclear
	}
	holds, err := c.Satisfied(v)
	switch {
	case err != nil:
		return unclear
	case holds:
		return affected
	}
	for _, r := range ranges {
		if r.Fix == nil || r.Fix.State != fixedState || r.Fix.Version == "" {
			continue
		}
		if order, err := v.Compare(version.NewWithConfig(r.Fix.Version, format, epochs)); err == nil && order >= 0 {
			return fixed
		}
	}
	return unclear
}

// constraintOf returns the constraints of the ranges joined, and the scheme of their type, as Grype makes the
// constraint of a vulnerability: the ranges without a constraint are left out, and of several types the first in
// order counts.
func constraintOf(ranges []versionRange) (string, version.Format) {
	var constraints, types []string
	for _, r := range ranges {
		if r.Version.Constraint == "" {
			continue
		}
		constraints = append(constraints, r.Version.Constraint)
		if r.Version.Type != "" {
			types = append(types, r.Version.Type)
		}
	}
	slices.Sort(types)
	format := version.UnknownFormat
	if len(types) > 0 {
		format = version.ParseFormat(types[0])
	}
	return strings.Join(constraints, "||"), format
}
