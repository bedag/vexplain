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

package grype

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/anchore/grype/grype/version"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Match is one vulnerability that Grype reports for one package. The strings are Grype's, as it writes them: the
// vulnerabilities collector keeps them as they are, and the rules map them onto the API's enums.
type Match struct {
	// VulnerabilityID is the CVE where one exists: the wrapper runs Grype with --by-cve, so that a GitHub or
	// distribution advisory with a CVE is reported under the CVE. An advisory without one keeps its own ID.
	VulnerabilityID string
	// PackageID is the SBOM's package ID, as Grype reports it.
	PackageID string
	// Severity is Grype's: Critical, High, Medium, Low, Negligible or Unknown.
	Severity string
	// FixState is Grype's: fixed, not-fixed, wont-fix or unknown. It is empty when the source of the match, such as
	// an NVD entry that names no fix, says nothing.
	FixState      string
	FixedVersions []string
	// KnownExploited is true when Grype lists the vulnerability in the CISA catalog of known exploited
	// vulnerabilities.
	KnownExploited bool
	// PackageName, PackageVersion and PackageType are the package as Grype reports it. A package can lack a version.
	PackageName    string
	PackageVersion string
	PackageType    string
	// CVSS holds the vectors of the vulnerability's scores, in Grype's order, each once.
	CVSS []CVSS
	// Aliases are the IDs of the related vulnerabilities, such as the GHSA ID of a CVE: each once, sorted, and
	// never the match's own ID.
	Aliases []string
	// ConstraintFormats are the version schemes that the constraints of the match's details name, each once, in
	// the order of the details. A constraint names the scheme that Grype compared the package's version in, such as
	// semver for an npm package, which the package type alone doesn't tell. A scheme that Grype calls unknown is
	// left out.
	ConstraintFormats []version.Format
}

// CVSS is one score of a vulnerability, as the vector that it is calculated from.
type CVSS struct {
	// Version is the version of CVSS, such as 3.1.
	Version string
	Vector  string
}

// Database says which vulnerability database Grype uses.
type Database struct {
	// Version changes whenever the content of the database changes. It is Grype's schema version and the build
	// time, such as v6.1.10+2026-10-30T06:23:28Z: the schema version alone stays the same across the daily builds.
	// The hub matches every manifest again when it changes.
	Version string
	// Built is when the database was built.
	Built time.Time
}

// Grype is the Grype CLI, working on one vulnerability database.
//
// An error of any of its methods has a fixed text: it names the command and how it ended, and
// nothing that Grype wrote. Grype's stderr can hold text from the SBOM, and the address of the proxy.
// It is logged at debug level, and goes no further.
type Grype interface {
	// Match runs Grype on the SBOM file at sbomPath, and returns its matches in one order. An
	// output that is not Grype's list of matches is an error, and never "no matches".
	Match(ctx context.Context, sbomPath string) ([]Match, error)
	// Update downloads the newest database, through the proxy of the environment. A failed update
	// leaves the database that was there.
	Update(ctx context.Context) error
	// Status describes the database in use. It is an error when there is none that Grype calls valid.
	Status(ctx context.Context) (Database, error)
}

// stderrLimit is how much of Grype's stderr the debug log keeps: its start.
const stderrLimit = 16 << 10

// waitDelay is how long the pipes of a Grype that was stopped may stay open after it ended. A child
// that Grype left behind would otherwise keep a stopped match from returning. It is a variable for
// the tests.
var waitDelay = 5 * time.Second

// errNoDatabase is the error of a status that doesn't describe a valid database. Grype's own
// description of what is wrong is for its stderr.
var errNoDatabase = errors.New("grype status: no valid vulnerability database")

// errBadOutput is the error of an output that is not what the command prints.
var errBadOutput = errors.New("grype match: the output is not a list of matches")

// NewGrype returns the CLI at binary, working on the database in dbDir.
//
// Every call gets the vulnerabilities collector's own environment, so that the proxy reaches an update, and so does a
// setting of Grype that an administrator adds, such as the URL of a mirror. On top of it come:
//   - GRYPE_DB_AUTO_UPDATE=false: the vulnerabilities collector updates, and a match never does.
//   - GRYPE_CHECK_FOR_APP_UPDATE=false: Grype doesn't look for a newer Grype.
//   - GRYPE_DB_CACHE_DIR=dbDir: the directory of the database.
//   - GRYPE_DB_VALIDATE_AGE=false: Grype refuses a database that it built more than five days ago,
//     and then both the status and every match fail. An offline vulnerabilities collector, or one whose updates fail
//     for a week, would stop matching. It keeps serving instead, and the database's version and
//     build time say how old it is.
func NewGrype(binary, dbDir string) Grype { return &cli{binary: binary, dbDir: dbDir} }

type cli struct {
	binary string
	dbDir  string
}

// env is the environment of every call. The last value of a name counts, so ours win.
func (c *cli) env() []string {
	return append(os.Environ(),
		"GRYPE_DB_AUTO_UPDATE=false",
		"GRYPE_CHECK_FOR_APP_UPDATE=false",
		"GRYPE_DB_VALIDATE_AGE=false",
		"GRYPE_DB_CACHE_DIR="+c.dbDir,
	)
}

// run runs Grype with args, and returns what it wrote to stdout. command names the call in the log
// and in the error.
func (c *cli) run(ctx context.Context, command string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.binary, args...)
	cmd.Env = c.env()
	cmd.WaitDelay = waitDelay
	var stdout bytes.Buffer
	stderr := &head{limit: stderrLimit}
	cmd.Stdout = &stdout
	cmd.Stderr = stderr
	err := cmd.Run()

	if text := stderr.String(); text != "" {
		logf.FromContext(ctx).V(1).Info("Grype wrote to stderr", "command", command, "stderr", text)
	}
	switch {
	case err == nil:
		return stdout.Bytes(), nil
	case ctx.Err() != nil:
		return nil, fmt.Errorf("grype %s: %w", command, ctx.Err())
	case cmd.ProcessState == nil:
		// Grype never ran, so the error can't hold anything it wrote: it names the binary, which
		// is the vulnerabilities collector's own setting.
		return nil, fmt.Errorf("grype %s: could not start: %w", command, err)
	default:
		// How it ended: "exit status 1", or a signal such as "signal: killed" for an out-of-memory kill.
		return nil, fmt.Errorf("grype %s: %s", command, cmd.ProcessState)
	}
}

// head keeps the start of what is written to it, up to limit bytes. It takes everything, so that
// the process that writes never blocks, and drops what is over the limit.
type head struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (h *head) Write(p []byte) (int, error) {
	room := h.limit - h.buf.Len()
	if room > 0 {
		h.buf.Write(p[:min(room, len(p))])
	}
	if len(p) > room {
		h.truncated = true
	}
	return len(p), nil
}

func (h *head) String() string {
	if h.truncated {
		return h.buf.String() + " [truncated]"
	}
	return h.buf.String()
}

// grypeOutput is what the vulnerabilities collector reads of the JSON that Grype prints for a match: the list of
// matches, and of each match the vulnerability's ID, severity, fix, known exploitation and CVSS vectors, and the
// package. Everything else, such as descriptions, URLs and the scores' values, is skipped.
type grypeOutput struct {
	// Matches is a pointer, so that a missing list or a null can be told from an empty one.
	Matches *[]grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		// KnownExploited is Grype's list of the CISA catalog's entries for the vulnerability, and
		// null for a vulnerability that is on no list (decision 16).
		KnownExploited []json.RawMessage `json:"knownExploited"`
		// CVSS is the list of the vulnerability's scores, of which only the version and the vector are read.
		CVSS []struct {
			Version string `json:"version"`
			Vector  string `json:"vector"`
		} `json:"cvss"`
		Fix struct {
			State    string   `json:"state"`
			Versions []string `json:"versions"`
		} `json:"fix"`
	} `json:"vulnerability"`
	RelatedVulnerabilities []struct {
		ID string `json:"id"`
	} `json:"relatedVulnerabilities"`
	MatchDetails []struct {
		// Found is what was matched on. Its shape depends on the kind of match, so it is read leniently.
		Found json.RawMessage `json:"found"`
	} `json:"matchDetails"`
	Artifact struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	} `json:"artifact"`
}

func (c *cli) Match(ctx context.Context, sbomPath string) ([]Match, error) {
	// --by-cve: a GitHub or distribution advisory that has a CVE is reported under the CVE. Findings,
	// the known exploited list and the worklist are keyed by CVE, and without the flag one CVE
	// appears under a GHSA ID for one package and under its own ID for another.
	out, err := c.run(ctx, "match", "sbom:"+sbomPath, "--by-cve", "-o", "json")
	if err != nil {
		return nil, err
	}
	var parsed grypeOutput
	if json.Unmarshal(out, &parsed) != nil || parsed.Matches == nil {
		return nil, errBadOutput
	}

	matches := make([]Match, 0, len(*parsed.Matches))
	for _, m := range *parsed.Matches {
		match := Match{
			VulnerabilityID: m.Vulnerability.ID,
			PackageID:       m.Artifact.ID,
			Severity:        m.Vulnerability.Severity,
			FixState:        m.Vulnerability.Fix.State,
			KnownExploited:  len(m.Vulnerability.KnownExploited) > 0,
			PackageName:     m.Artifact.Name,
			PackageVersion:  m.Artifact.Version,
			PackageType:     m.Artifact.Type,
		}
		if len(m.Vulnerability.Fix.Versions) > 0 {
			match.FixedVersions = m.Vulnerability.Fix.Versions
		}
		for _, score := range m.Vulnerability.CVSS {
			vector := CVSS{Version: score.Version, Vector: score.Vector}
			// A score without either is no vector to show, and evidence refuses one. The same vector twice, as
			// two sources can give it, is shown once.
			if vector.Version != "" && vector.Vector != "" && !slices.Contains(match.CVSS, vector) {
				match.CVSS = append(match.CVSS, vector)
			}
		}
		for _, related := range m.RelatedVulnerabilities {
			if related.ID != "" && related.ID != match.VulnerabilityID {
				match.Aliases = append(match.Aliases, related.ID)
			}
		}
		slices.Sort(match.Aliases)
		match.Aliases = slices.Compact(match.Aliases)
		for _, d := range m.MatchDetails {
			format := constraintFormat(d.Found)
			if format != version.UnknownFormat && !slices.Contains(match.ConstraintFormats, format) {
				match.ConstraintFormats = append(match.ConstraintFormats, format)
			}
		}
		matches = append(matches, match)
	}
	// Grype's order isn't the same from one run to the next. Matches of one vulnerability and
	// package that differ in anything else, such as two matchers' fix states, keep their order.
	slices.SortStableFunc(matches, func(a, b Match) int {
		return cmp.Or(cmp.Compare(a.VulnerabilityID, b.VulnerabilityID), cmp.Compare(a.PackageID, b.PackageID))
	})
	return matches, nil
}

// constraintFormat returns the version scheme that the constraint in what a match found names, or the unknown scheme.
// Grype writes a constraint with its scheme at the end, such as "< 4.17.21 (semver)".
func constraintFormat(found json.RawMessage) version.Format {
	var f struct {
		VersionConstraint string `json:"versionConstraint"`
	}
	if json.Unmarshal(found, &f) != nil {
		return version.UnknownFormat
	}
	constraint := strings.TrimSpace(f.VersionConstraint)
	open := strings.LastIndex(constraint, "(")
	if open < 0 || !strings.HasSuffix(constraint, ")") {
		return version.UnknownFormat
	}
	return version.ParseFormat(constraint[open+1 : len(constraint)-1])
}

func (c *cli) Update(ctx context.Context) error {
	_, err := c.run(ctx, "update", "db", "update")
	return err
}

func (c *cli) Status(ctx context.Context) (Database, error) {
	// With no database Grype prints a status that says so, and exits with 1: both are an error.
	out, err := c.run(ctx, "status", "db", "status", "-o", "json")
	if err != nil {
		return Database{}, err
	}
	var status struct {
		SchemaVersion string    `json:"schemaVersion"`
		Built         time.Time `json:"built"`
		Valid         bool      `json:"valid"`
	}
	if json.Unmarshal(out, &status) != nil || !status.Valid || status.SchemaVersion == "" || status.Built.IsZero() {
		return Database{}, errNoDatabase
	}
	// The version changes with the content, because the hub matches every manifest again when it
	// changes. The schema version alone, such as v6.1.10, stays the same across the daily builds, and
	// the status has no checksum of its own, so the build time, which is the second a build was made
	// in, completes it.
	built := status.Built.UTC()
	return Database{Version: status.SchemaVersion + "+" + built.Format(time.RFC3339), Built: built}, nil
}
