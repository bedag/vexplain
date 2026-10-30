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

package matcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/bedag/vexplain/internal/matchapi"
)

const (
	// The commands of the fake, as it names them.
	cmdMatch  = "match"
	cmdUpdate = "update"
	cmdStatus = "status"

	// What a failing fake writes. It stands for text from the SBOM, or a proxy's address.
	secretStderr = "SECRET-STDERR-OF-GRYPE"
	secretStdout = "SECRET-STDOUT-OF-GRYPE"

	goldenPath       = "testdata/grype-output.json"
	statusPath       = "testdata/db-status.json"
	statusNonePath   = "testdata/db-status-none.json"
	goldenBuilt      = "2026-10-30T06:23:28Z"
	goldenVersion    = "v6.1.10+" + goldenBuilt
	someOtherBuilt   = "2026-10-31T06:24:11Z"
	brotliPackageID  = "d116986055f229b7"
	muslPackageID    = "9153588f3b163ab9"
	brotliCVE        = "CVE-2026-111497"
	alpineMuslFixed  = "CVE-2020-28928"
	someSBOMPath     = "/tmp/sbom-123.json"
	typeAPK          = "apk"
	severityHigh     = "High"
	muslName         = "musl"
	muslVersion      = "1.1.24-r8"
	notJSON          = "not JSON"
	defaultDBDirName = "db"
)

// goldenMatches is what the wrapper makes of testdata/grype-output.json, in the order it returns
// them: by vulnerability ID, then package ID. The file is what Grype v0.121.0 printed on
// 2026-10-30 for testdata/sbom.json (see testdata/README).
var goldenMatches = []matchapi.Match{
	{
		VulnerabilityID: alpineMuslFixed, PackageID: muslPackageID, Severity: "Medium",
		FixState: "fixed", FixedVersions: []string{"1.1.24-r10"},
		PackageName: muslName, PackageVersion: muslVersion, PackageType: typeAPK,
	},
	{
		VulnerabilityID: "CVE-2025-26519", PackageID: muslPackageID, Severity: severityHigh, FixState: "unknown",
		PackageName: muslName, PackageVersion: muslVersion, PackageType: typeAPK,
	},
	{
		// Grype's own list of known exploited vulnerabilities names this one, and NVD names no fix.
		VulnerabilityID: brotliCVE, PackageID: brotliPackageID, Severity: "Critical", FixState: "unknown",
		KnownExploited: true,
		PackageName:    "brotli-libs", PackageVersion: "1.0.9-r1", PackageType: typeAPK,
	},
	{
		// A match that says nothing of a fix has an empty state, which the wrapper keeps.
		VulnerabilityID: "CVE-2026-40200", PackageID: muslPackageID, Severity: severityHigh, FixState: "",
		PackageName: muslName, PackageVersion: muslVersion, PackageType: typeAPK,
	},
}

// fakeGrype is a script that stands for the Grype CLI. Each call records its arguments in
// args.<command> and its environment in env.<command> of the script's directory.
type fakeGrype struct {
	t      *testing.T
	dir    string
	binary string
}

// newFakeGrype writes the script. behaviour is what it does after it has recorded the call: shell
// that can read $name, which is match, update or status.
func newFakeGrype(t *testing.T, behaviour string) *fakeGrype {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
dir=` + shellQuote(dir) + `
case "$1" in
  sbom:*) name=` + cmdMatch + ` ;;
  db) name=$2 ;;
  *) name=other ;;
esac
printf '%s\n' "$@" > "$dir/args.$name"
env > "$dir/env.$name"
` + behaviour
	binary := filepath.Join(dir, "grype")
	require.NoError(t, os.WriteFile(binary, []byte(script), 0o755))
	return &fakeGrype{t: t, dir: dir, binary: binary}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// prints is the behaviour of a Grype that works: it prints the golden output for a match, and the
// file for the status. An update prints a line, as Grype does.
func prints(statusFile string) string {
	return `case "$name" in
  ` + cmdMatch + `) cat ` + shellQuote(abs(goldenPath)) + ` ;;
  ` + cmdStatus + `) cat ` + shellQuote(abs(statusFile)) + ` ;;
  ` + cmdUpdate + `) echo "Vulnerability database updated to latest version!" ;;
esac
`
}

// fails is the behaviour of a Grype that fails: it writes to both outputs and exits with 3.
const fails = `echo ` + secretStdout + `
echo ` + secretStderr + ` >&2
exit 3
`

func abs(path string) string {
	a, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	return a
}

// args returns the arguments of the last call of a command.
func (f *fakeGrype) args(command string) []string {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, "args."+command))
	require.NoError(f.t, err, "Grype was not called for %s", command)
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// env returns the environment of the last call of a command, one NAME=value for each entry.
func (f *fakeGrype) env(command string) []string {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, "env."+command))
	require.NoError(f.t, err, "Grype was not called for %s", command)
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// commands run each of the three commands of the wrapper.
var commands = map[string]func(context.Context, Grype) error{
	cmdMatch:  func(ctx context.Context, g Grype) error { _, err := g.Match(ctx, someSBOMPath); return err },
	cmdUpdate: func(ctx context.Context, g Grype) error { return g.Update(ctx) },
	cmdStatus: func(ctx context.Context, g Grype) error { _, err := g.Status(ctx); return err },
}

func TestMatchParsesTheGoldenOutput(t *testing.T) {
	f := newFakeGrype(t, prints(statusPath))
	got, err := NewGrype(f.binary, t.TempDir()).Match(t.Context(), someSBOMPath)
	require.NoError(t, err)
	require.Equal(t, goldenMatches, got)
}

func TestMatchRunsGrypeOnTheSBOMByCVE(t *testing.T) {
	f := newFakeGrype(t, prints(statusPath))
	_, err := NewGrype(f.binary, t.TempDir()).Match(t.Context(), someSBOMPath)
	require.NoError(t, err)

	args := f.args(cmdMatch)
	require.Equal(t, "sbom:"+someSBOMPath, args[0])
	// R35: findings, the known exploited list and the owner's worklist are keyed by CVE.
	require.Contains(t, args, "--by-cve")
	require.Contains(t, strings.Join(args, " "), "-o json")
}

func TestUpdateRunsTheDatabaseUpdate(t *testing.T) {
	f := newFakeGrype(t, prints(statusPath))
	require.NoError(t, NewGrype(f.binary, t.TempDir()).Update(t.Context()))
	require.Equal(t, []string{"db", "update"}, f.args(cmdUpdate))
}

func TestStatusAsksForJSON(t *testing.T) {
	f := newFakeGrype(t, prints(statusPath))
	_, err := NewGrype(f.binary, t.TempDir()).Status(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{"db", "status", "-o", "json"}, f.args(cmdStatus))
}

func TestEveryCommandGetsTheEnvironmentOfTheDatabase(t *testing.T) {
	// The matcher's own environment reaches Grype: the proxy for an update, and any setting of Grype
	// that an administrator adds, such as the URL of a mirror. A setting of ours wins over the
	// same one of the matcher's own, because the last value of a name counts.
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	t.Setenv("NO_PROXY", "localhost,.cluster.local")
	t.Setenv("GRYPE_DB_UPDATE_URL", "https://mirror.example/databases")
	t.Setenv("GRYPE_DB_AUTO_UPDATE", "true")
	t.Setenv("GRYPE_CHECK_FOR_APP_UPDATE", "true")
	t.Setenv("GRYPE_DB_CACHE_DIR", "/somewhere/else")
	t.Setenv("GRYPE_DB_VALIDATE_AGE", "true")

	f := newFakeGrype(t, prints(statusPath))
	dbDir := filepath.Join(t.TempDir(), defaultDBDirName)
	g := NewGrype(f.binary, dbDir)
	for name, run := range commands {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, run(t.Context(), g))
			env := f.env(name)

			// The three variables of the brief, and each exactly once with our value.
			require.Equal(t, 1, count(env, "GRYPE_DB_AUTO_UPDATE="), "env: %v", env)
			require.Contains(t, env, "GRYPE_DB_AUTO_UPDATE=false")
			require.Equal(t, 1, count(env, "GRYPE_CHECK_FOR_APP_UPDATE="))
			require.Contains(t, env, "GRYPE_CHECK_FOR_APP_UPDATE=false")
			require.Equal(t, 1, count(env, "GRYPE_DB_CACHE_DIR="))
			require.Contains(t, env, "GRYPE_DB_CACHE_DIR="+dbDir)
			// A database older than Grype's five days still serves: an offline matcher, or one whose
			// updates fail, keeps matching, and the version says how old it is.
			require.Equal(t, 1, count(env, "GRYPE_DB_VALIDATE_AGE="))
			require.Contains(t, env, "GRYPE_DB_VALIDATE_AGE=false")

			// What is the matcher's own passes through.
			require.Contains(t, env, "HTTPS_PROXY=http://proxy.example:3128")
			require.Contains(t, env, "NO_PROXY=localhost,.cluster.local")
			require.Contains(t, env, "GRYPE_DB_UPDATE_URL=https://mirror.example/databases")
		})
	}
}

// count counts the entries of an environment that start with prefix.
func count(env []string, prefix string) int {
	n := 0
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

func TestAFailingGrypeGivesAnErrorWithoutItsOutput(t *testing.T) {
	f := newFakeGrype(t, fails)
	g := NewGrype(f.binary, t.TempDir())
	for name, run := range commands {
		t.Run(name, func(t *testing.T) {
			err := run(t.Context(), g)
			require.Error(t, err)
			// Its stderr can hold text from the SBOM or a proxy's address, and its stdout the SBOM's.
			require.NotContains(t, err.Error(), secretStderr)
			require.NotContains(t, err.Error(), secretStdout)
			// What helps is which command failed, and how.
			require.Contains(t, err.Error(), name)
			require.Contains(t, err.Error(), "3")
		})
	}
}

func TestAMissingGrypeGivesAnError(t *testing.T) {
	g := NewGrype(filepath.Join(t.TempDir(), "no-such-grype"), t.TempDir())
	for name, run := range commands {
		t.Run(name, func(t *testing.T) {
			require.Error(t, run(t.Context(), g))
		})
	}
}

// capture returns a logger that keeps what it writes at the verbosity, and a function for the text.
func capture(verbosity int) (logr.Logger, func() string) {
	var mu sync.Mutex
	var lines []string
	l := funcr.New(func(prefix, args string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, prefix+" "+args)
	}, funcr.Options{Verbosity: verbosity})
	return l, func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(lines, "\n")
	}
}

func TestGrypesStderrIsLoggedAtDebugLevelOnly(t *testing.T) {
	noisy := `echo "warning: ` + secretStderr + `" >&2
` + prints(statusPath)
	for name, behaviour := range map[string]string{"a call that works": noisy, "a call that fails": fails} {
		f := newFakeGrype(t, behaviour)
		g := NewGrype(f.binary, t.TempDir())
		for command, run := range commands {
			t.Run(name+", "+command, func(t *testing.T) {
				// At the usual level it is nowhere in the log.
				logger, logged := capture(0)
				_ = run(logf.IntoContext(t.Context(), logger), g)
				require.NotContains(t, logged(), secretStderr)
				require.NotContains(t, logged(), secretStdout)

				// At debug level, which is V(1), it is there, with the command.
				logger, logged = capture(1)
				_ = run(logf.IntoContext(t.Context(), logger), g)
				require.Contains(t, logged(), secretStderr)
				require.Contains(t, logged(), command)
				// Only stderr: the SBOM's matches are not for the log.
				require.NotContains(t, logged(), secretStdout)
			})
		}
	}
}

func TestOnlyTheStartOfAHugeStderrIsKept(t *testing.T) {
	// A Grype that goes wrong can write without end. It must neither stop, because nobody reads, nor
	// fill the matcher's memory or log.
	behaviour := `i=0
while [ $i -lt 4000 ]; do
  echo "line $i of a long complaint: ` + strings.Repeat("x", 100) + `" >&2
  i=$((i + 1))
done
` + prints(statusPath)
	f := newFakeGrype(t, behaviour)
	logger, logged := capture(1)
	_, err := NewGrype(f.binary, t.TempDir()).Match(logf.IntoContext(t.Context(), logger), someSBOMPath)
	require.NoError(t, err)
	require.Contains(t, logged(), "line 0 of")
	require.NotContains(t, logged(), "line 3999 of")
	require.Less(t, len(logged()), 4*stderrLimit)
}

func TestACancelledContextStopsGrype(t *testing.T) {
	// exec makes the sleep the process of the script itself, so the kill reaches it.
	f := newFakeGrype(t, "exec sleep 60\n")
	g := NewGrype(f.binary, t.TempDir())
	for name, run := range commands {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			err := run(ctx, g)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.Less(t, time.Since(start), 20*time.Second)
		})
	}
}

func TestAChildThatHoldsTheOutputDoesNotKeepAStoppedGrypeFromReturning(t *testing.T) {
	old := waitDelay
	waitDelay = 300 * time.Millisecond
	t.Cleanup(func() { waitDelay = old })

	// The child inherits the pipes of Grype's output and outlives it. Without a delay, Wait would
	// return when the child ends, three seconds after the match was stopped. The stop comes once the
	// child is there, which the script says by a file.
	childStarted := filepath.Join(t.TempDir(), "started")
	f := newFakeGrype(t, "sleep 3 &\ntouch "+shellQuote(childStarted)+"\nexec sleep 60\n")
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	stopped := make(chan time.Time, 1)
	go func() {
		for {
			if _, err := os.Stat(childStarted); err == nil {
				stopped <- time.Now()
				stop()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()

	_, err := NewGrype(f.binary, t.TempDir()).Match(ctx, someSBOMPath)
	returned := time.Now()
	require.ErrorIs(t, err, context.Canceled)
	select {
	case at := <-stopped:
		require.Less(t, returned.Sub(at), 2*time.Second)
	default:
		t.Fatal("the match ended before the child was there")
	}
}

func TestMatchOutputThatIsNotAListOfMatchesIsAnError(t *testing.T) {
	// A Grype that prints something else must not read as "no matches": a missing tool never moves
	// a verdict towards "not affected".
	for name, stdout := range map[string]string{
		notJSON:           "<html>" + secretStdout + "</html>",
		"nothing":         "",
		"an empty object": `{}`,
		"null matches":    `{"matches": null}`,
		"an object":       `{"matches": {"x": "` + secretStdout + `"}}`,
		"a list":          `[]`,
		"cut off":         `{"matches": [{"vulnerability": {"id": "CVE-2026-1"`,
		"wrong type":      `{"matches": [{"vulnerability": {"id": 7}}]}`,
		"trailing text":   `{"matches": []} ` + secretStdout,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGrype(t, "cat <<'EOF'\n"+stdout+"\nEOF\n")
			got, err := NewGrype(f.binary, t.TempDir()).Match(t.Context(), someSBOMPath)
			require.Error(t, err)
			require.Nil(t, got)
			require.NotContains(t, err.Error(), secretStdout)
		})
	}

	t.Run("an empty list is no matches", func(t *testing.T) {
		f := newFakeGrype(t, "echo '{\"matches\": []}'\n")
		got, err := NewGrype(f.binary, t.TempDir()).Match(t.Context(), someSBOMPath)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Empty(t, got)
	})
}

func TestKnownExploitationFollowsGrypesList(t *testing.T) {
	// Grype writes null when a vulnerability is on no list, and a list of entries when it is.
	const one = `{"vulnerability": {"id": "CVE-2026-1", "severity": "High", "knownExploited": %s,
		"fix": {"state": "fixed", "versions": ["1.2-r0", "1.3-r0"]}},
		"artifact": {"id": "p1", "name": "libx", "version": "1.0-r0", "type": "apk"}}`
	for knownExploited, want := range map[string]bool{
		"null":                    false,
		"[]":                      false,
		`[{"cve": "CVE-2026-1"}]`: true,
		`[{"cve": "CVE-2026-1"}, {"cve": "CVE-2026-1"}]`: true,
	} {
		t.Run(knownExploited, func(t *testing.T) {
			f := newFakeGrype(t, "cat <<'EOF'\n{\"matches\": ["+fmt.Sprintf(one, knownExploited)+"]}\nEOF\n")
			got, err := NewGrype(f.binary, t.TempDir()).Match(t.Context(), someSBOMPath)
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, want, got[0].KnownExploited)
			require.Equal(t, []string{"1.2-r0", "1.3-r0"}, got[0].FixedVersions)
		})
	}
}

func TestMatchesComeInOneOrder(t *testing.T) {
	// Grype's order isn't stable across runs, so the wrapper sorts by vulnerability ID, then package ID.
	const m = `{"vulnerability": {"id": %q, "severity": "Low", "fix": {"state": "unknown"}},
		"artifact": {"id": %q, "name": "n", "version": "1", "type": "apk"}}`
	out := `{"matches": [` + strings.Join([]string{
		fmt.Sprintf(m, "CVE-2026-2", "b"), fmt.Sprintf(m, "CVE-2026-1", "z"),
		fmt.Sprintf(m, "CVE-2026-2", "a"), fmt.Sprintf(m, "CVE-2026-1", "y"),
	}, ",") + `]}`
	f := newFakeGrype(t, "cat <<'EOF'\n"+out+"\nEOF\n")
	got, err := NewGrype(f.binary, t.TempDir()).Match(t.Context(), someSBOMPath)
	require.NoError(t, err)
	order := make([]string, 0, len(got))
	for _, match := range got {
		order = append(order, match.VulnerabilityID+"/"+match.PackageID)
	}
	require.Equal(t, []string{"CVE-2026-1/y", "CVE-2026-1/z", "CVE-2026-2/a", "CVE-2026-2/b"}, order)
}

func TestStatusReadsTheVersionAndTheBuildTime(t *testing.T) {
	f := newFakeGrype(t, prints(statusPath))
	got, err := NewGrype(f.binary, t.TempDir()).Status(t.Context())
	require.NoError(t, err)
	// R36: the schema version and the build time. The schema version alone stays the same across
	// the daily builds.
	require.Equal(t, goldenVersion, got.Version)
	require.True(t, time.Date(2026, 10, 30, 6, 23, 28, 0, time.UTC).Equal(got.Built), "built: %s", got.Built)
	require.Equal(t, time.UTC, got.Built.Location())
}

// statusReplacing returns the path of the status file with old replaced by new, which must be in it.
func statusReplacing(t *testing.T, old, replacement string) string {
	t.Helper()
	raw, err := os.ReadFile(statusPath)
	require.NoError(t, err)
	require.Contains(t, string(raw), old)
	path := filepath.Join(t.TempDir(), "status.json")
	require.NoError(t, os.WriteFile(path, []byte(strings.Replace(string(raw), old, replacement, 1)), 0o600))
	return path
}

func TestTheVersionChangesWithTheBuildTimeAndOnlyWithIt(t *testing.T) {
	status := func(file string) matchapi.Database {
		f := newFakeGrype(t, prints(file))
		got, err := NewGrype(f.binary, t.TempDir()).Status(t.Context())
		require.NoError(t, err)
		return got
	}
	first := status(statusPath)

	// The same status gives the same version, and so does one that differs only in where the
	// database is.
	require.Equal(t, first, status(statusPath))
	require.Equal(t, first.Version, status(statusReplacing(t, "/opt/grype-db", "/db")).Version)

	// A status that differs in nothing but the build time gives another version, and the build time.
	next := status(statusReplacing(t, goldenBuilt, someOtherBuilt))
	require.NotEqual(t, first.Version, next.Version)
	require.Equal(t, "v6.1.10+"+someOtherBuilt, next.Version)
	require.True(t, next.Built.After(first.Built))
}

func TestTheBuildTimeIsInUTCWhateverZoneGrypeWritesIt(t *testing.T) {
	// The same instant gives the same version, so a status that writes it with an offset doesn't
	// look like another build.
	f := newFakeGrype(t, prints(statusReplacing(t, goldenBuilt, "2026-10-30T08:23:28+02:00")))
	got, err := NewGrype(f.binary, t.TempDir()).Status(t.Context())
	require.NoError(t, err)
	require.Equal(t, goldenVersion, got.Version)
	require.Equal(t, time.UTC, got.Built.Location())
	require.True(t, time.Date(2026, 10, 30, 6, 23, 28, 0, time.UTC).Equal(got.Built))
}

func TestAStatusWithAnotherSchemaGivesAnotherVersion(t *testing.T) {
	f := newFakeGrype(t, prints(statusReplacing(t, `"schemaVersion": "v6.1.10"`, `"schemaVersion": "v6.2.0"`)))
	got, err := NewGrype(f.binary, t.TempDir()).Status(t.Context())
	require.NoError(t, err)
	require.Equal(t, "v6.2.0+"+goldenBuilt, got.Version)
}

func TestStatusOfAnEmptyDirectoryIsAnError(t *testing.T) {
	// What Grype prints when the directory holds no database, and its exit status 1.
	f := newFakeGrype(t, "cat "+shellQuote(abs(statusNonePath))+"\necho 'ERROR database does not exist' >&2\nexit 1\n")
	_, err := NewGrype(f.binary, t.TempDir()).Status(t.Context())
	require.Error(t, err)
	require.NotContains(t, err.Error(), "does not exist")
}

func TestStatusThatIsNotAValidDatabaseIsAnError(t *testing.T) {
	// Even with exit status 0, the server is ready only for a database that Grype calls valid.
	for name, stdout := range map[string]string{
		"not valid":         `{"schemaVersion": "v6.1.10", "built": "` + goldenBuilt + `", "valid": false, "error": "` + secretStdout + `"}`,
		"no valid field":    `{"schemaVersion": "v6.1.10", "built": "` + goldenBuilt + `"}`,
		"no schema version": `{"built": "` + goldenBuilt + `", "valid": true}`,
		"no build time":     `{"schemaVersion": "v6.1.10", "valid": true}`,
		"a bad build time":  `{"schemaVersion": "v6.1.10", "built": "` + secretStdout + `", "valid": true}`,
		notJSON:             "<html>" + secretStdout + "</html>",
		"nothing":           "",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGrype(t, "cat <<'EOF'\n"+stdout+"\nEOF\n")
			got, err := NewGrype(f.binary, t.TempDir()).Status(t.Context())
			require.Error(t, err)
			require.Zero(t, got)
			require.NotContains(t, err.Error(), secretStdout)
		})
	}
}
