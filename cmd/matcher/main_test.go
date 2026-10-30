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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/matcher"
)

const (
	// databaseFile is the file whose presence makes the fake Grype call a database valid.
	databaseFile = "6/vulnerability.db"
	readyz       = "/readyz"
	healthz      = "/healthz"
	// The flags that the tests pass most.
	flagListen         = "--listen"
	flagGrype          = "--grype"
	flagDBDir          = "--db-dir"
	flagOffline        = "--offline"
	flagSeedDB         = "--seed-db"
	flagUpdateInterval = "--update-interval"
	flagMaxConcurrent  = "--max-concurrent"
	sbomObject         = `{"schema": {"version": "16.1.11"}, "artifacts": []}`
	// fakeVersion is what the fake Grype's status gives.
	fakeVersion = "v6.1.10+2026-10-30T06:23:28Z"
)

var dbOne = matchapi.Database{Version: fakeVersion, Built: time.Date(2026, 10, 30, 6, 23, 28, 0, time.UTC)}

// syncBuffer is a buffer that the logger of the matcher may write to from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestParseOptionsDefaults(t *testing.T) {
	opts, err := parseOptions(nil, &bytes.Buffer{})
	require.NoError(t, err)
	require.Equal(t, ":8080", opts.listen)
	require.Equal(t, "/usr/local/bin/grype", opts.grype)
	require.Equal(t, "/db", opts.dbDir)
	require.Empty(t, opts.seedDB)
	require.False(t, opts.offline)
	require.Equal(t, 6*time.Hour, opts.updateInterval)
	require.Equal(t, 2, opts.maxConcurrent)
}

func TestParseOptions(t *testing.T) {
	opts, err := parseOptions([]string{
		flagListen, "127.0.0.1:9000", flagGrype, "/bin/grype", flagDBDir, "/data", flagOffline,
		flagSeedDB, "/opt/grype-db", flagUpdateInterval, "90m", flagMaxConcurrent, "5",
		"--zap-log-level", "debug",
	}, &bytes.Buffer{})
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:9000", opts.listen)
	require.Equal(t, "/bin/grype", opts.grype)
	require.Equal(t, "/data", opts.dbDir)
	require.Equal(t, "/opt/grype-db", opts.seedDB)
	require.True(t, opts.offline)
	require.Equal(t, 90*time.Minute, opts.updateInterval)
	require.Equal(t, 5, opts.maxConcurrent)
}

func TestParseOptionsRefuses(t *testing.T) {
	for name, args := range map[string][]string{
		"no slots":          {flagMaxConcurrent, "0"},
		"negative slots":    {flagMaxConcurrent, "-1"},
		"no interval":       {flagUpdateInterval, "0s"},
		"negative interval": {flagUpdateInterval, "-1h"},
		"a bad interval":    {flagUpdateInterval, "often"},
		"no address":        {flagListen, ""},
		"no Grype":          {flagGrype, ""},
		"no database dir":   {flagDBDir, ""},
		"an unknown flag":   {"--no-such-flag"},
		"an argument":       {"extra"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := parseOptions(args, &out)
			require.Error(t, err)
			require.NotEmpty(t, out.String(), "the reason is printed")
		})
	}
}

func TestHelpIsNotAnError(t *testing.T) {
	var stderr bytes.Buffer
	require.Equal(t, exitOK, run(t.Context(), []string{"--help"}, &stderr))
	// The flag package writes a flag with one dash, and accepts it with two.
	for _, name := range []string{
		"listen", "grype", "db-dir", "offline", "seed-db", "update-interval", "max-concurrent", "zap-log-level",
	} {
		require.Contains(t, stderr.String(), "-"+name)
	}
}

func TestTheHTTPServerHasItsTimeouts(t *testing.T) {
	srv := newHTTPServer(t.Context(), ":0", http.NotFoundHandler())
	require.Positive(t, srv.ReadHeaderTimeout)
	require.Positive(t, srv.ReadTimeout)
	require.Positive(t, srv.IdleTimeout)
	// Matching a large SBOM can take a minute. The client waits two, and the server must not cut
	// its answer off before it gives up.
	require.Greater(t, srv.WriteTimeout, matchapi.DefaultTimeout)
	require.GreaterOrEqual(t, srv.ReadTimeout, srv.ReadHeaderTimeout)
}

func TestTheServersContextCarriesTheLoggerButNotTheCancellation(t *testing.T) {
	type key struct{}
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), key{}, "carried"))
	srv := newHTTPServer(ctx, ":0", http.NotFoundHandler())
	base := srv.BaseContext(nil)
	require.Equal(t, "carried", base.Value(key{}))
	// A request that runs when the matcher is stopped may finish within the grace period.
	cancel()
	require.NoError(t, base.Err())
}

// seedTree writes a tree like the one `grype db update` leaves in its cache directory.
func seedTree(t *testing.T) string {
	t.Helper()
	seed := filepath.Join(t.TempDir(), "grype-db")
	require.NoError(t, os.MkdirAll(filepath.Join(seed, "6"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(seed, databaseFile), []byte("database"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seed, "6", "import.json"), []byte(`{"digest": "x"}`), 0o640))
	return seed
}

func TestSeedDatabaseCopiesTheTree(t *testing.T) {
	seed := seedTree(t)
	dir := filepath.Join(t.TempDir(), "db")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, seedDatabase(seed, dir))

	got, err := os.ReadFile(filepath.Join(dir, databaseFile))
	require.NoError(t, err)
	require.Equal(t, "database", string(got))
	got, err = os.ReadFile(filepath.Join(dir, "6", "import.json"))
	require.NoError(t, err)
	require.JSONEq(t, `{"digest": "x"}`, string(got))
	info, err := os.Stat(filepath.Join(dir, "6", "import.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm())

	// The seed is a copy's source, and stays as it is. No temporary file is left in the target.
	require.FileExists(t, filepath.Join(seed, databaseFile))
	entries, err := os.ReadDir(filepath.Join(dir, "6"))
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

func TestSeedDatabaseCreatesTheTargetAndReplacesWhatIsThere(t *testing.T) {
	seed := seedTree(t)
	// A target that doesn't exist yet, and a database in it that an earlier copy left half-written.
	dir := filepath.Join(t.TempDir(), "new", "db")
	require.NoError(t, seedDatabase(seed, dir))
	require.NoError(t, os.WriteFile(filepath.Join(dir, databaseFile), []byte("half"), 0o644))
	require.NoError(t, seedDatabase(seed, dir))
	got, err := os.ReadFile(filepath.Join(dir, databaseFile))
	require.NoError(t, err)
	require.Equal(t, "database", string(got))
}

func TestSeedDatabaseFails(t *testing.T) {
	dir := t.TempDir()
	t.Run("no seed", func(t *testing.T) {
		require.Error(t, seedDatabase(filepath.Join(t.TempDir(), "missing"), dir))
	})
	t.Run("a seed that is a file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "seed")
		require.NoError(t, os.WriteFile(file, []byte("database"), 0o644))
		target := filepath.Join(t.TempDir(), "db")
		require.Error(t, seedDatabase(file, target))
		require.NoFileExists(t, target)
	})
	t.Run("a seed that holds a link", func(t *testing.T) {
		seed := seedTree(t)
		require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(seed, "6", "link")))
		require.Error(t, seedDatabase(seed, filepath.Join(t.TempDir(), "db")))
	})
	t.Run("a target that can't be written", func(t *testing.T) {
		blocked := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(blocked, nil, 0o644))
		require.Error(t, seedDatabase(seedTree(t), filepath.Join(blocked, "db")))
	})
	t.Run("a failed copy leaves no temporary file", func(t *testing.T) {
		seed := seedTree(t)
		target := t.TempDir()
		// A directory where the file should go: the rename fails after the copy.
		require.NoError(t, os.MkdirAll(filepath.Join(target, databaseFile), 0o755))
		require.Error(t, seedDatabase(seed, target))
		entries, err := os.ReadDir(filepath.Join(target, "6"))
		require.NoError(t, err)
		for _, e := range entries {
			require.NotContains(t, e.Name(), ".seed", "left behind: %s", e.Name())
		}
	})
}

// database is a Grype for the tests of maintain. Its database is valid when databaseFile is in the
// database directory, so that seeding, which copies the file, makes it valid, as an update does.
type database struct {
	dir string

	mu      sync.Mutex
	updates int
	// updateErrs are the errors of the next updates, in order. An update after them works.
	updateErrs []error
}

func (d *database) Match(context.Context, string) ([]matchapi.Match, error) { return nil, nil }

func (d *database) Status(context.Context) (matchapi.Database, error) {
	if _, err := os.Stat(filepath.Join(d.dir, databaseFile)); err != nil {
		return matchapi.Database{}, errors.New("no database")
	}
	return dbOne, nil
}

func (d *database) Update(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.updates++
	if len(d.updateErrs) > 0 {
		err := d.updateErrs[0]
		d.updateErrs = d.updateErrs[1:]
		return err
	}
	if err := os.MkdirAll(filepath.Join(d.dir, "6"), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d.dir, databaseFile), []byte("database"), 0o644)
}

func (d *database) updateCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.updates
}

// put makes the database directory hold a database.
func (d *database) put(t *testing.T) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(d.dir, "6"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(d.dir, databaseFile), []byte("database"), 0o644))
}

func isReady(srv *matcher.Server) bool {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, readyz, nil))
	return rec.Code == http.StatusOK
}

// maintained runs maintain in the background. It returns the server and the database, and a stop
// that ends it and waits.
func maintained(t *testing.T, opts options, d *database) (srv *matcher.Server, stop func()) {
	t.Helper()
	srv = matcher.NewServer(d, 2)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		maintain(ctx, srv, opts)
	}()
	stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("maintain didn't stop when its context ended")
		}
	}
	t.Cleanup(stop)
	return srv, stop
}

func testOptions(d *database) options {
	return options{
		dbDir: d.dir, updateInterval: time.Hour, retryDelay: time.Hour, maxConcurrent: 2,
	}
}

func TestOfflineUsesTheDatabaseThatIsThereAndNeverUpdates(t *testing.T) {
	d := &database{dir: t.TempDir()}
	d.put(t)
	opts := testOptions(d)
	opts.offline = true
	opts.updateInterval = 5 * time.Millisecond
	opts.retryDelay = 5 * time.Millisecond

	srv, _ := maintained(t, opts, d)
	require.Eventually(t, func() bool { return isReady(srv) }, 5*time.Second, 5*time.Millisecond)
	// Not at start, and not on the interval, which is ten times over in the time that passes here.
	time.Sleep(60 * time.Millisecond)
	require.Zero(t, d.updateCount())
}

func TestOfflineWithoutADatabaseStaysNotReadyAndNeverUpdates(t *testing.T) {
	d := &database{dir: t.TempDir()}
	opts := testOptions(d)
	opts.offline = true
	opts.updateInterval = 5 * time.Millisecond
	opts.retryDelay = 5 * time.Millisecond

	srv, _ := maintained(t, opts, d)
	time.Sleep(60 * time.Millisecond)
	require.False(t, isReady(srv))
	require.Zero(t, d.updateCount())
}

func TestOfflineSeedsAnEmptyDatabaseDirectory(t *testing.T) {
	d := &database{dir: filepath.Join(t.TempDir(), "db")}
	opts := testOptions(d)
	opts.offline = true
	opts.seedDB = seedTree(t)

	srv, _ := maintained(t, opts, d)
	require.Eventually(t, func() bool { return isReady(srv) }, 5*time.Second, 5*time.Millisecond)
	require.FileExists(t, filepath.Join(d.dir, databaseFile))
	require.Zero(t, d.updateCount())
}

func TestASeedIsNotCopiedOverADatabaseThatIsThere(t *testing.T) {
	d := &database{dir: t.TempDir()}
	require.NoError(t, os.MkdirAll(filepath.Join(d.dir, "6"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(d.dir, databaseFile), []byte("newer database"), 0o644))
	opts := testOptions(d)
	opts.offline = true
	opts.seedDB = seedTree(t)

	srv, _ := maintained(t, opts, d)
	require.Eventually(t, func() bool { return isReady(srv) }, 5*time.Second, 5*time.Millisecond)
	got, err := os.ReadFile(filepath.Join(d.dir, databaseFile))
	require.NoError(t, err)
	require.Equal(t, "newer database", string(got))
	require.NoFileExists(t, filepath.Join(d.dir, "6", "import.json"))
}

func TestOfflineWithASeedThatHoldsNoDatabaseStaysNotReady(t *testing.T) {
	// An image built without WITH_DB has /opt/grype-db, and nothing in it.
	d := &database{dir: filepath.Join(t.TempDir(), "db")}
	opts := testOptions(d)
	opts.offline = true
	opts.seedDB = filepath.Join(t.TempDir(), "grype-db")
	require.NoError(t, os.MkdirAll(opts.seedDB, 0o755))

	srv, _ := maintained(t, opts, d)
	time.Sleep(60 * time.Millisecond)
	require.False(t, isReady(srv))
	require.Zero(t, d.updateCount())
}

func TestOfflineWithAMissingSeedStaysNotReady(t *testing.T) {
	d := &database{dir: t.TempDir()}
	opts := testOptions(d)
	opts.offline = true
	opts.seedDB = filepath.Join(t.TempDir(), "missing")

	srv, _ := maintained(t, opts, d)
	time.Sleep(60 * time.Millisecond)
	require.False(t, isReady(srv))
	require.Zero(t, d.updateCount())
}

func TestOnlineUpdatesAtStartWhenItHasNoDatabase(t *testing.T) {
	d := &database{dir: t.TempDir()}
	srv, _ := maintained(t, testOptions(d), d)
	require.Eventually(t, func() bool { return isReady(srv) }, 5*time.Second, 5*time.Millisecond)
	require.Equal(t, 1, d.updateCount())
}

func TestOnlineDoesNotUpdateAtStartWhenItHasADatabase(t *testing.T) {
	d := &database{dir: t.TempDir()}
	d.put(t)
	srv, _ := maintained(t, testOptions(d), d) // the interval is an hour
	require.Eventually(t, func() bool { return isReady(srv) }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	require.Zero(t, d.updateCount())
}

func TestOnlineSeedsFirstAndThenHasNoNeedToUpdateAtStart(t *testing.T) {
	d := &database{dir: filepath.Join(t.TempDir(), "db")}
	opts := testOptions(d)
	opts.seedDB = seedTree(t)
	srv, _ := maintained(t, opts, d)
	require.Eventually(t, func() bool { return isReady(srv) }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	require.Zero(t, d.updateCount())
}

func TestOnlineUpdatesEveryInterval(t *testing.T) {
	d := &database{dir: t.TempDir()}
	d.put(t)
	opts := testOptions(d)
	opts.updateInterval = 10 * time.Millisecond
	srv, _ := maintained(t, opts, d)
	require.Eventually(t, func() bool { return isReady(srv) && d.updateCount() >= 3 }, 5*time.Second, 5*time.Millisecond)
}

func TestOnlineTriesAgainSoonWhenItStillHasNoDatabase(t *testing.T) {
	// The first update fails, and the interval is an hour. Without a database the matcher is not
	// ready, so it doesn't wait for the interval.
	d := &database{dir: t.TempDir(), updateErrs: []error{errors.New("the proxy refused"), errors.New("and again")}}
	opts := testOptions(d)
	opts.retryDelay = 10 * time.Millisecond
	srv, _ := maintained(t, opts, d)
	require.Eventually(t, func() bool { return isReady(srv) }, 5*time.Second, 5*time.Millisecond)
	require.Equal(t, 3, d.updateCount())
}

func TestAFailedUpdateKeepsTheServerReady(t *testing.T) {
	d := &database{dir: t.TempDir()}
	d.put(t)
	d.updateErrs = []error{errors.New("the proxy refused"), errors.New("and again")}
	opts := testOptions(d)
	opts.updateInterval = 10 * time.Millisecond
	srv, _ := maintained(t, opts, d)
	require.Eventually(t, func() bool { return d.updateCount() >= 3 }, 5*time.Second, 5*time.Millisecond)
	require.True(t, isReady(srv), "two updates failed, and the third worked: the server stayed ready")
}

func TestMaintainStopsWhenItsContextEnds(t *testing.T) {
	d := &database{dir: t.TempDir()}
	d.put(t)
	opts := testOptions(d)
	opts.updateInterval = 5 * time.Millisecond
	_, stop := maintained(t, opts, d)
	time.Sleep(30 * time.Millisecond)
	stop()
	after := d.updateCount()
	time.Sleep(30 * time.Millisecond)
	require.Equal(t, after, d.updateCount(), "no update starts after the stop")
}

// fakeGrype writes a script that stands for the Grype CLI. Its database is valid when
// $GRYPE_DB_CACHE_DIR/6/vulnerability.db exists, and an update creates it, so that the test sees
// whether the matcher gave the CLI the directory of --db-dir. It appends a line to updatesLog for
// each update.
func fakeGrype(t *testing.T) (binary, updatesLog string) {
	t.Helper()
	dir := t.TempDir()
	updatesLog = filepath.Join(dir, "updates")
	script := `#!/bin/sh
db="$GRYPE_DB_CACHE_DIR/` + databaseFile + `"
case "$1" in
  sbom:*)
    # A test that sets these makes the match take time, and records when it starts and ends.
    [ -z "$MATCH_ORDER_LOG" ] || echo start >> "$MATCH_ORDER_LOG"
    [ -z "$MATCH_SECONDS" ] || sleep "$MATCH_SECONDS"
    [ -z "$MATCH_ORDER_LOG" ] || echo end >> "$MATCH_ORDER_LOG"
    cat <<'EOF'
{"matches": [{"vulnerability": {"id": "CVE-2026-0001", "severity": "High", "knownExploited": null,
  "fix": {"state": "fixed", "versions": ["1.2.3-r1"]}},
  "artifact": {"id": "p1", "name": "libexample", "version": "1.2.0-r0", "type": "apk"}}]}
EOF
    ;;
  db)
    case "$2" in
      status)
        if [ -f "$db" ]; then
          echo '{"schemaVersion": "v6.1.10", "built": "2026-10-30T06:23:28Z", "valid": true}'
        else
          echo '{"schemaVersion": "", "valid": false, "error": "database does not exist"}'
          exit 1
        fi
        ;;
      update)
        mkdir -p "$(dirname "$db")" && echo database > "$db"
        echo updated >> '` + updatesLog + `'
        ;;
    esac
    ;;
esac
`
	binary = filepath.Join(dir, "grype")
	require.NoError(t, os.WriteFile(binary, []byte(script), 0o755))
	return binary, updatesLog
}

// freeAddress returns an address on the loopback interface that nothing listens on.
func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

// running starts the matcher, and returns its base URL, its log, and a stop that ends it and returns
// its exit code.
func running(t *testing.T, args ...string) (baseURL string, logs *syncBuffer, stop func() int) {
	t.Helper()
	addr := freeAddress(t)
	logs = &syncBuffer{}
	ctx, cancel := context.WithCancel(t.Context())
	exit := make(chan int, 1)
	go func() { exit <- run(ctx, append([]string{flagListen, addr}, args...), logs) }()

	var once sync.Once
	var code int
	stop = func() int {
		once.Do(func() {
			cancel()
			select {
			case code = <-exit:
			case <-time.After(30 * time.Second):
				t.Error("the matcher didn't stop")
				code = -1
			}
		})
		return code
	}
	t.Cleanup(func() { stop() })
	return "http://" + addr, logs, stop
}

// waitFor waits until the matcher answers path with 200.
func waitFor(t *testing.T, baseURL, path string, logs *syncBuffer) {
	t.Helper()
	require.Eventually(t, func() bool { return get(baseURL, path) == http.StatusOK },
		30*time.Second, 20*time.Millisecond, "logs: %s", logs.String())
}

func get(baseURL, path string) int {
	resp, err := http.Get(baseURL + path)
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestRunServesTheMatcherOverASeededDatabase(t *testing.T) {
	binary, updates := fakeGrype(t)
	dbDir := filepath.Join(t.TempDir(), "db")
	baseURL, logs, stop := running(t, flagGrype, binary, flagDBDir, dbDir, flagOffline, flagSeedDB, seedTree(t))

	waitFor(t, baseURL, readyz, logs)
	require.Equal(t, http.StatusOK, get(baseURL, healthz))
	require.FileExists(t, filepath.Join(dbDir, databaseFile), "the seed went to --db-dir")

	c := &matchapi.Client{BaseURL: baseURL}
	db, err := c.Database(t.Context())
	require.NoError(t, err)
	require.Equal(t, fakeVersion, db.Version)

	got, err := c.Match(t.Context(), json.RawMessage(sbomObject))
	require.NoError(t, err)
	require.Equal(t, fakeVersion, got.DatabaseVersion)
	require.Equal(t, []matchapi.Match{{
		VulnerabilityID: "CVE-2026-0001", PackageID: "p1", Severity: "High", FixState: "fixed",
		FixedVersions: []string{"1.2.3-r1"}, PackageName: "libexample", PackageVersion: "1.2.0-r0", PackageType: "apk",
	}}, got.Matches)

	require.Equal(t, exitOK, stop())
	require.NoFileExists(t, updates, "--offline never updates")
}

func TestRunUpdatesWhenOnlineAndTheDirectoryHoldsNoDatabase(t *testing.T) {
	binary, updates := fakeGrype(t)
	dbDir := t.TempDir()
	baseURL, logs, stop := running(t, flagGrype, binary, flagDBDir, dbDir, flagUpdateInterval, "1h")

	waitFor(t, baseURL, readyz, logs)
	raw, err := os.ReadFile(updates)
	require.NoError(t, err)
	require.Equal(t, "updated\n", string(raw), "one update, at start")
	require.Equal(t, exitOK, stop())
}

func TestRunWithoutADatabaseIsNotReady(t *testing.T) {
	binary, _ := fakeGrype(t)
	baseURL, logs, stop := running(t, flagGrype, binary, flagDBDir, t.TempDir(), flagOffline)
	waitFor(t, baseURL, healthz, logs)
	require.Equal(t, http.StatusServiceUnavailable, get(baseURL, readyz))
	require.Equal(t, exitOK, stop())
	// The matcher says why, as an error. That is the only error here, and it has no stack trace.
	require.Contains(t, logs.String(), `"level":"error"`)
	require.NotContains(t, logs.String(), "stacktrace")
}

func TestStackTracesCanBeTurnedOn(t *testing.T) {
	binary, _ := fakeGrype(t)
	baseURL, logs, stop := running(t, flagGrype, binary, flagDBDir, t.TempDir(), flagOffline,
		"--zap-stacktrace-level", "error")
	waitFor(t, baseURL, healthz, logs)
	require.Equal(t, exitOK, stop())
	require.Contains(t, logs.String(), "stacktrace")
}

func TestRunLogsGrypesStderrOnlyAtDebugLevel(t *testing.T) {
	binary, _ := fakeGrype(t)
	noisy := filepath.Join(t.TempDir(), "grype")
	raw, err := os.ReadFile(binary)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(noisy, []byte(strings.Replace(string(raw), "case \"$1\" in",
		"echo SECRET-STDERR-OF-GRYPE >&2\ncase \"$1\" in", 1)), 0o755))

	for level, wantLogged := range map[string]bool{"info": false, "debug": true} {
		t.Run(level, func(t *testing.T) {
			baseURL, logs, stop := running(t, flagGrype, noisy, flagDBDir, t.TempDir(), flagSeedDB, seedTree(t),
				flagOffline, "--zap-log-level", level)
			waitFor(t, baseURL, readyz, logs)
			require.Equal(t, exitOK, stop())
			logged := strings.Contains(logs.String(), "SECRET-STDERR-OF-GRYPE")
			require.Equal(t, wantLogged, logged, "logs: %s", logs.String())
		})
	}
}

func TestRunMatchesAsManySBOMsAtOnceAsTheFlagSays(t *testing.T) {
	// Each match takes a second, and the fake logs when it starts and ends. With one slot the
	// matches run one after the other, and with two they overlap.
	const start, end = "start", "end"
	for slots, want := range map[string][]string{
		"1": {start, end, start, end},
		"2": {start, start, end, end},
	} {
		t.Run(slots+" slots", func(t *testing.T) {
			binary, _ := fakeGrype(t)
			orderLog := filepath.Join(t.TempDir(), "order")
			t.Setenv("MATCH_ORDER_LOG", orderLog)
			t.Setenv("MATCH_SECONDS", "1")
			baseURL, logs, stop := running(t, flagGrype, binary, flagDBDir, t.TempDir(), flagSeedDB, seedTree(t),
				flagOffline, flagMaxConcurrent, slots)
			waitFor(t, baseURL, readyz, logs)

			c := &matchapi.Client{BaseURL: baseURL}
			var wg sync.WaitGroup
			errs := make([]error, 2)
			for i := range errs {
				wg.Go(func() { _, errs[i] = c.Match(t.Context(), json.RawMessage(sbomObject)) })
			}
			wg.Wait()
			require.NoError(t, errs[0])
			require.NoError(t, errs[1])

			raw, err := os.ReadFile(orderLog)
			require.NoError(t, err)
			require.Equal(t, want, strings.Fields(string(raw)))
			require.Equal(t, exitOK, stop())
		})
	}
}

func TestRunFails(t *testing.T) {
	binary, _ := fakeGrype(t)
	t.Run("bad flags give 2, and say why", func(t *testing.T) {
		var stderr bytes.Buffer
		require.Equal(t, exitUsage, run(t.Context(), []string{flagMaxConcurrent, "0"}, &stderr))
		require.Contains(t, stderr.String(), "max-concurrent")
	})
	t.Run("a Grype that isn't there", func(t *testing.T) {
		var stderr syncBuffer
		missing := filepath.Join(t.TempDir(), "missing")
		code := run(t.Context(), []string{flagGrype, missing, flagListen, freeAddress(t)}, &stderr)
		require.Equal(t, exitFailed, code)
		require.Contains(t, stderr.String(), "grype")
	})
	t.Run("an address that is taken", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = l.Close() })
		var stderr syncBuffer
		require.Equal(t, exitFailed, run(t.Context(), []string{flagGrype, binary, flagListen, l.Addr().String()}, &stderr))
		require.NotEmpty(t, stderr.String())
	})
}
