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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/matchapi"
)

const (
	// sbomObject is the SBOM of a request. The server must hand Grype exactly these bytes.
	sbomObject = `{"schema": {"version": "16.1.11"}, "artifacts": []}`
	sbomBody   = `{"sbom": ` + sbomObject + `}`

	// secretError and secretFragment stand for text that must never reach a response: Grype's
	// stderr in an error, and a piece of the SBOM in a request that is refused.
	secretError    = "SECRET-ERROR-TEXT"
	secretFragment = "SECRET-SBOM-FRAGMENT"

	readyz  = "/readyz"
	healthz = "/healthz"
)

var (
	dbOne = matchapi.Database{Version: "v6.1.10+2026-10-30T06:23:28Z", Built: time.Date(2026, 10, 30, 6, 23, 28, 0, time.UTC)}
	dbTwo = matchapi.Database{Version: "v6.1.10+2026-10-31T06:24:11Z", Built: time.Date(2026, 10, 31, 6, 24, 11, 0, time.UTC)}

	someMatches = []matchapi.Match{{
		VulnerabilityID: "CVE-2026-0001", PackageID: "p1", Severity: severityHigh, FixState: "fixed",
		FixedVersions: []string{"1.2.3-r1"}, KnownExploited: true,
		PackageName: "libexample", PackageVersion: "1.2.0-r0", PackageType: typeAPK,
	}}
)

// backend is a Grype that the tests control. Its three commands run the functions that a test sets,
// and count their calls.
type backend struct {
	mu                      sync.Mutex
	matchFn                 func(ctx context.Context, sbomPath string) ([]matchapi.Match, error)
	updateFn                func(ctx context.Context) error
	statusFn                func(ctx context.Context) (matchapi.Database, error)
	matchCalls, updateCalls int
	statusCalls             int
	sbomPaths               []string
}

func (b *backend) Match(ctx context.Context, sbomPath string) ([]matchapi.Match, error) {
	b.mu.Lock()
	b.matchCalls++
	b.sbomPaths = append(b.sbomPaths, sbomPath)
	fn := b.matchFn
	b.mu.Unlock()
	if fn == nil {
		return someMatches, nil
	}
	return fn(ctx, sbomPath)
}

func (b *backend) Update(ctx context.Context) error {
	b.mu.Lock()
	b.updateCalls++
	fn := b.updateFn
	b.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(ctx)
}

func (b *backend) Status(ctx context.Context) (matchapi.Database, error) {
	b.mu.Lock()
	b.statusCalls++
	fn := b.statusFn
	b.mu.Unlock()
	if fn == nil {
		return dbOne, nil
	}
	return fn(ctx)
}

func (b *backend) calls() (match, update int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.matchCalls, b.updateCalls
}

// ready returns a server that has loaded dbOne.
func ready(t *testing.T, b *backend, maxConcurrent int) *Server {
	t.Helper()
	s := NewServer(b, maxConcurrent)
	require.NoError(t, s.Load(t.Context()))
	return s
}

// do sends a request to the handler, and returns what it answered.
func do(ctx context.Context, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, method, target, strings.NewReader(body)))
	return rec
}

func post(ctx context.Context, h http.Handler, body string) *httptest.ResponseRecorder {
	return do(ctx, h, http.MethodPost, matchapi.PathMatch, body)
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &v), "body: %s", rec.Body.String())
	return v
}

func TestMatchReturnsTheMatches(t *testing.T) {
	var gotSBOM []byte
	b := &backend{matchFn: func(_ context.Context, path string) ([]matchapi.Match, error) {
		var err error
		gotSBOM, err = os.ReadFile(path)
		require.NoError(t, err)
		return someMatches, nil
	}}
	rec := post(t.Context(), ready(t, b, 2).Handler(), sbomBody)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Equal(t, matchapi.MatchResponse{DatabaseVersion: dbOne.Version, Matches: someMatches},
		decode[matchapi.MatchResponse](t, rec))
	// Grype gets the SBOM object, and nothing of the request around it.
	require.Equal(t, sbomObject, string(gotSBOM))
}

func TestNoMatchesIsAnEmptyListAndNeverMissing(t *testing.T) {
	for name, matches := range map[string][]matchapi.Match{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			b := &backend{matchFn: func(context.Context, string) ([]matchapi.Match, error) { return matches, nil }}
			rec := post(t.Context(), ready(t, b, 2).Handler(), sbomBody)
			require.Equal(t, http.StatusOK, rec.Code)
			require.JSONEq(t, `{"databaseVersion": "`+dbOne.Version+`", "matches": []}`, rec.Body.String())
		})
	}
}

func TestTheSBOMFileLivesInTheTempDirAndIsRemovedAfterTheMatch(t *testing.T) {
	// The server writes under os.TempDir(), which the Deployment mounts as an emptyDir, because the root
	// filesystem is read-only.
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	for name, matchErr := range map[string]error{"a match that works": nil, "a match that fails": errors.New(secretError)} {
		t.Run(name, func(t *testing.T) {
			var during []string
			b := &backend{matchFn: func(_ context.Context, path string) ([]matchapi.Match, error) {
				require.Equal(t, dir, filepath.Dir(path))
				entries, err := os.ReadDir(dir)
				require.NoError(t, err)
				for _, e := range entries {
					during = append(during, e.Name())
				}
				return someMatches, matchErr
			}}
			post(t.Context(), ready(t, b, 2).Handler(), sbomBody)
			require.Len(t, during, 1, "the file is there while Grype reads it")

			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Empty(t, entries, "and gone after the match")
		})
	}
}

func TestAnSBOMThatCannotBeWrittenGives500(t *testing.T) {
	// The root filesystem is read-only, and without a volume at /tmp the server has nowhere to
	// write. That is a fault of the matcher, with a fixed text, and Grype is not asked.
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	t.Setenv("TMPDIR", missing)
	b := &backend{}
	rec := post(t.Context(), ready(t, b, 2).Handler(), sbomBody)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.NotContains(t, rec.Body.String(), missing)
	match, _ := b.calls()
	require.Zero(t, match)
}

func TestEachRequestGetsAFileOfItsOwn(t *testing.T) {
	b := &backend{}
	h := ready(t, b, 2).Handler()
	post(t.Context(), h, sbomBody)
	post(t.Context(), h, sbomBody)
	require.Len(t, b.sbomPaths, 2)
	require.NotEqual(t, b.sbomPaths[0], b.sbomPaths[1])
}

func TestAMatchThatFailsGivesAFixedText(t *testing.T) {
	bodies := map[string]string{}
	for name, err := range map[string]error{
		"one error": errors.New(secretError),
		"another":   errors.New(secretError + " that differs"),
		"a wrapped": errors.New("grype match: exit status 1: " + secretError),
	} {
		b := &backend{matchFn: func(context.Context, string) ([]matchapi.Match, error) { return nil, err }}
		rec := post(t.Context(), ready(t, b, 2).Handler(), sbomBody)
		require.Equal(t, http.StatusInternalServerError, rec.Code, name)
		require.NotContains(t, rec.Body.String(), secretError, name)
		bodies[name] = rec.Body.String()
	}
	// The same text for every failure: nothing of the error is in it.
	require.Len(t, bodies, 3)
	for _, body := range bodies {
		require.Equal(t, bodies["one error"], body)
	}
}

func TestBeforeADatabaseIsLoadedTheServerIsNotReady(t *testing.T) {
	b := &backend{statusFn: func(context.Context) (matchapi.Database, error) {
		return matchapi.Database{}, errors.New("no database")
	}}
	s := NewServer(b, 2)
	h := s.Handler()

	// Without a database, /v1/match and /v1/database answer as /readyz does.
	for _, tc := range []struct{ method, target, body string }{
		{http.MethodPost, matchapi.PathMatch, sbomBody},
		{http.MethodGet, matchapi.PathDatabase, ""},
		{http.MethodGet, readyz, ""},
	} {
		rec := do(t.Context(), h, tc.method, tc.target, tc.body)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, tc.target)
		require.Equal(t, "30", rec.Header().Get("Retry-After"), tc.target)
	}
	match, _ := b.calls()
	require.Zero(t, match, "Grype is not asked to match without a database")

	// The process is alive, though: /healthz doesn't depend on the database.
	require.Equal(t, http.StatusOK, do(t.Context(), h, http.MethodGet, healthz, "").Code)

	// A Load that finds no valid database leaves it not ready.
	require.Error(t, s.Load(t.Context()))
	require.Equal(t, http.StatusServiceUnavailable, do(t.Context(), h, http.MethodGet, readyz, "").Code)
}

func TestOnceADatabaseIsLoadedTheServerIsReady(t *testing.T) {
	var status func(context.Context) (matchapi.Database, error)
	b := &backend{statusFn: func(ctx context.Context) (matchapi.Database, error) { return status(ctx) }}
	s := NewServer(b, 2)
	h := s.Handler()

	status = func(context.Context) (matchapi.Database, error) { return matchapi.Database{}, errors.New("none yet") }
	require.Error(t, s.Load(t.Context()))
	require.Equal(t, http.StatusServiceUnavailable, do(t.Context(), h, http.MethodGet, readyz, "").Code)

	status = func(context.Context) (matchapi.Database, error) { return dbOne, nil }
	require.NoError(t, s.Load(t.Context()))
	require.Equal(t, http.StatusOK, do(t.Context(), h, http.MethodGet, readyz, "").Code)
	require.Equal(t, http.StatusOK, do(t.Context(), h, http.MethodGet, healthz, "").Code)
	require.Equal(t, http.StatusOK, post(t.Context(), h, sbomBody).Code)
}

func TestTheDatabaseEndpoint(t *testing.T) {
	rec := do(t.Context(), ready(t, &backend{}, 2).Handler(), http.MethodGet, matchapi.PathDatabase, "")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	got := decode[matchapi.Database](t, rec)
	require.Equal(t, dbOne.Version, got.Version)
	require.True(t, dbOne.Built.Equal(got.Built))
}

func TestTheMethodsAreChecked(t *testing.T) {
	h := ready(t, &backend{}, 2).Handler()
	for target, method := range map[string]string{
		matchapi.PathMatch:    http.MethodGet,
		matchapi.PathDatabase: http.MethodPost,
		"/readyz":             http.MethodPost,
		healthz:               http.MethodDelete,
	} {
		require.Equal(t, http.StatusMethodNotAllowed, do(t.Context(), h, method, target, sbomBody).Code, "%s %s", method, target)
	}
	require.Equal(t, http.StatusNotFound, do(t.Context(), h, http.MethodGet, "/nothing", "").Code)
}

func TestRequestsThatAreNotAnSBOMGive400(t *testing.T) {
	for name, body := range map[string]string{
		notJSON:           "not json " + secretFragment,
		"empty":           "",
		"cut off":         `{"sbom": {"artifacts": [` + secretFragment,
		"trailing text":   sbomBody + " " + secretFragment,
		"a list":          `[]`,
		"no sbom":         `{"other": "` + secretFragment + `"}`,
		"a null sbom":     `{"sbom": null}`,
		"a string sbom":   `{"sbom": "` + secretFragment + `"}`,
		"a number sbom":   `{"sbom": 7}`,
		"a list sbom":     `{"sbom": ["` + secretFragment + `"]}`,
		"a boolean sbom":  `{"sbom": true}`,
		"an empty sbom":   `{"sbom": }`,
		"two sbom fields": `{"sbom": ` + sbomObject + `, "sbom": "` + secretFragment + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			b := &backend{}
			rec := post(t.Context(), ready(t, b, 2).Handler(), body)
			// "two sbom fields" is JSON whose last value counts: a string, so not an object.
			require.Equal(t, http.StatusBadRequest, rec.Code)
			require.NotContains(t, rec.Body.String(), secretFragment)
			match, _ := b.calls()
			require.Zero(t, match, "Grype never sees what is not an SBOM")
		})
	}
}

func TestAnSBOMWithLeadingSpaceIsStillAnObject(t *testing.T) {
	rec := post(t.Context(), ready(t, &backend{}, 2).Handler(), "\n  {\"sbom\":\n\t "+sbomObject+" \n}\n")
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestTheRequestIsCapped(t *testing.T) {
	require.EqualValues(t, 64<<20, matchapi.MaxRequestBytes)
	require.EqualValues(t, matchapi.MaxRequestBytes, NewServer(&backend{}, 1).maxBody)

	const limit = 120
	newServer := func(t *testing.T) (*Server, *backend) {
		b := &backend{}
		s := ready(t, b, 2)
		s.maxBody = limit
		return s, b
	}
	// A body of exactly the limit: an SBOM object padded to it.
	exact := `{"sbom": {"p": "` + strings.Repeat("a", limit-len(`{"sbom": {"p": ""}}`)) + `"}}`
	require.Len(t, exact, limit)

	t.Run("a body at the limit is read", func(t *testing.T) {
		s, _ := newServer(t)
		require.Equal(t, http.StatusOK, post(t.Context(), s.Handler(), exact).Code)
	})
	t.Run("a body over the limit gives 413", func(t *testing.T) {
		s, b := newServer(t)
		rec := post(t.Context(), s.Handler(), exact+" ")
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		match, _ := b.calls()
		require.Zero(t, match)
	})
	t.Run("a length over the limit gives 413 without reading", func(t *testing.T) {
		s, _ := newServer(t)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, matchapi.PathMatch, iotest.ErrReader(errors.New("read")))
		req.ContentLength = limit + 1
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})
	t.Run("a body of no known length is counted as it is read", func(t *testing.T) {
		s, _ := newServer(t)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, matchapi.PathMatch, strings.NewReader(exact+exact))
		req.ContentLength = -1
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		require.NotContains(t, rec.Body.String(), "aaaa")
	})
	t.Run("a body that can't be read gives 400", func(t *testing.T) {
		s, b := newServer(t)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, matchapi.PathMatch,
			io.MultiReader(strings.NewReader(`{"sbom": {"p": "`), iotest.ErrReader(errors.New(secretError))))
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.NotContains(t, rec.Body.String(), secretError)
		match, _ := b.calls()
		require.Zero(t, match)
	})
}

// blocking is a match that tells when it has started, and ends when released.
func blocking(started chan<- string, release <-chan struct{}) func(context.Context, string) ([]matchapi.Match, error) {
	return func(_ context.Context, path string) ([]matchapi.Match, error) {
		started <- path
		<-release
		return someMatches, nil
	}
}

func TestAThirdRequestWaitsForASlotAndGives503WhenItsContextEnds(t *testing.T) {
	started := make(chan string, 8)
	release := make(chan struct{})
	b := &backend{matchFn: blocking(started, release)}
	h := ready(t, b, 2).Handler()

	// Two requests take both slots, and are inside Grype together: matches share access.
	var wg sync.WaitGroup
	first := make([]*httptest.ResponseRecorder, 2)
	for i := range first {
		wg.Go(func() { first[i] = post(context.Background(), h, sbomBody) })
	}
	<-started
	<-started

	// The third waits.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	third := make(chan *httptest.ResponseRecorder, 1)
	go func() { third <- post(ctx, h, sbomBody) }()
	select {
	case rec := <-third:
		t.Fatalf("the third request was answered while both slots were taken: %d", rec.Code)
	case <-started:
		t.Fatal("Grype was asked to match for the third request while both slots were taken")
	case <-time.After(150 * time.Millisecond):
	}

	// When its context ends, it gives 503, and Grype never saw it.
	cancel()
	rec := <-third
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Equal(t, "30", rec.Header().Get("Retry-After"))
	require.NotContains(t, rec.Body.String(), secretFragment)
	match, _ := b.calls()
	require.Equal(t, 2, match)

	close(release)
	wg.Wait()
	for _, rec := range first {
		require.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestARequestThatIsRefusedIsAnsweredAtOnceWhileAllSlotsAreTaken(t *testing.T) {
	// A request that is no SBOM has nothing to match, so it doesn't wait for a slot: its client
	// learns that it is wrong when it asks, and not when the matcher has time for it.
	started := make(chan string, 4)
	release := make(chan struct{})
	b := &backend{matchFn: blocking(started, release)}
	h := ready(t, b, 1).Handler()

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- post(context.Background(), h, sbomBody) }()
	<-started // the one slot is taken

	for name, body := range map[string]string{"not JSON": "not json", "not an object": `{"sbom": []}`} {
		answered := make(chan *httptest.ResponseRecorder, 1)
		go func() { answered <- post(t.Context(), h, body) }()
		select {
		case rec := <-answered:
			require.Equal(t, http.StatusBadRequest, rec.Code, name)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the request waits for a slot", name)
		}
	}
	close(release)
	require.Equal(t, http.StatusOK, (<-first).Code)
}

func TestAThirdRequestGetsTheSlotThatIsFreed(t *testing.T) {
	started := make(chan string, 8)
	release := make(chan struct{})
	b := &backend{matchFn: blocking(started, release)}
	h := ready(t, b, 2).Handler()

	var wg sync.WaitGroup
	recs := make([]*httptest.ResponseRecorder, 3)
	for i := range recs {
		wg.Go(func() { recs[i] = post(context.Background(), h, sbomBody) })
	}
	<-started
	<-started
	select {
	case <-started:
		t.Fatal("a third match started while both slots were taken")
	case <-time.After(100 * time.Millisecond):
	}

	release <- struct{}{} // one match ends
	<-started             // and the third one starts
	close(release)
	wg.Wait()
	for _, rec := range recs {
		require.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestAServerOfNoSlotsStillServes(t *testing.T) {
	// A limit below one would wait for ever. It means one.
	for _, n := range []int{0, -3} {
		rec := post(t.Context(), ready(t, &backend{}, n).Handler(), sbomBody)
		require.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestAnUpdateWaitsForTheMatchesThatRun(t *testing.T) {
	started := make(chan string, 8)
	release := make(chan struct{})
	b := &backend{matchFn: blocking(started, release)}
	s := ready(t, b, 2)

	matched := make(chan *httptest.ResponseRecorder, 1)
	go func() { matched <- post(context.Background(), s.Handler(), sbomBody) }()
	<-started

	updated := make(chan error, 1)
	go func() { updated <- s.Update(context.Background()) }()
	select {
	case err := <-updated:
		t.Fatalf("the update ran while a match was reading the database: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	_, updates := b.calls()
	require.Zero(t, updates, "Grype's update waits for the match: it swaps the files that the match reads")

	close(release)
	require.Equal(t, http.StatusOK, (<-matched).Code)
	require.NoError(t, <-updated)
	_, updates = b.calls()
	require.Equal(t, 1, updates)
}

func TestMatchesWaitForAnUpdateAndGetTheNewVersion(t *testing.T) {
	updating := make(chan struct{})
	finish := make(chan struct{})
	var current atomicDB
	current.set(dbOne)
	b := &backend{
		statusFn: func(context.Context) (matchapi.Database, error) { return current.get(), nil },
		updateFn: func(context.Context) error {
			close(updating)
			<-finish
			current.set(dbTwo) // the files change under the update's lock
			return nil
		},
	}
	s := ready(t, b, 2)
	h := s.Handler()

	updated := make(chan error, 1)
	go func() { updated <- s.Update(context.Background()) }()
	<-updating

	matched := make(chan *httptest.ResponseRecorder, 1)
	go func() { matched <- post(context.Background(), h, sbomBody) }()
	select {
	case rec := <-matched:
		t.Fatalf("a match ran during the update: %d", rec.Code)
	case <-time.After(150 * time.Millisecond):
	}
	match, _ := b.calls()
	require.Zero(t, match, "Grype is not asked to match while the update runs")

	// The readiness probe and the version don't wait: a probe that timed out during a long update
	// would take the matcher out of its Service.
	probe := make(chan *httptest.ResponseRecorder, 1)
	database := make(chan *httptest.ResponseRecorder, 1)
	go func() { probe <- do(context.Background(), h, http.MethodGet, readyz, "") }()
	go func() { database <- do(context.Background(), h, http.MethodGet, matchapi.PathDatabase, "") }()
	select {
	case rec := <-probe:
		require.Equal(t, http.StatusOK, rec.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("the readiness probe waits for the update")
	}
	select {
	case rec := <-database:
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, dbOne.Version, decode[matchapi.Database](t, rec).Version, "still the old version")
	case <-time.After(5 * time.Second):
		t.Fatal("the database endpoint waits for the update")
	}

	close(finish)
	require.NoError(t, <-updated)
	rec := <-matched
	require.Equal(t, http.StatusOK, rec.Code)
	// The match ran after the update, so its matches come from the new database, and say so.
	require.Equal(t, dbTwo.Version, decode[matchapi.MatchResponse](t, rec).DatabaseVersion)
	require.Equal(t, dbTwo.Version, decode[matchapi.Database](t, do(t.Context(), h, http.MethodGet, matchapi.PathDatabase, "")).Version)
}

// atomicDB is a database that a test changes while the server runs.
type atomicDB struct {
	mu sync.Mutex
	db matchapi.Database
}

func (a *atomicDB) set(db matchapi.Database) { a.mu.Lock(); a.db = db; a.mu.Unlock() }
func (a *atomicDB) get() matchapi.Database   { a.mu.Lock(); defer a.mu.Unlock(); return a.db }

func TestAFailedUpdateKeepsTheOldDatabaseAndTheServerStaysReady(t *testing.T) {
	b := &backend{updateFn: func(context.Context) error { return errors.New("the proxy refused") }}
	s := ready(t, b, 2)
	h := s.Handler()

	require.Error(t, s.Update(t.Context()))

	require.Equal(t, http.StatusOK, do(t.Context(), h, http.MethodGet, readyz, "").Code)
	require.Equal(t, dbOne.Version, decode[matchapi.Database](t, do(t.Context(), h, http.MethodGet, matchapi.PathDatabase, "")).Version)
	rec := post(t.Context(), h, sbomBody)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, dbOne.Version, decode[matchapi.MatchResponse](t, rec).DatabaseVersion)
	// The failed update didn't ask for a status that could replace the version.
	require.Equal(t, 1, b.statusCalls, "only the Load read the status")
}

func TestAnUpdateThatCannotBeReadAfterwardsKeepsServing(t *testing.T) {
	// Grype updated, but its status then fails. The server can't name the new database, so it
	// keeps the old version, which is never newer than what the files hold.
	var current atomicDB
	current.set(dbOne)
	fail := false
	b := &backend{statusFn: func(context.Context) (matchapi.Database, error) {
		if fail {
			return matchapi.Database{}, errors.New("status failed")
		}
		return current.get(), nil
	}}
	s := ready(t, b, 2)
	fail = true
	require.Error(t, s.Update(t.Context()))
	require.Equal(t, http.StatusOK, do(t.Context(), s.Handler(), http.MethodGet, readyz, "").Code)
	require.Equal(t, dbOne.Version, decode[matchapi.Database](t, do(t.Context(), s.Handler(), http.MethodGet, matchapi.PathDatabase, "")).Version)
}

func TestAnUpdateChangesTheVersion(t *testing.T) {
	var current atomicDB
	current.set(dbOne)
	b := &backend{
		statusFn: func(context.Context) (matchapi.Database, error) { return current.get(), nil },
		updateFn: func(context.Context) error { current.set(dbTwo); return nil },
	}
	s := ready(t, b, 2)
	h := s.Handler()
	require.Equal(t, dbOne.Version, decode[matchapi.MatchResponse](t, post(t.Context(), h, sbomBody)).DatabaseVersion)

	require.NoError(t, s.Update(t.Context()))

	got := decode[matchapi.Database](t, do(t.Context(), h, http.MethodGet, matchapi.PathDatabase, ""))
	require.Equal(t, dbTwo.Version, got.Version)
	require.True(t, dbTwo.Built.Equal(got.Built))
	require.Equal(t, dbTwo.Version, decode[matchapi.MatchResponse](t, post(t.Context(), h, sbomBody)).DatabaseVersion)
}

func TestAnUpdateOfADatabaseThatWasNeverLoadedMakesTheServerReady(t *testing.T) {
	loaded := false
	b := &backend{
		statusFn: func(context.Context) (matchapi.Database, error) {
			if !loaded {
				return matchapi.Database{}, errors.New("no database")
			}
			return dbOne, nil
		},
		updateFn: func(context.Context) error { loaded = true; return nil },
	}
	s := NewServer(b, 2)
	require.Error(t, s.Load(t.Context()))
	require.NoError(t, s.Update(t.Context()))
	require.Equal(t, http.StatusOK, do(t.Context(), s.Handler(), http.MethodGet, readyz, "").Code)
}

func TestTheClientAndTheServerAgree(t *testing.T) {
	b := &backend{}
	s := NewServer(b, 2)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	c := &matchapi.Client{BaseURL: srv.URL}

	// Not ready: 503, which the client reads as ErrNotReady.
	_, err := c.Match(t.Context(), json.RawMessage(sbomObject))
	require.ErrorIs(t, err, matchapi.ErrNotReady)
	_, err = c.Database(t.Context())
	require.ErrorIs(t, err, matchapi.ErrNotReady)

	require.NoError(t, s.Load(t.Context()))
	got, err := c.Match(t.Context(), json.RawMessage(sbomObject))
	require.NoError(t, err)
	require.Equal(t, matchapi.MatchResponse{DatabaseVersion: dbOne.Version, Matches: someMatches}, got)
	db, err := c.Database(t.Context())
	require.NoError(t, err)
	require.Equal(t, dbOne.Version, db.Version)
	require.True(t, dbOne.Built.Equal(db.Built))

	// An SBOM that is not an object gives 400, which names its status.
	_, err = c.Match(t.Context(), json.RawMessage(`[]`))
	require.ErrorContains(t, err, "400")
	require.NotErrorIs(t, err, matchapi.ErrNotReady)

	// A match that fails gives 500, with nothing of the error.
	b.matchFn = func(context.Context, string) ([]matchapi.Match, error) { return nil, errors.New(secretError) }
	_, err = c.Match(t.Context(), json.RawMessage(sbomObject))
	require.ErrorContains(t, err, "500")
	require.NotContains(t, err.Error(), secretError)

	// A request over the cap gives 413.
	small := ready(t, &backend{}, 2)
	small.maxBody = 10
	srvSmall := httptest.NewServer(small.Handler())
	t.Cleanup(srvSmall.Close)
	_, err = (&matchapi.Client{BaseURL: srvSmall.URL}).Match(t.Context(), json.RawMessage(sbomObject))
	require.ErrorContains(t, err, "413")
}
