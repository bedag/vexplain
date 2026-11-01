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

package hub_test

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/bedag/vexplain/internal/controller/hub"
	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/scan/result"
	sdkevidence "github.com/bedag/vexplain/sdk/evidence"
	subjects "github.com/bedag/vexplain/sdk/subject"
)

// These tests cover MatcherFindings: phase 2a's HTTP matcher as the findings collector of a playbook,
// which matches the SBOM of the scanner's evidence, and says when its database has changed.

// fakeMatcher is a matcher whose database gives the same matches for every SBOM. It records the
// SBOMs that it is asked to match.
type fakeMatcher struct {
	mu          sync.Mutex
	version     string
	matches     []matchapi.Match
	matchErr    error
	databaseErr error
	sboms       []json.RawMessage
}

// set changes the database to one of version that gives the matches.
func (m *fakeMatcher) set(version string, matches ...matchapi.Match) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.version, m.matches = version, slices.Clone(matches)
}

// failDatabase makes every read of the database fail with err, until it is called with nil.
func (m *fakeMatcher) failDatabase(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.databaseErr = err
}

// Match answers as the matcher's client does: with the version and the matches of the database, and
// a list of matches that is empty, never missing, when there are none.
func (m *fakeMatcher) Match(_ context.Context, sbom json.RawMessage) (matchapi.MatchResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sboms = append(m.sboms, slices.Clone(sbom))
	if m.matchErr != nil {
		return matchapi.MatchResponse{}, m.matchErr
	}
	return matchapi.MatchResponse{DatabaseVersion: m.version, Matches: append([]matchapi.Match{}, m.matches...)}, nil
}

func (m *fakeMatcher) Database(context.Context) (matchapi.Database, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.databaseErr != nil {
		return matchapi.Database{}, m.databaseErr
	}
	return matchapi.Database{Version: m.version, Built: t0}, nil
}

// matched returns the SBOMs that the matcher was asked to match, in order.
func (m *fakeMatcher) matched() []json.RawMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.sboms)
}

// newMatcherFindings returns the findings collector of a matcher whose database is v1 and gives the
// matches, and the queue that its Changed delivers into.
func newMatcherFindings(t *testing.T, matches ...matchapi.Match) (*hub.MatcherFindings, *fakeMatcher,
	workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	t.Helper()
	matcher := &fakeMatcher{}
	matcher.set(v1, matches...)
	f := &hub.MatcherFindings{Matcher: matcher, Collector: matcherCollector, Consumed: result.EvidenceType, Interval: time.Hour}
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	t.Cleanup(queue.ShutDown)
	// The assessor starts the source, as a controller starts every source it watches.
	require.NoError(t, f.Changed().Start(t.Context(), queue))
	return f, matcher, queue
}

// drain takes every request out of the queue, as the controller's workers would.
func drain(queue workqueue.TypedRateLimitingInterface[reconcile.Request]) []reconcile.Request {
	var requests []reconcile.Request
	for queue.Len() > 0 {
		req, _ := queue.Get()
		requests = append(requests, req)
		queue.Done(req)
	}
	return requests
}

// everySubject is the request through which a findings collector says that every subject changed.
var everySubject = []reconcile.Request{{}}

func TestMatcherFindingsMatchesTheSBOMOfTheScannersEvidence(t *testing.T) {
	fixed := matchapi.Match{
		VulnerabilityID: otherCVE, PackageID: otherPackage, Severity: critical, FixState: fixedState,
		FixedVersions: []string{otherFix}, KnownExploited: true, PackageName: otherName, PackageVersion: otherVersion,
		PackageType: deb,
	}
	f, matcher, _ := newMatcherFindings(t, fixed)
	manifest := digestOf(101)

	got, err := f.Find(t.Context(), matcherCollector, scanEventOf(t0, evidenceOf(manifest)))

	require.NoError(t, err)
	require.Equal(t, sdkevidence.Findings{Version: v1, Matches: []sdkevidence.Match{{
		VulnerabilityID: otherCVE, PackageID: otherPackage, PackageName: otherName, PackageVersion: otherVersion,
		PackageType: deb, Severity: critical, FixState: fixedState, FixedVersions: []string{otherFix}, KnownExploited: true,
	}}}, got)
	require.Len(t, matcher.matched(), 1)
	require.JSONEq(t, string(sbomOf(manifest)), string(matcher.matched()[0]), "the SBOM of the evidence is matched")
}

func TestMatcherFindingsServeTheCollectorThatItStandsForOnly(t *testing.T) {
	f, matcher, _ := newMatcherFindings(t)

	require.Equal(t, []string{result.EvidenceType}, f.Consumes(matcherCollector))
	require.Empty(t, f.Consumes("other-matcher"))
	_, err := f.Find(t.Context(), "other-matcher", scanEventOf(t0, evidenceOf(digestOf(101))))
	require.ErrorContains(t, err, "other-matcher")
	require.Empty(t, matcher.matched())
}

// The matcher matches the SBOM of the scanner's evidence. Evidence of another type, or without an SBOM,
// gives no match, and never an empty one. The error names nothing of the evidence, which an image can
// craft.
func TestMatcherFindingsRefuseEvidenceThatHasNoSBOMToMatch(t *testing.T) {
	manifest := digestOf(101)
	other, err := sdkevidence.New("com.example.sbom.v1", subjects.Manifest(manifest), map[string]any{"sbom": map[string]any{}},
		sdkevidence.WithPlatform(linuxAMD64))
	require.NoError(t, err)
	noSBOM, err := sdkevidence.New(result.EvidenceType, subjects.Manifest(manifest), map[string]any{"digest": "\x1b[31mcrafted"},
		sdkevidence.WithPlatform(linuxAMD64))
	require.NoError(t, err)

	for name, input := range map[string]struct {
		event cloudevents.Event
		want  string
	}{
		"evidence of another type": {other, "com.example.sbom.v1"},
		"evidence without an SBOM": {noSBOM, "no SBOM"},
	} {
		t.Run(name, func(t *testing.T) {
			f, matcher, _ := newMatcherFindings(t)

			_, err := f.Find(t.Context(), matcherCollector, input.event)

			require.ErrorContains(t, err, input.want)
			require.NotContains(t, err.Error(), "crafted")
			require.Empty(t, matcher.matched())
		})
	}
}

// A failed match is no answer, and never an empty list of matches.
func TestMatcherFindingsReturnAFailedMatch(t *testing.T) {
	f, matcher, _ := newMatcherFindings(t)
	matcher.matchErr = matchapi.ErrNotReady

	_, err := f.Find(t.Context(), matcherCollector, scanEventOf(t0, evidenceOf(digestOf(101))))

	require.ErrorIs(t, err, matchapi.ErrNotReady)
}

// The first read that succeeds says that every subject changed, as a change of the version does: a
// manifest that was matched before it may have been matched against another database.
func TestMatcherFindingsSayEverySubjectChangedAtTheFirstReadAndAtEachChange(t *testing.T) {
	f, matcher, queue := newMatcherFindings(t)

	hub.Poll(f, t.Context())
	require.Equal(t, everySubject, drain(queue))
	hub.Poll(f, t.Context())
	require.Empty(t, drain(queue), "the same version, read again, is no change")

	matcher.set(v2)
	hub.Poll(f, t.Context())
	require.Equal(t, everySubject, drain(queue))
	hub.Poll(f, t.Context())
	require.Empty(t, drain(queue))
}

func TestMatcherFindingsKeepTheVersionThatTheyReadLastWhenTheMatcherFails(t *testing.T) {
	f, matcher, queue := newMatcherFindings(t)
	hub.Poll(f, t.Context())
	drain(queue)

	matcher.failDatabase(matchapi.ErrUnavailable)
	hub.Poll(f, t.Context())
	require.Empty(t, drain(queue))

	// The next read that succeeds counts, and the same version is no change.
	matcher.failDatabase(nil)
	hub.Poll(f, t.Context())
	require.Empty(t, drain(queue))
	matcher.set(v2)
	hub.Poll(f, t.Context())
	require.Equal(t, everySubject, drain(queue))
}

// Before the assessor starts the source, there is no queue. The assessor matches every manifest when it
// starts, so a change that the findings read before then needs no request.
func TestMatcherFindingsFollowTheVersionBeforeTheirSourceStarts(t *testing.T) {
	matcher := &fakeMatcher{}
	matcher.set(v1)
	f := &hub.MatcherFindings{Matcher: matcher, Collector: matcherCollector, Consumed: result.EvidenceType, Interval: time.Hour}
	hub.Poll(f, t.Context())
	matcher.set(v2)
	hub.Poll(f, t.Context())

	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	t.Cleanup(queue.ShutDown)
	require.NoError(t, f.Changed().Start(t.Context(), queue))
	hub.Poll(f, t.Context())
	require.Empty(t, drain(queue), "the version is the one read last")
}

func TestMatcherFindingsRefuseANonPositiveInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Minute} {
		f := &hub.MatcherFindings{Matcher: &fakeMatcher{}, Collector: matcherCollector, Interval: interval}

		require.Error(t, f.Start(t.Context()))
	}
}

func TestMatcherFindingsReadTheDatabaseAtOnceAndStopWithTheirContext(t *testing.T) {
	f, _, queue := newMatcherFindings(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- f.Start(ctx) }()

	// The interval is an hour: only a read at once delivers within the test.
	require.Eventually(t, func() bool { return queue.Len() == 1 }, 5*time.Second, 10*time.Millisecond)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the findings did not stop when their context ended")
	}
}
