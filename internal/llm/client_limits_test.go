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

package llm_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/llm"
)

func TestCompleteRespectsMaxConcurrent(t *testing.T) {
	var inFlight, peak atomic.Int32
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		raiseTo(&peak, inFlight.Add(1))
		time.Sleep(50 * time.Millisecond)
		// The request leaves the count before the response is written out, so a call that starts
		// after this response has not been counted twice.
		inFlight.Add(-1)
		answer(completion)(w, r)
	})
	cfg := configFor(server)
	cfg.MaxConcurrent = 1

	errs := startCalls(newClient(server, cfg), 3)

	for range 3 {
		require.NoError(t, <-errs)
	}
	require.Equal(t, int32(1), peak.Load())
}

func TestCompleteRunsMaxConcurrentRequestsAtOnce(t *testing.T) {
	const parallel = 3
	arrived := make(chan struct{}, parallel)
	release := make(chan struct{})
	var releaseOnce sync.Once
	letGo := func() { releaseOnce.Do(func() { close(release) }) }
	defer letGo()
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		arrived <- struct{}{}
		<-release
		answer(completion)(w, r)
	})
	cfg := configFor(server)
	cfg.MaxConcurrent = parallel

	errs := startCalls(newClient(server, cfg), parallel)

	// A semaphore that is too small would let one request through, and hold the others.
	for range parallel {
		awaitArrival(t, arrived)
	}
	letGo()
	for range parallel {
		require.NoError(t, <-errs)
	}
}

func TestCompleteWaitsForASlotOnlyAsLongAsTheCallerAllows(t *testing.T) {
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	letGo := func() { releaseOnce.Do(func() { close(release) }) }
	defer letGo()
	var requests atomic.Int32
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		requests.Add(1)
		arrived <- struct{}{}
		<-release
		answer(completion)(w, r)
	})
	cfg := configFor(server)
	cfg.MaxConcurrent = 1
	seen := &observations{}
	client := newClient(server, cfg, llm.WithObserver(seen.observe))
	first := make(chan error, 1)
	go func() {
		_, err := client.Complete(t.Context(), ping())
		first <- err
	}()
	awaitArrival(t, arrived) // the first call holds the only slot

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := client.Complete(ctx, ping())

	// Only the caller's context bounds the wait. No request was made, so nothing is known of the
	// endpoint, and the error has no sentinel.
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NotErrorIs(t, err, llm.ErrUnreachable)
	require.Equal(t, int32(1), requests.Load())
	letGo()
	require.NoError(t, <-first)
	// The call that never got a slot is no request, so it is not observed.
	require.Equal(t, []string{outcomeOK}, seen.outcomes())
}

func TestCompleteMakesNoRequestForAContextThatIsDone(t *testing.T) {
	var requests atomic.Int32
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		answer(completion)(w, r)
	})
	seen := &observations{}
	client := newClient(server, configFor(server), llm.WithObserver(seen.observe))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// With a slot free, a select alone would pick between the slot and the done context at random.
	for range 20 {
		_, err := client.Complete(ctx, ping())
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, llm.ErrUnreachable)
	}

	require.Zero(t, requests.Load())
	require.Empty(t, seen.all())
}

func TestCompleteTimeout(t *testing.T) {
	server := serve(t, hang)
	cfg := configFor(server)
	cfg.Timeout = 100 * time.Millisecond
	seen := &observations{}

	_, err := newClient(server, cfg, llm.WithObserver(seen.observe)).Complete(t.Context(), ping())

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, llm.ErrUnreachable)
	require.Equal(t, []string{outcomeTimeout}, seen.outcomes())
}

func TestCompleteTimeoutCoversTheResponseBody(t *testing.T) {
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"choices":[`)
		w.(http.Flusher).Flush()
		<-r.Context().Done() // the rest of the answer never comes
	})
	cfg := configFor(server)
	cfg.Timeout = 200 * time.Millisecond
	seen := &observations{}

	_, err := newClient(server, cfg, llm.WithObserver(seen.observe)).Complete(t.Context(), ping())

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, llm.ErrUnreachable)
	require.Equal(t, []string{outcomeTimeout}, seen.outcomes())
}

func TestCompleteTimeoutBoundsTheExchangeNotTheWaitForASlot(t *testing.T) {
	const hold = 300 * time.Millisecond
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(hold)
		answer(completion)(w, r)
	})
	cfg := configFor(server)
	cfg.MaxConcurrent = 1
	// Longer than one exchange, shorter than the wait for the slot plus one exchange.
	cfg.Timeout = 500 * time.Millisecond
	seen := &observations{}
	client := newClient(server, cfg, llm.WithObserver(seen.observe))

	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := client.Complete(t.Context(), ping())
			errs <- err
		}()
	}

	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	observed := seen.all()
	require.Len(t, observed, 2)
	for _, obs := range observed {
		require.Equal(t, outcomeOK, obs.Outcome)
		// The duration is that of the exchange. The call that waited for the slot has a duration
		// of one exchange, and not of two.
		require.GreaterOrEqual(t, obs.Duration, hold)
		require.Less(t, obs.Duration, 2*hold-50*time.Millisecond)
	}
}

func TestCompleteStopsWhenTheCallersContextEnds(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		server := serve(t, hang)
		seen := &observations{}
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		_, err := newClient(server, configFor(server), llm.WithObserver(seen.observe)).Complete(ctx, ping())

		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorIs(t, err, llm.ErrUnreachable)
		require.Equal(t, []string{outcomeTimeout}, seen.outcomes())
	})
	t.Run("cancellation", func(t *testing.T) {
		server := serve(t, hang)
		seen := &observations{}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		time.AfterFunc(100*time.Millisecond, cancel)

		_, err := newClient(server, configFor(server), llm.WithObserver(seen.observe)).Complete(ctx, ping())

		// A caller that gives up says nothing about the endpoint.
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, llm.ErrUnreachable)
		require.NotErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, []string{outcomeError}, seen.outcomes())
	})
}

func TestCompleteCapsTheResponseBody(t *testing.T) {
	answerOf := func(size int) string {
		return `{"choices":[{"message":{"role":"assistant","content":"` + strings.Repeat("a", size) + `"}}]}`
	}
	cases := []struct {
		name    string
		size    int
		succeed bool
	}{
		{"1 MiB", 1 << 20, true},
		{"32 MiB", 32 << 20, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := serve(t, answer(answerOf(tc.size)))

			resp, err := newClient(server, configFor(server)).Complete(t.Context(), ping())

			if tc.succeed {
				require.NoError(t, err)
				require.Len(t, resp.Message.Content, tc.size)
				return
			}
			require.Error(t, err)
			var statusErr *llm.StatusError
			require.ErrorAs(t, err, &statusErr)
			require.Equal(t, http.StatusOK, statusErr.Code)
			require.Contains(t, err.Error(), "too large")
			require.NotContains(t, err.Error(), "aaaa")
		})
	}
}

// countingBody is a response body that counts the bytes read from it.
type countingBody struct {
	reader io.Reader
	read   atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read.Add(int64(n))
	return n, err
}

func (*countingBody) Close() error { return nil }

// repeated is a reader of endless 'a'.
type repeated struct{}

func (repeated) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestCompleteStopsReadingAnOversizedAnswer(t *testing.T) {
	const size = 64 << 20
	body := &countingBody{reader: io.MultiReader(
		strings.NewReader(`{"choices":[{"message":{"role":"assistant","content":"`),
		io.LimitReader(repeated{}, size),
	)}
	hc := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
	})}
	cfg := llm.Config{BaseURL: exampleURL, Model: testModel, APIKey: testAPIKey}

	_, err := llm.New(cfg, llm.WithHTTPClient(hc)).Complete(t.Context(), ping())

	require.Error(t, err)
	// The client buffers an answer to decode it, so what it reads is what its memory holds. It must
	// give up long before the end, and not read the whole answer to find out that it is too large.
	require.Less(t, body.read.Load(), int64(size/4))
}

func TestCompleteTreatsTheTimeoutOfTheCallersHTTPClientAsADeadline(t *testing.T) {
	server := serve(t, hang)
	// The Timeout of an http.Client ends a request without the contexts of the client being done, but
	// its error is a deadline all the same.
	hc := &http.Client{Transport: server.Client().Transport, Timeout: 100 * time.Millisecond}
	seen := &observations{}

	_, err := llm.New(configFor(server), llm.WithHTTPClient(hc), llm.WithObserver(seen.observe)).
		Complete(t.Context(), ping())

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, llm.ErrUnreachable)
	require.Equal(t, []string{outcomeTimeout}, seen.outcomes())
}
