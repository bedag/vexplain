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
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/llm"
)

const (
	// testKey is the API key of the tests. It is made up, and it must not show up in anything the
	// client prints or returns.
	testKey   = "secret-key-123"
	testModel = "m"
	redacted  = "[redacted]"

	// bodyMarker stands for the text of an error body. No error of the client may carry it.
	bodyMarker = "the-gateway-says"

	roleUser      = "user"
	roleAssistant = "assistant"
	roleTool      = "tool"

	toolName     = "lookup"
	badArguments = "{bad"

	// exampleURL is a base URL for the tests that never reach a server.
	exampleURL = "https://llm.example/v1"

	// The outcomes that the client reports.
	outcomeOK           = "ok"
	outcomeError        = "error"
	outcomeUnauthorized = "unauthorized"
	outcomeTimeout      = "timeout"

	// completion is the body of an answer: a text, and a usage of 3 prompt and 1 completion tokens.
	completion = `{"choices":[{"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":3,"completion_tokens":1}}`
)

// serve starts a TLS server that answers with handler, until the end of the test.
func serve(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server
}

// answer returns a handler that answers every request with 200 and body.
func answer(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
}

// refuse returns a handler that answers every request with status and a body like a gateway's: it
// carries the bodyMarker and echoes the Authorization header that it received, so the API key.
func refuse(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, bodyMarker+" "+r.Header.Get("Authorization"))
	}
}

// waitForClient holds a request until the client gives up. The server only notices that the client
// has gone once the handler has read the whole request body, so it reads that first. Without it, the
// handler would never return, and nor would the Close of the server.
func waitForClient(r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	<-r.Context().Done()
}

// hang is a handler that never answers.
func hang(_ http.ResponseWriter, r *http.Request) { waitForClient(r) }

// configFor returns the config of a client for server, with the made-up key.
func configFor(server *httptest.Server) llm.Config {
	return llm.Config{BaseURL: server.URL, Model: testModel, APIKey: testKey}
}

// newClient returns a client with cfg that trusts the certificate of server.
func newClient(server *httptest.Server, cfg llm.Config, opts ...llm.Option) *llm.Client {
	return llm.New(cfg, append([]llm.Option{llm.WithHTTPClient(server.Client())}, opts...)...)
}

// ping returns a request with a single user message.
func ping() llm.Request {
	return llm.Request{Messages: []llm.Message{{Role: roleUser, Content: "ping"}}}
}

// awaitArrival waits for a request to reach the server, and fails the test if none does.
func awaitArrival(t *testing.T, arrived <-chan struct{}) {
	t.Helper()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("a request did not reach the server")
	}
}

// startCalls starts n calls of Complete at once, and returns the channel that gets their errors.
func startCalls(client *llm.Client, n int) <-chan error {
	errs := make(chan error, n)
	for range n {
		go func() {
			_, err := client.Complete(context.Background(), ping())
			errs <- err
		}()
	}
	return errs
}

// raiseTo raises peak to n if it is lower.
func raiseTo(peak *atomic.Int32, n int32) {
	for {
		seen := peak.Load()
		if n <= seen || peak.CompareAndSwap(seen, n) {
			return
		}
	}
}

// observations records what a client reports to its observer. A client reports from the goroutine
// of each call, so it is safe for concurrent use.
type observations struct {
	mu   sync.Mutex
	seen []llm.Observation
}

func (o *observations) observe(obs llm.Observation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, obs)
}

func (o *observations) all() []llm.Observation {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.seen)
}

func (o *observations) outcomes() []string {
	all := o.all()
	outcomes := make([]string, 0, len(all))
	for _, obs := range all {
		outcomes = append(outcomes, obs.Outcome)
	}
	return outcomes
}

// requireNoLeak fails the test if text carries the key, or anything of an error body.
func requireNoLeak(t *testing.T, text string) {
	t.Helper()
	require.NotContains(t, text, testKey)
	require.NotContains(t, text, bodyMarker)
	require.NotContains(t, text, "Bearer")
}

// roundTripperFunc is an http.RoundTripper that fails the way a transport does.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
