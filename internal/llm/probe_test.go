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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/llm"
)

const (
	modelsPath = "/models"
	chatPath   = "/chat/completions"
)

// reply is what a probe server answers on one path.
type reply struct {
	status int
	body   string
}

// failing is a reply with a status that no probe accepts, and a body like a gateway's, which carries
// the bodyMarker and the API key.
func failing(status int) reply {
	return reply{status, bodyMarker + " Bearer " + testKey}
}

// listing is the reply of a models endpoint that lists the models with ids.
func listing(ids ...string) reply {
	data := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		data = append(data, map[string]string{"id": id})
	}
	body, err := json.Marshal(map[string]any{"object": "list", "data": data})
	if err != nil {
		panic(err)
	}
	return reply{http.StatusOK, string(body)}
}

// completed is the reply of a chat endpoint that answers.
var completed = reply{http.StatusOK, completion}

// probeHits counts the requests that a probe server got on each path.
type probeHits struct{ models, chat atomic.Int32 }

// probeServer answers GET /models with models and POST /chat/completions with chat, and checks the
// requests that it gets.
func probeServer(t *testing.T, models, chat reply) (*httptest.Server, *probeHits) {
	t.Helper()
	hits := &probeHits{}
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer "+testKey, r.Header.Get("Authorization"))
		var answer reply
		switch {
		case r.Method == http.MethodGet && r.URL.Path == modelsPath:
			hits.models.Add(1)
			answer = models
		case r.Method == http.MethodPost && r.URL.Path == chatPath:
			hits.chat.Add(1)
			var sent struct {
				Model    string `json:"model"`
				Messages []struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"messages"`
				MaxTokens int `json:"max_tokens"`
			}
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&sent))
			// The probe asks for the least that proves the model is served.
			assert.Equal(t, testModel, sent.Model)
			assert.Equal(t, 1, sent.MaxTokens)
			if assert.Len(t, sent.Messages, 1) {
				assert.Equal(t, roleUser, sent.Messages[0].Role)
				assert.Equal(t, "ping", sent.Messages[0].Content)
			}
			answer = chat
		default:
			answer = reply{http.StatusTeapot, ""}
		}
		w.WriteHeader(answer.status)
		_, _ = io.WriteString(w, answer.body)
	})
	return server, hits
}

func TestProbe(t *testing.T) {
	cases := []struct {
		name   string
		models reply
		chat   reply // used only when the models endpoint is missing
		want   error // the one sentinel that the error wraps, or nil for a probe that succeeds
		code   int   // the status code that the error carries
	}{
		{"the model is listed", listing("other", testModel), reply{}, nil, 0},
		{"the model is not listed", listing("other"), reply{}, llm.ErrModelNotFound, 200},
		{"no models listed", reply{200, `{}`}, reply{}, llm.ErrModelNotFound, 200},
		{"a list that is no JSON", reply{200, "<html>" + bodyMarker + testKey}, reply{}, llm.ErrUnreachable, 200},
		{"401", failing(401), reply{}, llm.ErrUnauthorized, 401},
		{"403", failing(403), reply{}, llm.ErrUnauthorized, 403},
		{"503", failing(503), reply{}, llm.ErrUnreachable, 503},
		{"a status outside the API: 400", failing(400), reply{}, llm.ErrUnreachable, 400},
		{"a 2xx that is no list: 204", reply{204, ""}, reply{}, llm.ErrUnreachable, 204},
		{"busy: 429", failing(429), reply{}, nil, 0},

		{"no models endpoint: 404, chat answers", failing(404), completed, nil, 0},
		{"no models endpoint: 405, chat answers", failing(405), completed, nil, 0},
		{"unknown model: 404 on chat", failing(404), failing(404), llm.ErrModelNotFound, 404},
		{"unknown model: 400 on chat", failing(404), failing(400), llm.ErrModelNotFound, 400},
		{"unauthorized: 401 on chat", failing(404), failing(401), llm.ErrUnauthorized, 401},
		{"unauthorized: 403 on chat", failing(404), failing(403), llm.ErrUnauthorized, 403},
		{"busy: 429 on chat", failing(404), failing(429), nil, 0},
		{"a status outside the API: 422 on chat", failing(404), failing(422), llm.ErrUnreachable, 422},
		{"a server error: 500 on chat", failing(404), failing(500), llm.ErrUnreachable, 500},
		{"an answer that is no chat completion", failing(404), reply{200, "no JSON " + testKey}, llm.ErrUnreachable, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, hits := probeServer(t, tc.models, tc.chat)

			latency, err := llm.Probe(t.Context(), configFor(server), server.Client())

			// The chat endpoint is only asked when there is no models endpoint.
			require.Equal(t, int32(1), hits.models.Load())
			if tc.models.status == http.StatusNotFound || tc.models.status == http.StatusMethodNotAllowed {
				require.Equal(t, int32(1), hits.chat.Load())
			} else {
				require.Zero(t, hits.chat.Load())
			}
			if tc.want == nil {
				require.NoError(t, err)
				require.Positive(t, latency)
				return
			}
			require.Error(t, err)
			require.Zero(t, latency)
			// Every failure wraps exactly one of the three sentinels.
			for _, sentinel := range []error{llm.ErrUnauthorized, llm.ErrModelNotFound, llm.ErrUnreachable} {
				require.Equal(t, sentinel == tc.want, errors.Is(err, sentinel), "wraps %v", sentinel)
			}
			var statusErr *llm.StatusError
			require.ErrorAs(t, err, &statusErr)
			require.Equal(t, tc.code, statusErr.Code)
			requireNoLeak(t, err.Error())
		})
	}
}

func TestProbeReportsAnUnreachableEndpoint(t *testing.T) {
	server := serve(t, answer(completion))
	server.Close()

	latency, err := llm.Probe(t.Context(), configFor(server), server.Client())

	require.ErrorIs(t, err, llm.ErrUnreachable)
	require.Zero(t, latency)
}

func TestProbeUsesTheDefaultClientWithoutOne(t *testing.T) {
	// A plain HTTP server, because the default client has no certificate of a test server to trust.
	server := httptest.NewServer(answer(listing(testModel).body))
	t.Cleanup(server.Close)

	latency, err := llm.Probe(t.Context(), llm.Config{BaseURL: server.URL, Model: testModel, APIKey: testAPIKey}, nil)

	require.NoError(t, err)
	require.Positive(t, latency)
}

// proxyChildEnv marks the run of the test binary that probes through a proxy.
const proxyChildEnv = "LLM_TEST_PROBE_THROUGH_PROXY"

// probeThroughProxy probes an endpoint that only the proxy at proxyURL can reach, in a child process,
// and returns what the child printed. net/http reads the proxy settings once per process, and never
// proxies loopback addresses, so a test can only see the proxy at work in a process of its own, for a
// host that is not loopback. The child is TestDefaultClientHonoursTheProxyEnvironment.
func probeThroughProxy(t *testing.T, proxyURL string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestDefaultClientHonoursTheProxyEnvironment$")
	cmd.Env = append(os.Environ(), proxyChildEnv+"=1",
		"HTTPS_PROXY="+proxyURL, "https_proxy="+proxyURL, "NO_PROXY=", "no_proxy=")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
	return string(output)
}

func TestDefaultClientHonoursTheProxyEnvironment(t *testing.T) {
	if os.Getenv(proxyChildEnv) != "" {
		// The child process. The probe must fail, because the proxy of the parent refuses it, and it
		// tells the parent how.
		cfg := llm.Config{BaseURL: exampleURL, Model: testModel, APIKey: testAPIKey}
		_, err := llm.Probe(context.Background(), cfg, nil)
		if !errors.Is(err, llm.ErrUnreachable) {
			fmt.Fprintf(os.Stderr, "the probe should have failed with ErrUnreachable, and returned %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("probe error: %v\n", err)
		return
	}

	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	connectLine := make(chan string, 1)
	go func() {
		conn, err := proxy.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		connectLine <- line
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	}()

	output := probeThroughProxy(t, "http://"+proxy.Addr().String())

	select {
	case line := <-connectLine:
		require.Equal(t, "CONNECT llm.example:443 HTTP/1.1\r\n", line)
	case <-time.After(5 * time.Second):
		t.Fatal("the probe did not go through the proxy")
	}
	// A proxy that answers the CONNECT with an error is at fault, and the error says so.
	require.Contains(t, output, "probe error: the endpoint is unreachable: the connection through the proxy failed")
}

func TestDefaultClientBlamesTheProxyWhenItCannotBeReached(t *testing.T) {
	// A proxy at an address that nothing listens on.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := closed.Addr().String()
	require.NoError(t, closed.Close())

	output := probeThroughProxy(t, "http://"+address)

	// The error of the dial is "connection refused", but the host that refuses is the proxy, and
	// not the endpoint.
	require.Contains(t, output, "probe error: the endpoint is unreachable: the connection through the proxy failed")
}

func TestProbeAppliesTheTimeoutToEachRequest(t *testing.T) {
	const step = 200 * time.Millisecond
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(step)
		if r.URL.Path == modelsPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		answer(completion)(w, r)
	})
	cfg := configFor(server)
	// Longer than one request, shorter than both together.
	cfg.Timeout = 300 * time.Millisecond

	latency, err := llm.Probe(t.Context(), cfg, server.Client())

	require.NoError(t, err)
	require.GreaterOrEqual(t, latency, 2*step)
}

func TestProbeGivesUpWhenTheEndpointDoesNotAnswer(t *testing.T) {
	t.Run("the timeout of the config", func(t *testing.T) {
		server := serve(t, hang)
		cfg := configFor(server)
		cfg.Timeout = 100 * time.Millisecond

		_, err := llm.Probe(t.Context(), cfg, server.Client())

		require.ErrorIs(t, err, llm.ErrUnreachable)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
	t.Run("the deadline of the caller", func(t *testing.T) {
		server := serve(t, hang)
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		_, err := llm.Probe(ctx, configFor(server), server.Client())

		require.ErrorIs(t, err, llm.ErrUnreachable)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
	t.Run("a caller that cancels", func(t *testing.T) {
		server := serve(t, hang)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		time.AfterFunc(100*time.Millisecond, cancel)

		_, err := llm.Probe(ctx, configFor(server), server.Client())

		// The probe was stopped, which says nothing about the endpoint, so no sentinel.
		require.ErrorIs(t, err, context.Canceled)
		for _, sentinel := range []error{llm.ErrUnauthorized, llm.ErrModelNotFound, llm.ErrUnreachable} {
			require.NotErrorIs(t, err, sentinel)
		}
	})
}
