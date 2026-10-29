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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/llm"
)

func TestCompleteMapsFailures(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		status  int
		is      error // the one sentinel that the error wraps, or nil for none
		outcome string
	}{
		{"401", refuse(401), 401, llm.ErrUnauthorized, outcomeUnauthorized},
		{"403", refuse(403), 403, llm.ErrUnauthorized, outcomeUnauthorized},
		{"500", refuse(500), 500, llm.ErrUnreachable, outcomeError},
		{"503", refuse(503), 503, llm.ErrUnreachable, outcomeError},
		{"429", refuse(429), 429, nil, outcomeError},
		{"400", refuse(400), 400, nil, outcomeError},
		{"404", refuse(404), 404, nil, outcomeError},
		{"an answer that is no JSON", answer("no JSON " + bodyMarker + " " + testKey), 200, nil, outcomeError},
		{"an answer without choices", answer(`{"choices":[],"note":"` + bodyMarker + `"}`), 200, nil, outcomeError},
		{"an answer without a body", refuse(204), 204, nil, outcomeError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := serve(t, tc.handler)
			seen := &observations{}

			_, err := newClient(server, configFor(server), llm.WithObserver(seen.observe)).Complete(t.Context(), ping())

			require.Error(t, err)
			// Complete never answers ErrModelNotFound: only the probe knows what a status means for a
			// model.
			for _, sentinel := range []error{llm.ErrUnauthorized, llm.ErrModelNotFound, llm.ErrUnreachable} {
				require.Equal(t, sentinel == tc.is, errors.Is(err, sentinel), "wraps %v", sentinel)
			}
			var statusErr *llm.StatusError
			require.ErrorAs(t, err, &statusErr)
			require.Equal(t, tc.status, statusErr.Code)
			require.Contains(t, err.Error(), strconv.Itoa(tc.status))
			requireNoLeak(t, err.Error())
			require.Equal(t, []string{tc.outcome}, seen.outcomes())
		})
	}
}

func TestCompleteReportsAnUnreachableEndpoint(t *testing.T) {
	server := serve(t, answer(completion))
	server.Close()
	seen := &observations{}

	_, err := newClient(server, configFor(server), llm.WithObserver(seen.observe)).Complete(t.Context(), ping())

	require.ErrorIs(t, err, llm.ErrUnreachable)
	require.NotErrorIs(t, err, context.DeadlineExceeded)
	require.Contains(t, err.Error(), "refused")
	// The address is the endpoint's own, but a URL can carry credentials, so no error quotes one.
	require.NotContains(t, err.Error(), strings.TrimPrefix(server.URL, "https://"))
	require.Equal(t, []string{outcomeError}, seen.outcomes())
}

// proxyReason is part of the reason for a failure of the proxy.
const proxyReason = "through the proxy"

// dialing wraps err the way net does for the failure of a dial.
func dialing(err error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: err}
}

// proxied wraps err the way net/http wraps the failure to reach a proxy (Go issue 16997): the
// error of the dial is inside, so that a check for it alone would blame the endpoint.
func proxied(err error) error {
	return &net.OpError{Op: "proxyconnect", Net: "tcp", Err: err}
}

func TestCompleteNamesTheReasonWithoutQuotingTheError(t *testing.T) {
	refused := &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}
	cases := []struct {
		name    string
		failure error
		reason  string
	}{
		{"unknown host", &net.DNSError{Err: "no such host", Name: "llm.example", IsNotFound: true}, "does not resolve"},
		{"certificate", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, "certificate"},
		{"refused", dialing(refused), "refused"},
		{"dial timeout", dialing(os.ErrDeadlineExceeded), "timed out"},
		// The proxy is at fault, and not the host of the endpoint, whatever the inner error says.
		{"proxy refuses", proxied(dialing(refused)), proxyReason},
		{"proxy host does not resolve", proxied(dialing(&net.DNSError{
			Err: "no such host", Name: "proxy.example", IsNotFound: true,
		})), proxyReason},
		{"proxy dial timeout", proxied(dialing(os.ErrDeadlineExceeded)), proxyReason},
		// Anything else is not quoted: it could hold the URL, or whatever a proxy or server said.
		{"anything else", errors.New("boom " + testKey + " " + bodyMarker), "failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hc := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, tc.failure
			})}
			// The URL of the request is part of the error that net/http returns.
			cfg := llm.Config{BaseURL: "https://llm.example/v1?token=" + testKey, Model: testModel, APIKey: testKey}

			_, err := llm.New(cfg, llm.WithHTTPClient(hc)).Complete(t.Context(), ping())

			require.ErrorIs(t, err, llm.ErrUnreachable)
			require.NotErrorIs(t, err, context.DeadlineExceeded)
			require.Contains(t, err.Error(), tc.reason)
			requireNoLeak(t, err.Error())
			require.NotContains(t, err.Error(), "llm.example")
		})
	}
}

func TestCompleteDoesNotChangeTheCallersHTTPClient(t *testing.T) {
	server := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == modelsPath {
			answer(listing(testModel).body)(w, r)
			return
		}
		answer(completion)(w, r)
	})
	hc := server.Client()
	cfg := configFor(server)
	cfg.Timeout = 5 * time.Second

	_, err := llm.New(cfg, llm.WithHTTPClient(hc)).Complete(t.Context(), ping())
	require.NoError(t, err)
	_, err = llm.Probe(t.Context(), cfg, hc)
	require.NoError(t, err)

	// The Timeout goes through the context of each request, and the refusal of redirects through a
	// copy of the client.
	require.Zero(t, hc.Timeout)
	require.Nil(t, hc.CheckRedirect)
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	// Go keeps the Authorization header when a request is redirected from https to http on the same
	// host, which would put the key on a plain connection. And an API like this has no reason to
	// redirect. So a redirect is an answer that the client refuses, with the status code of it.
	endpoints := []struct {
		name  string
		start func(t *testing.T, handler http.HandlerFunc) (llm.Config, *http.Client)
	}{
		{"a client passed in", func(t *testing.T, handler http.HandlerFunc) (llm.Config, *http.Client) {
			server := serve(t, handler)
			return configFor(server), server.Client()
		}},
		{"the default client", func(t *testing.T, handler http.HandlerFunc) (llm.Config, *http.Client) {
			// Plain HTTP, because the default client has no certificate of a test server to trust.
			server := httptest.NewServer(handler)
			t.Cleanup(server.Close)
			return configFor(server), nil
		}},
	}
	targets := []struct{ name, host string }{
		{"http on the same host", "127.0.0.1"},
		{"another host", "localhost"},
	}
	for _, endpoint := range endpoints {
		for _, target := range targets {
			for _, code := range []int{http.StatusMovedPermanently, http.StatusTemporaryRedirect} {
				t.Run(fmt.Sprintf("%s, %d to %s", endpoint.name, code, target.name), func(t *testing.T) {
					var reached atomic.Int32 // the requests that arrive at the target of the redirect
					elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
						reached.Add(1)
					}))
					t.Cleanup(elsewhere.Close)
					_, port, err := net.SplitHostPort(elsewhere.Listener.Addr().String())
					require.NoError(t, err)
					location := "http://" + net.JoinHostPort(target.host, port)
					var redirected atomic.Int32 // the requests that arrive at the endpoint
					cfg, hc := endpoint.start(t, func(w http.ResponseWriter, r *http.Request) {
						redirected.Add(1)
						http.Redirect(w, r, location+r.URL.Path, code)
					})

					_, completeErr := llm.New(cfg, llm.WithHTTPClient(hc)).Complete(t.Context(), ping())
					_, probeErr := llm.Probe(t.Context(), cfg, hc)

					for _, err := range []error{completeErr, probeErr} {
						var statusErr *llm.StatusError
						require.ErrorAs(t, err, &statusErr)
						require.Equal(t, code, statusErr.Code)
						require.Contains(t, err.Error(), "redirect")
						requireNoLeak(t, err.Error())
					}
					// Complete has no sentinel for it. For a probe it is an answer outside the API.
					for _, sentinel := range []error{llm.ErrUnauthorized, llm.ErrModelNotFound, llm.ErrUnreachable} {
						require.NotErrorIs(t, completeErr, sentinel)
					}
					require.ErrorIs(t, probeErr, llm.ErrUnreachable)
					// Each call got its redirect, and gave up there.
					require.Equal(t, int32(2), redirected.Load())
					require.Zero(t, reached.Load(), "a redirect was followed")
				})
			}
		}
	}
}
