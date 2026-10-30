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

package matchapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	// secretBody is what a misbehaving matcher puts in a response. It must not reach any error.
	secretBody = "SECRET-TEXT-FROM-THE-MATCHER"
	testSBOM   = `{"schema":{"version":"16.1.11"},"artifacts":[]}`
)

// seen is what the matcher received.
type seen struct {
	method, path, contentType, accept string
	body                              []byte
}

// serve starts a matcher that records each request and answers it with reply. The requests go
// through a channel, so that the test reads them without a race.
func serve(t *testing.T, reply func(w http.ResponseWriter)) (*Client, <-chan seen) {
	t.Helper()
	requests := make(chan seen, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- seen{r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Accept"), body}
		reply(w)
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL}, requests
}

// answer replies with a status and a body.
func answer(status int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// The two calls of the client, so that the rules for failures are tested for both.
var calls = map[string]func(context.Context, *Client) error{
	"Match": func(ctx context.Context, c *Client) error {
		_, err := c.Match(ctx, json.RawMessage(testSBOM))
		return err
	},
	"Database": func(ctx context.Context, c *Client) error {
		_, err := c.Database(ctx)
		return err
	},
}

func TestMatchSendsTheSBOMAndReadsTheMatches(t *testing.T) {
	want := MatchResponse{
		DatabaseVersion: someVersion,
		Matches: []Match{{
			VulnerabilityID: someCVE, PackageID: "p1", Severity: "High", FixState: "fixed",
			FixedVersions: []string{"1.2.3-r1"}, KnownExploited: true,
			PackageName: somePackage, PackageVersion: "1.2.0-r0", PackageType: typeAPK,
		}},
	}
	reply, err := json.Marshal(want)
	require.NoError(t, err)

	for _, suffix := range []string{"", "/"} {
		t.Run("base URL "+strconv.Quote(suffix), func(t *testing.T) {
			c, requests := serve(t, answer(http.StatusOK, string(reply)))
			c.BaseURL += suffix
			got, err := c.Match(t.Context(), json.RawMessage(testSBOM))
			require.NoError(t, err)
			require.Equal(t, want, got)

			r := <-requests
			require.Equal(t, http.MethodPost, r.method)
			require.Equal(t, "/v1/match", r.path)
			require.Equal(t, "application/json", r.contentType)
			require.Equal(t, "application/json", r.accept)
			require.JSONEq(t, `{"sbom": `+testSBOM+`}`, string(r.body))
		})
	}
}

func TestMatchWithNoMatchesIsAnEmptyList(t *testing.T) {
	c, _ := serve(t, answer(http.StatusOK, `{"databaseVersion": "v1", "matches": []}`))
	got, err := c.Match(t.Context(), json.RawMessage(testSBOM))
	require.NoError(t, err)
	require.Equal(t, "v1", got.DatabaseVersion)
	require.Empty(t, got.Matches)
}

func TestDatabase(t *testing.T) {
	c, requests := serve(t, answer(http.StatusOK, `{"version": "v6.1.10+2026-10-30T06:23:28Z", "built": "2026-10-30T06:23:28Z"}`))
	got, err := c.Database(t.Context())
	require.NoError(t, err)
	require.Equal(t, "v6.1.10+2026-10-30T06:23:28Z", got.Version)
	require.True(t, time.Date(2026, 10, 30, 6, 23, 28, 0, time.UTC).Equal(got.Built))

	r := <-requests
	require.Equal(t, http.MethodGet, r.method)
	require.Equal(t, "/v1/database", r.path)
	require.Equal(t, "application/json", r.accept)
}

func TestA503IsNotReady(t *testing.T) {
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			c, _ := serve(t, func(w http.ResponseWriter) {
				w.Header().Set("Retry-After", "30")
				answer(http.StatusServiceUnavailable, secretBody)(w)
			})
			err := call(t.Context(), c)
			require.ErrorIs(t, err, ErrNotReady)
			require.NotErrorIs(t, err, ErrUnavailable)
			require.NotContains(t, err.Error(), secretBody)
		})
	}
}

func TestAnotherStatusGivesAFixedTextThatNamesIt(t *testing.T) {
	for name, call := range calls {
		for _, status := range []int{
			http.StatusBadRequest, http.StatusNotFound, http.StatusRequestEntityTooLarge,
			http.StatusInternalServerError, http.StatusBadGateway, http.StatusGatewayTimeout,
		} {
			t.Run(name+" "+strconv.Itoa(status), func(t *testing.T) {
				c, _ := serve(t, answer(status, secretBody))
				err := call(t.Context(), c)
				require.Error(t, err)
				require.NotErrorIs(t, err, ErrNotReady)
				require.NotErrorIs(t, err, ErrUnavailable)
				require.Contains(t, err.Error(), strconv.Itoa(status))
				require.NotContains(t, err.Error(), secretBody)
			})
		}
	}
}

func TestAConnectionErrorIsUnavailable(t *testing.T) {
	for name, call := range calls {
		t.Run(name+", nobody listens", func(t *testing.T) {
			// The server has gone: its address now refuses connections.
			srv := httptest.NewServer(http.NotFoundHandler())
			gone := srv.URL
			srv.Close()
			err := call(t.Context(), &Client{BaseURL: gone})
			require.ErrorIs(t, err, ErrUnavailable)
			require.NotErrorIs(t, err, ErrNotReady)
		})
		t.Run(name+", the connection breaks", func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
			}))
			t.Cleanup(srv.Close)
			require.ErrorIs(t, call(t.Context(), &Client{BaseURL: srv.URL}), ErrUnavailable)
		})
		t.Run(name+", the body breaks off", func(t *testing.T) {
			// The headers promise more than the matcher sends before it hangs up.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "1000")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"databaseVersion": "`)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
			}))
			t.Cleanup(srv.Close)
			require.ErrorIs(t, call(t.Context(), &Client{BaseURL: srv.URL}), ErrUnavailable)
		})
	}
}

func TestASlowMatcherIsUnavailable(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	c := &Client{BaseURL: srv.URL, HTTP: &http.Client{Timeout: 50 * time.Millisecond}}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, call(t.Context(), c), ErrUnavailable)
		})
	}
}

func TestACancelledContextIsNotUnavailable(t *testing.T) {
	// Shutting down is not the matcher's fault: the caller can tell the two apart.
	c, _ := serve(t, answer(http.StatusOK, ""))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call(ctx, c)
			require.ErrorIs(t, err, context.Canceled)
			require.NotErrorIs(t, err, ErrUnavailable)
		})
	}
}

func TestAnAnswerThatIsNoAnswerGivesAFixedText(t *testing.T) {
	// A 200 that doesn't say what the call needs is no answer. In particular, a missing list of
	// matches is not an empty one: the hub must not read "no matches" from a matcher that didn't say it.
	bodies := map[string]map[string]string{
		"Match": {
			"not JSON":           "<html>" + secretBody + "</html>",
			"empty":              "",
			"null":               jsonNull,
			"no matches":         `{"databaseVersion": "v1"}`,
			"null matches":       `{"databaseVersion": "v1", "matches": null}`,
			"no version":         `{"matches": []}`,
			"empty version":      `{"databaseVersion": "", "matches": []}`,
			"a list":             `[]`,
			"wrong type":         `{"databaseVersion": 1, "matches": []}`,
			"trailing text":      `{"databaseVersion": "v1", "matches": []} ` + secretBody,
			"a secret in a type": `{"databaseVersion": "v1", "matches": "` + secretBody + `"}`,
		},
		"Database": {
			"not JSON":      "<html>" + secretBody + "</html>",
			"empty":         "",
			"null":          jsonNull,
			"no version":    `{"built": "2026-10-30T06:23:28Z"}`,
			"empty version": `{"version": "", "built": "2026-10-30T06:23:28Z"}`,
			"bad time":      `{"version": "v1", "built": "` + secretBody + `"}`,
		},
	}
	for name, call := range calls {
		for what, body := range bodies[name] {
			t.Run(name+", "+what, func(t *testing.T) {
				c, _ := serve(t, answer(http.StatusOK, body))
				err := call(t.Context(), c)
				require.Error(t, err)
				require.NotErrorIs(t, err, ErrNotReady)
				require.NotErrorIs(t, err, ErrUnavailable)
				require.NotContains(t, err.Error(), secretBody)
			})
		}
	}
}

func TestAnAnswerOverTheLimitIsRefused(t *testing.T) {
	old := maxResponseBytes
	maxResponseBytes = 64
	t.Cleanup(func() { maxResponseBytes = old })

	// Valid JSON, but longer than the limit.
	body := `{"databaseVersion": "v1", "matches": [], "padding": "` + secretBody + secretBody + secretBody + `"}`
	require.Greater(t, int64(len(body)), maxResponseBytes)
	c, _ := serve(t, answer(http.StatusOK, body))
	_, err := c.Match(t.Context(), json.RawMessage(testSBOM))
	require.Error(t, err)
	require.NotContains(t, err.Error(), secretBody)

	// The limit is on the answer, and not on what its JSON says: a short document with trailing
	// space that goes past it is refused too.
	padded := `{"databaseVersion": "v1", "matches": []}` + strings.Repeat(" ", 100)
	require.Greater(t, int64(len(padded)), maxResponseBytes)
	c, _ = serve(t, answer(http.StatusOK, padded))
	_, err = c.Match(t.Context(), json.RawMessage(testSBOM))
	require.Error(t, err)

	// One that fits is read.
	c, _ = serve(t, answer(http.StatusOK, `{"databaseVersion": "v1", "matches": []}`))
	_, err = c.Match(t.Context(), json.RawMessage(testSBOM))
	require.NoError(t, err)
}

func TestAnSBOMThatIsNotJSONIsRefusedBeforeItIsSent(t *testing.T) {
	c, requests := serve(t, answer(http.StatusOK, ""))
	// The error is the fixed one: the text of a JSON error names a character of the SBOM.
	_, err := c.Match(t.Context(), json.RawMessage(`{"secret-sbom-fragment": S`))
	require.ErrorIs(t, err, errBadSBOM)
	require.NotContains(t, err.Error(), "secret-sbom-fragment")
	require.NotContains(t, err.Error(), "character")
	require.Empty(t, requests)

	_, err = c.Match(t.Context(), nil)
	require.ErrorIs(t, err, errBadSBOM)
	require.Empty(t, requests)
}

func TestABadBaseURLGivesAFixedText(t *testing.T) {
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call(t.Context(), &Client{BaseURL: "http://user:pass@bad host\x7f"})
			require.Error(t, err)
			require.NotContains(t, err.Error(), "pass")
		})
	}
}

func TestTheDefaultClientHasNoProxyAndATwoMinuteTimeout(t *testing.T) {
	hc := (&Client{}).httpClient()
	require.Equal(t, 2*time.Minute, hc.Timeout)
	require.Equal(t, DefaultTimeout, hc.Timeout)
	tr, ok := hc.Transport.(*http.Transport)
	require.True(t, ok)
	// The matcher is in the hub's own cluster, so the proxy variables of the manager don't apply.
	require.Nil(t, tr.Proxy)
	// It is one client, so that connections are reused.
	require.Same(t, hc, (&Client{}).httpClient())

	// And it works.
	c, _ := serve(t, answer(http.StatusOK, `{"version": "v1", "built": "2026-10-30T06:23:28Z"}`))
	_, err := c.Database(t.Context())
	require.NoError(t, err)
}

func TestAGivenClientIsUsed(t *testing.T) {
	given := &http.Client{Timeout: time.Hour}
	require.Same(t, given, (&Client{HTTP: given}).httpClient())

	c, _ := serve(t, answer(http.StatusOK, `{"version": "v1", "built": "2026-10-30T06:23:28Z"}`))
	var used int
	c.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used++
		return http.DefaultTransport.RoundTrip(r)
	})}
	_, err := c.Database(t.Context())
	require.NoError(t, err)
	require.Equal(t, 1, used)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
