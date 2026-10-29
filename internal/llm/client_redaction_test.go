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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/llm"
)

func TestSecretRedacts(t *testing.T) {
	key := testAPIKey
	cfg := llm.Config{BaseURL: exampleURL, Model: testModel, APIKey: key, Timeout: time.Minute}
	client := llm.New(cfg)

	// fmt can't call a method of an unexported field, so it prints what such a field holds by
	// reflection. A struct that holds a Secret, a Config or a Client that way must not show the key.
	subjects := []struct {
		name  string
		value any
	}{
		{"Secret", key},
		{"pointer to Secret", &key},
		{"Config", cfg},
		{"pointer to Config", &cfg},
		{"Client", *client},
		{"pointer to Client", client},
		{"Secret in an unexported field", struct{ secret llm.Secret }{key}},
		{"Config in an unexported field", struct{ config llm.Config }{cfg}},
		{"Client in an unexported field", struct{ client llm.Client }{*client}},
	}
	// %p is handled before any method, and %w with an argument that is no error is reported as a bad
	// verb, which reprints the value by reflection and calls no method either. Format is not called
	// for either of them, so what the type holds is all that stands between them and the key.
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%p", "%w"}
	printers := []struct {
		name  string
		print func(format string, value any) string
	}{
		{"Sprintf", func(format string, value any) string { return fmt.Sprintf(format, value) }},
		{"Errorf", func(format string, value any) string { return fmt.Errorf(format, value).Error() }},
	}
	hexKey := hex.EncodeToString([]byte(testKey))
	for _, printer := range printers {
		for _, verb := range verbs {
			for _, subject := range subjects {
				printed := printer.print(verb, subject.value)
				where := fmt.Sprintf("%s of a %s, by %s", verb, subject.name, printer.name)
				require.NotContains(t, printed, testKey, where)
				require.NotContains(t, strings.ToLower(printed), hexKey, where)
				if verb == "%p" || verb == "%w" {
					continue // They don't reach Format, so they don't say "[redacted]".
				}
				switch subject.name {
				case "Secret", "pointer to Secret":
					require.Equal(t, redacted, printed, where)
				case "Config", "pointer to Config":
					require.Contains(t, printed, redacted, where)
				}
			}
		}
	}

	for _, value := range []any{cfg, &cfg, key, &key} {
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), testKey)
		require.NotContains(t, strings.ToLower(string(encoded)), hexKey)
		require.Contains(t, string(encoded), redacted)
	}

	require.Equal(t, redacted, key.String())
	encoded, err := key.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, `"`+redacted+`"`, string(encoded))
	// logr's loggers log the result of MarshalLog in place of a value that has one.
	var logged interface{ MarshalLog() any } = key
	require.Equal(t, redacted, logged.MarshalLog())
}

func TestZeroSecretIsAnEmptyKey(t *testing.T) {
	// A Config that was never given a key has the zero Secret. It must not panic, it prints like any
	// Secret, and it sends what an empty key has always sent: a bearer token with nothing after it.
	keys := map[string]llm.Secret{"the zero Secret": {}, "an empty key": llm.NewSecret("")}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			authorizations := make(chan string, 1)
			server := serve(t, func(w http.ResponseWriter, r *http.Request) {
				authorizations <- r.Header.Get("Authorization")
				answer(completion)(w, r)
			})
			cfg := configFor(server)
			cfg.APIKey = key

			_, err := newClient(server, cfg).Complete(t.Context(), ping())

			require.NoError(t, err)
			// Go writes the header without the space that ends it.
			require.Equal(t, "Bearer", <-authorizations)
			require.Equal(t, redacted, key.String())
			require.Equal(t, redacted, fmt.Sprint(key))
			encoded, err := json.Marshal(cfg)
			require.NoError(t, err)
			require.Contains(t, string(encoded), redacted)
		})
	}
}

func TestCompleteUnauthorizedDoesNotLeakKey(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			server := serve(t, refuse(status))
			// configFor sets the key secret-key-123.
			_, err := newClient(server, configFor(server)).Complete(t.Context(), ping())

			require.ErrorIs(t, err, llm.ErrUnauthorized)
			requireNoLeak(t, err.Error())
		})
	}
}

func TestEndpointURLThatIsNotValidIsNotQuoted(t *testing.T) {
	// Parsing the URL fails with an error that quotes it, userinfo included.
	cfg := llm.Config{BaseURL: "https://user:pass-word@bad host/v1", Model: testModel, APIKey: testAPIKey}

	_, completeErr := llm.New(cfg).Complete(t.Context(), ping())
	_, probeErr := llm.Probe(t.Context(), cfg, nil)

	for _, err := range []error{completeErr, probeErr} {
		require.ErrorIs(t, err, llm.ErrUnreachable)
		require.NotContains(t, err.Error(), "pass-word")
		require.NotContains(t, err.Error(), "bad host")
	}
}

// recordedTrips is what a recording HTTP client saw.
type recordedTrips struct {
	count         atomic.Int32
	authorization atomic.Value // the Authorization header of the last round trip, a string
}

// recordingClient returns an HTTP client whose transport makes no connection. It counts the round
// trips, keeps the Authorization header of the last one, and answers 200: with a chat completion,
// or for /models with a list that has the model.
func recordingClient() (*http.Client, *recordedTrips) {
	trips := &recordedTrips{}
	return &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		trips.count.Add(1)
		trips.authorization.Store(r.Header.Get("Authorization"))
		body := completion
		if strings.HasSuffix(r.URL.Path, modelsPath) {
			body = listing(testModel).body
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	})}, trips
}

func TestKeyIsOnlySentOverHTTPS(t *testing.T) {
	// The design makes the endpoint https only "because the key travels with every request", and the
	// CRD says so. The client says it too, because llm-smoke and later callers don't go through the
	// CRD. Nothing is sent, and the key is not even put on a request.
	cases := []struct{ name, baseURL string }{
		{"plain http", "http://llm.example/v1"},
		{"a name that starts with localhost", "http://localhost.example/v1"},
		{"a name that starts with an address", "http://127.0.0.1.example/v1"},
		{"localhost as the user name", "http://localhost@llm.example/v1"},
		{"a private address", "http://10.0.0.1/v1"},
		{"an IPv6 address that is no loopback", "http://[2001:db8::1]/v1"},
		{"another scheme", "ftp://llm.example/v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hc, trips := recordingClient()
			cfg := llm.Config{BaseURL: tc.baseURL, Model: testModel, APIKey: testAPIKey}

			_, completeErr := llm.New(cfg, llm.WithHTTPClient(hc)).Complete(t.Context(), ping())
			_, probeErr := llm.Probe(t.Context(), cfg, hc)

			for _, err := range []error{completeErr, probeErr} {
				require.ErrorIs(t, err, llm.ErrUnreachable)
				require.Contains(t, err.Error(), "https")
				requireNoLeak(t, err.Error())
				// The URL is not quoted: it can carry credentials.
				require.NotContains(t, err.Error(), "example")
			}
			require.Zero(t, trips.count.Load(), "a request was made")
		})
	}
}

func TestKeyIsSentOverPlainHTTPToTheLoopback(t *testing.T) {
	// Plain http never leaves the machine there, and it is what the tests and local development use.
	cases := []struct{ name, baseURL string }{
		{"an IPv4 loopback address", "http://127.0.0.1:8080/v1"},
		{"another address of the loopback range", "http://127.0.0.2:8080/v1"},
		{"localhost", "http://localhost:8080/v1"},
		{"localhost in capitals", "http://LOCALHOST:8080/v1"},
		{"an IPv6 loopback address", "http://[::1]:8080/v1"},
		{"https anywhere", "https://llm.example/v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hc, trips := recordingClient()
			cfg := llm.Config{BaseURL: tc.baseURL, Model: testModel, APIKey: testAPIKey}

			_, completeErr := llm.New(cfg, llm.WithHTTPClient(hc)).Complete(t.Context(), ping())
			_, probeErr := llm.Probe(t.Context(), cfg, hc)

			require.NoError(t, completeErr)
			require.NoError(t, probeErr)
			require.Equal(t, int32(2), trips.count.Load())
			require.Equal(t, "Bearer "+testKey, trips.authorization.Load())
		})
	}
}
