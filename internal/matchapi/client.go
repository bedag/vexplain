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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout is the timeout of the client when Client.HTTP is nil. Matching a large SBOM can
// take a minute, so the matcher's server allows at least this long to answer.
const DefaultTimeout = 2 * time.Minute

// maxResponseBytes is the most that the client reads of an answer. A response is a list of matches,
// far below the size of the SBOM that it answers, so the limit only stops a matcher that goes wrong
// from filling the manager's memory. It is a variable for the tests.
var maxResponseBytes int64 = MaxRequestBytes

// The errors that have no sentinel, because no caller needs to tell them apart. Like the sentinels
// of this package, their texts are fixed.
var (
	errBadSBOM     = errors.New("matcher: the SBOM is not valid JSON")
	errBadBaseURL  = errors.New("matcher: the base URL is not valid")
	errBadResponse = errors.New("matcher: malformed response")
)

// defaultHTTP is the client for a Client without one. The matcher is always in the hub's own
// cluster, so it has no proxy: the manager's HTTPS_PROXY is for the outside. It is one client for
// all, so that connections are reused.
var defaultHTTP = &http.Client{Timeout: DefaultTimeout, Transport: noProxyTransport()}

func noProxyTransport() *http.Transport {
	t, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		t = t.Clone()
	} else {
		t = &http.Transport{}
	}
	t.Proxy = nil
	return t
}

// Client calls the matcher. Its methods are safe for concurrent use.
type Client struct {
	// BaseURL is the matcher's address, such as http://matcher.vexplain-system.svc:8080.
	BaseURL string
	// HTTP is the client to use. Nil means one with no proxy and a timeout of DefaultTimeout.
	HTTP *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return defaultHTTP
}

// Match sends the SBOM, which is Syft's JSON as the scanner reduces it, and returns the matches.
//
// It returns ErrNotReady when the matcher answers 503, and ErrUnavailable when it can't be
// reached or doesn't answer in time. A cancelled or expired context gives its own error, so that a
// shutdown isn't taken for a fault of the matcher. Any other answer that is not a complete 200
// gives an error with a fixed text. No error holds any part of the matcher's answer.
func (c *Client) Match(ctx context.Context, sbom json.RawMessage) (MatchResponse, error) {
	if len(sbom) == 0 {
		return MatchResponse{}, errBadSBOM
	}
	body, err := json.Marshal(MatchRequest{SBOM: sbom})
	if err != nil {
		// The error's text names a character of the SBOM.
		return MatchResponse{}, errBadSBOM
	}
	var out MatchResponse
	if err := c.do(ctx, http.MethodPost, PathMatch, body, &out); err != nil {
		return MatchResponse{}, err
	}
	// An answer that doesn't say which database it comes from, or what it found, is no answer. In
	// particular a missing list of matches isn't an empty one.
	if out.DatabaseVersion == "" || out.Matches == nil {
		return MatchResponse{}, errBadResponse
	}
	return out, nil
}

// Database returns the database that the matcher uses, with the same errors as Match.
func (c *Client) Database(ctx context.Context) (Database, error) {
	var out Database
	if err := c.do(ctx, http.MethodGet, PathDatabase, nil, &out); err != nil {
		return Database{}, err
	}
	if out.Version == "" {
		return Database{}, errBadResponse
	}
	return out, nil
}

// do sends a request, and decodes a 200 answer into out.
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.BaseURL, "/")+path, reader)
	if err != nil {
		// The error's text holds the URL.
		return errBadBaseURL
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return failure(ctx)
	}
	defer func() {
		// Read a little of what is left, so that the connection can serve the next call. It is not
		// read for any other purpose.
		_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return ErrNotReady
	default:
		return fmt.Errorf("matcher: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return failure(ctx)
	}
	if int64(len(data)) > maxResponseBytes || json.Unmarshal(data, out) != nil {
		return errBadResponse
	}
	return nil
}

// failure is the error of a call that didn't get an answer: the caller's own end of the context,
// or else the matcher being unavailable, whatever the network said.
func failure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("matcher: %w", err)
	}
	return ErrUnavailable
}
