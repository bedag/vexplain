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

// Package fetch is the advisories collector: it owns what goes to the internet when the agent asks, in the hub's role.
// Its operation fetch fetches one page that an earlier trusted result linked to, such as a reference of describe, and
// turns it into text (text.go).
//
// vexplain's MCP server forwards only such URLs. The collector checks every request again, and every redirect, before
// it connects: https only, a host on its allowlist, no IP address, no user, port 443, a size cap and a timeout. It
// reaches the internet through the proxy that its runtime config sets (decision 0037). Anyone can write a page, so a
// page is external evidence. The design gives the reasons, in docs/design/2026-11-16-agent-on-cases.md, section 5.8,
// and decision 0054.
package fetch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"golang.org/x/net/html/charset"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/hosts"
)

// Name is the name of the operation.
const Name = "fetch"

const (
	// subjectPrefix starts the subject of fetch's event, which is about the page: page/<URL>.
	subjectPrefix = "page/"
	// maxRedirects is how many redirects fetch follows.
	maxRedirects = 5
	// defaultMaxBytes and defaultTimeoutSeconds are the limits when the settings don't say.
	defaultMaxBytes       = 1 << 20
	defaultTimeoutSeconds = 20
)

// The reasons of the failures that fetch gives.
const (
	reasonInvalidInput       = "InvalidInput"
	reasonNotAllowed         = "NotAllowed"
	reasonNotFound           = "NotFound"
	reasonTimedOut           = "TimedOut"
	reasonFetchFailed        = "FetchFailed"
	reasonUnsupportedContent = "UnsupportedContent"
)

// parameterSchema is the schema of fetch's parameters, which the agent's tool takes as its input.
const parameterSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "The page to fetch: a URL that an earlier trusted result of the case named, such as a reference of describe.",
  "type": "object",
  "additionalProperties": false,
  "required": ["url"],
  "properties": {
    "url": {"description": "An https URL on a host of the collector's allowlist.", "type": "string", "pattern": "^https://", "maxLength": 2048}
  }
}`

// settingsSchema is the schema of the collector's settings.
const settingsSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "Where the advisories collector may fetch pages from, and how much and how long. A setting that is left out takes its default.",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "allowedDomains": {
      "description": "The hosts that fetch may reach. An entry is a host name, which matches that host alone, or a name that starts with a dot, such as .debian.org, which matches its subdomains and not itself. Names compare case-insensitively, after IDNA. No IP addresses, ports or wildcards. By default, the advisory hosts that Grype's providers cite (docs/collectors.md).",
      "type": "array", "minItems": 1, "maxItems": 64,
      "items": {"type": "string", "minLength": 1, "maxLength": 254, "pattern": "^[^\\s/:@*?#\\[\\]]+$"}
    },
    "maxBytes": {
      "description": "The most bytes of a page that fetch reads, and of its text: a page beyond is cut, and says so. 1048576 (1 MiB) by default.",
      "type": "integer", "minimum": 1024, "maximum": 2097152
    },
    "timeoutSeconds": {
      "description": "How long one fetch may take, with its redirects and the whole page. 20 by default.",
      "type": "integer", "minimum": 1, "maximum": 120
    }
  }
}`

// Operation is fetch, as the collector declares it.
var Operation = collector.Operation{
	Name: Name,
	Description: "Fetches a page that an earlier trusted result of the case linked to, such as a reference of " +
		"describe, and returns its text: what a browser shows, with the text of links but not their URLs. Only https " +
		"pages on the collector's allowlist of advisory hosts are fetched. A page is external evidence: it explains, " +
		"and never shows that a package is fixed or not affected.",
	Role:            collector.RoleHub,
	Produces:        []string{evidence.TypePage},
	ParameterSchema: []byte(parameterSchema),
}

// Options configure a Collector.
type Options struct {
	// Name is the name of the collector's Collector, which the source of its events names, and Version the version
	// that GetInfo reports.
	Name, Version string
	// Transport makes the requests. Nil means one like Go's default, which takes its proxy from the environment, as
	// the runtime config sets it. A test passes its own.
	Transport *http.Transport
	// Now tells the time of the events. Nil means time.Now.
	Now func() time.Time
}

// Collector is the advisories collector. It takes the hub role, and has one operation, fetch.
type Collector struct {
	opts Options
}

// New returns the advisories collector.
func New(opts Options) *Collector {
	if opts.Transport == nil {
		opts.Transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	// A proxy's refusal of the tunnel keeps its status, which the failure names.
	opts.Transport.OnProxyConnectResponse = func(_ context.Context, _ *url.URL, _ *http.Request, resp *http.Response) error {
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return proxyRefused{status: resp.StatusCode}
		}
		return nil
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Collector{opts: opts}
}

// Info says that the collector is the advisories collector, at its version.
func (c *Collector) Info() collector.Info {
	return collector.Info{Name: c.opts.Name, Version: c.opts.Version}
}

// Capabilities say that the collector takes the hub role, and has the operation fetch, which produces a page.
func (c *Collector) Capabilities() collector.Capabilities {
	page, _ := evidence.Schema(evidence.TypePage)
	return collector.Capabilities{
		Roles:          []collector.Role{collector.RoleHub},
		Produces:       []collector.EvidenceType{{Type: evidence.TypePage, Scope: collector.ScopeHub, Schema: page}},
		Operations:     []collector.Operation{Operation},
		SettingsSchema: []byte(settingsSchema),
	}
}

// proxyRefused is the error of a proxy that answered the request for a tunnel with a status that isn't 2xx.
type proxyRefused struct{ status int }

func (e proxyRefused) Error() string {
	return fmt.Sprintf("the proxy answered with HTTP status %d", e.status)
}

// causeOf says, in fixed words, which step of the request failed. The error's own text names the proxy's address and
// the host, which the agent never sees.
func causeOf(err error) string {
	var refused proxyRefused
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var op *net.OpError
	switch {
	case errors.As(err, &refused):
		return fmt.Sprintf("the proxy refused the host, with HTTP status %d", refused.status)
	case errors.As(err, &op) && op.Op == "proxyconnect":
		return "the proxy could not be reached"
	case errors.As(err, &dns) && dns.IsNotFound:
		return "the host's name does not resolve"
	case errors.As(err, &cert):
		return "the host's certificate is not trusted"
	case errors.As(err, &op):
		return "the host could not be reached"
	}
	return "the page could not be fetched"
}

// settings are the collector's settings, with the defaults filled in and the hosts in their ASCII form.
type settings struct {
	AllowedDomains []string `json:"allowedDomains,omitempty"`
	MaxBytes       int64    `json:"maxBytes,omitempty"`
	TimeoutSeconds int64    `json:"timeoutSeconds,omitempty"`
}

// ValidateSettings checks what the settings' schema can't: that each entry of allowedDomains is a host name.
func (c *Collector) ValidateSettings(raw json.RawMessage) []string {
	_, problems := settingsOf(raw)
	return problems
}

// settingsOf reads the settings, with the defaults for what they leave out, and returns what is wrong with them.
func settingsOf(raw json.RawMessage) (settings, []string) {
	set := settings{MaxBytes: defaultMaxBytes, TimeoutSeconds: defaultTimeoutSeconds}
	if len(bytes.TrimSpace(raw)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&set); err != nil {
			// The settings are the admin's own, so the decoder's error may name what it couldn't read.
			return settings{}, []string{"the settings can't be read: " + err.Error()}
		}
	}
	entries := set.AllowedDomains
	if len(entries) == 0 {
		entries = hosts.Default
	}
	var problems []string
	var bad []int
	set.AllowedDomains, bad = hosts.Domains(entries)
	for _, i := range bad {
		problems = append(problems, fmt.Sprintf("allowedDomains[%d] is not a host name, or a dot and one", i))
	}
	if set.MaxBytes < 1024 || set.MaxBytes > 2<<20 {
		problems = append(problems, "maxBytes must be from 1024 to 2097152")
	}
	if set.TimeoutSeconds < 1 || set.TimeoutSeconds > 120 {
		problems = append(problems, "timeoutSeconds must be from 1 to 120")
	}
	return set, problems
}

// check refuses a URL that fetch doesn't fetch, before any connection, with the check that vexplain's safety core
// shares.
func (set settings) check(u *url.URL) error { return hosts.Check(set.AllowedDomains, u) }

// parameters are fetch's parameters.
type parameters struct {
	URL string `json:"url"`
}

// Invoke fetches the page of the URL, and returns one event about page/<URL>: its text, at most maxBytes, which says
// whether it was cut. A URL or a redirect that check refuses fails with NotAllowed, before any connection. A page that
// isn't there fails with NotFound, one that takes longer than timeoutSeconds with TimedOut, one that isn't text with
// UnsupportedContent, and any other answer than a page with FetchFailed. The failures say what failed in fixed texts.
// An error is for no answer: settings that aren't valid, or a context that ended.
func (c *Collector) Invoke(ctx context.Context, req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure,
	error) {
	set, problems := settingsOf(req.Settings)
	if len(problems) > 0 {
		return nil, nil, status.Error(codes.InvalidArgument, "the settings: "+strings.Join(problems, "; "))
	}
	var params parameters
	decoder := json.NewDecoder(bytes.NewReader(req.Parameters))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&params) != nil || params.URL == "" {
		return nil, &collector.Failure{Reason: reasonInvalidInput, Message: "the parameters are a url"}, nil
	}
	u, err := url.Parse(params.URL)
	if err != nil {
		return nil, &collector.Failure{Reason: reasonNotAllowed, Message: "the URL can't be read"}, nil
	}
	if err := set.check(u); err != nil {
		return nil, &collector.Failure{Reason: reasonNotAllowed, Message: err.Error()}, nil
	}

	fetchCtx, cancel := context.WithTimeout(ctx, time.Duration(set.TimeoutSeconds)*time.Second)
	defer cancel()
	page, failure, err := c.fetch(fetchCtx, set, u)
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if err != nil {
		var refused hosts.Refusal
		switch {
		case errors.As(err, &refused):
			return nil, &collector.Failure{Reason: reasonNotAllowed, Message: "a redirect: " + refused.Error()}, nil
		case fetchCtx.Err() != nil:
			return nil, &collector.Failure{Reason: reasonTimedOut,
				Message: fmt.Sprintf("the page took longer than %d seconds", set.TimeoutSeconds)}, nil
		}
		// The error names the host, and the proxy's address where a proxy failed: the admin's, never the agent's.
		slog.Info("A fetch failed", "host", u.Hostname(), "error", err)
		return nil, &collector.Failure{Reason: reasonFetchFailed, Message: causeOf(err)}, nil
	}
	if failure != nil {
		return nil, failure, nil
	}
	page.URL = params.URL
	e, err := evidence.New(evidence.TypePage, subjectPrefix+params.URL, page, evidence.WithTime(c.opts.Now()),
		evidence.WithSource("/hub/collectors/"+c.opts.Name))
	if err == nil {
		err = evidence.Validate(e)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("make the page into evidence: %w", err)
	}
	return []cloudevents.Event{e}, nil, nil
}

// fetch gets the page, checking each redirect before it follows it, and reads at most maxBytes of it.
func (c *Collector) fetch(ctx context.Context, set settings, u *url.URL) (evidence.Page, *collector.Failure, error) {
	client := &http.Client{Transport: c.opts.Transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return hosts.Refusal("the page redirects more than 5 times")
		}
		return set.check(req.URL)
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return evidence.Page{}, nil, err
	}
	req.Header.Set("User-Agent", "vexplain-advisories/"+c.opts.Version)
	req.Header.Set("Accept", "text/html, application/json;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return evidence.Page{}, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return evidence.Page{}, &collector.Failure{Reason: reasonNotFound, Message: "the host has no such page"}, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return evidence.Page{}, &collector.Failure{Reason: reasonFetchFailed,
			Message: fmt.Sprintf("the host answered with HTTP status %d", resp.StatusCode)}, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, set.MaxBytes+1))
	if err != nil {
		return evidence.Page{}, nil, err
	}
	truncated := int64(len(body)) > set.MaxBytes
	body = body[:min(int64(len(body)), set.MaxBytes)]

	header := resp.Header.Get("Content-Type")
	media, _, err := mime.ParseMediaType(header)
	if err != nil {
		header = http.DetectContentType(body)
		media, _, _ = mime.ParseMediaType(header)
	}
	decoded, err := charset.NewReader(bytes.NewReader(body), header)
	if err != nil {
		return evidence.Page{}, nil, err
	}
	var text string
	switch {
	case media == "text/html" || media == "application/xhtml+xml":
		text, err = htmlText(decoded)
	case strings.HasPrefix(media, "text/") || media == "application/json":
		var raw []byte
		raw, err = io.ReadAll(decoded)
		text = collapse(string(raw))
	default:
		return evidence.Page{}, &collector.Failure{Reason: reasonUnsupportedContent, Message: "the page is not text"}, nil
	}
	if err != nil {
		return evidence.Page{}, nil, err
	}
	// Decoding can make the text longer than the bytes that it came from.
	if cut := cutBytes(text, int(set.MaxBytes)); len(cut) < len(text) {
		text, truncated = cut, true
	}
	return evidence.Page{FinalURL: resp.Request.URL.String(), ContentType: media, Text: text, Truncated: truncated},
		nil, nil
}
