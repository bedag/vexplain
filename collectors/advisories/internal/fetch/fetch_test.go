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

package fetch_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/bedag/vexplain/collectors/advisories/internal/fetch"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/conformance"
	"github.com/bedag/vexplain/sdk/evidence"
)

// These tests serve pages from an httptest TLS server, never from the internet. Its certificate covers example.com and
// *.example.com, and the collector's transport dials the server whatever host a request names, so a host is allowed or
// refused only by the collector's own checks.

const (
	allowed  = "advisories.example.com"
	unlisted = "other.example.com"
	// caseSubject is the subject of the case that the agent fetches for: the event is about the page instead.
	caseSubject      = "manifest/sha256:0000000000000000000000000000000000000000000000000000000000000000"
	reasonNotAllowed = "NotAllowed"
	version          = "0.1.0"
)

// site is a test server and what it saw: the addresses that the collector dialed, and the requests, as host and path.
type site struct {
	mu       sync.Mutex
	dials    []string
	requests []string
}

func (s *site) dialed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.dials...)
}

func (s *site) served() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

func newCollector(transport *http.Transport) *fetch.Collector {
	return fetch.New(fetch.Options{Name: "advisories", Version: version, Transport: transport})
}

// serveSite starts a TLS server with the handler, and returns the collector, whose transport dials it and trusts its
// certificate, and what the server saw.
func serveSite(t *testing.T, handler http.HandlerFunc) (*fetch.Collector, *site) {
	t.Helper()
	s := &site{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.Host+r.URL.Path)
		s.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		s.mu.Lock()
		s.dials = append(s.dials, addr)
		s.mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, network, server.Listener.Addr().String())
	}
	return newCollector(transport), s
}

// page answers with an HTML page.
func page(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(body))
	}
}

// settingsOf returns the settings that allow the hosts.
func settingsOf(hosts ...string) string {
	b, _ := json.Marshal(map[string]any{"allowedDomains": hosts})
	return string(b)
}

// invoke runs fetch on the URL, with the settings, and returns the page, or the failure.
func invoke(t *testing.T, c *fetch.Collector, settings, rawURL string) (*evidence.Page, *collector.Failure) {
	t.Helper()
	params, err := json.Marshal(map[string]string{"url": rawURL})
	require.NoError(t, err)
	events, failure, err := c.Invoke(t.Context(), collector.InvokeRequest{
		Operation: fetch.Name, Subject: caseSubject, Parameters: params, Settings: json.RawMessage(settings),
		Role: collector.RoleHub,
	})
	require.NoError(t, err)
	if failure != nil {
		require.Empty(t, events)
		return nil, failure
	}
	require.Len(t, events, 1)
	e := events[0]
	require.NoError(t, evidence.Validate(e))
	require.Equal(t, evidence.TypePage, e.Type())
	require.Equal(t, "page/"+rawURL, e.Subject(), "the event is about the page, whatever subject fetch ran for")
	require.Equal(t, "/hub/collectors/advisories", e.Source())
	var p evidence.Page
	decoder := json.NewDecoder(strings.NewReader(string(e.Data())))
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(&p))
	return &p, nil
}

// TestOnlyHTTPSToAnAllowedHost: a URL that isn't https, names a host that isn't on the list, an IP address, a user or
// a port other than 443 is refused before any connection. A host matches an entry exactly, case-insensitively and
// after IDNA, or as a subdomain of an entry that starts with a dot.
func TestOnlyHTTPSToAnAllowedHost(t *testing.T) {
	c, s := serveSite(t, page("<p>An advisory</p>"))
	settings := settingsOf(allowed, "bücher.example.com")
	// An entry that starts with a dot allows its subdomains, and not the domain itself.
	subdomains := settingsOf(".example.com")

	for _, tc := range []struct{ settings, url string }{
		{settings, "http://" + allowed + "/a"},
		{settings, "ftp://" + allowed + "/a"},
		{settings, "https://" + unlisted + "/a"},
		{settings, "https://" + allowed + ".other.example/a"},
		{settings, "https://127.0.0.1/a"},
		{settings, "https://[::1]/a"},
		{settings, "https://user:secret@" + allowed + "/a"},
		{settings, "https://user@" + allowed + "/a"},
		{settings, "https://" + allowed + ":8443/a"},
		{settings, "not a URL"},
		{subdomains, "https://example.com/a"},
		{subdomains, "https://example.com.other.example/a"},
		// A host has no empty label.
		{subdomains, "https://www..example.com/a"},
		{subdomains, "https://.example.com/a"},
		{subdomains, "https://www.example.com./a"},
		{settings, "https://" + allowed + "./a"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			p, failure := invoke(t, c, tc.settings, tc.url)
			require.Nil(t, p)
			require.NotNil(t, failure)
			require.Equal(t, reasonNotAllowed, failure.Reason)
			require.NotContains(t, failure.Message, "secret", "the failure repeats nothing of the URL")
		})
	}
	require.Empty(t, s.dialed(), "a refused URL is refused before any connection")

	for _, tc := range []struct{ settings, url string }{
		{settings, "https://" + allowed + "/a"},
		{settings, "https://ADVISORIES.Example.COM/a"},
		{settings, "https://" + allowed + ":443/a"},
		// The entry in Unicode allows the host in its ASCII form, in any case.
		{settings, "https://XN--BCHER-KVA.example.com/a"},
		{subdomains, "https://www.example.com/a"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			p, failure := invoke(t, c, tc.settings, tc.url)
			require.Nil(t, failure)
			require.Equal(t, tc.url, p.URL)
			require.Equal(t, "An advisory", p.Text)
		})
	}
	require.Len(t, s.served(), 5)
}

// The default list holds the advisory hosts of Grype's providers, such as NVD's, and no other host.
func TestTheDefaultListHoldsTheAdvisoryHosts(t *testing.T) {
	c, s := serveSite(t, page("<p>An advisory</p>"))

	_, failure := invoke(t, c, `{}`, "https://"+unlisted+"/a")
	require.Equal(t, reasonNotAllowed, failure.Reason)
	require.Empty(t, s.dialed())

	// The test server can't show NVD's certificate, so the fetch fails, after the collector connected.
	_, failure = invoke(t, c, `{}`, "https://nvd.nist.gov/vuln/detail/CVE-2026-0001")
	require.NotNil(t, failure)
	require.NotEqual(t, reasonNotAllowed, failure.Reason)
	require.Equal(t, []string{"nvd.nist.gov:443"}, s.dialed())

	// www.cve.org serves no page that the agent can read, and go.dev holds the Go vulnerability database's issues.
	_, failure = invoke(t, c, `{}`, "https://www.cve.org/CVERecord?id=CVE-2026-0001")
	require.Equal(t, reasonNotAllowed, failure.Reason)
	_, failure = invoke(t, c, `{}`, "https://go.dev/issue/1")
	require.NotNil(t, failure)
	require.NotEqual(t, reasonNotAllowed, failure.Reason)
}

// A request says that it accepts HTML and JSON, as some advisory hosts answer nothing else.
func TestARequestAcceptsHTMLAndJSON(t *testing.T) {
	accept := make(chan string, 1)
	c, _ := serveSite(t, func(w http.ResponseWriter, r *http.Request) {
		accept <- r.Header.Get("Accept")
		page("<p>An advisory</p>")(w, r)
	})
	_, failure := invoke(t, c, settingsOf(allowed), "https://"+allowed+"/a")
	require.Nil(t, failure)
	require.Equal(t, "text/html, application/json;q=0.9", <-accept)
}

// collectorVia returns a collector whose transport asks the proxy for a tunnel, and the proxy's address.
func collectorVia(t *testing.T, status int) (*fetch.Collector, string) {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(proxy.Close)
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	return newCollector(&http.Transport{Proxy: http.ProxyURL(proxyURL)}), proxyURL.Host
}

// A proxy that refuses the tunnel is named, with its status, and its address stays with the admin.
func TestAProxysRefusalIsNamed(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusProxyAuthRequired} {
		c, proxyHost := collectorVia(t, code)
		_, failure := invoke(t, c, settingsOf(allowed), "https://"+allowed+"/a")
		require.NotNil(t, failure)
		require.Equal(t, "FetchFailed", failure.Reason)
		require.Equal(t, fmt.Sprintf("the proxy refused the host, with HTTP status %d", code), failure.Message)
		require.NotContains(t, failure.Message, proxyHost)
	}
}

// A failure says which step failed, in fixed words.
func TestAFailureNamesItsCause(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := closed.Addr().String()
	require.NoError(t, closed.Close())
	proxyURL, err := url.Parse("http://" + closedAddr)
	require.NoError(t, err)

	untrusted := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(untrusted.Close)

	dialing := func(dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
		return &http.Transport{DialContext: dial}
	}
	for _, tc := range []struct {
		name      string
		transport *http.Transport
		want      string
	}{
		{"proxy down", &http.Transport{Proxy: http.ProxyURL(proxyURL)}, "the proxy could not be reached"},
		{"name unresolved", dialing(func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.DNSError{Err: "no such host", Name: allowed, IsNotFound: true}
		}), "the host's name does not resolve"},
		{"certificate", dialing(func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, untrusted.Listener.Addr().String())
		}), "the host's certificate is not trusted"},
		{"port closed", dialing(func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, closedAddr)
		}), "the host could not be reached"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newCollector(tc.transport)
			_, failure := invoke(t, c, settingsOf(allowed), "https://"+allowed+"/a")
			require.NotNil(t, failure)
			require.Equal(t, "FetchFailed", failure.Reason)
			require.Equal(t, tc.want, failure.Message)
		})
	}
}

// TestEveryRedirectHopIsChecked: a redirect is checked as the first request is, before the collector follows it.
func TestEveryRedirectHopIsChecked(t *testing.T) {
	c, s := serveSite(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, "https://"+unlisted+"/next", http.StatusFound)
		case "/plain":
			http.Redirect(w, r, "http://"+allowed+"/next", http.StatusMovedPermanently)
		case "/moved":
			http.Redirect(w, r, "/next", http.StatusFound)
		default:
			page("<p>Next</p>")(w, r)
		}
	})
	settings := settingsOf(allowed)

	for _, path := range []string{"/away", "/plain"} {
		_, failure := invoke(t, c, settings, "https://"+allowed+path)
		require.NotNil(t, failure, path)
		require.Equal(t, reasonNotAllowed, failure.Reason, path)
		require.NotContains(t, failure.Message, unlisted, "the failure names no URL that the page gave")
	}
	require.Equal(t, []string{allowed + "/away", allowed + "/plain"}, s.served(),
		"the collector never followed a redirect that it refused")

	p, failure := invoke(t, c, settings, "https://"+allowed+"/moved")
	require.Nil(t, failure)
	require.Equal(t, "https://"+allowed+"/moved", p.URL)
	require.Equal(t, "https://"+allowed+"/next", p.FinalURL)
	require.Equal(t, "Next", p.Text)
}

// TestThePageIsCappedAndTimed: a page over maxBytes is cut, and says so, and a page that takes longer than
// timeoutSeconds fails.
func TestThePageIsCappedAndTimed(t *testing.T) {
	c, _ := serveSite(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/long":
			page("<p>"+strings.Repeat("word ", 1000)+"</p>")(w, r)
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		default:
			page("<p>short</p>")(w, r)
		}
	})
	settings := `{"allowedDomains": ["` + allowed + `"], "maxBytes": 1024, "timeoutSeconds": 1}`

	p, failure := invoke(t, c, settings, "https://"+allowed+"/long")
	require.Nil(t, failure)
	require.True(t, p.Truncated)
	require.LessOrEqual(t, len(p.Text), 1024)
	require.True(t, strings.HasPrefix(p.Text, "word word"))

	p, failure = invoke(t, c, settings, "https://"+allowed+"/short")
	require.Nil(t, failure)
	require.False(t, p.Truncated)
	require.Equal(t, "short", p.Text)

	start := time.Now()
	_, failure = invoke(t, c, settings, "https://"+allowed+"/slow")
	require.NotNil(t, failure)
	require.Equal(t, "TimedOut", failure.Reason)
	require.Less(t, time.Since(start), 5*time.Second)
}

// A page that isn't there, or isn't text, fails with a reason of its own.
func TestAPageThatIsNotThereOrNotTextFails(t *testing.T) {
	c, _ := serveSite(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gone":
			http.NotFound(w, r)
		case "/broken":
			http.Error(w, "broken", http.StatusInternalServerError)
		case "/image":
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("\x89PNG\r\n\x1a\n"))
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id": "GO-2026-0001",` + "\n\n\n" + `  "summary": "A flaw"}`))
		}
	})
	settings := settingsOf(allowed)

	for path, reason := range map[string]string{"/gone": "NotFound", "/broken": "FetchFailed", "/image": "UnsupportedContent"} {
		_, failure := invoke(t, c, settings, "https://"+allowed+path)
		require.NotNil(t, failure, path)
		require.Equal(t, reason, failure.Reason, path)
	}

	p, failure := invoke(t, c, settings, "https://"+allowed+"/json")
	require.Nil(t, failure)
	require.Equal(t, "application/json", p.ContentType)
	require.Equal(t, "{\"id\": \"GO-2026-0001\",\n\"summary\": \"A flaw\"}", p.Text)
}

// The settings name hosts, never IP addresses, ports or wildcards.
func TestTheSettingsNameHosts(t *testing.T) {
	c := fetch.New(fetch.Options{Name: "advisories", Version: version})
	require.Empty(t, c.ValidateSettings(json.RawMessage(`{}`)))
	require.Empty(t, c.ValidateSettings(json.RawMessage(settingsOf(allowed, ".debian.org", "bücher.example"))))
	// A name has no empty label: no dot at its end, no two in a row, and no dot at its start but the one of an entry
	// for subdomains.
	for _, entry := range []string{"10.0.0.1", "::1", "*.example.com", allowed + ":443", "a b.example", ".",
		allowed + ".", "advisories..example.com", "..example.com", ".example.com.", "..", "a.\u3002example.com"} {
		require.NotEmpty(t, c.ValidateSettings(json.RawMessage(settingsOf(entry))), entry)
	}
}

// TestConformance runs the conformance suite of the SDK against the collector, which fetches from the test server.
func TestConformance(t *testing.T) {
	c, _ := serveSite(t, page("<p>An advisory</p>"))
	conformance.Run(t, conformance.Target{
		Dial:            serve(t, c),
		Settings:        json.RawMessage(settingsOf(allowed)),
		InvalidSettings: json.RawMessage(settingsOf("10.0.0.1")),
		Context:         collector.Context{Cluster: "cluster-a"},
		Invocations: []conformance.Invocation{
			{Operation: fetch.Name, Subject: caseSubject, Parameters: json.RawMessage(`{"url": "https://` + allowed + `/a"}`)},
		},
	})
}

// serve runs the collector in this process until the test ends, without TLS and on a listener that only this test
// reaches, and returns the Dial that connects the suite to it.
func serve(t *testing.T, c collector.Collector) func(ctx context.Context) (*grpc.ClientConn, error) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	health, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- collector.Serve(ctx, c, collector.Options{Insecure: true, GRPCListener: listener, HealthListener: health})
	}()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	return func(context.Context) (*grpc.ClientConn, error) {
		return grpc.NewClient("passthrough:///bufconn",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
}
