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

// Package hosts holds the allowlist of the hosts that a collector's fetch may reach, and the check of the URLs that it
// takes, as the advisories collector and vexplain's safety core both use them: the collector to refuse a URL, the core
// to tell the agent which references it can't fetch.
package hosts

import (
	"net"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

// Default are the hosts of the advisories that Grype's providers cite, which the vulnerabilities
// collector's database names as each record's own reference: each provider's first reference, counted over a Grype
// database v6 of 2026-11-06, and in the describe fixtures of collectors/vulnerabilities/internal/describe/testdata.
// Bitnami's records cite many hosts and none of their own, so it adds none.
var Default = []string{
	"nvd.nist.gov",                // nvd, mariner
	"www.cisa.gov",                // kev: the catalog of known exploited vulnerabilities, which NVD's records cite
	"github.com",                  // github: GitHub's advisory database, /advisories; govulndb, minimos, secureos
	"pkg.go.dev",                  // Go's vulnerability database, which GitHub's advisories of Go modules cite
	"go.dev",                      // Go's vulnerability database cites its issues
	"security-tracker.debian.org", // debian
	"ubuntu.com",                  // ubuntu
	"access.redhat.com",           // rhel, alma, hummingbird
	"errata.almalinux.org",        // alma
	"security.alpinelinux.org",    // alpine
	"alas.aws.amazon.com",         // amazon
	"security.archlinux.org",      // arch
	"images.chainguard.dev",       // chainguard, wolfi
	"bodhi.fedoraproject.org",     // fedora
	"linux.oracle.com",            // oracle
	"www.suse.com",                // sles
	"security.secureos.io",        // secureos
}

// MaxURL is the longest URL that a fetch takes, the first or a redirect's, in characters.
const MaxURL = 2048

// Refusal is why a fetch refuses a URL, in a fixed text: it repeats nothing of the URL, which a page may have given.
type Refusal string

func (r Refusal) Error() string { return string(r) }

// The refusals of Check.
const (
	RefusedScheme Refusal = "only https URLs are fetched"
	RefusedLength Refusal = "the URL is longer than 2048 characters"
	RefusedUser   Refusal = "a URL with a user or a password is refused"
	RefusedPort   Refusal = "only port 443 is fetched"
	RefusedIP     Refusal = "an IP address is refused: the host must be a name on the allowlist"
	RefusedHost   Refusal = "the host is not on the allowlist"
)

// Check returns the Refusal of a URL that a fetch never takes, before any connection, or nil: it takes only https, at
// most MaxURL characters, no user or password, port 443, and a host that is a name, not an IP address, which domains
// allow.
func Check(domains []string, u *url.URL) error {
	host := u.Hostname()
	switch {
	case u.Scheme != "https" || u.Opaque != "" || host == "":
		return RefusedScheme
	case len(u.String()) > MaxURL:
		return RefusedLength
	case u.User != nil:
		return RefusedUser
	case u.Port() != "" && u.Port() != "443":
		return RefusedPort
	case net.ParseIP(host) != nil:
		return RefusedIP
	case !Allows(domains, host):
		return RefusedHost
	}
	return nil
}

// Domains returns the entries in the form that Allows compares: a host name in its ASCII form, lower case, or a dot and
// one, which stands for its subdomains. bad holds the indexes of the entries that are neither.
func Domains(entries []string) (domains []string, bad []int) {
	domains = make([]string, 0, len(entries))
	for i, entry := range entries {
		rest, dot := strings.CutPrefix(entry, ".")
		host, ok := name(rest)
		if !ok {
			bad = append(bad, i)
			continue
		}
		if dot {
			host = "." + host
		}
		domains = append(domains, host)
	}
	return domains, bad
}

// Allows reports whether the host is on the domains, as Domains returns them: one of them, or a subdomain of one that
// starts with a dot. An IP address is never on them.
func Allows(domains []string, host string) bool {
	h, ok := name(host)
	return ok && slices.ContainsFunc(domains, func(d string) bool {
		return h == d || (strings.HasPrefix(d, ".") && strings.HasSuffix(h, d))
	})
}

// name returns the host name in its ASCII form, lower case, or false for anything else: an IP address, a name with an
// empty label, such as one that starts or ends with a dot or holds two in a row, which an entry for subdomains would
// match as a suffix, or a name that IDNA refuses, such as one with a port, a wildcard or a space.
func name(s string) (string, bool) {
	if s == "" || net.ParseIP(s) != nil {
		return "", false
	}
	host, err := idna.Lookup.ToASCII(s)
	if err != nil || host == "" || net.ParseIP(host) != nil || slices.Contains(strings.Split(host, "."), "") {
		return "", false
	}
	return host, true
}
