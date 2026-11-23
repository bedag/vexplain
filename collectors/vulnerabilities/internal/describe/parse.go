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

package describe

import (
	"encoding/json"
	"errors"
)

// What describe reads of Grype's two searches of its database, `db search vuln -o json -- <ID>...`, which prints a
// record of each provider for each ID, and `db search -o json --vuln=<ID>...`, which prints each record that lists
// packages with the packages that it lists. Grype v0.121.0 prints them so, with a database of schema v6.
//
// The testdata of the tests is what that Grype printed on 2026-11-16, with the database v6.1.10+2026-11-06T06:21:59Z
// that the vulnerabilities collector's image holds, built as for the e2e tests and run with Docker's network off,
// which shows that the searches need none. From the root of the repository, and then in testdata:
//
//	docker build -f collectors/vulnerabilities/Dockerfile --build-arg WITH_DB=true \
//	  -t example.com/vexplain-vulnerabilities:v0.0.1 .
//	grype() {
//	  docker run --rm --network none --entrypoint /usr/local/bin/grype \
//	    -e GRYPE_DB_AUTO_UPDATE=false -e GRYPE_CHECK_FOR_APP_UPDATE=false -e GRYPE_DB_VALIDATE_AGE=false \
//	    -e GRYPE_DB_CACHE_DIR=/opt/grype-db example.com/vexplain-vulnerabilities:v0.0.1 "$@"
//	}
//	grype db search vuln -o json --limit 0 --provider debian --provider nvd --provider ubuntu -- CVE-2026-111497 \
//	  > debian-records.json
//	grype db search -o json --limit 0 --provider debian --provider nvd --provider ubuntu --vuln=CVE-2026-111497 \
//	  > debian-packages.json
//	grype db search vuln -o json --limit 0 -- GHSA-2c4m-59x9-fr2g > ghsa-records.json
//	grype db search -o json --limit 0 --vuln=GHSA-2c4m-59x9-fr2g > ghsa-packages.json
//	grype db search vuln -o json --limit 0 -- GHSA-2c4m-59x9-fr2g CVE-2023-29401 > ghsa-alias-records.json
//	grype db search -o json --limit 0 --vuln=GHSA-2c4m-59x9-fr2g --vuln=CVE-2023-29401 > ghsa-alias-packages.json
//	grype db search vuln -o json --limit 0 -- CVE-2099-0001 > unknown-records.json
//	grype db search -o json --limit 0 --vuln=CVE-2099-0001 > unknown-packages.json
//	grype db search vuln -o json --limit 0 -- CVE-2026-111497 > all-records.json
//	grype db search -o json --limit 0 --vuln=CVE-2026-111497 > all-packages.json
//	jq '[.[] | select(.provider == "rhel")]' all-records.json > rhel-records.json
//	jq '[.[] | select(.vulnerability.provider == "rhel") | .packages |= map(select(.package.name == "brotli"
//	  and (.os.version == "9" or .os.version == "9.6+eus")))]' all-packages.json > rhel-packages.json
//	rm all-records.json all-packages.json
//	grype db search vuln -o json --limit 0 --provider govulndb -- GO-2026-6612 > go-records.json
//	grype db search -o json --limit 0 --provider govulndb --vuln=GO-2026-6612 > go-packages.json
//	grype db search vuln -o json --limit 0 --provider govulndb -- GO-2026-6612 CVE-2026-78663 > go-alias-records.json
//	grype db search -o json --limit 0 --provider govulndb --vuln=GO-2026-6612 --vuln=CVE-2026-78663 \
//	  > go-alias-packages.json
//	grype db search vuln -o json --limit 0 --provider nvd -- CVE-2022-48174 > busybox-records.json
//	grype db search -o json --limit 0 --provider nvd --vuln=CVE-2022-48174 > busybox-packages.json
//
// CVE-2026-111497 is a vulnerability of Brotli that Debian 12 fixed in 1.0.9-2+deb12u1. The --provider flags keep
// the files small: SUSE alone lists over a thousand packages for it. GHSA-2c4m-59x9-fr2g is a GitHub advisory of the
// Go module of Gin, whose CVE is CVE-2023-29401, and CVE-2099-0001 is in no database. The rhel files keep two rows of
// Red Hat 9 for Brotli: the fix of the release, and that of an extended update stream, which Grype lists under the
// same namespace. GO-2026-6612 is a vulnerability of Go's standard library and of golang.org/x/net, in the Go
// vulnerability database, whose CVE is CVE-2026-78663. The Go
// database's record names the CVE as an alias, and the database holds no govulndb record under the CVE itself, so the
// search with both IDs returns the same rows, and the alias files equal the plain ones. CVE-2022-48174 is a
// vulnerability of BusyBox, which NVD lists by CPE alone: one for BusyBox, and one for Debian 11.
// Grype answers from its database, so a newer database gives other files.

// record is a provider's record of a vulnerability, as both searches print it.
type record struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	Description string `json:"description"`
	Refs        []struct {
		URL string `json:"url"`
	} `json:"refs"`
	Aliases []string `json:"aliases"`
	// Severities holds scores of several schemes. A CVSS score's value is an object with its vector and version, and
	// that of another scheme a string.
	Severities []struct {
		Scheme string          `json:"scheme"`
		Value  json.RawMessage `json:"value"`
	} `json:"severities"`
	// KnownExploited is Grype's list of the CISA catalog's entries for the vulnerability.
	KnownExploited []json.RawMessage `json:"known_exploited"`
	EPSS           []struct {
		CVE  string  `json:"cve"`
		EPSS float64 `json:"epss"`
		Date string  `json:"date"`
	} `json:"epss"`
}

// cvss is the value of a CVSS score.
type cvss struct {
	Vector  string `json:"vector"`
	Version string `json:"version"`
}

// listing is a record that lists packages, with the packages, as `db search --vuln` prints it.
type listing struct {
	Vulnerability record `json:"vulnerability"`
	Packages      []struct {
		// Namespace is Grype's, such as debian:distro:debian:12, github:language:go or nvd:cpe.
		Namespace string `json:"namespace"`
		// Package names a package of a distribution or an ecosystem, and CPE what NVD lists instead.
		Package *struct {
			Name string `json:"name"`
		} `json:"package"`
		CPE    string `json:"cpe"`
		Detail struct {
			Ranges []versionRange `json:"ranges"`
		} `json:"detail"`
	} `json:"packages"`
}

// versionRange is a range of affected versions, in the scheme of its type, and its fix.
type versionRange struct {
	Version struct {
		Type       string `json:"type"`
		Constraint string `json:"constraint"`
	} `json:"version"`
	Fix *struct {
		Version string `json:"version"`
		State   string `json:"state"`
	} `json:"fix"`
}

// row is a package that a provider lists for a vulnerability, by the vulnerability's ID, in a namespace, with the
// ranges of its affected versions.
type row struct {
	provider, vulnerability, namespace, name string
	ranges                                   []versionRange
}

// errBadOutput is the error of an output that is not what the searches print. Grype's output holds nothing from the
// request but the IDs, and the error repeats nothing of it.
var errBadOutput = errors.New("grype search: the output is not a list of records")

// parse reads the outputs of the two searches: the records, and a row for each package that a record lists. A list
// that is missing or null is an error, and never a vulnerability that no provider tracks.
func parse(recordsJSON, packagesJSON []byte) ([]record, []row, error) {
	var records []record
	var listings []listing
	if json.Unmarshal(recordsJSON, &records) != nil || records == nil ||
		json.Unmarshal(packagesJSON, &listings) != nil || listings == nil {
		return nil, nil, errBadOutput
	}
	var rows []row
	for _, l := range listings {
		for _, p := range l.Packages {
			name := p.CPE
			if p.Package != nil {
				name = p.Package.Name
			}
			if l.Vulnerability.Provider == "" || l.Vulnerability.ID == "" || p.Namespace == "" || name == "" {
				return nil, nil, errBadOutput
			}
			rows = append(rows, row{provider: l.Vulnerability.Provider, vulnerability: l.Vulnerability.ID,
				namespace: p.Namespace, name: name, ranges: p.Detail.Ranges})
		}
	}
	return records, rows, nil
}
