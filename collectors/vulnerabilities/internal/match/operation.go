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

// Package match is the vulnerabilities collector: the hub's one vulnerability database. Its operation match turns the
// SBOM of a manifest, evidence of the core type sbom that any producer can deliver (decision 0044), into findings, by
// running the Grype CLI on a document of Syft's JSON that it makes of the SBOM (decision 0022, which phase 2a built as
// an HTTP service), and its Watch sends no evidence: it only says when the database has changed, so that vexplain
// matches the manifests again.
//
// The SBOM, and everything Grype writes about it, can hold text from an image that anyone may have built. So no
// failure, error or log line carries Grype's stderr, a piece of the SBOM, or the text of an error that holds one:
// package grype's errors are fixed texts, and Grype's stderr is logged at debug level only.
//
// The design of collectors, evidence and rules gives the reasons, in docs/design/2026-10-31-collectors-evidence-rules.md,
// sections 5.3, 5.5 and 5.12.
package match

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/bedag/vexplain/collectors/vulnerabilities/internal/grype"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/evidence"
	"github.com/bedag/vexplain/sdk/subject"
)

// operationName is the name of the collector's one operation.
const operationName = "match"

// The reasons of the failures that match gives. The vocabulary of reasons is open, and these two are the vulnerabilities collector's.
const (
	// reasonNotReady says that the vulnerabilities collector has no database yet: a first download can take long, and a match asked
	// for then fails, so that the hub asks again. It is no failure of the collector, whose health stays SERVING.
	reasonNotReady = "NotReady"
	// reasonInvalidInput says that the evidence holds no SBOM that match can match.
	reasonInvalidInput = "InvalidInput"
	// reasonInternal says that Grype's answer can't be made into evidence.
	reasonInternal = "Internal"
)

// Options configure a Collector.
type Options struct {
	// Name is the name of the collector's Collector, which the source of its events names, and Version the version
	// that GetInfo reports.
	Name, Version string
	// Grype is the Grype CLI on the database in DBDir.
	Grype grype.Grype
	// DBDir is the database directory of Grype, into which a seed is copied.
	DBDir string
	// After returns a channel that gets the time once d has passed: how the vulnerabilities collector waits to update the database. Nil
	// means time.After. A test passes its own.
	After func(d time.Duration) <-chan time.Time
	// RetryDelay is how long the vulnerabilities collector waits to update again when it still has no database, instead of the
	// interval, which is hours. Zero means a minute.
	RetryDelay time.Duration
	// Now tells the time of the events. Nil means time.Now.
	Now func() time.Time
}

// Collector is the vulnerabilities collector. It takes the hub role, watches only to say that its database has changed, and has
// one operation, match.
type Collector struct {
	opts Options

	// mu keeps matches and updates apart. Matches share it, and an update holds it alone, because an update replaces
	// the database's files under a match that reads them. The database that db names is replaced under the same lock,
	// so a match always names the version it ran on.
	mu sync.RWMutex
	// db is the database in use, or nil while there is none. It is read without mu, so that a match asked for during
	// an update, which can take minutes, learns that there is a database. Once set, it is never cleared: a failed
	// update keeps the old database.
	db atomic.Pointer[grype.Database]

	// notifyMu serialises the sends of SourceChanged, and notified is the version that the last one said: Watches
	// come and go, and each says a version once.
	notifyMu sync.Mutex
	notified string

	// slotsMu guards running, the matches that hold a place, and freed, which closes when one gives it back.
	slotsMu sync.Mutex
	running int
	freed   chan struct{}
}

// New returns the vulnerabilities collector.
func New(opts Options) *Collector {
	if opts.After == nil {
		opts.After = time.After
	}
	if opts.RetryDelay == 0 {
		opts.RetryDelay = time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Collector{opts: opts, freed: make(chan struct{})}
}

// Info says that the collector is the vulnerabilities collector, at its version.
func (m *Collector) Info() collector.Info {
	return collector.Info{Name: m.opts.Name, Version: m.opts.Version}
}

// parameterSchema is the schema of the parameters of match, which has none.
const parameterSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "match takes no parameters: the SBOM of the manifest, which it is given as its input, is all it needs.",
  "type": "object",
  "additionalProperties": false
}`

// settingsSchema is the schema of the collector's settings.
const settingsSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "description": "How the vulnerabilities collector keeps its vulnerability database and how many SBOMs it matches at once. A setting that is left out takes its default.",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "updateIntervalSeconds": {
      "description": "How often the database is updated. 21600 by default, which is 6 hours. It has no effect with databaseUpdates Offline.",
      "type": "integer", "minimum": 60, "maximum": 2592000
    },
    "maxConcurrent": {
      "description": "How many SBOMs are matched at once: a match that finds them all busy waits for one. 2 by default, which is as many matches as the hub's assessor asks for at once.",
      "type": "integer", "minimum": 1, "maximum": 8
    },
    "databaseUpdates": {
      "description": "Online updates the database, through the proxy of the collector's environment, when it has none and then every updateIntervalSeconds. Offline never updates it: the database is the one that is there, or the seed. Online by default.",
      "type": "string", "enum": ["Online", "Offline"]
    },
    "seedDatabase": {
      "description": "The absolute path of a directory that holds a database, such as the one that the image carries for a cluster without internet. At start, when the database directory holds no database, it is copied there before the database is loaded.",
      "type": "string", "minLength": 1, "maxLength": 4096
    }
  }
}`

// Capabilities say that the collector takes the hub role. It watches, only to say that its database changed, and has
// the operation match, which consumes the SBOM of a manifest and produces findings, which stay on the hub.
func (m *Collector) Capabilities() collector.Capabilities {
	schema, _ := evidence.Schema(evidence.TypeFindings)
	return collector.Capabilities{
		Roles:    []collector.Role{collector.RoleHub},
		Produces: []collector.EvidenceType{{Type: evidence.TypeFindings, Scope: collector.ScopeHub, Schema: schema}},
		Consumes: []string{evidence.TypeSBOM},
		Watches:  true,
		Operations: []collector.Operation{{
			Name: operationName,
			Description: "Matches the packages of a manifest's SBOM against the vulnerability database: the findings " +
				"of the manifest, with severities, fixes, known exploitation and CVSS vectors.",
			Role:            collector.RoleHub,
			Consumes:        []string{evidence.TypeSBOM},
			Produces:        []string{evidence.TypeFindings},
			ParameterSchema: []byte(parameterSchema),
		}},
		SettingsSchema: []byte(settingsSchema),
	}
}

// The values of databaseUpdates.
const (
	updatesOnline  = "Online"
	updatesOffline = "Offline"
)

// settings are the collector's settings, with the defaults filled in.
type settings struct {
	UpdateIntervalSeconds int32  `json:"updateIntervalSeconds,omitempty"`
	MaxConcurrent         int32  `json:"maxConcurrent,omitempty"`
	DatabaseUpdates       string `json:"databaseUpdates,omitempty"`
	SeedDatabase          string `json:"seedDatabase,omitempty"`
}

// ValidateSettings checks what the settings' schema can't: that the seed is an absolute path. It also holds the
// settings to their ranges, which the schema checks first, so that no caller needs to know the order.
func (m *Collector) ValidateSettings(raw json.RawMessage) []string {
	_, problems := settingsOf(raw)
	return problems
}

// settingsOf reads the settings, with the defaults for what they leave out, and returns what is wrong with them.
func settingsOf(raw json.RawMessage) (settings, []string) {
	set := settings{UpdateIntervalSeconds: 21600, MaxConcurrent: 2, DatabaseUpdates: updatesOnline}
	if len(bytes.TrimSpace(raw)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&set); err != nil {
			// The settings are the admin's own, so the decoder's error may name what it couldn't read.
			return settings{}, []string{"the settings can't be read: " + err.Error()}
		}
	}
	var problems []string
	if set.UpdateIntervalSeconds < 60 {
		problems = append(problems, "updateIntervalSeconds must be at least 60")
	}
	if set.MaxConcurrent < 1 || set.MaxConcurrent > 8 {
		problems = append(problems, "maxConcurrent must be from 1 to 8")
	}
	if set.DatabaseUpdates != updatesOnline && set.DatabaseUpdates != updatesOffline {
		problems = append(problems, "databaseUpdates must be Online or Offline")
	}
	if set.SeedDatabase != "" && !strings.HasPrefix(set.SeedDatabase, "/") {
		problems = append(problems, "seedDatabase must be an absolute path")
	}
	return set, problems
}

// Invoke runs match for a manifest, manifest/ and its digest, with the SBOM of the manifest as the input:
//   - Without a database it fails with NotReady, and runs nothing.
//   - It waits for one of maxConcurrent places, and runs Grype on a document of Syft's JSON that it makes of the SBOM
//     (documentOf), which it writes to a file of its own that it removes afterwards.
//   - It returns one findings event about the manifest, with the input's platform, and the database's version as the
//     findings' version. The matches are 2a's: severities, fix states and fixed versions, and known exploitation from
//     Grype's own field, with the CVSS vectors besides. Each names its package by the package's ID in the SBOM.
//
// Input that holds no SBOM that match can match fails with InvalidInput, and Grype's matches that no evidence can hold
// fail with Internal. An error is for no answer: Grype that fails, or a context that ended. It never means that there
// are no findings.
func (m *Collector) Invoke(ctx context.Context, req collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure,
	error) {
	about, err := subject.Parse(req.Subject)
	if err != nil || about.Kind != subject.KindManifest {
		return nil, nil, status.Error(codes.InvalidArgument, "the vulnerabilities collector matches a manifest: manifest/ and a digest")
	}
	set, problems := settingsOf(req.Settings)
	if len(problems) > 0 {
		return nil, nil, status.Error(codes.InvalidArgument, "the settings: "+strings.Join(problems, "; "))
	}
	if len(req.Inputs) != 1 || req.Inputs[0].Type() != evidence.TypeSBOM || req.Inputs[0].Subject() != req.Subject {
		return nil, nil, status.Error(codes.InvalidArgument,
			"the vulnerabilities collector takes the SBOM of the manifest as its one input")
	}
	input := req.Inputs[0]
	platform, _ := evidence.Platform(input)

	if m.db.Load() == nil {
		return nil, &collector.Failure{Reason: reasonNotReady, Message: "the vulnerabilities collector has no vulnerability database yet"}, nil
	}
	sbom, why := sbomOf(input)
	if why != "" {
		return nil, &collector.Failure{Reason: reasonInvalidInput, Message: why}, nil
	}
	release, err := m.takeSlot(ctx, int(set.MaxConcurrent))
	if err != nil {
		return nil, nil, err
	}
	defer release()

	version, matches, err := m.run(ctx, sbom)
	if err != nil {
		return nil, nil, fmt.Errorf("match the packages of %s: %w", req.Subject, err)
	}
	found := evidence.Findings{Version: version, Matches: make([]evidence.Match, 0, len(matches))}
	for _, match := range matches {
		found.Matches = append(found.Matches, matchOf(match))
	}
	return m.eventOf(req, platform, found)
}

// sbomOf returns the document of Syft's JSON that Grype matches the SBOM of the input from, or why there is none, in a
// fixed text: the data must be an SBOM, which names its producer and its packages, each with a name and an ID of its
// own. Grype would take two packages of one ID for one, and a match names its package by the ID, as the rules that
// join a finding to its package do.
func sbomOf(input cloudevents.Event) ([]byte, string) {
	var sbom evidence.SBOM
	if json.Unmarshal(input.Data(), &sbom) != nil || sbom.Packages == nil || sbom.Producer.Name == "" {
		return nil, "the evidence holds no SBOM to match"
	}
	ids := make(map[string]bool, len(sbom.Packages))
	for _, p := range sbom.Packages {
		if p.ID == "" || p.Name == "" || ids[p.ID] {
			return nil, "the SBOM has a package without a name or an ID, or two of one ID"
		}
		ids[p.ID] = true
	}
	document, err := documentOf(sbom)
	if err != nil {
		// What can't be written is in the SBOM, which an image's scan made, so the error isn't passed on.
		return nil, "the SBOM can't be made into a document that Grype reads"
	}
	return document, ""
}

// matchOf maps one of Grype's matches onto the findings' type.
func matchOf(g grype.Match) evidence.Match {
	m := evidence.Match{
		VulnerabilityID: g.VulnerabilityID,
		PackageID:       g.PackageID,
		PackageName:     g.PackageName,
		PackageVersion:  g.PackageVersion,
		PackageType:     g.PackageType,
		Severity:        g.Severity,
		FixState:        g.FixState,
		FixedVersions:   g.FixedVersions,
		KnownExploited:  g.KnownExploited,
	}
	for _, score := range g.CVSS {
		m.CVSS = append(m.CVSS, evidence.CVSS{Version: score.Version, Vector: score.Vector})
	}
	return m
}

// run runs Grype on the SBOM while it holds the database for reading, and returns the version of the database that it
// ran on, with the matches.
func (m *Collector) run(ctx context.Context, sbom []byte) (string, []grype.Match, error) {
	path, err := writeSBOM(sbom)
	if err != nil {
		return "", nil, errors.New("write the SBOM to a file")
	}
	defer func() { _ = os.Remove(path) }()
	m.mu.RLock()
	defer m.mu.RUnlock()
	// The database is never cleared once there is one, and Invoke has checked that there is.
	version := m.db.Load().Version
	matches, err := m.opts.Grype.Match(ctx, path)
	return version, matches, err
}

// writeSBOM writes the SBOM to a file of its own under os.TempDir(), and returns its path. The Collector's runtime
// config mounts a volume there, because the root filesystem is read-only.
func writeSBOM(sbom []byte) (string, error) {
	f, err := os.CreateTemp("", "sbom-*.json")
	if err != nil {
		return "", err
	}
	_, err = f.Write(sbom)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// eventOf makes the findings event about the request's manifest, with the platform of its input. Evidence that
// vexplain can't hold fails the match, and none of it is returned: a match that names no package, or a message above
// what the collector API holds.
func (m *Collector) eventOf(req collector.InvokeRequest, platform string, found evidence.Findings) (
	[]cloudevents.Event, *collector.Failure, error) {
	var err error
	var e cloudevents.Event
	if !holdable(found) {
		err = errors.New("a match that the findings' schema refuses")
	} else if e, err = evidence.New(evidence.TypeFindings, req.Subject, found, evidence.WithPlatform(platform),
		evidence.WithTime(m.opts.Now()), evidence.WithSource("/hub/collectors/"+m.opts.Name)); err == nil {
		err = evidence.Validate(e)
	}
	if err != nil {
		// Grype's strings, which an image's SBOM chose, may be in the error, so it isn't passed on.
		return nil, &collector.Failure{Reason: reasonInternal,
			Message: "the matches of the database can't be made into evidence"}, nil
	}
	size, err := messageSize(e)
	if err != nil {
		return nil, nil, fmt.Errorf("measure the findings of %s: %w", req.Subject, err)
	}
	if size > collector.MaxMessageSize {
		return nil, &collector.Failure{Reason: "TooLarge",
			Message: "the findings are more than a message of the collector API holds"}, nil
	}
	return []cloudevents.Event{e}, nil, nil
}

// holdable reports whether the schema of the findings takes every match: it asks for a vulnerability, a package ID and
// a package name, and for a version, a fixed version and a CVSS vector that aren't empty where they are given. Grype
// gives each in practice, but what it gives follows its database and the SBOM, which an image's scan made, and evidence
// that a reader refuses is worse than a failure that says so.
func holdable(found evidence.Findings) bool {
	for _, m := range found.Matches {
		if m.VulnerabilityID == "" || m.PackageID == "" || m.PackageName == "" ||
			slices.Contains(m.FixedVersions, "") {
			return false
		}
		for _, score := range m.CVSS {
			if score.Version == "" || score.Vector == "" {
				return false
			}
		}
	}
	return true
}

// messageSize returns the size of the message that carries e to vexplain, an item of the answer of Invoke, once
// decompressed.
func messageSize(e cloudevents.Event) (int, error) {
	p, err := evidence.ToProto(e)
	if err != nil {
		return 0, err
	}
	return proto.Size(&collectorv1alpha1.InvokeResponse{Item: &collectorv1alpha1.InvokeResponse_Event{Event: p}}), nil
}

// ---- the places of the matches ----

// takeSlot waits until fewer than maxConcurrent matches hold a place, and takes one, until ctx ends. It returns the
// function that gives the place back.
func (m *Collector) takeSlot(ctx context.Context, maxConcurrent int) (func(), error) {
	for {
		m.slotsMu.Lock()
		if m.running < maxConcurrent {
			m.running++
			m.slotsMu.Unlock()
			var once sync.Once
			return func() { once.Do(m.giveSlotBack) }, nil
		}
		freed := m.freed
		m.slotsMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-freed:
		}
	}
}

// giveSlotBack frees a place, and tells the matches that wait.
func (m *Collector) giveSlotBack() {
	m.slotsMu.Lock()
	defer m.slotsMu.Unlock()
	m.running--
	close(m.freed)
	m.freed = make(chan struct{})
}
