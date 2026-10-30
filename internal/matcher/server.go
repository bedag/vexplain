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

// Package matcher is the server of the matcher: the hub's one vulnerability database, behind a
// small HTTP API (decision 0022). It runs the Grype CLI, which holds the database, for each SBOM
// that the hub sends, and answers with the matches. The matcher's binary is cmd/matcher.
//
// The package belongs to that binary. The manager imports only internal/matchapi, which has the
// wire format and the client.
//
// The SBOM, and everything Grype writes about it, can hold text from an image that anyone may have
// built. So no response and no error carries Grype's stderr, a piece of the SBOM, or the text of an
// error: they are fixed texts. Grype's stderr is logged at debug level, and goes no further.
package matcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"

	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/bedag/vexplain/internal/matchapi"
)

const (
	// retryAfter is what a 503 tells the client to wait, in seconds: the time of the matcher's
	// readiness probe, and of a short match.
	retryAfter = "30"

	// The texts of the error responses. They are fixed, and say nothing of the request.
	textNotReady    = "the matcher has no database yet"
	textBusy        = "the matcher is busy"
	textBadRequest  = "the request is not a JSON object with an SBOM object"
	textTooLarge    = "the request is too large"
	textMatchFailed = "the match failed"
)

// Server answers the matcher's API with Grype. Make one with NewServer, and call Load, or Update,
// until the server has a database: before that it answers 503.
type Server struct {
	grype Grype

	// mu keeps matches and updates apart. Matches share it, and an update holds it alone, because
	// an update replaces the database's files under a match that reads them (R37). The database
	// that db names is replaced under the same lock, so a match always names the version it ran on.
	mu sync.RWMutex
	// db is the database in use, or nil while there is none. It is read without mu, so that
	// /readyz and /v1/database answer during an update, which can take minutes: a probe that waited
	// for it would take the matcher out of its Service. Once set, it is never cleared: a failed
	// update keeps the old database, and the server stays ready.
	db atomic.Pointer[matchapi.Database]

	// slots has a place for each match that may run at once. A request holds one while it is
	// matched, and waits for one when they are all taken.
	slots chan struct{}
	// maxBody is the most that a request may hold. It is a field for the tests.
	maxBody int64

	mux *http.ServeMux
}

// NewServer returns a server that runs at most maxConcurrent matches at once, at least one.
func NewServer(g Grype, maxConcurrent int) *Server {
	s := &Server{
		grype:   g,
		slots:   make(chan struct{}, max(maxConcurrent, 1)),
		maxBody: matchapi.MaxRequestBytes,
		mux:     http.NewServeMux(),
	}
	// A method in a pattern makes the mux answer another one with 405.
	s.mux.HandleFunc("POST "+matchapi.PathMatch, s.handleMatch)
	s.mux.HandleFunc("GET "+matchapi.PathDatabase, s.handleDatabase)
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleReady)
	return s
}

// Handler returns the API: /v1/match and /v1/database, and /healthz and /readyz for the kubelet.
func (s *Server) Handler() http.Handler { return s.mux }

// Load asks Grype for the status of the database that is in its directory. When the status is
// valid, the server is ready, with that database. An error leaves the server as it was.
func (s *Server) Load(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.grype.Status(ctx)
	if err != nil {
		return err
	}
	s.db.Store(&db)
	logf.FromContext(ctx).Info("Loaded the vulnerability database", "version", db.Version, "built", db.Built)
	return nil
}

// Update updates the database. It waits for the matches that run, and holds them back until it is
// done. A failed update keeps the database that was in use, and so does one whose status can't be
// read afterwards: the version then stays the old one, which is never newer than the files.
func (s *Server) Update(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.grype.Update(ctx); err != nil {
		return err
	}
	db, err := s.grype.Status(ctx)
	if err != nil {
		return fmt.Errorf("reading the status after the update: %w", err)
	}
	old := s.db.Swap(&db)
	log := logf.FromContext(ctx)
	if old != nil && old.Version == db.Version {
		log.Info("The vulnerability database is up to date", "version", db.Version)
	} else {
		log.Info("Updated the vulnerability database", "version", db.Version, "built", db.Built)
	}
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "ok\n")
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if s.db.Load() == nil {
		unavailable(w, textNotReady)
		return
	}
	_, _ = io.WriteString(w, "ok\n")
}

func (s *Server) handleDatabase(w http.ResponseWriter, r *http.Request) {
	db := s.db.Load()
	if db == nil {
		unavailable(w, textNotReady)
		return
	}
	writeJSON(r.Context(), w, db)
}

func (s *Server) handleMatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.db.Load() == nil {
		unavailable(w, textNotReady)
		return
	}
	// The body is read before a slot is taken. A client that has gone is noticed once its body
	// is read, so a request that waits for a slot is dropped when its client gives up, and not
	// matched for nobody.
	sbom, ok := s.readSBOM(w, r)
	if !ok {
		return
	}

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		unavailable(w, textBusy)
		return
	}

	path, err := writeSBOM(sbom)
	if err != nil {
		logf.FromContext(ctx).Error(err, "Could not write the SBOM to a file")
		http.Error(w, textMatchFailed, http.StatusInternalServerError)
		return
	}
	defer func() { _ = os.Remove(path) }()

	resp, err := s.match(ctx, path)
	if err != nil {
		// The error's text is fixed, so it may be logged.
		logf.FromContext(ctx).Error(err, "Could not match an SBOM")
		http.Error(w, textMatchFailed, http.StatusInternalServerError)
		return
	}
	writeJSON(ctx, w, resp)
}

// match runs Grype on the SBOM file while it holds the database for reading.
func (s *Server) match(ctx context.Context, sbomPath string) (matchapi.MatchResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// The database is never cleared once there is one, and the handler has checked that there is.
	version := s.db.Load().Version
	matches, err := s.grype.Match(ctx, sbomPath)
	if err != nil {
		return matchapi.MatchResponse{}, err
	}
	if matches == nil {
		// No matches is an empty list in the response, and never a missing one.
		matches = []matchapi.Match{}
	}
	return matchapi.MatchResponse{DatabaseVersion: version, Matches: matches}, nil
}

// readSBOM reads the SBOM from the request. When the request is refused, it has answered, and
// ok is false: 413 for a request over the cap, and 400 for one that is not JSON, or whose "sbom" is
// missing or not an object.
func (s *Server) readSBOM(w http.ResponseWriter, r *http.Request) (sbom json.RawMessage, ok bool) {
	if r.ContentLength > s.maxBody {
		http.Error(w, textTooLarge, http.StatusRequestEntityTooLarge)
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBody))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		http.Error(w, textTooLarge, http.StatusRequestEntityTooLarge)
		return nil, false
	case err != nil:
		http.Error(w, textBadRequest, http.StatusBadRequest)
		return nil, false
	}

	var req matchapi.MatchRequest
	if json.Unmarshal(body, &req) != nil || !isObject(req.SBOM) {
		http.Error(w, textBadRequest, http.StatusBadRequest)
		return nil, false
	}
	return req.SBOM, true
}

// isObject reports whether a JSON value is an object. It is JSON already, so its first byte tells.
func isObject(value json.RawMessage) bool {
	value = bytes.TrimLeft(value, " \t\r\n")
	return len(value) > 0 && value[0] == '{'
}

// writeSBOM writes the SBOM to a file of its own under os.TempDir() (R3), and returns its path.
// The Deployment mounts a volume there, because the root filesystem is read-only.
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

// unavailable answers 503, and says when to try again.
func unavailable(w http.ResponseWriter, text string) {
	w.Header().Set("Retry-After", retryAfter)
	http.Error(w, text, http.StatusServiceUnavailable)
}

func writeJSON(ctx context.Context, w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The client went away, or took too long to read.
		logf.FromContext(ctx).V(1).Info("Could not write a response", "error", err.Error())
	}
}
