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

// Package collector holds what the operator knows about the health of its collectors.
//
// A collector is a source of data, such as the pods of the cluster. Until a collector runs from a
// package of its own, it runs inside the operator and reports the outcome of each run to a Registry,
// under the name of its Collector object. The Collector controller reads the Registry and turns the
// health into the status of the Collector object and into events.
package collector

import (
	"errors"
	"sync"
	"time"
)

// errNoError stands in for the error of a failure that was reported without one.
var errNoError = errors.New("the collector reported a failure without an error")

// health is what a collector last reported.
type health struct {
	// lastSuccess is when the collector last reported a success. It is the zero time if it never
	// has. A failure leaves it as it was.
	lastSuccess time.Time
	// lastErr is the error of the last report, or nil when that report was a success.
	lastErr error
}

// Registry holds the health of each collector, by the name of its Collector: the outcome of its last
// report. It reflects that report only, with no timer that makes old health stale. It doesn't check
// that a Collector of the name exists.
//
// It lives in memory, so a restart of the operator empties it, and the collectors report again as
// they run. Collectors report from their reconcilers while the Collector controller reads, so every
// method is safe for concurrent use.
type Registry struct {
	mu     sync.RWMutex
	health map[string]health
}

// NewRegistry returns a Registry in which no collector has reported yet.
func NewRegistry() *Registry {
	return &Registry{health: make(map[string]health)}
}

// ReportSuccess records that the last run of the collector named name succeeded, just now.
func (r *Registry) ReportSuccess(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.health[name] = health{lastSuccess: time.Now()}
}

// ReportFailure records that the last run of the collector named name failed with err. The time of
// the last success stays. A nil err still counts as a failure, so that a failure never reads as
// healthy.
func (r *Registry) ReportFailure(name string, err error) {
	if err == nil {
		err = errNoError
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	reported := r.health[name]
	reported.lastErr = err
	r.health[name] = reported
}

// Health returns what the collector named name last reported: when it last succeeded, which is the
// zero time if it never has since the operator started, and the error of its last run, which is
// nil if that run succeeded. known is false if the collector has not reported at all.
func (r *Registry) Health(name string) (lastSuccess time.Time, lastErr error, known bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reported, known := r.health[name]
	return reported.lastSuccess, reported.lastErr, known
}
