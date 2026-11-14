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

package collectorclient

import "time"

// The bounds of the wait before a broken stream opens again.
const (
	FirstRetry = firstRetry
	MaxRetry   = maxRetry
)

// NextRetry is how long a stream waits after its next break, when it waited d after the last.
func NextRetry(d time.Duration) time.Duration { return nextRetry(d) }

// SetResync sets how often s reads the Collectors and the context again, before Start. The tests
// shorten it, so that a change is followed within a moment.
func (s *Streams) SetResync(d time.Duration) { s.resync = d }

// SetBounds sets the bounds of the snapshots of s, before Start: how long a snapshot may take, and how much it may
// hold, and how long a stream must stay open past its snapshot for its waits to start again from a second. The tests
// shorten them.
func (s *Streams) SetBounds(snapshotTime time.Duration, snapshotBytes int, settledAfter time.Duration) {
	s.bounds = streamBounds{snapshotTime: snapshotTime, snapshotBytes: snapshotBytes, settledAfter: settledAfter}
}

// The bounds of what a collector sends.
const (
	MaxSnapshotTime  = maxSnapshotTime
	MaxSnapshotBytes = maxSnapshotBytes
	SettledAfter     = settledAfter
	MaxAnswerEvents  = maxAnswerEvents
	MaxAnswerBytes   = maxAnswerBytes
)

// SetAnswerBounds sets how many events, and how many bytes of messages, an answer to Invoke through p may hold,
// before its first call. The tests lower them.
func (p *Pool) SetAnswerBounds(events, bytes int) {
	p.answerEvents, p.answerBytes = events, bytes
}

// Connected says whether p holds a connection to the collector.
func (p *Pool) Connected(collector string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.conns[collector]
	return ok
}

// FireTimeout is how long a Fire may take.
const FireTimeout = fireTimeout
