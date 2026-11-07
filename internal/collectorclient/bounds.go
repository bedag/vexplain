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

import (
	"sync"
	"time"

	"github.com/bedag/vexplain/internal/metrics"
)

// What a collector sends is bounded (design 5.9), so that a collector that misbehaves can neither exhaust the
// operator's memory nor hold it forever. A collector past a bound breaks the API's contract: its stream or its call
// ends, the log names the collector and the bound, and the metric vexplain_collector_contract_breaks_total counts it.
const (
	// maxSnapshotTime is how long a snapshot may take, from its SnapshotStart to its SnapshotEnd: the contract's
	// minute. maxSnapshotBytes is the most that the messages of a snapshot may hold together, 64 MiB: the streams
	// hold the whole snapshot until its end.
	maxSnapshotTime  = time.Minute
	maxSnapshotBytes = 64 << 20
	// settledAfter is how long a stream must stay open past its snapshot before the wait before its next opening
	// starts again from a second. A stream that ends sooner, even without an error, waits as one that fails, so that
	// a collector whose Watch returns after its snapshot isn't watched again every second, with a whole snapshot.
	settledAfter = time.Minute
	// maxAnswerEvents is the most events of an answer to Invoke. maxAnswerBytes is the most that the messages of an
	// answer may hold together, 128 MiB: the scanner's answer about an image of 8 platforms holds the evidence of a
	// manifest in each of 8 messages of up to 16 MiB.
	maxAnswerEvents = 64
	maxAnswerBytes  = 128 << 20
)

// The bounds, as the log and the metric name them.
const (
	// BoundSnapshotTime is a snapshot that didn't end within a minute of its start, and BoundSnapshotSize one whose
	// messages held more than 64 MiB.
	BoundSnapshotTime = "snapshot_time"
	BoundSnapshotSize = "snapshot_size"
	// BoundAnswerEvents is an answer to Invoke with more events than the call takes, and BoundAnswerSize one whose
	// messages held more than 128 MiB.
	BoundAnswerEvents = "answer_events"
	BoundAnswerSize   = "answer_size"
	// BoundDeadline is an evidence request that the collector didn't answer within its deadline.
	BoundDeadline = "deadline"
)

// CountBreak counts a stream or a call of the collector that ended because the collector passed the bound, in the
// cluster, whose name the context of the call holds.
func CountBreak(cluster, collector, bound string) {
	metrics.CollectorContractBreaksTotal.WithLabelValues(cluster, collector, bound).Inc()
}

// boundError is how a collector passed a bound. Its text is fixed: it repeats nothing that the collector sent.
type boundError struct {
	bound, why string
}

func (e boundError) Error() string { return e.why }

// snapshotClock ends a Watch whose snapshot doesn't end in time: started at its SnapshotStart, it calls expire once
// the time has passed, unless the SnapshotEnd came first. It tells the two apart under its lock, so that a snapshot
// either reaches the sink or ends the stream, and never both.
type snapshotClock struct {
	mu      sync.Mutex
	timer   *time.Timer
	ended   bool
	expired bool
}

// start starts the clock, which calls expire after the time.
func (c *snapshotClock) start(after time.Duration, expire func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timer = time.AfterFunc(after, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.ended {
			c.expired = true
			expire()
		}
	})
}

// end reports whether the snapshot ended in time, and stops the clock when it did.
func (c *snapshotClock) end() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.expired {
		return false
	}
	c.ended = true
	if c.timer != nil {
		c.timer.Stop()
	}
	return true
}

// stop stops the clock, as when the stream ends.
func (c *snapshotClock) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
	}
}
