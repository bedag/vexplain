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

package scan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bedag/vexplain/sdk/collector"
)

// slotLabels returns the labels of the scan Jobs of the scanner's Collector, which hold its slots: the label of
// vexplain's own pods, which the context c names, as a scan's, and the name of the Collector.
func (s *Scanner) slotLabels(c collector.Context) map[string]string {
	return map[string]string{ownPodLabel(c): scanTask, scannerLabel: s.opts.Name}
}

// takeSlot waits until fewer scan Jobs than maxScans hold a slot, and takes one, until ctx ends. A slot is held by a
// Job that the API server has with the labels, those of slotLabels, and that hasn't finished, and by a scan of this
// process, from before it reads anything of the cluster until its Job is gone: of the two counts, the larger counts,
// since the Jobs of this process's scans are among the first once they are created. A scan of this process that ends
// frees its slot at once; a Job of another process, such as one that a restart left, is counted again every SlotWait.
// It returns the function that gives the slot back.
func (s *Scanner) takeSlot(ctx context.Context, maxScans int32, labels map[string]string) (func(), error) {
	for {
		s.mu.Lock()
		active, err := s.opts.Runner.Active(ctx, labels)
		if err != nil {
			s.mu.Unlock()
			return nil, fmt.Errorf("count the scan Jobs: %w", err)
		}
		if max(active, s.running) < int(maxScans) {
			s.running++
			s.mu.Unlock()
			var once sync.Once
			return func() { once.Do(s.giveSlotBack) }, nil
		}
		freed := s.freed
		s.mu.Unlock()
		timer := time.NewTimer(s.opts.SlotWait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-freed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// giveSlotBack frees the slot of a scan of this process, and tells the scans that wait.
func (s *Scanner) giveSlotBack() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running--
	close(s.freed)
	s.freed = make(chan struct{})
}
