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

package collector

import (
	"context"
	"net"
	"time"
)

// ReloadInterval is how often Serve checks its TLS files.
const ReloadInterval = reloadInterval

// ServeOn is Serve on listeners that a test opened, which checks the TLS files every reload instead
// of every ReloadInterval, so that a test of a change doesn't wait for seconds.
func ServeOn(ctx context.Context, c Collector, opts Options, grpcListener, healthListener net.Listener,
	reload time.Duration) error {
	s, err := newServer(c, opts, reload)
	if err != nil {
		return err
	}
	return s.run(ctx, grpcListener, healthListener)
}
