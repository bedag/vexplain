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

package exposure

import (
	"context"

	"k8s.io/utils/clock"
)

// Resync is how often the running asker makes a pass when nothing wakes it sooner.
const Resync = resync

// FirstList lists the store's subjects once, as the manager runs it once its caches have synced.
func (v *View) FirstList(ctx context.Context) error { return v.firstList(ctx) }

// Changed is what wakes the asker when the view changes.
func (v *View) Changed() <-chan struct{} { return v.changed }

// UseClock makes the asker tell the time by c.
func (a *Asker) UseClock(c clock.Clock) { a.clock = c }

// Pass makes one pass of the asker, as the running asker makes one each time it wakes.
func (a *Asker) Pass(ctx context.Context) { a.pass(ctx) }
