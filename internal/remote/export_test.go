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

package remote

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"
	toolscache "k8s.io/client-go/tools/cache"
)

// WithheldAnswers returns lw as a cache of a spoke lists and watches through it.
func WithheldAnswers(lw toolscache.ListerWatcherWithContext) toolscache.ListerWatcherWithContext {
	return withheldAnswers{lw}
}

// CheckCore checks the event as the copier checks a copy before it puts it.
func CheckCore(e cloudevents.Event) error { return checkCore(e) }

// RefuseEntry refuses the entry of the image of the digest, as the copier refuses one that isn't the spoke's.
func RefuseEntry(c *Copier, reason, digest string) { c.refuseEntry(reason, digest) }

// NormalServer returns the URL of an API server as the pin of the hub's own token compares it.
func NormalServer(server string) string { return normalServer(server) }
