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

// Package tasks is how the hub asks a spoke for work (decision 0021). The hub decides what needs
// doing, and a spoke does it with its own hands: the hub never reaches into a spoke's code, and a
// spoke reports what it found only through the inventory stores.
//
// Hub and spoke both import this package, so it holds nothing but the requests and the interface
// that carries them.
package tasks

import "context"

// ScanRequest asks a spoke to scan the image of one digest.
type ScanRequest struct {
	// Digest is a repository digest: "sha256:" followed by 64 lowercase hex digits.
	Digest string
	// Repositories are where the digest was pulled from, as the presence entries of its
	// ImageInventory say. The spoke pulls the image from one of them.
	Repositories []string
}

// Executor is how the hub asks a spoke for work. RequestScan returns at once; the result arrives
// through the stores. Asking again for a digest that is being scanned changes nothing.
type Executor interface {
	RequestScan(ctx context.Context, req ScanRequest) error
}
