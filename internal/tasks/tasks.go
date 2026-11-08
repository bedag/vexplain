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
// spoke reports what it found only through the evidence and inventory stores.
//
// The hub asks a spoke for a type of evidence about a subject, from the collectors that it names: the
// producers of the type whose evidence it misses (decision 0043). The spoke asks only them, so that a
// producer whose evidence is current isn't asked again, and each producer's failures stay its own.
//
// Hub and spoke both import this package, so it holds nothing but the request and the interface that
// carries it.
package tasks

import "context"

// Request asks a spoke for evidence of one type about one image.
type Request struct {
	// Type is the type of the evidence asked for, such as
	// ch.bedag.vexplain.scanner.image-contents.v1alpha1. Subject is the image that it is about:
	// image/ and a repository digest, "sha256:" followed by 64 lowercase hex digits.
	Type, Subject string
	// Repositories are where the digest was pulled from, as the presence entries of its ImageInventory
	// say. A collector that pulls the image pulls it from one of them.
	Repositories []string
	// Collectors are the Collectors to ask, by name: the producers of the type whose evidence about the
	// image the hub misses or holds stale. A spoke asks only them, and of them only those that can be
	// used and have an operation that produces the type, so that a producer whose evidence is current
	// isn't asked to deliver it again. A request names at least one.
	Collectors []string
}

// Executor is how the hub asks a spoke for evidence. Request returns at once; the evidence arrives
// through the stores. Asking again for evidence that is being collected changes nothing.
type Executor interface {
	Request(ctx context.Context, r Request) error
}
