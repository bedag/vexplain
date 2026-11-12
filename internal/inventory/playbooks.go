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

package inventory

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// Playbooks reads the Playbooks, which the hub's admins write. A spoke reads them only through it, as it reads the
// sheets only through a VerdictsStore (decision 0021).
type Playbooks interface {
	// List returns every Playbook, the oldest first: by the time of its creation, and by its name for two of one
	// second, an order that every replica sees alike.
	List(ctx context.Context) ([]configv1alpha1.Playbook, error)
}

// cachedPlaybooks reads the Playbooks through a client that reads them from the manager's cache.
type cachedPlaybooks struct {
	reader client.Reader
}

// The Playbooks are listed from the manager's cache, whose informer lists and watches them.
// +kubebuilder:rbac:groups=config.vexplain.bedag.ch,resources=playbooks,verbs=list;watch

// NewPlaybooks returns Playbooks that reads them through reader: the manager's client, which reads the Playbooks
// from its cache. A Playbook is small, and the hub's controllers watch them all already.
func NewPlaybooks(reader client.Reader) Playbooks {
	return cachedPlaybooks{reader: reader}
}

func (p cachedPlaybooks) List(ctx context.Context) ([]configv1alpha1.Playbook, error) {
	var list configv1alpha1.PlaybookList
	if err := p.reader.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list the Playbooks: %w", err)
	}
	slices.SortFunc(list.Items, func(a, b configv1alpha1.Playbook) int {
		return cmp.Or(a.CreationTimestamp.Compare(b.CreationTimestamp.Time), strings.Compare(a.Name, b.Name))
	})
	return list.Items, nil
}
