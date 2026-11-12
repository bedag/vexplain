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

package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// The Playbooks come oldest first, and two of one second by their names, so that every replica orders them alike.
func TestPlaybooksListsTheOldestFirst(t *testing.T) {
	c := newClient(t, interceptor.Funcs{})
	first := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	for name, created := range map[string]time.Time{
		"b-newest": first.Add(time.Hour), "c-oldest": first, "a-second": first.Add(time.Minute), "b-second": first.Add(time.Minute),
	} {
		require.NoError(t, c.Create(t.Context(), &configv1alpha1.Playbook{
			ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: metav1.NewTime(created)},
		}))
	}

	got, err := inventory.NewPlaybooks(c).List(t.Context())

	require.NoError(t, err)
	names := make([]string, 0, len(got))
	for _, playbook := range got {
		names = append(names, playbook.Name)
	}
	require.Equal(t, []string{"c-oldest", "a-second", "b-second", "b-newest"}, names)
}

func TestPlaybooksReturnsAFailedList(t *testing.T) {
	errList := errors.New("list failed")
	c := newClient(t, interceptor.Funcs{List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
		return errList
	}})

	_, err := inventory.NewPlaybooks(c).List(t.Context())

	require.ErrorIs(t, err, errList, "a failed list is never one without playbooks")
}
