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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	inventoryv1alpha1 "github.com/bedag/vexplain/api/inventory/v1alpha1"
	"github.com/bedag/vexplain/internal/inventory"
)

// These tests cover the LedgerStore: one Ledger per case, named as its Assessment, written once at the end of the case.

// ledgerName is the name of the case of the tests' ledgers.
const ledgerName = "cve-2026-0001-0123456789abcdef"

// aLedger returns the ledger of the case with n entries.
func aLedger(n int) *inventoryv1alpha1.Ledger {
	l := &inventoryv1alpha1.Ledger{ObjectMeta: metav1.ObjectMeta{Name: ledgerName,
		Labels: map[string]string{"vexplain.bedag.ch/vulnerability": "CVE-2026-0001"}}}
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("ev-%d", i)
		l.Spec.Entries = append(l.Spec.Entries, inventoryv1alpha1.LedgerEntry{
			ID: id, Tool: "search_evidence", Arguments: ptr.To(`{"name":"sbom","query":"libexample"}`),
			DurationMilliseconds: ptr.To(int64(3)), Trust: inventoryv1alpha1.LedgerTrustKnown,
			OutputRef: inventoryv1alpha1.LedgerOutputReference{Subject: "assessment/" + ledgerName,
				Type: "ch.bedag.vexplain.agent.tool-output.v1alpha1", Source: id},
			OutputBytes: ptr.To(int64(40)), ShownBytes: ptr.To(int64(40)),
			OutputSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Preview:      ptr.To(`packages[0].name = "libexample1"`),
		})
	}
	return l
}

func TestALedgerIsWrittenReadAndDeleted(t *testing.T) {
	ctx := t.Context()
	store := inventory.NewCRDLedgerStore(newClient(t, interceptor.Funcs{}))

	got, err := store.Get(ctx, ledgerName)
	require.NoError(t, err)
	require.Nil(t, got, "no ledger yet")

	first := aLedger(1)
	require.NoError(t, store.Put(ctx, first))
	got, err = store.Get(ctx, ledgerName)
	require.NoError(t, err)
	require.Equal(t, first.Spec, got.Spec)
	require.Equal(t, first.Labels, got.Labels)

	// A case that is judged again writes its new ledger over the old one.
	again := aLedger(2)
	require.NoError(t, store.Put(ctx, again))
	got, err = store.Get(ctx, ledgerName)
	require.NoError(t, err)
	require.Equal(t, again.Spec, got.Spec)

	require.NoError(t, store.Delete(ctx, ledgerName))
	got, err = store.Get(ctx, ledgerName)
	require.NoError(t, err)
	require.Nil(t, got)
	require.NoError(t, store.Delete(ctx, ledgerName), "a ledger that is gone")
}

// A read that fails is never mistaken for a ledger that doesn't exist.
func TestAFailedReadOfALedgerIsAnError(t *testing.T) {
	failure := errors.New("the API server is away")
	store := inventory.NewCRDLedgerStore(newClient(t, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return failure
		},
	}))

	got, err := store.Get(t.Context(), ledgerName)
	require.ErrorIs(t, err, failure)
	require.Nil(t, got)
	require.ErrorIs(t, store.Put(t.Context(), aLedger(1)), failure)
}
