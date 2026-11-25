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

package remote_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/bedag/vexplain/internal/remote"
	"github.com/bedag/vexplain/internal/testenv"
)

// A renewed token goes into the hub's own Secret of the spoke, labelled with the Spoke's name and owned by the Spoke,
// so that it goes with the Spoke, and the admin's Secret stays as the admin wrote it. The spoke's TokenRequest API
// gives the new token, which works on the spoke and renews itself in turn.
func TestTheRenewedTokenGoesIntoTheHubsOwnSecret(t *testing.T) {
	obj := newSpoke(t, spokeCredentials(t))
	admin := adminSecret(t, obj)

	renewer := dueRenewer()
	// The first renewal creates the hub's Secret, and the second, with the first's token, updates it.
	for range 2 {
		cfg, err := remote.Config(ctx, hub.client, namespace, obj)
		require.NoError(t, err)
		expires, err := renewer.Renew(ctx, obj, cfg)
		require.NoError(t, err)
		require.WithinDuration(t, time.Now().Add(time.Hour), expires, time.Minute)

		own := ownSecret(t, obj)
		require.Equal(t, spoke.cfg.Host, string(own.Data[remote.ServerKey]), "the server that issued the token")
		require.Equal(t, caHash(spoke.cfg.CAData), string(own.Data[remote.CAHashKey]), "the CA bundle it was issued with")
		require.Equal(t, obj.Name, own.Labels[remote.SpokeLabel])
		require.True(t, metav1.IsControlledBy(own, obj), "the Spoke owns the hub's Secret")
		require.NotEqual(t, cfg.BearerToken, string(own.Data[remote.TokenKey]), "a new token")
	}

	require.Equal(t, admin.ResourceVersion, adminSecret(t, obj).ResourceVersion, "the admin's Secret is never written")
	cfg, err := remote.Config(ctx, hub.client, namespace, obj)
	require.NoError(t, err)
	id, err := clusterID(cfg)
	require.NoError(t, err)
	require.Equal(t, spokeID(t), id)
}

// The hub renews a token once it has lived half its lifetime, by its claims, and not before. It asks for a token of the
// lifetime that the hub sets, of the ServiceAccount that the token names.
func TestTheTokenIsRenewedAtHalfItsLifetime(t *testing.T) {
	// The test hands Renew the config itself, so the admin's Secret plays no part.
	obj := newSpoke(t, nil)
	issued := time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC)
	cfg := &rest.Config{BearerToken: testenv.UnsignedToken(namespace, testenv.HubAccount, issued, issued.Add(2*time.Hour))}
	now := issued
	var asked []string
	renewer := &remote.Renewer{Client: hub.client, Namespace: namespace, Lifetime: 24 * time.Hour,
		Now: func() time.Time { return now },
		Request: func(_ context.Context, got *rest.Config, ns, account string, seconds int64) (string, time.Time, error) {
			require.Same(t, cfg, got, "the request goes through the seam's config")
			asked = append(asked, fmt.Sprintf("%s/%s for %ds", ns, account, seconds))
			return "token-b", now.Add(24 * time.Hour), nil
		}}

	now = issued.Add(time.Hour - time.Second)
	expires, err := renewer.Renew(ctx, obj, cfg)
	require.NoError(t, err)
	require.WithinDuration(t, issued.Add(2*time.Hour), expires, 0, "the token in use")
	require.Empty(t, asked)
	err = hub.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: remote.TokenSecretName(obj.Name)},
		&corev1.Secret{})
	require.True(t, apierrors.IsNotFound(err), "no Secret of the hub's yet: %v", err)

	now = issued.Add(time.Hour)
	expires, err = renewer.Renew(ctx, obj, cfg)
	require.NoError(t, err)
	require.WithinDuration(t, now.Add(24*time.Hour), expires, 0, "the new token")
	require.Equal(t, []string{"vexplain-system/vexplain-hub for 86400s"}, asked)
	require.Equal(t, "token-b", string(ownSecret(t, obj).Data[remote.TokenKey]))
}

// A token from a Secret of type kubernetes.io/service-account-token, as Kubernetes made them before bound tokens,
// names its ServiceAccount in its subject and in flat claims only, and says no expiry. The hub renews it at once, for
// the account of its subject.
func TestALegacyTokenIsRenewedForTheAccountOfItsSubject(t *testing.T) {
	obj := newSpoke(t, nil)
	encode := func(v any) string {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	legacy := encode(map[string]string{"alg": "RS256"}) + "." + encode(map[string]string{
		"iss":                                    "kubernetes/serviceaccount",
		"kubernetes.io/serviceaccount/namespace": namespace,
		"kubernetes.io/serviceaccount/service-account.name": testenv.HubAccount,
		"sub": "system:serviceaccount:" + namespace + ":" + testenv.HubAccount,
	}) + ".unsigned"
	var asked []string
	renewer := &remote.Renewer{Client: hub.client, Namespace: namespace, Lifetime: time.Hour,
		Request: func(_ context.Context, _ *rest.Config, ns, account string, _ int64) (string, time.Time, error) {
			asked = append(asked, ns+"/"+account)
			return "token-b", time.Now().Add(time.Hour), nil
		}}

	_, err := renewer.Renew(ctx, obj, &rest.Config{BearerToken: legacy})
	require.NoError(t, err)
	require.Equal(t, []string{namespace + "/" + testenv.HubAccount}, asked)
}

// The hub learns from a token which ServiceAccount to renew, so a token that names none, or whose claims can't be
// read, is refused, and the spoke is asked nothing.
func TestATokenThatNamesNoServiceAccountIsNotRenewed(t *testing.T) {
	obj := newSpoke(t, nil)
	renewer := &remote.Renewer{Client: hub.client, Namespace: namespace, Lifetime: time.Hour,
		Request: func(context.Context, *rest.Config, string, string, int64) (string, time.Time, error) {
			t.Fatal("the spoke was asked for a token")
			return "", time.Time{}, nil
		}}
	for _, token := range []string{
		testenv.UnsignedToken("", "", time.Now().Add(-time.Hour), time.Now()),
		"an-opaque-token",
	} {
		_, err := renewer.Renew(ctx, obj, &rest.Config{BearerToken: token})
		require.ErrorIs(t, err, remote.ErrNotRenewable)
		require.NotContains(t, err.Error(), token, "the error holds no token")
	}
}
