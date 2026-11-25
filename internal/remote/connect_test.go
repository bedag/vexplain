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
	"crypto/x509"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/bedag/vexplain/internal/remote"
)

// TLS to a spoke is verified against the ca.crt of the admin's Secret, and nothing turns that off: a ca.crt of another
// authority fails the call with an x509 error, whatever else the Secret holds. A Secret without a certificate, or with
// a server that isn't https, gives no config at all, rather than one that trusts the system's roots or sends the token
// in the clear.
func TestTheSeamVerifiesTheSpokesCertificate(t *testing.T) {
	data := credentials(spoke.cfg.Host, hub.cfg.CAData, bootstrapToken(t))
	data["insecure-skip-tls-verify"] = []byte("true")
	obj := newSpoke(t, data)

	cfg, err := remote.Config(ctx, hub.client, namespace, obj)
	require.NoError(t, err)
	require.False(t, cfg.Insecure)
	_, err = clusterID(cfg)
	var unknown x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknown)

	for name, test := range map[string]struct {
		change  func(map[string][]byte)
		refusal string
	}{
		"no ca.crt": {func(d map[string][]byte) { delete(d, remote.CAKey) }, "no PEM certificate"},
		"a ca.crt that is no certificate": {func(d map[string][]byte) { d[remote.CAKey] = []byte("not a certificate") },
			"no PEM certificate"},
		"a server over http": {func(d map[string][]byte) {
			d[remote.ServerKey] = []byte(strings.Replace(spoke.cfg.Host, "https://", "http://", 1))
		}, "no https URL"},
		"a server with user information": {func(d map[string][]byte) {
			d[remote.ServerKey] = []byte(strings.Replace(spoke.cfg.Host, "https://", "https://admin:secret@", 1))
		}, "no https URL"},
	} {
		t.Run(name, func(t *testing.T) {
			data := spokeCredentials(t)
			test.change(data)
			_, err := remote.Config(ctx, hub.client, namespace, newSpoke(t, data))
			require.ErrorContains(t, err, test.refusal)
		})
	}
}

// An admin often writes the Secret from files, whose values end with a line break: the seam takes them as meant.
func TestTheSeamTakesValuesThatEndWithALineBreak(t *testing.T) {
	data := spokeCredentials(t)
	for _, key := range []string{remote.ServerKey, remote.TokenKey} {
		data[key] = append(data[key], '\n')
	}

	cfg, err := remote.Config(ctx, hub.client, namespace, newSpoke(t, data))
	require.NoError(t, err)
	id, err := clusterID(cfg)
	require.NoError(t, err)
	require.Equal(t, spokeID(t), id)
}

// The hub renews into a Secret of its own, so that a pipeline that applies the admin's Secret again, with the bootstrap
// token that has expired since, takes nothing from the hub: it connects with its own token while that is valid.
func TestTheHubKeepsItsOwnTokenWhenTheAdminsSecretIsAppliedAgain(t *testing.T) {
	obj := newSpoke(t, spokeCredentials(t))
	cfg, err := remote.Config(ctx, hub.client, namespace, obj)
	require.NoError(t, err)
	_, err = dueRenewer().Renew(ctx, obj, cfg)
	require.NoError(t, err)
	own := string(ownSecret(t, obj).Data[remote.TokenKey])

	admin := adminSecret(t, obj)
	admin.Data[remote.TokenKey] = []byte(expiredToken())
	require.NoError(t, hub.client.Update(ctx, admin))

	cfg, err = remote.Config(ctx, hub.client, namespace, obj)
	require.NoError(t, err)
	require.Equal(t, own, cfg.BearerToken)
	id, err := clusterID(cfg)
	require.NoError(t, err)
	require.Equal(t, spokeID(t), id)
}

// The hub's own token renews itself, so it goes to no server but the one that issued it. Once the admin's Secret names
// another server, whether by a mistake or by a pipeline that may write it, the hub sends the admin's token there, and
// an API server that moved needs a new bootstrap token.
func TestTheHubsOwnTokenGoesOnlyToTheServerItWasIssuedFor(t *testing.T) {
	obj := newSpoke(t, spokeCredentials(t))
	cfg, err := remote.Config(ctx, hub.client, namespace, obj)
	require.NoError(t, err)
	_, err = dueRenewer().Renew(ctx, obj, cfg)
	require.NoError(t, err)
	own := string(ownSecret(t, obj).Data[remote.TokenKey])

	// Only the server changes: spokes can share one CA, and the CA's check alone would not stop the token then. The test
	// connects nowhere, so the CA bundle may stay the spoke's.
	admin := adminSecret(t, obj)
	admin.Data[remote.ServerKey] = []byte(hub.cfg.Host)
	require.NoError(t, hub.client.Update(ctx, admin))

	cfg, err = remote.Config(ctx, hub.client, namespace, obj)
	require.NoError(t, err)
	require.Equal(t, hub.cfg.Host, cfg.Host)
	require.NotEqual(t, own, cfg.BearerToken, "the hub's own token went to another server")
	require.Equal(t, string(admin.Data[remote.TokenKey]), cfg.BearerToken)
}

// The hub's own token goes with no CA bundle but the one that it was issued with. Whoever can write the admin's Secret,
// and steer the server's traffic, could otherwise swap the CA and take the token. A CA that rotates needs a new
// bootstrap token.
func TestTheHubsOwnTokenGoesOnlyWithTheCAItWasIssuedWith(t *testing.T) {
	obj := newSpoke(t, spokeCredentials(t))
	cfg, err := remote.Config(ctx, hub.client, namespace, obj)
	require.NoError(t, err)
	_, err = dueRenewer().Renew(ctx, obj, cfg)
	require.NoError(t, err)
	own := string(ownSecret(t, obj).Data[remote.TokenKey])

	// A bundle that still verifies the spoke, with another authority's certificate beside its own.
	admin := adminSecret(t, obj)
	admin.Data[remote.CAKey] = append(append([]byte{}, spoke.cfg.CAData...), hub.cfg.CAData...)
	require.NoError(t, hub.client.Update(ctx, admin))

	cfg, err = remote.Config(ctx, hub.client, namespace, obj)
	require.NoError(t, err)
	require.NotEqual(t, own, cfg.BearerToken, "the hub's own token went with another CA bundle")
	require.Equal(t, string(admin.Data[remote.TokenKey]), cfg.BearerToken)

	// A Secret of the hub's that doesn't say which CA bundle its token was issued with is set aside too.
	admin = adminSecret(t, obj)
	admin.Data[remote.CAKey] = spoke.cfg.CAData
	require.NoError(t, hub.client.Update(ctx, admin))
	unrecorded := ownSecret(t, obj)
	delete(unrecorded.Data, remote.CAHashKey)
	require.NoError(t, hub.client.Update(ctx, unrecorded))
	cfg, err = remote.Config(ctx, hub.client, namespace, obj)
	require.NoError(t, err)
	require.Equal(t, string(admin.Data[remote.TokenKey]), cfg.BearerToken)
}

// The hub's own token gives way once it has expired, as after an outage of the hub that outlasted it: the hub then
// connects with the admin's token, which an admin put into the admin's Secret anew.
func TestAnExpiredOwnTokenGivesWayToTheAdmins(t *testing.T) {
	data := spokeCredentials(t)
	obj := newSpoke(t, data)
	own := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: remote.TokenSecretName(obj.Name)},
		Data: map[string][]byte{remote.TokenKey: []byte(expiredToken()),
			remote.ServerKey: []byte(spoke.cfg.Host), remote.CAHashKey: []byte(caHash(spoke.cfg.CAData))},
	}
	require.NoError(t, controllerutil.SetControllerReference(obj, own, hub.client.Scheme()))
	require.NoError(t, hub.client.Create(ctx, own))

	cfg, err := remote.Config(ctx, hub.client, namespace, obj)
	require.NoError(t, err)
	require.Equal(t, string(data[remote.TokenKey]), cfg.BearerToken)
}

// The hub writes its own Secret of a spoke and never the admin's, so the seam takes no other Secret for its own: not
// an admin's Secret that has its name, and not a Secret of that name that the Spoke doesn't own.
func TestTheSeamTakesNoOtherSecretForTheHubsOwn(t *testing.T) {
	obj := newSpoke(t, spokeCredentials(t))
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: remote.TokenSecretName(obj.Name)},
		Data:       map[string][]byte{remote.TokenKey: []byte(bootstrapToken(t))},
	}
	require.NoError(t, hub.client.Create(ctx, foreign))
	_, err := remote.Config(ctx, hub.client, namespace, obj)
	require.ErrorContains(t, err, "doesn't own it")

	obj.Spec.CredentialsSecretRef.Name = foreign.Name
	_, err = remote.Config(ctx, hub.client, namespace, obj)
	require.ErrorContains(t, err, "can't be the admin's")
}
