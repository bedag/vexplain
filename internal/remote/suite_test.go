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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/remote"
	"github.com/bedag/vexplain/internal/settings"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/testenv"
)

// These tests run two API servers of envtest as two clusters: the hub, which holds the Spokes and their Secrets, and
// the spoke, which the hub reaches with a token of the ServiceAccount that the spoke's install creates for it.
// TestMain starts both, and stops them.

// namespace is the operator's namespace, on the hub and on the spoke.
const namespace = "vexplain-system"

// cluster is one of the two API servers, with a client of its admin.
type cluster struct {
	env    *envtest.Environment
	cfg    *rest.Config
	client client.Client
}

var (
	ctx        = context.Background()
	hub, spoke cluster
	// spokes numbers the Spokes that the tests create.
	spokes atomic.Int64
)

func TestMain(m *testing.M) {
	code := 1
	if err := start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	} else {
		code = m.Run()
	}
	for _, c := range []*cluster{&hub, &spoke} {
		if c.env == nil {
			continue
		}
		if err := c.env.Stop(); err != nil {
			fmt.Fprintln(os.Stderr, "stopping an API server:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// start starts the hub and the spoke, each with the operator's namespace, and creates the hub's ServiceAccount on the
// spoke.
func start() error {
	scheme := runtime.NewScheme()
	if err := setup.AddToScheme(scheme); err != nil {
		return err
	}
	for _, c := range []*cluster{&hub, &spoke} {
		env := &envtest.Environment{
			CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
			ErrorIfCRDPathMissing: true,
			BinaryAssetsDirectory: assetsDirectory(),
		}
		cfg, err := env.Start()
		if err != nil {
			return fmt.Errorf("start an API server: KUBEBUILDER_ASSETS names its binaries, which `make setup-envtest` "+
				"fetches: %w", err)
		}
		c.env, c.cfg = env, cfg
		if c.client, err = client.New(cfg, client.Options{Scheme: scheme}); err != nil {
			return err
		}
		if err := c.client.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
			return err
		}
	}
	return testenv.GrantHub(ctx, spoke.client, namespace)
}

// assetsDirectory is where the binaries of the API server are when KUBEBUILDER_ASSETS, which `make test` sets, is
// not: the repository's bin/k8s, which `make setup-envtest` fills.
func assetsDirectory() string {
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		return ""
	}
	root := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(root, entry.Name())
		}
	}
	return ""
}

// newSpoke creates the admin's Secret with data, and a Spoke that names it, and returns the Spoke. Both go when the
// test ends, with the hub's own Secret of the spoke.
func newSpoke(t *testing.T, data map[string][]byte) *configv1alpha1.Spoke {
	t.Helper()
	name := fmt.Sprintf("cluster-%d", spokes.Add(1))
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name + "-credentials"}, Data: data}
	require.NoError(t, hub.client.Create(ctx, secret))
	obj := &configv1alpha1.Spoke{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       configv1alpha1.SpokeSpec{CredentialsSecretRef: configv1alpha1.SecretReference{Name: secret.Name}},
	}
	require.NoError(t, hub.client.Create(ctx, obj))
	t.Cleanup(func() {
		own := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: remote.TokenSecretName(name)}}
		for _, o := range []client.Object{obj, secret, own} {
			require.NoError(t, client.IgnoreNotFound(hub.client.Delete(ctx, o)))
		}
	})
	return obj
}

// credentials is what an admin puts into the admin's Secret of a spoke.
func credentials(server string, ca []byte, token string) map[string][]byte {
	return map[string][]byte{remote.ServerKey: []byte(server), remote.CAKey: ca, remote.TokenKey: []byte(token)}
}

// spokeCredentials are the credentials of the spoke, with a bootstrap token of the hub's ServiceAccount.
func spokeCredentials(t *testing.T) map[string][]byte {
	t.Helper()
	return credentials(spoke.cfg.Host, spoke.cfg.CAData, bootstrapToken(t))
}

// bootstrapToken returns a token of the hub's ServiceAccount on the spoke that lives 10 minutes, the least that
// TokenRequest gives, as an admin creates the first one.
func bootstrapToken(t *testing.T) string {
	t.Helper()
	token, err := testenv.Token(ctx, spoke.client, namespace, testenv.HubAccount, 600)
	require.NoError(t, err)
	return token
}

// expiredToken returns a token of the hub's ServiceAccount that expired an hour ago.
func expiredToken() string {
	return testenv.UnsignedToken(namespace, testenv.HubAccount, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
}

// dueRenewer renews through the spoke's TokenRequest API, with tokens of an hour, on a clock an hour ahead, at which
// every token of an hour or less is due.
func dueRenewer() *remote.Renewer {
	return &remote.Renewer{Client: hub.client, Namespace: namespace, Lifetime: time.Hour,
		Now: func() time.Time { return time.Now().Add(time.Hour) }}
}

// adminSecret returns the admin's Secret of obj, as the hub holds it.
func adminSecret(t *testing.T, obj *configv1alpha1.Spoke) *corev1.Secret {
	t.Helper()
	var secret corev1.Secret
	require.NoError(t, hub.client.Get(ctx, client.ObjectKey{Namespace: namespace,
		Name: obj.Spec.CredentialsSecretRef.Name}, &secret))
	return &secret
}

// ownSecret returns the hub's own Secret of obj.
func ownSecret(t *testing.T, obj *configv1alpha1.Spoke) *corev1.Secret {
	t.Helper()
	var secret corev1.Secret
	require.NoError(t, hub.client.Get(ctx, client.ObjectKey{Namespace: namespace,
		Name: remote.TokenSecretName(obj.Name)}, &secret))
	return &secret
}

// clusterID reads the identity of the cluster that cfg reaches.
func clusterID(cfg *rest.Config) (string, error) {
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		return "", err
	}
	return settings.ClusterID(ctx, c)
}

// caHash is the SHA-256 of a CA bundle, in hex, as the hub's own Secret keeps it.
func caHash(ca []byte) string {
	sum := sha256.Sum256(ca)
	return hex.EncodeToString(sum[:])
}

// spokeID is the spoke's identity, as its admin reads it.
func spokeID(t *testing.T) string {
	t.Helper()
	id, err := settings.ClusterID(ctx, spoke.client)
	require.NoError(t, err)
	return id
}
