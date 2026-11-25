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

// Package remote connects the hub to the API servers of its spokes (decisions 0060 to 0062). Config, with AdminConfig
// for when a spoke refuses the hub's own token, is the one seam that turns a Spoke into a client's config, where a
// tunnel or another source of tokens fits in later. The Renewer renews the hub's token for a spoke into a Secret of the
// hub's own, so that the admin's Secret is never written.
package remote

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// The keys of the admin's Secret of a spoke, which the Spoke's credentialsSecretRef names: the https URL of the
// spoke's API server, its CA bundle, and the bootstrap token of the ServiceAccount that the spoke's install creates for
// the hub. The hub's own Secret holds its token under TokenKey too, the server that issued it under ServerKey, and
// under CAHashKey the SHA-256, in hex, of the CA bundle that it was issued with.
const (
	ServerKey = "server"
	CAKey     = "ca.crt"
	TokenKey  = "token"
	CAHashKey = "ca.sha256"
)

// SpokeLabel labels the hub's own Secret of a spoke with the Spoke's name.
const SpokeLabel = "vexplain.bedag.ch/spoke"

// ErrTokenExpired says that the hub holds no valid token for a spoke: its own expired before it could renew it, or it
// never had one, and the admin's has expired too. An admin puts a new bootstrap token into the admin's Secret.
var ErrTokenExpired = errors.New("no valid token for the spoke")

// TokenSecretName is the name of the hub's own Secret of the spoke, in the operator's namespace, where the hub keeps
// the token that it renews.
func TokenSecretName(spoke string) string {
	return "spoke-" + spoke + "-token"
}

// Config returns the config of a client of the spoke's API server. It reads the admin's Secret, which spoke names, and
// the hub's own, both in namespace, with c.
//
// TLS is always verified, against the admin's ca.crt alone. No key of the Secret and no field of the Spoke turns the
// check off, and a Secret without a certificate gives no config, rather than one that trusts the system's roots. The
// server is an https URL without user information, so that no credential travels in the clear or shows in an error.
// The token is the hub's own while it is valid and the admin's Secret names the server and the CA bundle that it was
// issued for, and the admin's otherwise. The hub's own token renews itself, so it goes to no other server, whether the
// admin's Secret names one by a mistake or by a pipeline that may write it, and with no CA bundle that someone who also
// steers the server's traffic could swap in. An API server that moved, or a CA that rotated, needs a new bootstrap
// token. When the admin's token has expired too, Config fails with ErrTokenExpired. A spoke's warnings, which can echo
// the token, go to no log.
//
// It refuses an admin's Secret that has the name of the hub's own, and a Secret of that name that the Spoke doesn't
// own, since the hub writes its own Secret, and must never write another. Its errors hold no value of either Secret.
func Config(ctx context.Context, c client.Reader, namespace string, spoke *configv1alpha1.Spoke) (*rest.Config, error) {
	return config(ctx, c, namespace, spoke, true)
}

// AdminConfig returns the config that Config returns, with the admin's token whatever the hub's own Secret holds. A
// spoke can refuse the hub's own token before it expires, as when its ServiceAccount was made anew, which no claim
// tells: a token that the spoke refuses is no valid one, and the hub tries the admin's.
func AdminConfig(ctx context.Context, c client.Reader, namespace string, spoke *configv1alpha1.Spoke) (*rest.Config,
	error) {
	return config(ctx, c, namespace, spoke, false)
}

// config is Config, with the hub's own token while it is valid when useOwn says so, and with the admin's otherwise.
func config(ctx context.Context, c client.Reader, namespace string, spoke *configv1alpha1.Spoke, useOwn bool) (
	*rest.Config, error) {
	name := spoke.Spec.CredentialsSecretRef.Name
	if name == TokenSecretName(spoke.Name) {
		return nil, fmt.Errorf("the Secret %s has the name of the hub's own Secret of the spoke, so it can't be the "+
			"admin's", name)
	}
	var admin corev1.Secret
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &admin); err != nil {
		return nil, fmt.Errorf("read the Secret %s: %w", name, err)
	}
	// A value written from a file often ends with a line break, which would make it no URL, and no token.
	server, ca := strings.TrimSpace(string(admin.Data[ServerKey])), admin.Data[CAKey]
	if u, err := url.Parse(server); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("the Secret %s holds no https URL without user information under %s", name, ServerKey)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("the Secret %s holds no PEM certificate under %s", name, CAKey)
	}
	cfg := &rest.Config{Host: server, TLSClientConfig: rest.TLSClientConfig{CAData: ca},
		// A spoke's warnings are its own text, which can carry what the hub sent, its token included: none is logged.
		WarningHandlerWithContext: rest.NoWarnings{}}
	token, err := tokenFor(ctx, c, namespace, spoke, &admin, cfg, useOwn)
	if err != nil {
		return nil, err
	}
	cfg.BearerToken = token
	return cfg, nil
}

// tokenFor returns the token of the hub for spoke, which cfg reaches: its own, from its own Secret, while it is valid
// and was issued for cfg's server and CA bundle, when useOwn says so, and the admin's, from admin, otherwise. It checks
// the hub's own Secret either way, since the hub renews into it.
func tokenFor(ctx context.Context, c client.Reader, namespace string, spoke *configv1alpha1.Spoke,
	admin *corev1.Secret, cfg *rest.Config, useOwn bool) (string, error) {
	now := time.Now()
	var own corev1.Secret
	key := client.ObjectKey{Namespace: namespace, Name: TokenSecretName(spoke.Name)}
	switch err := c.Get(ctx, key, &own); {
	case apierrors.IsNotFound(err):
	case err != nil:
		return "", fmt.Errorf("read the Secret %s: %w", key.Name, err)
	case !metav1.IsControlledBy(&own, spoke):
		return "", fmt.Errorf("the Secret %s isn't the hub's own: the Spoke doesn't own it", key.Name)
	case useOwn && string(own.Data[ServerKey]) == cfg.Host && string(own.Data[CAHashKey]) == caHash(cfg.CAData) &&
		expiresAfter(string(own.Data[TokenKey]), now):
		return string(own.Data[TokenKey]), nil
	}
	token := strings.TrimSpace(string(admin.Data[TokenKey]))
	if token == "" {
		return "", fmt.Errorf("the Secret %s holds no token under %s", admin.Name, TokenKey)
	}
	// A token whose claims can't be read, or say no expiry, may be valid all the same: the spoke tells.
	if claimed, err := claimsOf(token); err == nil && claimed.Expiry != 0 && !expiresAfter(token, now) {
		return "", fmt.Errorf("%w: the token in the Secret %s expired at %s", ErrTokenExpired, admin.Name,
			time.Unix(claimed.Expiry, 0).UTC().Format(time.RFC3339))
	}
	return token, nil
}

// caHash is the SHA-256 of a CA bundle, in hex, as the hub's own Secret keeps it under CAHashKey.
func caHash(ca []byte) string {
	sum := sha256.Sum256(ca)
	return hex.EncodeToString(sum[:])
}

// expiresAfter says whether the claims of token say that it expires after now.
func expiresAfter(token string, now time.Time) bool {
	c, err := claimsOf(token)
	return err == nil && time.Unix(c.Expiry, 0).After(now)
}
