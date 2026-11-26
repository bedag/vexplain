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
// hub's own, so that the admin's Secret is never written. The Copier copies a spoke's records into the hub's stores,
// over a cache of the spoke that NewCluster makes on the seam's config (decision 0063).
package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
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
// under CAHashKey the hash of the CA bundle that it was issued with, as CAHash makes it.
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
// issued for, and the admin's otherwise. The same server and the same CA bundle are those that a Secret written again
// can name in another text: a URL whose scheme or host differ in case, that gives the default port or not, or ends in a
// slash, and the same certificates with other line endings, or in another order. The hub's own token renews itself, so it goes to no other server, whether the
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

// config is Config, with the hub's own token while it is valid when useOwn says so, and with the admin's otherwise. It
// reads the Secrets quietly: client-go logs their bodies from V(8) on.
func config(ctx context.Context, c client.Reader, namespace string, spoke *configv1alpha1.Spoke, useOwn bool) (
	*rest.Config, error) {
	ctx = Quiet(ctx)
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
	case useOwn && normalServer(string(own.Data[ServerKey])) == normalServer(cfg.Host) &&
		string(own.Data[CAHashKey]) == CAHash(cfg.CAData) && expiresAfter(string(own.Data[TokenKey]), now):
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

// CAHash is the hash of a CA bundle, as the hub's own Secret keeps it under CAHashKey: the SHA-256, in hex, of the DER of
// the bundle's certificates, in sorted order, so that the same certificates hash the same in another PEM text. DER
// gives each certificate's length, so that their concatenation is unambiguous.
func CAHash(ca []byte) string {
	var certificates [][]byte
	for block, more := pem.Decode(ca); block != nil; block, more = pem.Decode(more) {
		if block.Type == "CERTIFICATE" {
			certificates = append(certificates, block.Bytes)
		}
	}
	slices.SortFunc(certificates, bytes.Compare)
	sum := sha256.New()
	for _, der := range certificates {
		sum.Write(der)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// normalServer returns the https URL of an API server as the pin of the hub's own token compares it: the scheme and the
// host in lower case, without the default port and without the slashes that end the path. A URL that doesn't parse
// stays as it is.
func normalServer(server string) string {
	u, err := url.Parse(server)
	if err != nil {
		return server
	}
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && port != "443" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return strings.ToLower(u.Scheme) + "://" + host + strings.TrimRight(u.EscapedPath(), "/")
}

// maxCallVerbosity is the most verbose level that a call to a spoke logs at, through the logger of its context.
// client-go logs a call's debug lines from V(4) on, and the bodies of the request and of the answer from V(8) on, and a
// spoke's answers can carry the token that the hub sent, as a TokenRequest's answer carries the token that it renews.
const maxCallVerbosity = 3

// Quiet returns ctx with a logger that passes on the lines up to V(3) and the errors of the logger that ctx carries,
// and drops the others: client-go logs a call through its context's logger, at the verbosity that the manager's logger
// allows. Each call to a spoke runs with such a context, and so does each read and write of a Secret of a spoke, which
// hold tokens. A context without a logger gets one that logs nothing. ctx's cancellation and deadline stay.
func Quiet(ctx context.Context) context.Context {
	return logr.NewContext(ctx, logr.New(quietSink{logr.FromContextOrDiscard(ctx).GetSink()}))
}

// quietSink passes on to sink the lines up to maxCallVerbosity, and the errors. sink is nil when there is none.
type quietSink struct {
	sink logr.LogSink
}

// Init does nothing: sink was initialized with its logger.
func (quietSink) Init(logr.RuntimeInfo) {}

// Enabled says whether a line of the level is logged.
func (q quietSink) Enabled(level int) bool {
	return level <= maxCallVerbosity && q.sink != nil && q.sink.Enabled(level)
}

// Info logs a line of the level, if it is enabled.
func (q quietSink) Info(level int, msg string, keysAndValues ...any) {
	if q.Enabled(level) {
		q.sink.Info(level, msg, keysAndValues...)
	}
}

// Error logs an error.
func (q quietSink) Error(err error, msg string, keysAndValues ...any) {
	if q.sink != nil {
		q.sink.Error(err, msg, keysAndValues...)
	}
}

// WithValues returns the sink with the values added.
func (q quietSink) WithValues(keysAndValues ...any) logr.LogSink {
	if q.sink == nil {
		return q
	}
	return quietSink{q.sink.WithValues(keysAndValues...)}
}

// WithName returns the sink with the name added.
func (q quietSink) WithName(name string) logr.LogSink {
	if q.sink == nil {
		return q
	}
	return quietSink{q.sink.WithName(name)}
}

// expiresAfter says whether the claims of token say that it expires after now.
func expiresAfter(token string, now time.Time) bool {
	c, err := claimsOf(token)
	return err == nil && time.Unix(c.Expiry, 0).After(now)
}
