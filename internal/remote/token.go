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

package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
)

// ErrNotRenewable says that the hub can't renew a token, since it can't learn from it which ServiceAccount to renew:
// the token's claims can't be read, or name none. The token can't serve, though the spoke may take it.
var ErrNotRenewable = errors.New("the hub can't renew the token")

// TokenRequester asks the spoke that cfg reaches for a token of the ServiceAccount namespace/serviceAccount that lives
// seconds, and returns it with the time it expires.
type TokenRequester func(ctx context.Context, cfg *rest.Config, namespace, serviceAccount string, seconds int64) (
	token string, expires time.Time, err error)

// Renewer renews the hub's token for a spoke at half its lifetime, and keeps it in the hub's own Secret of the spoke.
type Renewer struct {
	// Client writes the hub's own Secrets. Renew reads none through it, since the manager's cache holds no Secret.
	Client client.Client
	// Namespace is the operator's namespace on the hub, where the hub's own Secrets are.
	Namespace string
	// Lifetime is how long a token that the hub asks for lives. TokenRequest gives 10 minutes at least.
	Lifetime time.Duration
	// Now is the clock that says when a token is due. Nil means time.Now.
	Now func() time.Time
	// Request asks the spoke for a token. Nil means the spoke's TokenRequest API.
	Request TokenRequester
}

// Renew renews the token that cfg, the config that Config built, holds, once it has lived half its lifetime. It asks
// the spoke through cfg for a token of the ServiceAccount that the token names, and writes it, with the server that
// issued it, into the hub's own Secret of the spoke, labelled with the Spoke's name and owned by the Spoke, so that
// Config sends it to no other server. It returns when the token that the hub uses from then on expires.
//
// Renew reads the token's claims without checking their signature: the hub can't, and the spoke's API server checks
// the request anyway. A token that says no lifetime is due at once, and a token that names no ServiceAccount, or whose
// claims can't be read, is refused with ErrNotRenewable. Renew writes the hub's own Secret whatever it holds, which
// Config checked to be the hub's, and never the admin's. Its errors hold no token.
func (r *Renewer) Renew(ctx context.Context, spoke *configv1alpha1.Spoke, cfg *rest.Config) (time.Time, error) {
	return r.renew(ctx, spoke, cfg, false)
}

// RenewNow renews as Renew does, at once, whatever the age of the token that cfg holds. Once the spoke has refused the
// hub's own token, a token renewed from the admin's, which AdminConfig gives, replaces it before the next check.
func (r *Renewer) RenewNow(ctx context.Context, spoke *configv1alpha1.Spoke, cfg *rest.Config) (time.Time, error) {
	return r.renew(ctx, spoke, cfg, true)
}

// renew is Renew, which renews a token that isn't due yet too when atOnce says so.
func (r *Renewer) renew(ctx context.Context, spoke *configv1alpha1.Spoke, cfg *rest.Config, atOnce bool) (
	time.Time, error) {
	c, err := claimsOf(cfg.BearerToken)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrNotRenewable, err)
	}
	namespace, account := c.serviceAccount()
	if namespace == "" || account == "" {
		return time.Time{}, fmt.Errorf("%w: the token names no ServiceAccount", ErrNotRenewable)
	}
	if !atOnce && r.now().Before(c.renewal()) {
		return time.Unix(c.Expiry, 0), nil
	}
	request := r.Request
	if request == nil {
		request = requestToken
	}
	token, expires, err := request(ctx, cfg, namespace, account, int64(r.Lifetime/time.Second))
	if err != nil {
		return time.Time{}, fmt.Errorf("ask the spoke for a token of the ServiceAccount %s/%s: %w", namespace, account, err)
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: r.Namespace, Name: TokenSecretName(spoke.Name),
			Labels: map[string]string{SpokeLabel: spoke.Name}},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{TokenKey: []byte(token), ServerKey: []byte(cfg.Host)},
	}
	if err := controllerutil.SetControllerReference(spoke, secret, r.Client.Scheme()); err != nil {
		return time.Time{}, fmt.Errorf("own the Secret %s: %w", secret.Name, err)
	}
	// An update without a resource version replaces the Secret as it stands, so no read of it is needed.
	err = r.Client.Create(ctx, secret)
	if apierrors.IsAlreadyExists(err) {
		err = r.Client.Update(ctx, secret)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("write the token into the Secret %s: %w", secret.Name, err)
	}
	return expires, nil
}

// now returns the time on the renewer's clock.
func (r *Renewer) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// requestToken asks the spoke's TokenRequest API, through cfg, for a token of the ServiceAccount that lives seconds.
func requestToken(ctx context.Context, cfg *rest.Config, namespace, serviceAccount string, seconds int64) (
	string, time.Time, error) {
	core, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return "", time.Time{}, err
	}
	answer, err := core.ServiceAccounts(namespace).CreateToken(ctx, serviceAccount, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: &seconds},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", time.Time{}, err
	}
	return answer.Status.Token, answer.Status.ExpirationTimestamp.Time, nil
}

// claims are what the hub reads of a ServiceAccount token: when it was issued and when it expires, in seconds since
// the epoch, and the ServiceAccount that it names.
type claims struct {
	IssuedAt   int64  `json:"iat"`
	Expiry     int64  `json:"exp"`
	Subject    string `json:"sub"`
	Kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

// serviceAccount returns the namespace and the name of the ServiceAccount that the token names: in its kubernetes.io
// claims, which a bound token has, or else in its subject, system:serviceaccount:<namespace>:<name>, which is all that
// a token of a Secret of type kubernetes.io/service-account-token has besides flat claims.
func (c claims) serviceAccount() (namespace, name string) {
	if c.Kubernetes.Namespace != "" || c.Kubernetes.ServiceAccount.Name != "" {
		return c.Kubernetes.Namespace, c.Kubernetes.ServiceAccount.Name
	}
	if account, ok := strings.CutPrefix(c.Subject, "system:serviceaccount:"); ok {
		namespace, name, _ = strings.Cut(account, ":")
	}
	return namespace, name
}

// errUnreadable says that a token's claims can't be read. It stands for the errors of decoding them, which could quote
// a piece of the token.
var errUnreadable = errors.New("the token is no JWT whose claims can be read")

// claimsOf reads the claims of a JWT, without checking its signature.
func claimsOf(token string) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims{}, errUnreadable
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var c claims
	if err != nil || json.Unmarshal(payload, &c) != nil {
		return claims{}, errUnreadable
	}
	return c, nil
}

// renewal is when the token has lived half its lifetime: the zero time, so at once, for a token that says no lifetime.
func (c claims) renewal() time.Time {
	if c.IssuedAt == 0 || c.Expiry <= c.IssuedAt {
		return time.Time{}
	}
	return time.Unix(c.IssuedAt+(c.Expiry-c.IssuedAt)/2, 0)
}
