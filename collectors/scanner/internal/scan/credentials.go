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

package scan

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	k8schain "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The scanner reads the pull secrets that a pod names, its service account and that account's pull secrets, in whatever
// namespace the pod runs, and the Secrets that the admin lists in adminPullSecrets, in the operator's, one at a time
// with get (design 6.11). It never lists or watches either, so it can't enumerate the Secrets of the cluster. Its
// capabilities declare the permission.

// CredentialSource builds the credentials that a scan Job pulls its image with.
type CredentialSource interface {
	// Credentials returns the credentials for pulling repository: the logins, in the order that the scan tries them
	// (decision 0047), those of pod's pull secrets and of its service account's, as the kubelet takes them
	// (CopyFromWorkload), then those of the Secrets named admin, which the admin provides (AdminProvided); and the
	// Secrets named admin that gave none.
	Credentials(ctx context.Context, pod *corev1.Pod, repository string, admin []string) (Credentials, error)
}

// Credentials are what a scan pulls with, and what a failure that no login worked for names.
type Credentials struct {
	// Logins are the logins, in the order that the scan tries them.
	Logins []Login
	// Missing names the Secrets that the admin provides that don't exist, and NoLogin those that hold no login for
	// the registry, such as one of another type, by their names in the settings, in the settings' order.
	Missing, NoLogin []string
}

// Login is the login of one pull secret for the registry of a repository.
type Login struct {
	// Secret names the pull secret, as namespace/name, which a failure may name.
	Secret string
	// Config is a Docker config.json that holds the login, and nothing else.
	Config []byte
}

// errUnreadablePullSecret stands in for the error of a pull secret whose content doesn't parse.
// That error can quote the content, so its text never goes further.
var errUnreadablePullSecret = errors.New("it doesn't hold Docker credentials that can be read")

// NewKeychainCredentials returns a CredentialSource that authenticates as the kubelet does: with each pull secret that
// the pod names, then each that its service account names, through go-containerregistry's Kubernetes keychain, and
// then with each Secret that the admin provides in namespace, the operator's. It reads them with cs, from the API
// server: never from a cache, which would hold every Secret of the cluster. A pull secret or a service account that
// doesn't exist adds nothing, and is no error, and a pull secret that both the pod and its service account name is read
// once.
//
// Like the kubelet, it finds the login of Docker Hub under both its names: index.docker.io, the
// keychain's, and docker.io, under which kubectl create secret docker-registry --docker-server=docker.io
// writes it. A key of docker.io counts for Docker Hub alone, and a key docker.io/<organisation> for
// that organisation alone.
//
// Each Login holds the one login that the keychain finds in its pull secret for the repository's registry, and a pull
// secret that holds none gives no Login: an anonymous pull has none. The Credentials name the Secrets that the admin
// provides that gave no Login, by name. The values never appear in an error or a log line.
func NewKeychainCredentials(cs kubernetes.Interface, namespace string) CredentialSource {
	return &keychainCredentials{clientset: cs, namespace: namespace}
}

// keychainCredentials builds credentials from the pull secrets of pods, and from those that the admin provides.
type keychainCredentials struct {
	clientset kubernetes.Interface
	// namespace holds the Secrets that the admin provides.
	namespace string
}

func (c *keychainCredentials) Credentials(ctx context.Context, pod *corev1.Pod, repository string,
	admin []string) (Credentials, error) {
	repo, err := name.NewRepository(repository)
	if err != nil {
		return Credentials{}, fmt.Errorf("build the pull credentials for %q: it isn't a repository", repository)
	}
	var creds Credentials
	read := map[string]bool{}
	// add adds the login of the pull secret of the namespace and name, and reports whether it exists.
	add := func(namespace, secret string) (bool, error) {
		if read[namespace+"/"+secret] {
			return true, nil
		}
		read[namespace+"/"+secret] = true
		login, found, err := c.loginOf(ctx, namespace, secret, repo)
		if login != nil {
			creds.Logins = append(creds.Logins, *login)
		}
		return found, err
	}
	for _, secret := range pod.Spec.ImagePullSecrets {
		if _, err := add(pod.Namespace, secret.Name); err != nil {
			return Credentials{}, err
		}
	}
	account := cmp.Or(pod.Spec.ServiceAccountName, "default")
	sa, err := c.clientset.CoreV1().ServiceAccounts(pod.Namespace).Get(ctx, account, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		sa = &corev1.ServiceAccount{}
	case err != nil:
		return Credentials{}, fmt.Errorf("read the service account of pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	for _, secret := range sa.ImagePullSecrets {
		if _, err := add(pod.Namespace, secret.Name); err != nil {
			return Credentials{}, err
		}
	}
	for _, secret := range admin {
		if read[c.namespace+"/"+secret] {
			// The workload named it too: its login is tried already.
			continue
		}
		logins := len(creds.Logins)
		found, err := add(c.namespace, secret)
		switch {
		case err != nil:
			return Credentials{}, err
		case !found:
			creds.Missing = append(creds.Missing, secret)
		case len(creds.Logins) == logins:
			creds.NoLogin = append(creds.NoLogin, secret)
		}
	}
	return creds, nil
}

// loginOf returns the Login that the pull secret of the namespace and name holds for repo's registry, or nil when it
// holds none, and whether the Secret exists. An error of the API server names the Secret, and holds nothing of it, so
// it is returned as it is.
func (c *keychainCredentials) loginOf(ctx context.Context, namespace, secretName string, repo name.Repository) (*Login,
	bool, error) {
	secret, err := c.clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("read pull secret %s/%s: %w", namespace, secretName, err)
	}
	keychain, err := k8schain.NewFromPullSecrets(ctx, []corev1.Secret{*secret})
	if err != nil {
		return nil, true, fmt.Errorf("read pull secret %s/%s: %w", namespace, secretName, errUnreadablePullSecret)
	}
	login, err := loginFor(ctx, keychain, repo)
	if err == nil && *login == (authn.AuthConfig{}) && repo.RegistryStr() == name.DefaultRegistry {
		// The keychain names Docker Hub index.docker.io, which a pull secret keyed docker.io doesn't
		// match, though the kubelet matches it. So a Docker Hub repository that found no login is
		// looked up again under docker.io.
		login, err = loginFor(ctx, keychain, dockerHubRepository{path: repo.RepositoryStr()})
	}
	if err != nil {
		return nil, true, fmt.Errorf("read pull secret %s/%s: %w", namespace, secretName, errUnreadablePullSecret)
	}
	// The keychain splits the auth field of a pull secret into the username and the password.
	entry := dockerLogin{
		Username:      login.Username,
		Password:      login.Password,
		IdentityToken: login.IdentityToken,
		RegistryToken: login.RegistryToken,
	}
	if entry == (dockerLogin{}) {
		return nil, true, nil
	}
	config, err := json.Marshal(dockerConfig{Auths: map[string]dockerLogin{configKey(repo): entry}})
	if err != nil {
		return nil, true, fmt.Errorf("write the login of pull secret %s/%s: %w", namespace, secretName, err)
	}
	return &Login{Secret: namespace + "/" + secretName, Config: config}, true, nil
}

// loginFor returns the login that keychain finds for target: an empty one for an anonymous pull.
func loginFor(ctx context.Context, keychain authn.Keychain, target authn.Resource) (*authn.AuthConfig, error) {
	authenticator, err := authn.Resolve(ctx, keychain, target)
	if err != nil {
		return nil, err
	}
	login, err := authn.Authorization(ctx, authenticator)
	if err != nil {
		return nil, err
	}
	if login == nil {
		return &authn.AuthConfig{}, nil
	}
	return login, nil
}

// dockerHubHost is the name under which the kubelet, and the pull secrets that people write, know
// Docker Hub.
const dockerHubHost = "docker.io"

// dockerHubRepository is a repository of Docker Hub named under dockerHubHost, so that the keychain
// matches it against keys of docker.io, and of docker.io/<organisation>.
type dockerHubRepository struct {
	// path is the repository's path on Docker Hub, such as library/nginx.
	path string
}

func (r dockerHubRepository) String() string { return dockerHubHost + "/" + r.path }

func (r dockerHubRepository) RegistryStr() string { return dockerHubHost }

// configKey returns the key under which a config.json holds the login of repo's registry: the key
// under which the scan's keychain looks it up in the scan pod, as go-containerregistry's DefaultKeychain
// does. That is Docker's historical key for Docker Hub, and the host, with its port, for every other
// registry.
func configKey(repo name.Repository) string {
	if repo.RegistryStr() == name.DefaultRegistry {
		return authn.DefaultAuthKey
	}
	return repo.RegistryStr()
}

// dockerConfig is a Docker config.json that holds logins and nothing else.
type dockerConfig struct {
	Auths map[string]dockerLogin `json:"auths"`
}

// dockerLogin is the login of one registry in a config.json, in the fields that Docker's loader, and
// the scan's keychain, read. It leaves out auth, the base64 of username:password: the loader only
// splits it into these two fields again, and refuses it without a username.
type dockerLogin struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
	RegistryToken string `json:"registrytoken,omitempty"`
}
