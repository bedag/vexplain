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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/google/go-containerregistry/pkg/authn"
	k8schain "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
)

// The runner reads the pull secrets that a pod names, and its service account, one at a time with
// get, in whatever namespace the pod runs (design 6.11). It never lists or watches either, so it
// can't enumerate the Secrets of the cluster.
// +kubebuilder:rbac:groups="",resources=secrets;serviceaccounts,verbs=get

// CredentialSource builds the credentials that a scan Job pulls its image with.
type CredentialSource interface {
	// DockerConfig returns the config.json for pulling repository with pod's credentials.
	DockerConfig(ctx context.Context, pod *corev1.Pod, repository string) ([]byte, error)
}

// errUnreadablePullSecret stands in for the error of a pull secret whose content doesn't parse.
// That error can quote the content, so its text never goes further.
var errUnreadablePullSecret = errors.New("a pull secret of the pod doesn't hold Docker credentials that can be read")

// NewKeychainCredentials returns a CredentialSource that authenticates as the kubelet does: with the
// pull secrets that the pod names, then those of its service account, through go-containerregistry's
// Kubernetes keychain. It reads them with cs, from the API server: never from a cache, which would
// hold every Secret of the cluster. A pull secret that doesn't exist adds nothing, and is no error.
//
// Like the kubelet, it finds the login of Docker Hub under both its names: index.docker.io, the
// keychain's, and docker.io, under which kubectl create secret docker-registry --docker-server=docker.io
// writes it. A key of docker.io counts for Docker Hub alone, and a key docker.io/<organisation> for
// that organisation alone.
//
// The config.json holds the one login that the keychain finds for the repository's registry, or no
// login for an anonymous pull. Its values never appear in an error or a log line.
func NewKeychainCredentials(cs kubernetes.Interface) CredentialSource {
	return &keychainCredentials{clientset: cs}
}

// keychainCredentials builds credentials from the pull secrets of pods.
type keychainCredentials struct {
	clientset kubernetes.Interface
}

func (c *keychainCredentials) DockerConfig(ctx context.Context, pod *corev1.Pod, repository string) ([]byte, error) {
	repo, err := name.NewRepository(repository)
	if err != nil {
		return nil, fmt.Errorf("build the pull credentials for %q: it isn't a repository", repository)
	}
	secrets := make([]string, 0, len(pod.Spec.ImagePullSecrets))
	for _, secret := range pod.Spec.ImagePullSecrets {
		secrets = append(secrets, secret.Name)
	}
	keychain, err := k8schain.New(ctx, c.clientset, k8schain.Options{
		Namespace:          pod.Namespace,
		ServiceAccountName: pod.Spec.ServiceAccountName,
		ImagePullSecrets:   secrets,
	})
	if err != nil {
		if !fromTheAPI(ctx, err) {
			err = errUnreadablePullSecret
		}
		return nil, fmt.Errorf("read the pull secrets of pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	login, err := loginFor(ctx, keychain, repo)
	if err == nil && *login == (authn.AuthConfig{}) && repo.RegistryStr() == name.DefaultRegistry {
		// The keychain names Docker Hub index.docker.io, which a pull secret keyed docker.io doesn't
		// match, though the kubelet matches it. So a Docker Hub repository that found no login is
		// looked up again under docker.io. Each lookup keeps the order of the pull secrets.
		login, err = loginFor(ctx, keychain, dockerHubRepository{path: repo.RepositoryStr()})
	}
	if err != nil {
		return nil, fmt.Errorf("find the pull credentials of pod %s/%s for %s: %w",
			pod.Namespace, pod.Name, repository, errUnreadablePullSecret)
	}

	config := dockerConfig{Auths: map[string]dockerLogin{}}
	// The keychain splits the auth field of a pull secret into the username and the password.
	entry := dockerLogin{
		Username:      login.Username,
		Password:      login.Password,
		IdentityToken: login.IdentityToken,
		RegistryToken: login.RegistryToken,
	}
	if entry != (dockerLogin{}) {
		config.Auths[configKey(repo)] = entry
	}
	return json.Marshal(config)
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

// fromTheAPI reports whether err is the error of a call to the API server: an error status, a
// request that failed, or the end of ctx. Such a text names objects, and never holds their content.
// Any other error of the keychain comes from parsing a pull secret.
func fromTheAPI(ctx context.Context, err error) bool {
	if errors.As(err, new(apierrors.APIStatus)) {
		return true
	}
	// A pull secret's registry that doesn't parse as a URL fails with the URL in the text, but as a
	// parse and never as a request.
	var request *url.Error
	if errors.As(err, &request) && request.Op != "parse" {
		return true
	}
	return ctx.Err() != nil
}

// configKey returns the key under which a config.json holds the login of repo's registry: the key
// under which go-containerregistry's DefaultKeychain looks it up in the scan pod. That is Docker's
// historical key for Docker Hub, and the host, with its port, for every other registry.
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

// dockerLogin is the login of one registry in a config.json, in the fields that Docker's loader
// reads. It leaves out auth, the base64 of username:password: the loader only splits it into these
// two fields again, and refuses it without a username.
type dockerLogin struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
	RegistryToken string `json:"registrytoken,omitempty"`
}
