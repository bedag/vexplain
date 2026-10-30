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

package scan_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"

	"github.com/bedag/vexplain/internal/controller/scan"
)

// These tests cover the credentials of a scan Job: the config.json that NewKeychainCredentials
// builds from a pod's pull secrets, the way the kubelet finds them, and that the scanner's keychain
// reads back. The Secrets and service accounts live in a fake clientset.

const (
	// credentialsNamespace is the namespace of the pod whose credentials the tests build.
	credentialsNamespace = "team-a"
	// privateRegistry is a registry that wants credentials, and otherRegistry another one, with a port.
	privateRegistry = "artifacts.example"
	otherRegistry   = "artifacts.example:5000"
	// The repositories that the tests pull from: one on each registry, and one on Docker Hub.
	privateRepository = privateRegistry + "/team-a/app"
	otherRepository   = otherRegistry + "/team-a/tool"
	hubRepository     = "docker.io/team-a/app"
	// hubKey is the key under which Docker's config.json holds the credentials of Docker Hub.
	hubKey = "https://index.docker.io/v1/"
	// podUsername and podPassword are the login in the pull secret that a pod names, and saPassword
	// the password in the pull secret of its service account.
	podUsername = "team-a-puller"
	podPassword = "pod-secret-password"
	saPassword  = "sa-secret-password"
	// dockerIOKey is the key under which kubectl create secret docker-registry, given
	// --docker-server=docker.io, writes a login of Docker Hub. hubUsername and dockerIOPassword are
	// such a login.
	dockerIOKey      = "docker.io"
	hubUsername      = "hub-puller"
	dockerIOPassword = "docker-io-password"
)

// registryLogin is what a pull secret holds for one registry. Each test gives its logins values of
// their own, so that a test can tell which Secret a credential came from.
type registryLogin struct {
	username, password, identityToken string
}

// pullSecret returns a Secret of the type kubernetes.io/dockerconfigjson, named secretName, that
// holds a login for each registry, as kubectl create secret docker-registry writes it.
func pullSecret(secretName string, logins map[string]registryLogin) *corev1.Secret {
	auths := map[string]map[string]string{}
	for registry, login := range logins {
		entry := map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(login.username + ":" + login.password))}
		if login.identityToken != "" {
			entry["identitytoken"] = login.identityToken
		}
		auths[registry] = entry
	}
	config, err := json.Marshal(map[string]any{"auths": auths})
	if err != nil {
		panic(err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: credentialsNamespace, Name: secretName},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: config},
	}
}

// serviceAccount returns a service account named accountName whose pull secrets are secrets.
func serviceAccount(accountName string, secrets ...string) *corev1.ServiceAccount {
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: credentialsNamespace, Name: accountName}}
	for _, secret := range secrets {
		sa.ImagePullSecrets = append(sa.ImagePullSecrets, corev1.LocalObjectReference{Name: secret})
	}
	return sa
}

// workloadPod returns a pod that runs as the service account named serviceAccountName and names the
// pull secrets secrets.
func workloadPod(serviceAccountName string, secrets ...string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: credentialsNamespace, Name: appPod},
		Spec:       corev1.PodSpec{ServiceAccountName: serviceAccountName},
	}
	for _, secret := range secrets {
		pod.Spec.ImagePullSecrets = append(pod.Spec.ImagePullSecrets, corev1.LocalObjectReference{Name: secret})
	}
	return pod
}

// dockerConfigOf builds the config.json for pulling repository with the credentials of pod, over a
// clientset that holds objs.
func dockerConfigOf(t *testing.T, pod *corev1.Pod, repository string, objs ...runtime.Object) []byte {
	t.Helper()
	config, err := scan.NewKeychainCredentials(fake.NewClientset(objs...)).DockerConfig(t.Context(), pod, repository)
	require.NoError(t, err)
	return config
}

// configEntry is an entry of the auths of a config.json, in the fields that Docker's loader reads.
type configEntry struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	Auth          string `json:"auth"`
	IdentityToken string `json:"identitytoken"`
	RegistryToken string `json:"registrytoken"`
}

// authsOf decodes the auths of a config.json.
func authsOf(t *testing.T, config []byte) map[string]configEntry {
	t.Helper()
	var decoded struct {
		Auths map[string]configEntry `json:"auths"`
	}
	require.NoError(t, json.Unmarshal(config, &decoded))
	return decoded.Auths
}

// entryFor is the entry of the auths that holds login.
func entryFor(login registryLogin) configEntry {
	return configEntry{Username: login.username, Password: login.password, IdentityToken: login.identityToken}
}

func TestDockerConfigHoldsThePullSecretsOfThePod(t *testing.T) {
	login := registryLogin{username: podUsername, password: podPassword}
	pod := workloadPod("app", "regcred")

	config := dockerConfigOf(t, pod, privateRepository,
		pullSecret("regcred", map[string]registryLogin{privateRegistry: login}), serviceAccount("app"))

	require.Equal(t, map[string]configEntry{privateRegistry: entryFor(login)}, authsOf(t, config))
}

func TestDockerConfigHoldsThePullSecretsOfTheServiceAccount(t *testing.T) {
	login := registryLogin{username: "builder-puller", password: saPassword}
	pod := workloadPod("builder")

	config := dockerConfigOf(t, pod, privateRepository,
		pullSecret("builder-cred", map[string]registryLogin{privateRegistry: login}),
		serviceAccount("builder", "builder-cred"))

	require.Equal(t, map[string]configEntry{privateRegistry: entryFor(login)}, authsOf(t, config))
}

// The kubelet reads the pull secrets of the pod and those of its service account together, the
// pod's first. So does the scan: each repository gets the credentials of its own registry, wherever
// they came from, and where both name one registry the pod's come first.
func TestDockerConfigReadsThePodAndItsServiceAccountTogether(t *testing.T) {
	podLogin := registryLogin{username: "pod-puller", password: podPassword}
	saLogin := registryLogin{username: "sa-puller", password: saPassword}
	saOtherLogin := registryLogin{username: "sa-other-puller", password: "sa-other-password"}
	objs := []runtime.Object{
		pullSecret("pod-cred", map[string]registryLogin{privateRegistry: podLogin}),
		pullSecret("sa-cred", map[string]registryLogin{privateRegistry: saLogin, otherRegistry: saOtherLogin}),
		serviceAccount("app", "sa-cred"),
	}
	pod := workloadPod("app", "pod-cred")

	require.Equal(t, map[string]configEntry{privateRegistry: entryFor(podLogin)},
		authsOf(t, dockerConfigOf(t, pod, privateRepository, objs...)), "the pod's own pull secret comes first")
	require.Equal(t, map[string]configEntry{otherRegistry: entryFor(saOtherLogin)},
		authsOf(t, dockerConfigOf(t, pod, otherRepository, objs...)), "the service account's pull secret fills in")
}

// A public image needs no credentials, and a config.json without any makes the scanner pull it
// anonymously. Credentials for other registries never go into the Job's Secret.
func TestDockerConfigOfAnAnonymousPull(t *testing.T) {
	login := registryLogin{username: "other-puller", password: "other-registry-password"}
	pod := workloadPod("app", "regcred")

	config := dockerConfigOf(t, pod, hubRepository,
		pullSecret("regcred", map[string]registryLogin{otherRegistry: login}), serviceAccount("app"))

	require.JSONEq(t, `{"auths":{}}`, string(config))
	require.NotContains(t, string(config), login.password)
}

// A pod can name a pull secret that doesn't exist; the kubelet then pulls without it. The scan does
// the same: the missing Secret adds nothing, and is no error.
func TestDockerConfigSkipsAPullSecretThatDoesNotExist(t *testing.T) {
	login := registryLogin{username: podUsername, password: podPassword}
	objs := []runtime.Object{pullSecret("regcred", map[string]registryLogin{privateRegistry: login}), serviceAccount("app")}

	config := dockerConfigOf(t, workloadPod("app", "missing", "regcred"), privateRepository, objs...)
	require.Equal(t, map[string]configEntry{privateRegistry: entryFor(login)}, authsOf(t, config))

	config = dockerConfigOf(t, workloadPod("app", "missing"), privateRepository, objs...)
	require.JSONEq(t, `{"auths":{}}`, string(config))
}

// The scanner reads the config.json through go-containerregistry's DefaultKeychain, which looks up
// Docker Hub under Docker's historical key and every other registry under its host. A key that it
// doesn't look up would make every private pull anonymous, so the scanner's own keychain must find
// the credentials that the pod's pull secrets gave.
func TestDockerConfigRoundTripsThroughTheScannersKeychain(t *testing.T) {
	cases := []struct {
		name           string
		repository     string
		secretRegistry string // the key of the pull secret, as people write it
		login          registryLogin
	}{
		{"Docker Hub", hubRepository, hubKey, registryLogin{username: hubUsername, password: "hub-password"}},
		// kubectl create secret docker-registry --docker-server=docker.io writes this key, and the
		// kubelet matches it against Docker Hub.
		{"Docker Hub under docker.io", hubRepository, dockerIOKey,
			registryLogin{username: hubUsername, password: dockerIOPassword}},
		{"Docker Hub under docker.io and an organisation", hubRepository, dockerIOKey + "/team-a",
			registryLogin{username: "hub-team-puller", password: "docker-io-team-password"}},
		{"an official Docker Hub image under docker.io", "docker.io/library/nginx", dockerIOKey,
			registryLogin{username: hubUsername, password: "docker-io-library-password"}},
		{"another registry", privateRepository, privateRegistry,
			registryLogin{username: podUsername, password: "private-password"}},
		{"a registry with a port", otherRepository, "https://" + otherRegistry,
			registryLogin{username: "tool-puller", password: "tool-password"}},
		{"an identity token", privateRepository, privateRegistry,
			registryLogin{username: "<token>", identityToken: "refresh-token-value"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := dockerConfigOf(t, workloadPod("app", "regcred"), tc.repository,
				pullSecret("regcred", map[string]registryLogin{tc.secretRegistry: tc.login}), serviceAccount("app"))

			got := resolveWithTheScannersKeychain(t, config, tc.repository)

			require.Equal(t, tc.login.username, got.Username)
			require.Equal(t, tc.login.password, got.Password)
			require.Equal(t, tc.login.identityToken, got.IdentityToken)
		})
	}
}

// A pull secret keyed docker.io is for Docker Hub, and for no other registry; one keyed with an
// organisation of Docker Hub is for that organisation alone.
func TestDockerConfigMatchesDockerIOKeysOnlyOnDockerHub(t *testing.T) {
	login := registryLogin{username: hubUsername, password: dockerIOPassword}
	objs := []runtime.Object{
		pullSecret("hubcred", map[string]registryLogin{dockerIOKey: login}),
		pullSecret("teamcred", map[string]registryLogin{dockerIOKey + "/team-b": login}),
		serviceAccount("app"),
	}

	require.JSONEq(t, `{"auths":{}}`, string(dockerConfigOf(t, workloadPod("app", "hubcred"), privateRepository, objs...)),
		"a docker.io key gives nothing for another registry")
	require.JSONEq(t, `{"auths":{}}`, string(dockerConfigOf(t, workloadPod("app", "teamcred"), hubRepository, objs...)),
		"a key of another organisation gives nothing")
}

// Docker Hub is looked up under docker.io only when the keychain found nothing under its own name
// for it, index.docker.io. The order of the pull secrets holds in each lookup: the pod's come before
// its service account's.
func TestDockerConfigLooksUpDockerIOOnlyWhenDockerHubFoundNothing(t *testing.T) {
	indexLogin := registryLogin{username: "index-puller", password: "index-password"}
	dockerIOLogin := registryLogin{username: "docker-io-puller", password: dockerIOPassword}
	both := pullSecret("bothcred", map[string]registryLogin{hubKey: indexLogin, dockerIOKey: dockerIOLogin})

	config := dockerConfigOf(t, workloadPod("app", "bothcred"), hubRepository, both, serviceAccount("app"))
	require.Equal(t, map[string]configEntry{hubKey: entryFor(indexLogin)}, authsOf(t, config))

	podLogin := registryLogin{username: "pod-puller", password: podPassword}
	saLogin := registryLogin{username: "sa-puller", password: saPassword}
	config = dockerConfigOf(t, workloadPod("builder", "podcred"), hubRepository,
		pullSecret("podcred", map[string]registryLogin{dockerIOKey: podLogin}),
		pullSecret("sacred", map[string]registryLogin{dockerIOKey: saLogin}),
		serviceAccount("builder", "sacred"))
	require.Equal(t, map[string]configEntry{hubKey: entryFor(podLogin)}, authsOf(t, config))
}

// resolveWithTheScannersKeychain writes config as the config.json of a Docker config directory, as
// the Job's Secret volume does, and resolves repository through authn.DefaultKeychain in the
// environment of the scan container: DOCKER_CONFIG names the directory, and the home directory
// holds no config of its own.
func resolveWithTheScannersKeychain(t *testing.T, config []byte, repository string) *authn.AuthConfig {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), config, 0o440))
	t.Setenv("DOCKER_CONFIG", dir)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DOCKER_AUTH_CONFIG", "")
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	repo, err := name.NewRepository(repository)
	require.NoError(t, err)
	authenticator, err := authn.DefaultKeychain.Resolve(repo)
	require.NoError(t, err)
	got, err := authn.Authorization(t.Context(), authenticator)
	require.NoError(t, err)
	return got
}

// logCapture holds what every logger that the credentials could reach writes: go-containerregistry's
// loggers and the logger in the context.
type logCapture struct {
	mu  sync.Mutex
	out bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.String()
}

// captureLogs sends go-containerregistry's loggers to a capture until the test ends, and returns it
// with a context whose logger writes there too, at every verbosity.
func captureLogs(t *testing.T) (*logCapture, context.Context) {
	t.Helper()
	capture := &logCapture{}
	for _, logger := range []interface {
		Writer() io.Writer
		SetOutput(io.Writer)
	}{logs.Warn, logs.Progress, logs.Debug} {
		previous := logger.Writer()
		logger.SetOutput(capture)
		t.Cleanup(func() { logger.SetOutput(previous) })
	}
	sink := funcr.New(func(prefix, args string) {
		_, _ = fmt.Fprintln(capture, prefix, args)
	}, funcr.Options{Verbosity: 10})
	return capture, logr.NewContext(t.Context(), sink)
}

// The values of pull secrets never appear in a log or an error. A missing Secret is logged by name,
// and a Secret that doesn't parse fails without its content.
func TestDockerConfigNeverLogsTheCredentials(t *testing.T) {
	capture, ctx := captureLogs(t)
	login := registryLogin{username: podUsername, password: "never-logged-password", identityToken: "never-logged-token"}
	encoded := base64.StdEncoding.EncodeToString([]byte(login.username + ":" + login.password))
	malformed := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: credentialsNamespace, Name: "broken"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"` + privateRegistry + `":{"auth":"never-logged-broken`)},
	}
	hubLogin := registryLogin{username: hubUsername, password: "never-logged-hub-password"}
	credentials := scan.NewKeychainCredentials(fake.NewClientset(
		pullSecret("regcred", map[string]registryLogin{privateRegistry: login}), malformed,
		pullSecret("hubcred", map[string]registryLogin{dockerIOKey: hubLogin}), serviceAccount("app")))

	config, err := credentials.DockerConfig(ctx, workloadPod("app", "missing", "regcred"), privateRepository)
	require.NoError(t, err)
	require.Contains(t, string(config), login.password, "the config.json itself holds the credentials")
	config, err = credentials.DockerConfig(ctx, workloadPod("app", "missing", "hubcred"), hubRepository)
	require.NoError(t, err)
	require.Contains(t, string(config), hubLogin.password, "the Docker Hub login, found under docker.io")
	_, err = credentials.DockerConfig(ctx, workloadPod("app", "broken"), privateRepository)
	require.ErrorContains(t, err, "a pull secret of the pod doesn't hold Docker credentials that can be read",
		"the parser's error, which can quote the Secret, goes no further")

	captured := capture.String() + err.Error()
	require.Contains(t, captured, "missing", "the missing Secret is logged by name")
	for _, value := range []string{login.password, login.identityToken, encoded, "never-logged-broken", hubLogin.password} {
		require.NotContains(t, captured, value)
	}
}

// A repository that isn't a reference can't be pulled, so it has no credentials.
func TestDockerConfigRefusesARepositoryThatIsNotOne(t *testing.T) {
	_, err := scan.NewKeychainCredentials(fake.NewClientset(serviceAccount("app"))).
		DockerConfig(t.Context(), workloadPod("app"), "Artifacts.Example/Team A")

	require.ErrorContains(t, err, "Artifacts.Example/Team A")
}

// An error of the API server names the Secret, and never holds its content, so it says what went
// wrong as it is: the request is tried again, and the Scanner shows why.
func TestDockerConfigReturnsTheErrorsOfTheAPIServer(t *testing.T) {
	clientset := fake.NewClientset(serviceAccount("app"))
	clientset.PrependReactor("get", "secrets", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "regcred", errors.New("denied"))
	})

	_, err := scan.NewKeychainCredentials(clientset).DockerConfig(t.Context(), workloadPod("app", "regcred"), privateRepository)

	require.True(t, apierrors.IsForbidden(err), "the API server's error stays an error of its kind: %v", err)
	require.ErrorContains(t, err, `secrets "regcred" is forbidden`)
}

// A request that never reaches the API server fails with the request in its text, which names the
// Secret and holds nothing of it.
func TestDockerConfigReturnsAFailedRequest(t *testing.T) {
	unreachable, err := kubernetes.NewForConfig(&rest.Config{Host: "http://127.0.0.1:1", Timeout: time.Second})
	require.NoError(t, err)

	_, err = scan.NewKeychainCredentials(unreachable).DockerConfig(t.Context(), workloadPod("app", "regcred"), privateRepository)

	require.ErrorContains(t, err, "regcred")
	require.NotContains(t, err.Error(), "doesn't hold Docker credentials", "a failed request is no bad pull secret")
}
