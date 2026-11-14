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
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/google/go-containerregistry/pkg/logs"
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

	"github.com/bedag/vexplain/collectors/scanner/internal/scan"
)

// These tests cover the logins of a scan Job: one config.json for each pull secret that holds a login for the
// registry, which NewKeychainCredentials builds from a pod's pull secrets, the way the kubelet finds them, and from the
// Secrets that the admin provides (decision 0047). The scan's keychain reads them back, in their order: its tests are
// in cmd. The Secrets and service accounts live in a fake clientset.

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
	// appPod is the pod whose credentials the tests build.
	appPod = "app-0"
	// adminOpaque names a Secret that the admin provides, of another type than a pull secret's.
	adminOpaque = "admin-opaque"
	// podPuller and saPuller are the users of the logins of a pod's pull secret and of its service account's, and
	// regcred and saCred name those pull secrets, as a failure names them.
	podPuller = "pod-puller"
	saPuller  = "sa-puller"
	regcred   = "team-a/regcred"
	saCred    = "team-a/sa-cred"
)

// registryLogin is what a pull secret holds for one registry. Each test gives its logins values of
// their own, so that a test can tell which Secret a credential came from.
type registryLogin struct {
	username, password, identityToken string
}

// pullSecret returns a Secret of the type kubernetes.io/dockerconfigjson in the pod's namespace, named secretName, that
// holds a login for each registry, as kubectl create secret docker-registry writes it.
func pullSecret(secretName string, logins map[string]registryLogin) *corev1.Secret {
	return pullSecretIn(credentialsNamespace, secretName, logins)
}

// pullSecretIn is pullSecret in the namespace.
func pullSecretIn(namespace, secretName string, logins map[string]registryLogin) *corev1.Secret {
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
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: secretName},
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

// newCredentials returns the credentials of a scan over a clientset that holds objs, with the Secrets that the admin
// provides in ownNamespace.
func newCredentials(objs ...runtime.Object) scan.CredentialSource {
	return scan.NewKeychainCredentials(fake.NewClientset(objs...), ownNamespace)
}

// credentialsOf builds the credentials for pulling repository with those of pod, and of the Secrets of admin, over a
// clientset that holds objs.
func credentialsOf(t *testing.T, pod *corev1.Pod, repository string, admin []string,
	objs ...runtime.Object) scan.Credentials {
	t.Helper()
	credentials, err := newCredentials(objs...).Credentials(t.Context(), pod, repository, admin)
	require.NoError(t, err)
	return credentials
}

// loginsOf returns the logins of credentialsOf.
func loginsOf(t *testing.T, pod *corev1.Pod, repository string, admin []string, objs ...runtime.Object) []scan.Login {
	t.Helper()
	return credentialsOf(t, pod, repository, admin, objs...).Logins
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

// tried is a login that a test expects: the pull secret, as namespace/name, and the auths of its config.
type tried struct {
	secret string
	auths  map[string]configEntry
}

// triedOf decodes logins into what a test expects of them.
func triedOf(t *testing.T, logins []scan.Login) []tried {
	t.Helper()
	out := make([]tried, 0, len(logins))
	for _, login := range logins {
		out = append(out, tried{secret: login.Secret, auths: authsOf(t, login.Config)})
	}
	return out
}

func TestTheLoginsHoldThePullSecretsOfThePod(t *testing.T) {
	login := registryLogin{username: podUsername, password: podPassword}
	pod := workloadPod("app", "regcred")

	logins := loginsOf(t, pod, privateRepository, nil,
		pullSecret("regcred", map[string]registryLogin{privateRegistry: login}), serviceAccount("app"))

	require.Equal(t, []tried{{regcred, map[string]configEntry{privateRegistry: entryFor(login)}}},
		triedOf(t, logins))
}

func TestTheLoginsHoldThePullSecretsOfTheServiceAccount(t *testing.T) {
	login := registryLogin{username: "builder-puller", password: saPassword}
	pod := workloadPod("builder")

	logins := loginsOf(t, pod, privateRepository, nil,
		pullSecret("builder-cred", map[string]registryLogin{privateRegistry: login}),
		serviceAccount("builder", "builder-cred"))

	require.Equal(t, []tried{{"team-a/builder-cred", map[string]configEntry{privateRegistry: entryFor(login)}}},
		triedOf(t, logins))
}

// The kubelet reads the pull secrets of the pod and those of its service account together, the pod's first, and tries
// each login for the registry until one works. So does the scan: each pull secret that holds a login for the
// repository's registry gives a login of its own, the pod's first, and each holds that registry's login only, wherever
// it came from.
func TestTheLoginsReadThePodAndItsServiceAccountTogether(t *testing.T) {
	podLogin := registryLogin{username: podPuller, password: podPassword}
	saLogin := registryLogin{username: saPuller, password: saPassword}
	saOtherLogin := registryLogin{username: "sa-other-puller", password: "sa-other-password"}
	objs := []runtime.Object{
		pullSecret("pod-cred", map[string]registryLogin{privateRegistry: podLogin}),
		pullSecret("sa-cred", map[string]registryLogin{privateRegistry: saLogin, otherRegistry: saOtherLogin}),
		serviceAccount("app", "sa-cred"),
	}
	pod := workloadPod("app", "pod-cred")

	require.Equal(t, []tried{
		{"team-a/pod-cred", map[string]configEntry{privateRegistry: entryFor(podLogin)}},
		{saCred, map[string]configEntry{privateRegistry: entryFor(saLogin)}},
	}, triedOf(t, loginsOf(t, pod, privateRepository, nil, objs...)), "the pod's own pull secret comes first")
	require.Equal(t, []tried{{saCred, map[string]configEntry{otherRegistry: entryFor(saOtherLogin)}}},
		triedOf(t, loginsOf(t, pod, otherRepository, nil, objs...)), "the service account's pull secret fills in")
}

// The logins of the workload come first (CopyFromWorkload), then those of the Secrets that the admin lists in
// adminPullSecrets, in their order, from the operator's namespace (AdminProvided). A Secret that holds no login for
// the registry, or doesn't exist, adds no login, and a Secret that both the pod and its service account name is tried
// once. The credentials name the admin's Secrets that gave no login: those that don't exist, and those that hold none
// for the registry, such as one of another type.
func TestTheWorkloadsLoginsComeBeforeTheAdmins(t *testing.T) {
	podLogin := registryLogin{username: podPuller, password: podPassword}
	saLogin := registryLogin{username: saPuller, password: saPassword}
	adminLogin := registryLogin{username: "admin-puller", password: "admin-password"}
	secondAdminLogin := registryLogin{username: "second-admin-puller", password: "second-admin-password"}
	objs := []runtime.Object{
		pullSecret("pod-cred", map[string]registryLogin{privateRegistry: podLogin}),
		pullSecret("sa-cred", map[string]registryLogin{privateRegistry: saLogin}),
		serviceAccount("app", "pod-cred", "sa-cred"),
		pullSecretIn(ownNamespace, "admin-b", map[string]registryLogin{privateRegistry: secondAdminLogin}),
		pullSecretIn(ownNamespace, "admin-a", map[string]registryLogin{privateRegistry: adminLogin}),
		pullSecretIn(ownNamespace, "admin-other", map[string]registryLogin{otherRegistry: adminLogin}),
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: ownNamespace, Name: adminOpaque},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"password": []byte(adminLogin.password)},
		},
		// A Secret of the same name in the pod's namespace is the workload's, and never the admin's.
		pullSecret("admin-a", map[string]registryLogin{privateRegistry: podLogin}),
	}

	credentials := credentialsOf(t, workloadPod("app", "pod-cred"), privateRepository,
		[]string{"admin-a", "admin-missing", "admin-other", adminOpaque, "admin-b"}, objs...)

	require.Equal(t, []string{"admin-missing"}, credentials.Missing)
	require.Equal(t, []string{"admin-other", adminOpaque}, credentials.NoLogin)
	logins := credentials.Logins
	require.Equal(t, []tried{
		{"team-a/pod-cred", map[string]configEntry{privateRegistry: entryFor(podLogin)}},
		{saCred, map[string]configEntry{privateRegistry: entryFor(saLogin)}},
		{"vexplain-system/admin-a", map[string]configEntry{privateRegistry: entryFor(adminLogin)}},
		{"vexplain-system/admin-b", map[string]configEntry{privateRegistry: entryFor(secondAdminLogin)}},
	}, triedOf(t, logins))
}

// A Secret that the workload names and adminPullSecrets names too, as for a pod in the operator's namespace, is tried
// once, as the workload's, and isn't one of the admin's that gave no login.
func TestASecretThatTheWorkloadAndTheAdminNameIsTriedOnce(t *testing.T) {
	login := registryLogin{username: podUsername, password: podPassword}
	pod := workloadPod("app", "admin-a")
	pod.Namespace = ownNamespace
	sa := serviceAccount("app")
	sa.Namespace = ownNamespace

	credentials := credentialsOf(t, pod, privateRepository, []string{"admin-a"},
		pullSecretIn(ownNamespace, "admin-a", map[string]registryLogin{privateRegistry: login}), sa)

	require.Equal(t, []tried{{"vexplain-system/admin-a", map[string]configEntry{privateRegistry: entryFor(login)}}},
		triedOf(t, credentials.Logins))
	require.Empty(t, credentials.Missing)
	require.Empty(t, credentials.NoLogin)
}

// A public image needs no credentials: without a login for its registry, the scan pulls it anonymously. Credentials
// for other registries never go into the Job's Secret.
func TestThereAreNoLoginsForAnAnonymousPull(t *testing.T) {
	login := registryLogin{username: "other-puller", password: "other-registry-password"}
	pod := workloadPod("app", "regcred")

	logins := loginsOf(t, pod, hubRepository, []string{"admin-pull"},
		pullSecret("regcred", map[string]registryLogin{otherRegistry: login}), serviceAccount("app"),
		pullSecretIn(ownNamespace, "admin-pull", map[string]registryLogin{privateRegistry: login}))

	require.Empty(t, logins)
}

// A pod can name a pull secret that doesn't exist; the kubelet then pulls without it. The scan does
// the same: the missing Secret adds nothing, and is no error.
func TestTheLoginsSkipAPullSecretThatDoesNotExist(t *testing.T) {
	login := registryLogin{username: podUsername, password: podPassword}
	objs := []runtime.Object{pullSecret("regcred", map[string]registryLogin{privateRegistry: login}), serviceAccount("app")}

	logins := loginsOf(t, workloadPod("app", "missing", "regcred"), privateRepository, nil, objs...)
	require.Equal(t, []tried{{regcred, map[string]configEntry{privateRegistry: entryFor(login)}}},
		triedOf(t, logins))

	require.Empty(t, loginsOf(t, workloadPod("app", "missing"), privateRepository, nil, objs...))
	require.Empty(t, loginsOf(t, workloadPod("missing-account"), privateRepository, nil, objs...),
		"a service account that doesn't exist adds nothing either")
}

// The scan's keychain looks up Docker Hub under Docker's historical key and every other registry under its host, as
// go-containerregistry's DefaultKeychain does. So each login is held under that key, whatever key its pull secret
// used, as the round trip through the scan's keychain in cmd shows.
func TestEachLoginIsHeldUnderTheKeyOfItsRegistry(t *testing.T) {
	login := registryLogin{username: hubUsername, password: "key-password"}
	cases := []struct {
		name           string
		repository     string
		secretRegistry string // the key of the pull secret, as people write it
		key            string
		login          registryLogin
	}{
		{"Docker Hub", hubRepository, hubKey, hubKey, login},
		// kubectl create secret docker-registry --docker-server=docker.io writes this key, and the
		// kubelet matches it against Docker Hub.
		{"Docker Hub under docker.io", hubRepository, dockerIOKey, hubKey, login},
		{"Docker Hub under docker.io and an organisation", hubRepository, dockerIOKey + "/team-a", hubKey, login},
		{"an official Docker Hub image under docker.io", "docker.io/library/nginx", dockerIOKey, hubKey, login},
		{"another registry", privateRepository, privateRegistry, privateRegistry, login},
		{"a registry with a port", otherRepository, "https://" + otherRegistry, otherRegistry, login},
		{"an identity token", privateRepository, privateRegistry, privateRegistry,
			registryLogin{username: "<token>", identityToken: "refresh-token-value"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logins := loginsOf(t, workloadPod("app", "regcred"), tc.repository, nil,
				pullSecret("regcred", map[string]registryLogin{tc.secretRegistry: tc.login}), serviceAccount("app"))

			require.Equal(t, []tried{{regcred, map[string]configEntry{tc.key: entryFor(tc.login)}}},
				triedOf(t, logins))
		})
	}
}

// A pull secret keyed docker.io is for Docker Hub, and for no other registry; one keyed with an
// organisation of Docker Hub is for that organisation alone.
func TestTheLoginsMatchDockerIOKeysOnlyOnDockerHub(t *testing.T) {
	login := registryLogin{username: hubUsername, password: dockerIOPassword}
	objs := []runtime.Object{
		pullSecret("hubcred", map[string]registryLogin{dockerIOKey: login}),
		pullSecret("teamcred", map[string]registryLogin{dockerIOKey + "/team-b": login}),
		serviceAccount("app"),
	}

	require.Empty(t, loginsOf(t, workloadPod("app", "hubcred"), privateRepository, nil, objs...),
		"a docker.io key gives nothing for another registry")
	require.Empty(t, loginsOf(t, workloadPod("app", "teamcred"), hubRepository, nil, objs...),
		"a key of another organisation gives nothing")
}

// Docker Hub is looked up under docker.io only when a pull secret holds nothing under its own name for it,
// index.docker.io. Each pull secret gives its login, the pod's before its service account's.
func TestTheLoginsLookUpDockerIOOnlyWhenDockerHubFoundNothing(t *testing.T) {
	indexLogin := registryLogin{username: "index-puller", password: "index-password"}
	dockerIOLogin := registryLogin{username: "docker-io-puller", password: dockerIOPassword}
	both := pullSecret("bothcred", map[string]registryLogin{hubKey: indexLogin, dockerIOKey: dockerIOLogin})

	logins := loginsOf(t, workloadPod("app", "bothcred"), hubRepository, nil, both, serviceAccount("app"))
	require.Equal(t, []tried{{"team-a/bothcred", map[string]configEntry{hubKey: entryFor(indexLogin)}}},
		triedOf(t, logins))

	podLogin := registryLogin{username: podPuller, password: podPassword}
	saLogin := registryLogin{username: saPuller, password: saPassword}
	logins = loginsOf(t, workloadPod("builder", "podcred"), hubRepository, nil,
		pullSecret("podcred", map[string]registryLogin{dockerIOKey: podLogin}),
		pullSecret("sacred", map[string]registryLogin{dockerIOKey: saLogin}),
		serviceAccount("builder", "sacred"))
	require.Equal(t, []tried{
		{"team-a/podcred", map[string]configEntry{hubKey: entryFor(podLogin)}},
		{"team-a/sacred", map[string]configEntry{hubKey: entryFor(saLogin)}},
	}, triedOf(t, logins))
}

// logCapture holds what every logger that the credentials could reach writes: go-containerregistry's
// loggers, the logger in the context, and slog's default logger, which the collector logs through.
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

// captureLogs sends go-containerregistry's loggers and slog's default logger to a capture until the test ends, and
// returns it with a context whose logger writes there too, at every verbosity.
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
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(capture, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	sink := funcr.New(func(prefix, args string) {
		_, _ = fmt.Fprintln(capture, prefix, args)
	}, funcr.Options{Verbosity: 10})
	return capture, logr.NewContext(t.Context(), sink)
}

// The values of pull secrets never appear in a log or an error. A Secret that doesn't parse fails with its name, and
// without its content, whether the workload or the admin provides it.
func TestTheLoginsNeverLogTheCredentials(t *testing.T) {
	capture, ctx := captureLogs(t)
	login := registryLogin{username: podUsername, password: "never-logged-password", identityToken: "never-logged-token"}
	encoded := base64.StdEncoding.EncodeToString([]byte(login.username + ":" + login.password))
	malformed := func(namespace string) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "broken"},
			Type:       corev1.SecretTypeDockerConfigJson,
			Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{"` + privateRegistry +
				`":{"auth":"never-logged-broken`)},
		}
	}
	hubLogin := registryLogin{username: hubUsername, password: "never-logged-hub-password"}
	credentials := newCredentials(
		pullSecret("regcred", map[string]registryLogin{privateRegistry: login}), malformed(credentialsNamespace),
		malformed(ownNamespace), pullSecret("hubcred", map[string]registryLogin{dockerIOKey: hubLogin}),
		serviceAccount("app"))

	found, err := credentials.Credentials(ctx, workloadPod("app", "missing", "regcred"), privateRepository, nil)
	require.NoError(t, err)
	require.Len(t, found.Logins, 1)
	require.Contains(t, string(found.Logins[0].Config), login.password, "the config.json itself holds the credentials")
	found, err = credentials.Credentials(ctx, workloadPod("app", "missing", "hubcred"), hubRepository, nil)
	require.NoError(t, err)
	require.Len(t, found.Logins, 1)
	require.Contains(t, string(found.Logins[0].Config), hubLogin.password, "the Docker Hub login, found under docker.io")
	_, err = credentials.Credentials(ctx, workloadPod("app", "broken"), privateRepository, nil)
	require.EqualError(t, err, "read pull secret team-a/broken: it doesn't hold Docker credentials that can be read",
		"the parser's error, which can quote the Secret, goes no further")
	captured := capture.String() + err.Error()
	_, err = credentials.Credentials(ctx, workloadPod("app"), privateRepository, []string{"broken"})
	require.EqualError(t, err,
		"read pull secret vexplain-system/broken: it doesn't hold Docker credentials that can be read")

	captured += err.Error()
	for _, value := range []string{login.password, login.identityToken, encoded, "never-logged-broken", hubLogin.password} {
		require.NotContains(t, captured, value)
	}
}

// A repository that isn't a reference can't be pulled, so it has no credentials.
func TestTheLoginsRefuseARepositoryThatIsNotOne(t *testing.T) {
	_, err := newCredentials(serviceAccount("app")).Credentials(t.Context(), workloadPod("app"),
		"Artifacts.Example/Team A", nil)

	require.ErrorContains(t, err, "Artifacts.Example/Team A")
}

// An error of the API server names the Secret, and never holds its content, so it says what went
// wrong as it is: the request is tried again, and the Scanner shows why.
func TestTheLoginsReturnTheErrorsOfTheAPIServer(t *testing.T) {
	for name, admin := range map[string][]string{"the workload's": nil, "the admin's": {"regcred"}} {
		t.Run(name, func(t *testing.T) {
			pod := workloadPod("app", "regcred")
			if admin != nil {
				pod = workloadPod("app")
			}
			clientset := fake.NewClientset(serviceAccount("app"))
			clientset.PrependReactor("get", "secrets", func(clienttesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "regcred",
					errors.New("denied"))
			})

			_, err := scan.NewKeychainCredentials(clientset, ownNamespace).Credentials(t.Context(), pod, privateRepository,
				admin)

			require.True(t, apierrors.IsForbidden(err), "the API server's error stays an error of its kind: %v", err)
			require.ErrorContains(t, err, `secrets "regcred" is forbidden`)
		})
	}
}

// A request that never reaches the API server fails with the request in its text, which names the
// Secret and holds nothing of it.
func TestTheLoginsReturnAFailedRequest(t *testing.T) {
	unreachable, err := kubernetes.NewForConfig(&rest.Config{Host: "http://127.0.0.1:1", Timeout: time.Second})
	require.NoError(t, err)

	_, err = scan.NewKeychainCredentials(unreachable, ownNamespace).Credentials(t.Context(),
		workloadPod("app", "regcred"), privateRepository, nil)

	require.ErrorContains(t, err, "regcred")
	require.NotContains(t, err.Error(), "doesn't hold Docker credentials", "a failed request is no bad pull secret")
}
