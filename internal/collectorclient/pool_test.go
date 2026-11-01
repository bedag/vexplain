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

package collectorclient_test

import (
	"crypto/tls"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/collector/certs"
	"github.com/bedag/vexplain/internal/collectorclient"
	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
	"github.com/bedag/vexplain/sdk/subject"
)

func TestThePoolCallsACollectorAtItsServiceOverMutualTLS(t *testing.T) {
	e := newEnv(t)
	e.serve("hello-pool", newHello(collector.RoleSpoke, collector.RoleHub))
	ctx := t.Context()

	info, err := e.pool.Info(ctx, "hello-pool")
	require.NoError(t, err)
	require.Equal(t, "hello", info.GetName())
	require.Equal(t, "0.1.0", info.GetVersion())
	require.Equal(t, []string{"v1alpha1"}, info.GetApiVersions())

	capabilities, err := e.pool.Capabilities(ctx, "hello-pool")
	require.NoError(t, err)
	require.True(t, capabilities.GetWatches())
	require.Equal(t, []collectorv1alpha1.Role{collectorv1alpha1.Role_ROLE_SPOKE, collectorv1alpha1.Role_ROLE_HUB},
		capabilities.GetRoles())
	require.Len(t, capabilities.GetProduces(), 1)
	require.Equal(t, helloType, capabilities.GetProduces()[0].GetType())

	problems, err := e.pool.ValidateSettings(ctx, "hello-pool", []byte(`{"greeting": "hello"}`))
	require.NoError(t, err)
	require.Empty(t, problems)
	problems, err = e.pool.ValidateSettings(ctx, "hello-pool", []byte(`{"greeting": 1}`))
	require.NoError(t, err)
	require.NotEmpty(t, problems, "the settings break the collector's settings schema")

	require.NoError(t, e.pool.Health(ctx, "hello-pool"))

	require.Equal(t, []string{"vexplain-collector-hello-pool.vexplain-system.svc:9443"}, e.dialedAddresses(),
		"the pool reaches the collector at its Service, on port 9443, and keeps one connection for all its calls")
}

func TestThePoolChecksTheNameInTheCollectorsCertificate(t *testing.T) {
	e := newEnv(t)
	// What answers at the address of hello-name is hello-other, with its certificate, which the same authority
	// issued, but for the name of hello-other's Service.
	e.route("hello-name", e.serve("hello-other", newHello(collector.RoleSpoke)))

	_, err := e.pool.Info(t.Context(), "hello-name")
	require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
	_, err = e.pool.Info(t.Context(), "hello-other")
	require.NoError(t, err, "the collector answers under its own name")
}

// The pool asks for its TLS at each connection, so that a renewed client certificate or a new authority takes effect
// at the next connection, without a restart of the operator. Each start of the operator creates a new authority,
// which issues every collector's certificate again, and a collector loads its new files a little later.
func TestAConnectionMadeAfterTheAuthorityChangesTrustsTheNewAuthority(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	first := e.authority
	// current is the authority whose TLS the pool takes, when the pool asks for it.
	var current atomic.Pointer[certs.Authority]
	pool := e.newPool(func() (*tls.Config, error) { return current.Load().ClientTLS() })

	listener := listen(t)
	e.route("hello-ca", listener.Addr().String())
	stopFirst := startServer(t, newHello(collector.RoleSpoke), e.tlsFiles(first, "hello-ca"), listener)

	// Before the authority exists, the pool has no TLS, and gets through to no collector.
	current.Store(certs.NewAuthority(e.api, e.api, namespace, time.Now))
	_, err := pool.Info(ctx, "hello-ca")
	require.Error(t, err)

	// Once it exists, the next connection of the same pool gets through.
	current.Store(first)
	require.Eventually(t, func() bool {
		_, err := pool.Info(ctx, "hello-ca")
		return err == nil
	}, wait, tick)

	// The authority changes, and the collector loads the certificate that the new one issued. The connection that
	// the pool makes then trusts the new authority, and presents a certificate that the new authority issued.
	second := certs.NewAuthority(e.api, e.api, namespace, time.Now)
	stopFirst()
	listener = listen(t)
	e.route("hello-ca", listener.Addr().String())
	startServer(t, newHello(collector.RoleSpoke), e.tlsFiles(second, "hello-ca"), listener)
	current.Store(second)
	require.Eventually(t, func() bool {
		_, err := pool.Info(ctx, "hello-ca")
		return err == nil
	}, wait, tick)
}

func TestHealthIsTheStandardHealthCheck(t *testing.T) {
	e := newEnv(t)
	r := newRaw()
	e.serveRaw("hello-health", r)

	require.NoError(t, e.pool.Health(t.Context(), "hello-health"))
	r.health.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	require.Error(t, e.pool.Health(t.Context(), "hello-health"))
	r.health.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	require.NoError(t, e.pool.Health(t.Context(), "hello-health"))

	e.unroute("hello-health")
	e.pool.Forget("hello-health")
	require.Error(t, e.pool.Health(t.Context(), "hello-health"), "a collector that can't be reached isn't healthy")
}

func TestForgetClosesTheConnection(t *testing.T) {
	e := newEnv(t)
	e.serve("hello-forget", newHello(collector.RoleSpoke))
	ctx := t.Context()

	_, err := e.pool.Info(ctx, "hello-forget")
	require.NoError(t, err)
	require.True(t, e.pool.Connected("hello-forget"))
	e.pool.Forget("hello-forget")
	require.False(t, e.pool.Connected("hello-forget"))
	e.pool.Forget("hello-forget")
	e.pool.Forget("hello-never")

	_, err = e.pool.Info(ctx, "hello-forget")
	require.NoError(t, err, "a call after Forget connects again")
	require.Equal(t, []string{address("hello-forget"), address("hello-forget")}, e.dialedAddresses())
}

func TestThePoolCompressesItsCallsAndTakesMessagesUpTo16MiB(t *testing.T) {
	e := newEnv(t)
	r := newRaw()
	e.serveRaw("hello-gzip", r)
	require.NoError(t, e.pool.Health(t.Context(), "hello-gzip"))
	require.Equal(t, []string{"gzip"}, r.compressionsOfCalls())

	// An answer of 5 MiB, more than gRPC takes by default.
	big := eventOf(t, helloType, subject.Image(digest(1)), map[string]string{"blob": strings.Repeat("a", 5<<20)})
	h := newHello(collector.RoleSpoke)
	h.greeter = func(collector.InvokeRequest) ([]cloudevents.Event, *collector.Failure, error) {
		return []cloudevents.Event{big}, nil, nil
	}
	e.serve("hello-big", h)
	events, failure, err := e.pool.Invoke(t.Context(), "hello-big", greeting(1))
	require.NoError(t, err)
	require.Nil(t, failure)
	require.Equal(t, ids(big), ids(events...))
	require.Equal(t, big.Data(), events[0].Data())
}

// greeting is a request of the operation greet for the image of digest(n), in the spoke's role.
func greeting(n int) *collectorv1alpha1.InvokeRequest {
	return &collectorv1alpha1.InvokeRequest{
		Operation: greet,
		Subject:   subject.Image(digest(n)),
		Role:      collectorv1alpha1.Role_ROLE_SPOKE,
	}
}

func TestACallToANameThatNoCollectorCanHaveFails(t *testing.T) {
	e := newEnv(t)
	for _, name := range []string{"", "Hello", "hello.other-namespace", "hello:8080", "hello/path"} {
		_, err := e.pool.Info(t.Context(), name)
		require.Error(t, err, "%q", name)
	}
	require.Empty(t, e.dialedAddresses(), "the pool dials nothing for a name that no Collector can have")
}

func TestUsable(t *testing.T) {
	t.Parallel()
	collectorWith := func(capabilities bool, ready ...metav1.Condition) *configv1alpha1.Collector {
		c := &configv1alpha1.Collector{ObjectMeta: metav1.ObjectMeta{Name: "hello"}}
		if capabilities {
			c.Status.Capabilities = &configv1alpha1.CollectorCapabilities{
				Roles: []configv1alpha1.CollectorRole{configv1alpha1.CollectorRoleSpoke},
				Watch: configv1alpha1.CollectorWatchSupported,
			}
		}
		for _, condition := range ready {
			meta.SetStatusCondition(&c.Status.Conditions, condition)
		}
		return c
	}
	condition := func(value metav1.ConditionStatus, reason string) metav1.Condition {
		return metav1.Condition{Type: configv1alpha1.ConditionReady, Status: value, Reason: reason}
	}
	deleting := collectorWith(true, condition(metav1.ConditionTrue, configv1alpha1.ReasonHealthy))
	deleting.DeletionTimestamp = &metav1.Time{Time: time.Now()}

	for name, tc := range map[string]struct {
		collector *configv1alpha1.Collector
		usable    bool
	}{
		"recorded capabilities, and no Ready yet": {collectorWith(true), true},
		"NoData, until the first health check": {
			collectorWith(true, condition(metav1.ConditionUnknown, configv1alpha1.ReasonNoData)), true},
		"Progressing, while the Deployment rolls out": {
			collectorWith(true, condition(metav1.ConditionUnknown, configv1alpha1.ReasonProgressing)), true},
		"Healthy": {collectorWith(true, condition(metav1.ConditionTrue, configv1alpha1.ReasonHealthy)), true},
		"no capabilities recorded": {
			collectorWith(false, condition(metav1.ConditionUnknown, configv1alpha1.ReasonNoData)), false},
		"CollectorFailing": {
			collectorWith(true, condition(metav1.ConditionFalse, configv1alpha1.ReasonCollectorFailing)), false},
		"PackageInvalid": {
			collectorWith(true, condition(metav1.ConditionFalse, configv1alpha1.ReasonPackageInvalid)), false},
		"IncompatibleAPI": {
			collectorWith(true, condition(metav1.ConditionFalse, configv1alpha1.ReasonIncompatibleAPI)), false},
		"SettingsInvalid": {
			collectorWith(true, condition(metav1.ConditionFalse, configv1alpha1.ReasonSettingsInvalid)), false},
		"MissingPermissions": {
			collectorWith(true, condition(metav1.ConditionFalse, configv1alpha1.ReasonMissingPermissions)), false},
		"RuntimeConfigInvalid": {
			collectorWith(true, condition(metav1.ConditionFalse, configv1alpha1.ReasonRuntimeConfigInvalid)), false},
		"WrongRole, from phase 6": {collectorWith(true, condition(metav1.ConditionFalse, "WrongRole")), false},
		// The reasons are an open set. A collector that is False for a reason that this version doesn't know gets
		// no requests: what it would deliver is missing, and missing evidence settles nothing.
		"False for a reason that this version doesn't know": {
			collectorWith(true, condition(metav1.ConditionFalse, "SomethingNew")), false},
		"being deleted": {deleting, false},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.usable, collectorclient.Usable(tc.collector))
		})
	}
}
