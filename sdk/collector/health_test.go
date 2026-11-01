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

package collector_test

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
)

func TestGRPCHealthCheckAnswersServing(t *testing.T) {
	s := serve(t, &fakeCollector{caps: capabilities()})
	client := healthpb.NewHealthClient(s.conn)

	// The deployer checks the server as a whole, and a client may check each service of the API.
	for _, service := range []string{"", "vexplain.collector.v1alpha1.Identity", "vexplain.collector.v1alpha1.Evidence"} {
		resp, err := client.Check(callContext(t), &healthpb.HealthCheckRequest{Service: service})
		require.NoError(t, err, service)
		require.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus(), service)
	}
}

func TestReadyzAnswers503UntilTheCertificatesLoad(t *testing.T) {
	dir := t.TempDir()
	r := start(t, &fakeCollector{caps: capabilities()}, collector.Options{TLSDir: dir}, bufconn.Listen(bufferSize))
	ready := func() bool { return httpStatus(r.health+"/readyz") == http.StatusOK }

	require.Equal(t, http.StatusServiceUnavailable, httpStatus(r.health+"/readyz"))
	require.Equal(t, http.StatusOK, httpStatus(r.health+"/healthz"), "a server that waits for its certificates is alive")
	require.Never(t, ready, 10*reload, reload, "no certificates, not ready")

	ca := newAuthority(t)
	install(t, dir, ca.issue(t, x509.ExtKeyUsageServerAuth), ca)
	require.Eventually(t, ready, wait, reload)
	require.Equal(t, http.StatusOK, httpStatus(r.health+"/healthz"))
}

func TestHealthWhileTheServerStops(t *testing.T) {
	release := make(chan struct{})
	c := &fakeCollector{caps: capabilities(), watch: func(ctx context.Context, _ collector.WatchRequest,
		sink collector.Sink) error {
		if err := sink.SnapshotStart(); err != nil {
			return err
		}
		<-ctx.Done()
		// The collector takes its time to end the call, and the server waits for it.
		<-release
		return ctx.Err()
	}}
	listener := bufconn.Listen(bufferSize)
	r := start(t, c, collector.Options{Insecure: true}, listener)
	conn := dial(t, listener)
	require.Eventually(t, func() bool { return httpStatus(r.health+"/readyz") == http.StatusOK }, wait, reload)

	checksCtx, stopChecks := context.WithCancel(callContext(t))
	checks, err := healthpb.NewHealthClient(conn).Watch(checksCtx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	check, err := checks.Recv()
	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_SERVING, check.GetStatus())
	stream, err := collectorv1alpha1.NewEvidenceClient(conn).Watch(callContext(t), watchRequest())
	require.NoError(t, err)
	_, err = stream.Recv()
	require.NoError(t, err)

	r.cancel()
	check, err = checks.Recv()
	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, check.GetStatus())
	stopChecks()
	require.Eventually(t, func() bool { return httpStatus(r.health+"/readyz") == http.StatusServiceUnavailable },
		wait, reload)
	require.Equal(t, http.StatusOK, httpStatus(r.health+"/healthz"), "a stopping server is alive")

	close(release)
	require.NoError(t, r.stop())
}

func TestReadyzWithoutTLS(t *testing.T) {
	s := serve(t, &fakeCollector{caps: capabilities()})

	require.Eventually(t, func() bool { return httpStatus(s.health+"/readyz") == http.StatusOK }, wait, reload)
	require.Equal(t, http.StatusOK, httpStatus(s.health+"/healthz"))
}

// scrape returns what /metrics serves.
func scrape(t *testing.T, health string) string {
	t.Helper()
	resp, err := httpClient.Get(health + "/metrics")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func TestMetricsCountTheCallsOfTheCollectorAPI(t *testing.T) {
	s := serve(t, &fakeCollector{caps: capabilities(), watch: func(_ context.Context, _ collector.WatchRequest,
		sink collector.Sink) error {
		if err := sink.SnapshotStart(); err != nil {
			return err
		}
		return sink.SnapshotEnd()
	}})

	_, err := s.identityClient().GetInfo(callContext(t), &collectorv1alpha1.GetInfoRequest{})
	require.NoError(t, err)
	watch, err := s.evidenceClient().Watch(callContext(t), watchRequest())
	require.NoError(t, err)
	_, err = receiveAll(watch)
	require.NoError(t, err)
	unknown := invokeRequest(t)
	unknown.Operation = "wave"
	invoke, err := s.evidenceClient().Invoke(callContext(t), unknown)
	require.NoError(t, err)
	_, err = receiveAll(invoke)
	require.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = healthpb.NewHealthClient(s.conn).Check(callContext(t), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)

	metrics := scrape(t, s.health)
	// A call without a context, such as those of Identity, counts for no cluster.
	require.Contains(t, metrics, `vexplain_collector_requests_total{cluster="",code="OK",method="GetInfo"} 1`)
	require.Contains(t, metrics, `vexplain_collector_requests_total{cluster="cluster-a",code="OK",method="Watch"} 1`)
	require.Contains(t, metrics,
		`vexplain_collector_requests_total{cluster="cluster-a",code="Unimplemented",method="Invoke"} 1`)
	require.NotContains(t, metrics, `method="Check"`, "the health service's calls don't count")
	for line := range strings.Lines(metrics) {
		if strings.HasPrefix(line, "#") {
			continue
		}
		require.True(t, strings.HasPrefix(line, "vexplain_"), "every metric is vexplain's: %s", line)
		require.Contains(t, line, `cluster="`, "every metric names its cluster")
	}
}

func TestMetricsGoToTheRegistryOfTheOptions(t *testing.T) {
	registry := prometheus.NewRegistry()
	greetings := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_hello_greetings_total",
		Help: "The greetings of the fake collector.",
	}, []string{"cluster"})
	registry.MustRegister(greetings)
	greetings.WithLabelValues(clusterA).Inc()
	opts := collector.Options{Insecure: true, Registry: registry}

	// Two servers can share a registry, as the tests of a collector may.
	for range 2 {
		s := serveWith(t, plainCollector{}, opts)
		_, err := s.identityClient().GetInfo(callContext(t), &collectorv1alpha1.GetInfoRequest{})
		require.NoError(t, err)

		metrics := scrape(t, s.health)
		require.Contains(t, metrics, `vexplain_hello_greetings_total{cluster="cluster-a"} 1`,
			"/metrics serves the collector's own metrics")
		require.Contains(t, metrics, `vexplain_collector_requests_total{cluster="",code="OK",method="GetInfo"}`)
	}
	families, err := registry.Gather()
	require.NoError(t, err)
	var counted float64
	for _, family := range families {
		if family.GetName() == "vexplain_collector_requests_total" {
			for _, metric := range family.GetMetric() {
				counted += metric.GetCounter().GetValue()
			}
		}
	}
	require.Equal(t, float64(2), counted, "both servers count into the registry")
}

func TestServeRefusesARegistryThatItCannotServe(t *testing.T) {
	// A wrapped registry takes metrics, but /metrics can't gather them from it.
	wrapped := prometheus.WrapRegistererWithPrefix("vexplain_", prometheus.NewRegistry())
	requireRefused(t, plainCollector{}, collector.Options{
		GRPCAddress: freeAddress(t), HealthAddress: freeAddress(t), Insecure: true, Registry: wrapped,
	})
}
