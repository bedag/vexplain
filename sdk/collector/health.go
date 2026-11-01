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

package collector

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
)

// apiServices are the services of the collector API, whose calls the metrics count.
var apiServices = []string{
	collectorv1alpha1.Identity_ServiceDesc.ServiceName,
	collectorv1alpha1.Evidence_ServiceDesc.ServiceName,
}

// newHealthService is the standard gRPC health service. It answers SERVING for the server as a whole,
// which vexplain's deployer checks, and for each service of the API, until it shuts down.
func newHealthService() *health.Server {
	checks := health.NewServer()
	for _, service := range apiServices {
		checks.SetServingStatus(service, healthpb.HealthCheckResponse_SERVING)
	}
	return checks
}

// healthHandler serves the probes and the metrics in plain HTTP, because the kubelet's probes can't
// present a client certificate:
//   - /healthz answers 200 while Serve runs, including while it waits for its TLS files.
//   - /readyz answers 200 once the gRPC server serves, with its TLS files loaded, and 503 until then
//     and once it stops.
//   - /metrics serves what gatherer gathers.
func healthHandler(ready *atomic.Bool, gatherer prometheus.Gatherer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready.Load() {
			answer(w, http.StatusOK)
			return
		}
		answer(w, http.StatusServiceUnavailable)
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{}))
	return mux
}

// answer writes a status, with its text as the body.
func answer(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, http.StatusText(code)+"\n")
}

// newRequests registers vexplain_collector_requests_total on registry, or on a registry of its own
// when registry is nil, and returns it with the gatherer that /metrics serves. That is the registry
// itself, so it must be a prometheus.Gatherer too, as a *prometheus.Registry is. When the registry
// holds the counter already, from another server, the servers share it.
//
// The counter counts each call of the collector API by the cluster that the context of its request
// names, as every metric of vexplain names its cluster, by its method and by its gRPC code. The calls
// of Identity carry no context, and count for the cluster "".
func newRequests(registry prometheus.Registerer) (*prometheus.CounterVec, prometheus.Gatherer, error) {
	if registry == nil {
		registry = prometheus.NewRegistry()
	}
	gatherer, ok := registry.(prometheus.Gatherer)
	if !ok {
		return nil, nil, errors.New("/metrics serves the registry of the options, which isn't a prometheus.Gatherer")
	}
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vexplain_collector_requests_total",
		Help: "The calls of the collector API, by the cluster that the call's context names, its method and its code.",
	}, []string{"cluster", "method", "code"})
	if err := registry.Register(requests); err != nil {
		var registered prometheus.AlreadyRegisteredError
		if !errors.As(err, &registered) {
			return nil, nil, err
		}
		existing, ok := registered.ExistingCollector.(*prometheus.CounterVec)
		if !ok {
			return nil, nil, err
		}
		requests = existing
	}
	return requests, gatherer, nil
}

// countUnary counts each unary call of the collector API as it ends.
func countUnary(requests *prometheus.CounterVec) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		resp, err := handler(ctx, req)
		count(requests, info.FullMethod, req, err)
		return resp, err
	}
}

// countStream counts each streaming call of the collector API as it ends.
func countStream(requests *prometheus.CounterVec) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		recorder := &firstRequest{ServerStream: stream}
		err := handler(srv, recorder)
		count(requests, info.FullMethod, recorder.request, err)
		return err
	}
}

// firstRequest remembers the request of a stream, whose context names the cluster.
type firstRequest struct {
	grpc.ServerStream
	request any
}

func (r *firstRequest) RecvMsg(m any) error {
	err := r.ServerStream.RecvMsg(m)
	if err == nil && r.request == nil {
		r.request = m
	}
	return err
}

// count counts a call that ended with err, unless it isn't one of the collector API's, as a call of
// the health service isn't. A cluster that can't be a label's value, which isn't UTF-8, leaves the
// call uncounted, where WithLabelValues would panic. gRPC refuses such a request before, though.
func count(requests *prometheus.CounterVec, fullMethod string, req any, err error) {
	for _, service := range apiServices {
		if method, ok := strings.CutPrefix(fullMethod, "/"+service+"/"); ok {
			counter, labelErr := requests.GetMetricWithLabelValues(clusterOf(req), method, codeOf(err).String())
			if labelErr == nil {
				counter.Inc()
			}
			return
		}
	}
}

// clusterOf is the cluster that the context of a request names, and "" for a request without one.
func clusterOf(req any) string {
	if withContext, ok := req.(interface {
		GetContext() *collectorv1alpha1.Context
	}); ok {
		return withContext.GetContext().GetCluster()
	}
	return ""
}

// codeOf is the code of the status that gRPC sends for a call whose handler returned err.
func codeOf(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	if s, ok := status.FromError(err); ok {
		return s.Code()
	}
	return status.FromContextError(err).Code()
}
