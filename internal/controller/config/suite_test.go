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

package config_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/bedag/vexplain/internal/collector"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/testenv"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.
//
// The specs are in the external package config_test, because internal/setup, which the suite
// runs, imports this package.

// operatorNamespace is the namespace the manager under test runs in, and where the ModelConfig
// specs keep their Secrets.
const operatorNamespace = "vexplain-system"

var (
	ctx = context.Background()
	// k8sClient reads and writes through the API server, without a cache.
	k8sClient client.Client
	// k8sManager runs the controllers, wired by setup.Register as in production.
	k8sManager ctrl.Manager
	// collectorRegistry is the health registry that the manager's Collector controller reads. A
	// spec reports into it as a collector would.
	collectorRegistry *collector.Registry
	// llmServer is the model endpoint of the ModelConfig specs. The manager probes it.
	llmServer *llmEndpoint
	// suiteLog holds every line that the suite logs, the manager's included.
	suiteLog *logRecorder
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	suiteLog = &logRecorder{}
	logf.SetLogger(zap.New(zap.WriteTo(io.MultiWriter(GinkgoWriter, suiteLog)), zap.UseDevMode(true)))

	// Registered before the manager starts, so it closes after the manager has stopped.
	llmServer = newLLMEndpoint()
	DeferCleanup(llmServer.Close)

	collectorRegistry = collector.NewRegistry()
	env := testenv.Start(setup.Options{
		OperatorNamespace: operatorNamespace,
		CollectorRegistry: collectorRegistry,
		// The controller reads the registry once per resync, so a short one lets a spec see a
		// reported health within seconds.
		CollectorResync: time.Second,
		// The client of the TLS test server, which trusts its certificate.
		HTTPClient: llmServer.Client(),
	})
	k8sClient, k8sManager = env.Client, env.Manager

	By("creating the operator namespace")
	Expect(k8sClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace},
	})).To(Succeed())
})

// What the model endpoint of the specs knows. Its answer depends on the request alone: the API key
// and the path.
const (
	// listedModel is the one model that the endpoint lists. A ModelConfig for any other model, such
	// as missingModel, is not served.
	listedModel  = "model-listed"
	missingModel = "model-missing"
	// rejectedKey is the API key that the endpoint rejects, with a 401 whose body echoes the
	// Authorization header, as some gateways do.
	rejectedKey = "key-that-the-endpoint-rejects"
	// hangingKey is the API key of requests that get no answer until the client gives up.
	hangingKey = "key-that-gets-no-answer"
)

// llmEndpoint is an OpenAI-compatible API at URL + "/v1", served over TLS. GET /v1/models lists
// listedModel. Every other path gets a 404, and the keys rejectedKey and hangingKey get the
// answers above. It counts the requests by API key, so that a spec can count the probes of its
// own ModelConfig.
type llmEndpoint struct {
	*httptest.Server

	mu   sync.Mutex
	hits map[string]int
}

// newLLMEndpoint starts an llmEndpoint. Close it.
func newLLMEndpoint() *llmEndpoint {
	e := &llmEndpoint{hits: make(map[string]int)}
	e.Server = httptest.NewTLSServer(http.HandlerFunc(e.serve))
	return e
}

// apiURL is the base URL of the API, as a ModelConfig's endpoint names it.
func (e *llmEndpoint) apiURL() string { return e.URL + "/v1" }

// Hits returns the number of requests that carried the API key key.
func (e *llmEndpoint) Hits(key string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.hits[key]
}

func (e *llmEndpoint) serve(w http.ResponseWriter, r *http.Request) {
	authorization := r.Header.Get("Authorization")
	key := strings.TrimPrefix(authorization, "Bearer ")
	e.mu.Lock()
	e.hits[key]++
	e.mu.Unlock()

	switch {
	case key == hangingKey:
		// The server notices that the client has gone only once the body is read.
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	case key == rejectedKey:
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "invalid API key: "+authorization)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"`+listedModel+`","object":"model"}]}`)
	default:
		http.NotFound(w, r)
	}
}

// logRecorder keeps what a logger writes. The manager logs from many goroutines, so it is safe
// for concurrent use.
type logRecorder struct {
	mu    sync.Mutex
	lines strings.Builder
}

func (l *logRecorder) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lines.Write(p)
}

// String returns everything written so far.
func (l *logRecorder) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lines.String()
}
