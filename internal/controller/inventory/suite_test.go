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

package inventory_test

import (
	"context"
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
// The specs are in the external package inventory_test, because internal/setup, which the suite
// runs, imports this package.

// operatorNamespace is the namespace the manager under test runs in.
const operatorNamespace = "vexplain-system"

var (
	ctx = context.Background()
	// k8sClient reads and writes through the API server, without a cache.
	k8sClient client.Client
	// k8sManager runs the controllers, wired by setup.Register as in production.
	k8sManager ctrl.Manager
	// collectorRegistry is the health registry that the manager's pod inventory reports into.
	collectorRegistry *collector.Registry
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	collectorRegistry = collector.NewRegistry()
	env := testenv.Start(setup.Options{
		OperatorNamespace: operatorNamespace,
		CollectorRegistry: collectorRegistry,
		// The gauge of running images is set once per interval, so a short one lets a spec see it
		// follow a change within seconds.
		GaugeInterval: time.Second,
	})
	k8sClient, k8sManager = env.Client, env.Manager

	// The task pods of the specs run in the operator's namespace, so it must exist.
	By("creating the operator namespace")
	Expect(k8sClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace},
	})).To(Succeed())
})
