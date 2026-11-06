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

package triage_test

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/testenv"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.
//
// The suite checks the schemas of the triage kinds against a real API server. It runs the manager that
// every suite runs, because that is how the scheme and the CRDs reach the client of the specs, but
// without the renderer of the reports: the specs write reports for workloads that don't exist, which
// the renderer would delete. The specs are in the external package triage_test, as in
// the other suites.

const (
	// operatorNamespace is the namespace the manager under test runs in.
	operatorNamespace = "vexplain-system"
	// workloadNamespace is the namespace of the workloads whose reports the specs write. A report
	// lives in the namespace of its workload. otherNamespace is a second one, for the specs that
	// compare two.
	workloadNamespace = "team-a"
	otherNamespace    = "team-b"
)

var (
	ctx = context.Background()
	// k8sClient reads and writes through the API server, without a cache.
	k8sClient client.Client
)

func TestTriageAPI(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Triage API Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	env := testenv.Start(setup.Options{OperatorNamespace: operatorNamespace, DisableReports: true})
	k8sClient = env.Client

	By("creating the namespaces of the workloads")
	for _, name := range []string{workloadNamespace, otherNamespace} {
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})).To(Succeed())
	}
})
