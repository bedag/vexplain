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

package chain_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/yaml"

	configv1alpha1 "github.com/bedag/vexplain/api/config/v1alpha1"
	"github.com/bedag/vexplain/internal/setup"
	"github.com/bedag/vexplain/internal/testenv"
)

// This suite runs the production wiring of the hub, from the presence of an image to its sheet: setup.Register with
// no Executor and no Findings of its own, so the assessor asks the spoke's real executor, which invokes the scanner
// collector, and matches through the real findings collector, which invokes the vulnerabilities collector and hears its
// stream. The collectors are served in this process, over mutual TLS, with the certificates that the manager's
// authority issued for their Deployments.
//
// The collectors of the packages, the scanner's and the vulnerabilities collector's, are modules of their own, whose internal packages
// the operator's module can't import, so the collectors here stand in for them: they declare the same roles, types
// and operations, and answer from memory. Their capabilities are read from the golden files that the two collectors'
// own tests hold their GetCapabilities to, so they can't drift. The packages' own tests run the real ones, on a fake
// Job runner and a fake Grype, through the SDK's conformance suite.

const (
	// operatorNamespace is the namespace the manager runs in.
	operatorNamespace = "vexplain-system"

	startup = 60 * time.Second
	poll    = 100 * time.Millisecond
	// quiet is how long a spec watches for something that must not happen.
	quiet = 3 * time.Second
)

var (
	ctx = context.Background()
	// k8sClient reads and writes through the API server, without a cache.
	k8sClient client.Client
)

func TestChain(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Setup chain suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	env := testenv.Start(setup.Options{
		OperatorNamespace: operatorNamespace,
		// The Collector controller checks each collector once per resync, so a short one lets a spec see a change
		// within seconds.
		CollectorResync: time.Second,
		// The pool reaches the collectors that the suite serves in this process.
		CollectorDialer: collectors.dial,
	})
	k8sClient = env.Client

	By("creating the operator namespace")
	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace}})).To(Succeed())

	By("applying the default rules and the default playbook, as the install ships them")
	for _, rule := range defaultRules() {
		Expect(k8sClient.Create(ctx, rule)).To(Succeed())
	}
	Expect(k8sClient.Create(ctx, defaultPlaybook())).To(Succeed())
})

// repositoryRoot is the root of the repository, from the directory of this package.
var repositoryRoot = filepath.Join("..", "..", "..")

// readYAML reads a YAML file into out, and refuses a field that out doesn't have.
func readYAML(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.UnmarshalStrict(raw, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// kustomized returns the files that the kustomization.yaml of a directory of config lists.
func kustomized(dir string) []string {
	GinkgoHelper()
	var kustomization struct {
		Resources []string `json:"resources"`
	}
	Expect(readYAML(filepath.Join(repositoryRoot, "config", dir, "kustomization.yaml"), &kustomization)).To(Succeed())
	files := slices.Clone(kustomization.Resources)
	for i := range files {
		files[i] = filepath.Join(repositoryRoot, "config", dir, files[i])
	}
	return files
}

// defaultRules returns the default rules, each a file that config/rules lists.
func defaultRules() []*configv1alpha1.Rule {
	GinkgoHelper()
	files := kustomized("rules")
	rules := make([]*configv1alpha1.Rule, 0, len(files))
	for _, file := range files {
		rule := &configv1alpha1.Rule{}
		Expect(readYAML(file, rule)).To(Succeed())
		rules = append(rules, rule)
	}
	return rules
}

// defaultPlaybook returns the default playbook, the one file that config/playbooks lists.
func defaultPlaybook() *configv1alpha1.Playbook {
	GinkgoHelper()
	files := kustomized("playbooks")
	Expect(files).To(HaveLen(1))
	playbook := &configv1alpha1.Playbook{}
	Expect(readYAML(files[0], playbook)).To(Succeed())
	return playbook
}
