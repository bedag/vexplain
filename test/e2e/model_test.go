//go:build e2e
// +build e2e

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

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/gomega"

	"github.com/bedag/vexplain/test/utils"
)

// The scripted model of the agent's specs: an OpenAI-compatible endpoint that test/e2e/images/scripted-model builds,
// which judges the planted images' cases without a real model.
const (
	scriptedModelImage = "example.com/vexplain-scripted-model:v0.0.1"
	// modelNamespace holds the scripted model's Deployment and Service, both named scriptedModel.
	modelNamespace = "e2e-model"
	scriptedModel  = "scripted-model"
	// modelName is the model that it serves.
	modelName = "scripted"
	// modelKeySecret holds the API key of the ModelConfig, which the scripted model doesn't check.
	modelKeySecret = "e2e-model-key"
	// modelCAFile is where the suite writes the scripted model's authority, which test/e2e/config mounts into the
	// manager and the agent workers as their trusted roots.
	modelCAFile = "test/e2e/config/model-ca.crt"
)

// modelHost is the name under which the agent workers reach the scripted model, which its certificate names.
var modelHost = scriptedModel + "." + modelNamespace + ".svc"

// The MCP server of the agent's specs: a stand-in for a wiki's that test/e2e/images/mcp-stand-in builds, which serves
// search, get_page and delete_page. It runs beside the scripted model, with its certificate.
const (
	mcpStandInImage = "example.com/vexplain-mcp-stand-in:v0.0.1"
	// mcpStandIn names its Deployment and Service.
	mcpStandIn = "mcp-stand-in"
	// wikiCollector is the Collector that names it, and lists search and get_page, and not delete_page.
	wikiCollector = "wiki"
	// wikiHeadersSecret holds the header that it takes, wikiToken.
	wikiHeadersSecret = "e2e-wiki-mcp"
	wikiToken         = "e2e-wiki-token"
)

// mcpHost is the name under which the manager and the agent workers reach the MCP server.
var mcpHost = mcpStandIn + "." + modelNamespace + ".svc"

// modelCert and modelKey are the scripted model's certificate and key, PEM, which writeModelAuthority makes.
var modelCert, modelKey []byte

// writeModelAuthority makes an authority and a certificate of the Services of the scripted model and the MCP server
// that it signs, and writes the authority to modelCAFile, before the deployment reads it. Both live for a day.
func writeModelAuthority() {
	projectDir, err := utils.GetProjectDir()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "e2e scripted model authority"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: modelHost},
		DNSNames:  []string{modelHost, modelHost + ".cluster.local", mcpHost, mcpHost + ".cluster.local"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalECPrivateKey(key)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	modelCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	modelKey = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	ExpectWithOffset(1, os.WriteFile(filepath.Join(projectDir, modelCAFile),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644)).To(Succeed())
}

// removeModelAuthority removes the file that writeModelAuthority wrote.
func removeModelAuthority() {
	projectDir, err := utils.GetProjectDir()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	_ = os.Remove(filepath.Join(projectDir, modelCAFile))
}

// scriptedModelManifest returns the scripted model's TLS Secret, Deployment and Service. The case of the manifest
// loopOn reaches the step limit, and every other case is affected.
func scriptedModelManifest(loopOn string) string {
	indent := func(pemData []byte) string {
		out := ""
		for _, line := range strings.Split(strings.TrimRight(string(pemData), "\n"), "\n") {
			out += "    " + line + "\n"
		}
		return out
	}
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %[1]s-tls
  namespace: %[2]s
type: kubernetes.io/tls
stringData:
  tls.crt: |
%[3]s  tls.key: |
%[4]s---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
    spec:
      containers:
      - name: model
        image: %[5]s
        imagePullPolicy: IfNotPresent
        env:
        - name: LOOP_ON
          value: %[6]q
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: tls
          mountPath: /tls
          readOnly: true
      volumes:
      - name: tls
        secret:
          secretName: %[1]s-tls
---
apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  selector:
    app: %[1]s
  ports:
  - port: 443
    targetPort: 8443
`, scriptedModel, modelNamespace, indent(modelCert), indent(modelKey), scriptedModelImage, loopOn)
}

// modelKeyManifest returns the labelled Secret of the ModelConfig's API key, in the operator's namespace.
func modelKeyManifest() string {
	return fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
  labels:
    vexplain.bedag.ch/llm-api-key: "true"
stringData:
  api-key: e2e-not-a-secret
`, modelKeySecret, namespace)
}

// scriptedModelPatch returns the merge patch that points the ModelConfig at the scripted model.
func scriptedModelPatch() string {
	return fmt.Sprintf(`{"spec":{"endpoint":"https://%s/v1","model":%q,"apiKeySecretRef":{"name":%q,"key":"api-key"}}}`,
		modelHost, modelName, modelKeySecret)
}

// mcpStandInManifest returns the MCP server's Deployment and Service, which serve with the scripted model's TLS Secret,
// and the labelled Secret of its header in the operator's namespace.
func mcpStandInManifest() string {
	return fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  replicas: 1
  selector:
    matchLabels:
      app: %[1]s
  template:
    metadata:
      labels:
        app: %[1]s
    spec:
      containers:
      - name: mcp
        image: %[3]s
        imagePullPolicy: IfNotPresent
        env:
        - name: TOKEN
          value: %[4]s
        ports:
        - containerPort: 8443
        volumeMounts:
        - name: tls
          mountPath: /tls
          readOnly: true
      volumes:
      - name: tls
        secret:
          secretName: %[5]s-tls
---
apiVersion: v1
kind: Service
metadata:
  name: %[1]s
  namespace: %[2]s
spec:
  selector:
    app: %[1]s
  ports:
  - port: 443
    targetPort: 8443
---
apiVersion: v1
kind: Secret
metadata:
  name: %[6]s
  namespace: %[7]s
  labels:
    vexplain.bedag.ch/mcp-headers: "true"
stringData:
  Authorization: Bearer %[4]s
`, mcpStandIn, modelNamespace, mcpStandInImage, wikiToken, scriptedModel, wikiHeadersSecret, namespace)
}

// wikiCollectorManifest returns the Collector of the MCP server, whose list leaves delete_page off.
func wikiCollectorManifest() string {
	return fmt.Sprintf(`apiVersion: config.vexplain.bedag.ch/v1alpha1
kind: Collector
metadata:
  name: %s
spec:
  mcp:
    url: https://%s/mcp
    headersFrom:
    - secretRef:
        name: %s
    tools: [search, get_page]
`, wikiCollector, mcpHost, wikiHeadersSecret)
}
