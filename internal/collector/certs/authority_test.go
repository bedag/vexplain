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

package certs_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"maps"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/bedag/vexplain/internal/collector/certs"
)

// These tests cover the authority that the operator keeps for its collectors: the authority itself,
// which lives in the memory of one process; the server certificate of each collector, in its Secret;
// and the operator's client certificate, in memory. A certificate is renewed once it has 30 days left,
// which the tests check on the day and a day either side of it, on a clock of their own.

const (
	namespace = "vexplain-system"
	workloads = "workloads"
	scanner   = "scanner"

	// The keys of a collector's Secret: its certificate, its key, and the authority's certificate.
	certKey = "tls.crt"
	keyKey  = "tls.key"
	caKey   = "ca.crt"

	day = 24 * time.Hour
)

// t0 is when each test starts: a whole second, as a certificate keeps its times to the second. It lies
// years before any run of the tests, so that a certificate checked against the wall clock, and not
// against the authority's clock, fails the test.
var t0 = time.Date(2016, time.January, 1, 12, 0, 0, 0, time.UTC)

// errReadThroughWriter is what a read through the Authority's writer gives. The writer stands for the
// manager's client, whose cache holds only the Secrets of the LLM keys, so it never sees the Secrets of
// the collectors.
var errReadThroughWriter = errors.New("read through the manager's client, whose cache doesn't hold this Secret")

// clock is the time that an Authority reads, which a test moves.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// env is an Authority, the API server whose Secrets it keeps, and its clock.
type env struct {
	ctx       context.Context
	authority *certs.Authority
	// api reads and writes the Secrets of the API server directly, as the tests and the deployer do.
	api client.Client
	// writer is the Authority's client.
	writer client.Client
	clock  *clock
}

// newEnv returns an Authority of the namespace over an empty API server, with its clock at t0. Its
// writer fails every read, as the manager's client does for the Secrets of the collectors, so the
// Authority must read them through its reader, the API server's.
func newEnv(t *testing.T) *env {
	t.Helper()
	api := fake.NewClientBuilder().Build()
	writer := interceptor.NewClient(api, interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errReadThroughWriter
		},
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errReadThroughWriter
		},
	})
	e := &env{ctx: logr.NewContext(t.Context(), testr.New(t)), api: api, writer: writer, clock: &clock{now: t0}}
	e.restart()
	return e
}

// restart gives e a new Authority over its API server and its clock, as a new process of the operator
// has: with nothing in memory.
func (e *env) restart() {
	e.authority = certs.NewAuthority(e.writer, e.api, namespace, e.clock.Now)
}

// secret reads a Secret of the namespace from the API server.
func (e *env) secret(t *testing.T, name string) corev1.Secret {
	t.Helper()
	var s corev1.Secret
	require.NoError(t, e.api.Get(e.ctx, client.ObjectKey{Namespace: namespace, Name: name}, &s))
	return s
}

// secrets lists the Secrets of the namespace.
func (e *env) secrets(t *testing.T) []corev1.Secret {
	t.Helper()
	var list corev1.SecretList
	require.NoError(t, e.api.List(e.ctx, &list, client.InNamespace(namespace)))
	return list.Items
}

// names returns the names of secrets, sorted.
func names(secrets []corev1.Secret) []string {
	result := make([]string, 0, len(secrets))
	for _, s := range secrets {
		result = append(result, s.Name)
	}
	slices.Sort(result)
	return result
}

// ensureServers ensures the TLS Secrets of the collectors.
func (e *env) ensureServers(t *testing.T, collectors ...string) {
	t.Helper()
	for _, collector := range collectors {
		_, err := e.authority.EnsureServer(e.ctx, collector)
		require.NoError(t, err, collector)
	}
}

// caCert returns the certificate of the authority, from the TLS Secret of a collector.
func (e *env) caCert(t *testing.T, collector string) *x509.Certificate {
	t.Helper()
	return parseCert(t, e.secret(t, certs.SecretName(collector)).Data[caKey])
}

// serverPair returns a collector's certificate and key, from its TLS Secret.
func (e *env) serverPair(t *testing.T, collector string) tls.Certificate {
	t.Helper()
	s := e.secret(t, certs.SecretName(collector))
	pair, err := tls.X509KeyPair(s.Data[certKey], s.Data[keyKey])
	require.NoError(t, err, "tls.key is the key of tls.crt")
	return pair
}

// clientConfig returns the operator's client side for a connection to a collector, as the collector
// client sets it up: from ClientTLS, with the collector's server name.
func (e *env) clientConfig(t *testing.T, collector string) *tls.Config {
	t.Helper()
	config, err := e.authority.ClientTLS()
	require.NoError(t, err)
	config.ServerName = certs.ServerName(collector, namespace)
	return config
}

// issueForWorkloads returns a certificate for the names of the workloads collector, for usages, valid
// for 90 days from now, and its key, both in PEM: signed by the authority, which wouldn't issue it.
func (e *env) issueForWorkloads(t *testing.T, usages ...x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	name := certs.ServerName(workloads, namespace)
	now := e.clock.Now()
	certPEM, keyPEM, err := e.authority.Issue(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "vexplain-collector-workloads"},
		DNSNames:              []string{name, name + ".cluster.local"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * day),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usages,
		BasicConstraintsValid: true,
	})
	require.NoError(t, err)
	return certPEM, keyPEM
}

// parseCert parses a PEM that holds one certificate.
func parseCert(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode(data)
	require.NotNil(t, block, "a PEM block")
	require.Equal(t, "CERTIFICATE", block.Type)
	require.Empty(t, strings.TrimSpace(string(rest)), "one certificate")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// poolOf returns a pool of the certificates.
func poolOf(cas ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, ca := range cas {
		pool.AddCert(ca)
	}
	return pool
}

// verify checks cert against the authority ca at the time at, for usage, and for the DNS name name
// unless it is empty.
func verify(cert, ca *x509.Certificate, name string, usage x509.ExtKeyUsage, at time.Time) error {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:       poolOf(ca),
		DNSName:     name,
		KeyUsages:   []x509.ExtKeyUsage{usage},
		CurrentTime: at,
	})
	return err
}

// requireP256 checks that the key of cert is an ECDSA key on P-256.
func requireP256(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "an ECDSA key")
	require.Equal(t, elliptic.P256(), key.Curve)
}

// handshake connects a client with config to a server that presents server and, as a collector's
// server does, requires a client certificate that ca signed for a client. The server reads the clock
// of e, which stands for the collector's clock. It returns the error of the client and the error of the
// server, both nil when the connection gets through.
func (e *env) handshake(t *testing.T, server tls.Certificate, ca *x509.Certificate, config *tls.Config) (clientErr, serverErr error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer func() { _ = conn.Close() }()
		serverConn := tls.Server(conn, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{server},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    poolOf(ca),
			Time:         e.clock.Now,
		})
		err = serverConn.HandshakeContext(ctx)
		if err == nil {
			// A byte tells the client that it got through.
			_, err = serverConn.Write([]byte{1})
		}
		served <- err
	}()

	conn, err := (&tls.Dialer{Config: config}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		// A dial that never connected leaves the server waiting for a connection, until the listener closes.
		_ = listener.Close()
		return err, <-served
	}
	defer func() { _ = conn.Close() }()
	// In TLS 1.3 the client's handshake ends before the server has checked the client's certificate. The
	// client learns the server's answer from what it reads next: the byte, or the server's refusal.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = io.ReadFull(conn, make([]byte, 1))
	return err, <-served
}

// requireNoKey fails the test when text holds the private key that keyPEM encodes, in any form that a
// careless Secret, log line or error would give it: a line of the PEM; the DER as it is, or in base64,
// as JSON writes bytes; or the secret scalar of the key as it is, in hex, in base64, or in decimal, as
// %v writes a big.Int.
func requireNoKey(t *testing.T, text string, keyPEM []byte) {
	t.Helper()
	block, _ := pem.Decode(keyPEM)
	require.NotNil(t, block, "a PEM key")
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	key, ok := parsed.(*ecdsa.PrivateKey)
	require.True(t, ok, "an ECDSA key")
	scalar, err := key.Bytes()
	require.NoError(t, err)
	forms := []string{
		string(block.Bytes),
		base64.StdEncoding.EncodeToString(block.Bytes),
		string(scalar),
		hex.EncodeToString(scalar),
		base64.StdEncoding.EncodeToString(scalar),
		new(big.Int).SetBytes(scalar).String(),
	}
	for line := range strings.Lines(string(keyPEM)) {
		if line = strings.TrimSpace(line); len(line) >= 16 && !strings.HasPrefix(line, "-----") {
			forms = append(forms, line)
		}
	}
	for _, form := range forms {
		require.NotContains(t, text, form, "a private key")
	}
}

// clientKeyPEM encodes the private key of a client certificate as a Secret would hold it.
func clientKeyPEM(t *testing.T, pair tls.Certificate) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestTheAuthorityIsCreatedOncePerProcessAndKeptInMemory(t *testing.T) {
	e := newEnv(t)
	require.NoError(t, e.authority.EnsureCA(e.ctx))
	require.NoError(t, e.authority.EnsureCA(e.ctx))
	require.Empty(t, e.secrets(t), "the authority is in no Secret")

	e.ensureServers(t, workloads)
	require.Equal(t, []string{"vexplain-collector-workloads-tls"}, names(e.secrets(t)))
	ca := e.caCert(t, workloads)
	require.True(t, ca.IsCA)
	require.NotZero(t, ca.KeyUsage&x509.KeyUsageCertSign, "it signs certificates")
	require.True(t, ca.MaxPathLenZero, "it signs no other authority")
	require.Zero(t, ca.MaxPathLen, "it signs no other authority")
	requireP256(t, ca)
	require.False(t, ca.NotBefore.After(t0), "valid from its creation")
	require.WithinDuration(t, t0.AddDate(10, 0, 0), ca.NotAfter, 0, "valid for 10 years")

	// Within the process the authority stays, and so do the certificates that it issued.
	require.NoError(t, e.authority.EnsureCA(e.ctx))
	renewed, err := e.authority.EnsureServer(e.ctx, workloads)
	require.NoError(t, err)
	require.False(t, renewed)
	config, err := e.authority.ClientTLS()
	require.NoError(t, err)
	require.True(t, config.RootCAs.Equal(poolOf(ca)), "the client trusts the authority, and nothing else")
}

func TestARestartIssuesANewAuthorityAndEveryServerCertificateAgain(t *testing.T) {
	// Each process of the operator has an authority of its own. A new process issues every collector's
	// certificate again from its authority, and its client trusts that authority alone.
	e := newEnv(t)
	collectors := []string{workloads, scanner}
	e.ensureServers(t, collectors...)
	old := e.caCert(t, workloads)

	e.restart()
	require.NoError(t, e.authority.EnsureCA(e.ctx))
	for _, collector := range collectors {
		renewed, err := e.authority.EnsureServer(e.ctx, collector)
		require.NoError(t, err)
		require.True(t, renewed, collector)
	}
	ca := e.caCert(t, workloads)
	require.False(t, ca.Equal(old), "a new authority")
	for _, collector := range collectors {
		require.True(t, e.caCert(t, collector).Equal(ca), "one authority for every collector")
		cert := e.serverPair(t, collector).Leaf
		name := certs.ServerName(collector, namespace)
		require.NoError(t, verify(cert, ca, name, x509.ExtKeyUsageServerAuth, t0), collector)
		require.Error(t, verify(cert, old, name, x509.ExtKeyUsageServerAuth, t0), collector)
	}
	config := e.clientConfig(t, workloads)
	require.True(t, config.RootCAs.Equal(poolOf(ca)), "the new client trusts the new authority alone")
	clientErr, serverErr := e.handshake(t, e.serverPair(t, workloads), ca, config)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
}

func TestNoSecretHoldsTheKeyOfTheAuthority(t *testing.T) {
	// A collector may read Secrets, as the scanner reads pull secrets across the cluster. With the key of
	// the authority it could sign a client certificate and call every collector, so the key never leaves
	// the memory of the process that created it.
	e := newEnv(t)
	collectors := []string{workloads, scanner}
	e.ensureServers(t, collectors...)
	e.clock.Set(t0.Add(61 * day))
	e.ensureServers(t, collectors...)
	first := e.authority.CAKeyPEM()
	e.restart()
	e.ensureServers(t, collectors...)
	second := e.authority.CAKeyPEM()

	secrets := e.secrets(t)
	require.Equal(t, []string{certs.SecretName(scanner), certs.SecretName(workloads)}, names(secrets))
	for _, s := range secrets {
		require.Equal(t, []string{caKey, certKey, keyKey}, slices.Sorted(maps.Keys(s.Data)), s.Name)
		_, err := tls.X509KeyPair(s.Data[certKey], s.Data[keyKey])
		require.NoError(t, err, "the key in %s is the key of its own certificate", s.Name)
		for _, value := range s.Data {
			requireNoKey(t, string(value), first)
			requireNoKey(t, string(value), second)
		}
	}
}

// A Collector's name has at most 44 characters, as its CRD requires, because the operator names the
// collector's Service, Deployment and service account vexplain-collector-<name>, and a Service's name is a
// DNS-1035 label of at most 63 characters. So is the first label of the collector's TLS server name.
func TestTheServiceOfACollectorWithTheLongestNameIsNamedWithADNSLabel(t *testing.T) {
	longest := strings.Repeat("a", 44)

	name := certs.ServiceName(longest)

	require.Equal(t, "vexplain-collector-"+longest, name)
	require.LessOrEqual(t, len(name), 63)
	require.Empty(t, validation.IsDNS1035Label(name), "the Service's name is a DNS-1035 label")
	require.Equal(t, name+"."+namespace+".svc", certs.ServerName(longest, namespace), "the server name starts with it")
	require.Equal(t, name+"-tls", certs.SecretName(longest))
	require.NotEmpty(t, validation.IsDNS1035Label(certs.ServiceName(longest+"a")), "a 45th character is one too many")
}

func TestAServerCertificateVerifiesForItsOwnNameOnly(t *testing.T) {
	e := newEnv(t)
	// The deployer may call EnsureServer first: it creates the authority that it needs.
	renewed, err := e.authority.EnsureServer(e.ctx, workloads)
	require.NoError(t, err)
	require.True(t, renewed, "a new Secret holds a new certificate")

	require.Equal(t, "vexplain-collector-workloads-tls", certs.SecretName(workloads))
	s := e.secret(t, certs.SecretName(workloads))
	require.Equal(t, corev1.SecretTypeTLS, s.Type)
	require.Equal(t, []string{caKey, certKey, keyKey}, slices.Sorted(maps.Keys(s.Data)))
	ca := e.caCert(t, workloads)
	cert := e.serverPair(t, workloads).Leaf

	name := "vexplain-collector-workloads.vexplain-system.svc"
	require.Equal(t, name, certs.ServerName(workloads, namespace))
	require.Equal(t, []string{name, name + ".cluster.local"}, cert.DNSNames)
	for _, valid := range cert.DNSNames {
		require.NoError(t, verify(cert, ca, valid, x509.ExtKeyUsageServerAuth, t0), valid)
	}
	for _, other := range []string{
		certs.ServerName(scanner, namespace),
		certs.ServerName(workloads, "team-a"),
		"vexplain-collector-workloads",
	} {
		var wrongName x509.HostnameError
		require.ErrorAs(t, verify(cert, ca, other, x509.ExtKeyUsageServerAuth, t0), &wrongName, other)
	}
	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, cert.ExtKeyUsage, "for a server only")
	require.False(t, cert.IsCA)
	requireP256(t, cert)
	require.False(t, cert.NotBefore.After(t0), "valid from its issue")
	require.WithinDuration(t, t0.Add(90*day), cert.NotAfter, 0, "valid for 90 days")

	// The operator's client gets through to the collector, which checks it as the SDK's server does.
	clientErr, serverErr := e.handshake(t, e.serverPair(t, workloads), ca, e.clientConfig(t, workloads))
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	// A client that dials another collector doesn't take this certificate.
	clientErr, _ = e.handshake(t, e.serverPair(t, workloads), ca, e.clientConfig(t, scanner))
	var wrongName x509.HostnameError
	require.ErrorAs(t, clientErr, &wrongName)
}

func TestAServerCertificateIsRefusedAsAClientCertificate(t *testing.T) {
	// Each collector holds a certificate from the authority that signs the operator's client certificate.
	// The collector's is for a server only, so it can't use it to call another collector.
	e := newEnv(t)
	e.ensureServers(t, workloads, scanner)
	config := e.clientConfig(t, workloads)
	config.Certificates = []tls.Certificate{e.serverPair(t, scanner)}

	_, serverErr := e.handshake(t, e.serverPair(t, workloads), e.caCert(t, workloads), config)
	var refused x509.CertificateInvalidError
	require.ErrorAs(t, serverErr, &refused)
	require.Equal(t, x509.IncompatibleUsage, refused.Reason)
}

func TestAServerCertificateIsRenewedWith30DaysLeft(t *testing.T) {
	e := newEnv(t)
	e.ensureServers(t, workloads)
	// The deployer labels the Secret, and makes the Collector its controller owner.
	owned := e.secret(t, certs.SecretName(workloads))
	owned.Labels = map[string]string{"vexplain.bedag.ch/collector": workloads}
	owned.OwnerReferences = []metav1.OwnerReference{{
		APIVersion:         "config.vexplain.bedag.ch/v1alpha1",
		Kind:               "Collector",
		Name:               workloads,
		UID:                "uid-workloads",
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}}
	require.NoError(t, e.api.Update(e.ctx, &owned))
	owned = e.secret(t, certs.SecretName(workloads))
	first := e.serverPair(t, workloads).Leaf

	e.clock.Set(first.NotAfter.Add(-31 * day))
	renewed, err := e.authority.EnsureServer(e.ctx, workloads)
	require.NoError(t, err)
	require.False(t, renewed, "31 days left")
	require.Equal(t, owned.ResourceVersion, e.secret(t, certs.SecretName(workloads)).ResourceVersion, "nothing is written")

	renewal := first.NotAfter.Add(-29 * day)
	e.clock.Set(renewal)
	renewed, err = e.authority.EnsureServer(e.ctx, workloads)
	require.NoError(t, err)
	require.True(t, renewed, "29 days left")
	s := e.secret(t, certs.SecretName(workloads))
	second := e.serverPair(t, workloads).Leaf
	require.NotEqual(t, first.SerialNumber, second.SerialNumber)
	require.NotEqual(t, owned.Data[keyKey], s.Data[keyKey], "a renewed certificate comes with a new key")
	require.WithinDuration(t, renewal.Add(90*day), second.NotAfter, 0, "valid for 90 days from its renewal")
	require.NoError(t, verify(second, e.caCert(t, workloads), certs.ServerName(workloads, namespace),
		x509.ExtKeyUsageServerAuth, renewal))
	require.Equal(t, owned.Labels, s.Labels, "the deployer's labels stay")
	require.Equal(t, owned.OwnerReferences, s.OwnerReferences, "and so does the owner")
	require.Equal(t, owned.Type, s.Type)

	// The renewed certificate stays until it has 30 days left in turn.
	renewed, err = e.authority.EnsureServer(e.ctx, workloads)
	require.NoError(t, err)
	require.False(t, renewed)
}

func TestACertificateWithExactly30DaysLeftIsRenewed(t *testing.T) {
	e := newEnv(t)
	e.ensureServers(t, workloads)
	server := e.serverPair(t, workloads).Leaf
	clientCert := e.clientConfig(t, workloads).Certificates[0].Leaf
	// Both were issued at t0, so both have 30 days left at the same moment.
	e.clock.Set(server.NotAfter.Add(-30 * day))

	renewed, err := e.authority.EnsureServer(e.ctx, workloads)
	require.NoError(t, err)
	require.True(t, renewed, "the server's certificate")
	require.NotEqual(t, clientCert.SerialNumber, e.clientConfig(t, workloads).Certificates[0].Leaf.SerialNumber,
		"the client's certificate")
}

func TestTheClientCertificateVerifiesAndIsRenewedWith30DaysLeft(t *testing.T) {
	e := newEnv(t)
	require.NoError(t, e.authority.EnsureCA(e.ctx))
	config, err := e.authority.ClientTLS()
	require.NoError(t, err)
	require.Empty(t, e.secrets(t), "the client's certificate is kept in memory, and in no Secret")
	e.ensureServers(t, workloads)
	ca := e.caCert(t, workloads)

	require.Equal(t, uint16(tls.VersionTLS13), config.MinVersion)
	require.True(t, config.RootCAs.Equal(poolOf(ca)), "it trusts the authority, and nothing else")
	require.NotNil(t, config.Time, "it checks certificates at the authority's clock")
	require.Equal(t, t0, config.Time())
	require.Len(t, config.Certificates, 1)
	first := config.Certificates[0].Leaf
	require.NoError(t, verify(first, ca, "", x509.ExtKeyUsageClientAuth, t0))
	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, first.ExtKeyUsage, "for a client only")
	requireP256(t, first)
	require.WithinDuration(t, t0.Add(90*day), first.NotAfter, 0, "valid for 90 days")

	e.clock.Set(first.NotAfter.Add(-31 * day))
	config, err = e.authority.ClientTLS()
	require.NoError(t, err)
	require.Equal(t, first.SerialNumber, config.Certificates[0].Leaf.SerialNumber, "31 days left")

	renewal := first.NotAfter.Add(-29 * day)
	e.clock.Set(renewal)
	config, err = e.authority.ClientTLS()
	require.NoError(t, err)
	second := config.Certificates[0].Leaf
	require.NotEqual(t, first.SerialNumber, second.SerialNumber, "29 days left")
	require.NoError(t, verify(second, ca, "", x509.ExtKeyUsageClientAuth, renewal))
	require.WithinDuration(t, renewal.Add(90*day), second.NotAfter, 0, "valid for 90 days from its renewal")
}

func TestClientTLSNeedsTheAuthority(t *testing.T) {
	_, err := newEnv(t).authority.ClientTLS()
	require.Error(t, err, "before EnsureCA, there is no authority to trust")
}

func TestAServerSecretWithoutACurrentCertificateIsIssuedAgain(t *testing.T) {
	// A collector can only serve the operator with the Secret that the authority would issue now. Any
	// other Secret of the name is issued again, with the labels and the owner that it has.
	other := newEnv(t)
	other.ensureServers(t, workloads)
	stranger := other.secret(t, certs.SecretName(workloads)).Data

	for name, change := range map[string]func(t *testing.T, e *env, own map[string][]byte){
		"no data": func(_ *testing.T, _ *env, own map[string][]byte) { clear(own) },
		"a key that isn't the certificate's": func(t *testing.T, e *env, own map[string][]byte) {
			own[keyKey] = e.secret(t, certs.SecretName(scanner)).Data[keyKey]
		},
		"another collector's certificate": func(t *testing.T, e *env, own map[string][]byte) {
			scanners := e.secret(t, certs.SecretName(scanner)).Data
			own[certKey], own[keyKey] = scanners[certKey], scanners[keyKey]
		},
		"a certificate from another authority": func(_ *testing.T, _ *env, own map[string][]byte) {
			own[certKey], own[keyKey] = stranger[certKey], stranger[keyKey]
		},
		"another authority as ca.crt": func(_ *testing.T, _ *env, own map[string][]byte) {
			own[caKey] = stranger[caKey]
		},
		// Signed by the authority and for the collector's names, but good for a client too: the
		// collector could call another collector with it.
		"a certificate for a server and a client": func(t *testing.T, e *env, own map[string][]byte) {
			own[certKey], own[keyKey] = e.issueForWorkloads(t, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
		},
		// Without extended key usages a certificate is good for any usage, a client's included.
		"a certificate without extended key usages": func(t *testing.T, e *env, own map[string][]byte) {
			own[certKey], own[keyKey] = e.issueForWorkloads(t)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.ensureServers(t, workloads, scanner)
			s := e.secret(t, certs.SecretName(workloads))
			s.Labels = map[string]string{"vexplain.bedag.ch/collector": workloads}
			change(t, e, s.Data)
			require.NoError(t, e.api.Update(e.ctx, &s))

			renewed, err := e.authority.EnsureServer(e.ctx, workloads)
			require.NoError(t, err)
			require.True(t, renewed)
			issued := e.secret(t, certs.SecretName(workloads))
			require.Equal(t, s.Labels, issued.Labels)
			require.Equal(t, e.secret(t, certs.SecretName(scanner)).Data[caKey], issued.Data[caKey], "the authority's certificate")
			cert := e.serverPair(t, workloads).Leaf
			require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, cert.ExtKeyUsage)
			require.NoError(t, verify(cert, e.caCert(t, scanner), certs.ServerName(workloads, namespace),
				x509.ExtKeyUsageServerAuth, t0))
		})
	}
}

func TestNoPrivateKeyIsLogged(t *testing.T) {
	var logged strings.Builder
	e := newEnv(t)
	e.ctx = logr.NewContext(e.ctx, funcr.New(func(prefix, args string) {
		logged.WriteString(prefix + " " + args + "\n")
	}, funcr.Options{Verbosity: 10}))

	// The authority is created, a server certificate and the client's are issued and renewed, and the
	// operator restarts with a new authority.
	e.ensureServers(t, workloads)
	firstCA, firstServer := e.authority.CAKeyPEM(), e.secret(t, certs.SecretName(workloads)).Data[keyKey]
	firstClient := clientKeyPEM(t, e.clientConfig(t, workloads).Certificates[0])
	e.clock.Set(t0.Add(61 * day))
	e.ensureServers(t, workloads)
	renewedServer := e.secret(t, certs.SecretName(workloads)).Data[keyKey]
	renewedClient := clientKeyPEM(t, e.clientConfig(t, workloads).Certificates[0])
	e.restart()
	e.ensureServers(t, workloads)
	secondCA, secondServer := e.authority.CAKeyPEM(), e.secret(t, certs.SecretName(workloads)).Data[keyKey]

	require.NotEmpty(t, logged.String(), "the authority logs that it was created")
	for _, key := range [][]byte{firstCA, firstServer, firstClient, renewedServer, renewedClient, secondCA, secondServer} {
		requireNoKey(t, logged.String(), key)
	}
}

func TestTheAuthorityServesClientsWhileItEnsuresSecrets(t *testing.T) {
	// The collector client asks for its TLS at each connection, while the deployer ensures the Secrets of
	// the collectors, and the client's certificate comes due for renewal in between. The race detector
	// checks this test.
	e := newEnv(t)
	require.NoError(t, e.authority.EnsureCA(e.ctx))
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 50 {
				_, err := e.authority.ClientTLS()
				assert.NoError(t, err)
			}
		})
	}
	for _, collector := range []string{workloads, scanner, "vulnerabilities", "network-reach"} {
		wg.Go(func() {
			_, err := e.authority.EnsureServer(e.ctx, collector)
			assert.NoError(t, err, collector)
		})
	}
	wg.Go(func() { e.clock.Set(t0.Add(61 * day)) })
	wg.Wait()

	config := e.clientConfig(t, workloads)
	require.NoError(t, verify(config.Certificates[0].Leaf, e.caCert(t, workloads), "", x509.ExtKeyUsageClientAuth,
		t0.Add(61*day)))
}
