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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	collectorv1alpha1 "github.com/bedag/vexplain/sdk/api/collector/v1alpha1"
	"github.com/bedag/vexplain/sdk/collector"
)

// serverName is the name in the server certificates, as vexplain names a collector's Service.
const serverName = "vexplain-collector-hello.vexplain-system.svc"

// authority is a certificate authority, as vexplain keeps one for its collectors: ECDSA P-256.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

// keyPair is a certificate that an authority issued, with its key.
type keyPair struct {
	certPEM, keyPEM []byte
	serial          *big.Int
	certificate     tls.Certificate
}

func serialNumber(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	require.NoError(t, err)
	return serial
}

func newAuthority(t *testing.T) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serialNumber(t),
		Subject:               pkix.Name{CommonName: "vexplain-collector-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &authority{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue returns a certificate for usage: a server's, for serverName, or a client's.
func (a *authority) issue(t *testing.T, usage x509.ExtKeyUsage) keyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serialNumber(t),
		Subject:      pkix.Name{CommonName: "vexplain"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		template.DNSNames = []string{serverName}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pair := keyPair{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		serial:  template.SerialNumber,
	}
	pair.certificate, err = tls.X509KeyPair(pair.certPEM, pair.keyPEM)
	require.NoError(t, err)
	return pair
}

// install writes the files that a collector's TLS Secret holds into dir: the server's certificate
// and key, and the authority's certificate, which clients must be signed by.
func install(t *testing.T, dir string, server keyPair, ca *authority) {
	t.Helper()
	for name, content := range map[string][]byte{"tls.crt": server.certPEM, "tls.key": server.keyPEM, "ca.crt": ca.pem} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), content, 0o600))
	}
}

// clientConfig is the TLS of a client that trusts ca for the server, and presents client, unless it
// is nil.
func clientConfig(ca *authority, client *keyPair) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	config := &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
	if client != nil {
		config.Certificates = []tls.Certificate{client.certificate}
	}
	return config
}

// serveTLS runs the fake collector with the TLS files in dir, on a real listener, until the test
// ends, and returns its address.
func serveTLS(t *testing.T, dir string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	start(t, &fakeCollector{caps: capabilities()}, collector.Options{TLSDir: dir, GRPCListener: listener})
	return listener.Addr().String()
}

// getInfo calls GetInfo on a new connection to address, with config.
func getInfo(address string, config *tls.Config) error {
	conn, err := grpc.NewClient("passthrough:///"+address, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	_, err = collectorv1alpha1.NewIdentityClient(conn).GetInfo(ctx, &collectorv1alpha1.GetInfoRequest{})
	return err
}

// presented returns the serial number of the certificate that the server at address presents to a
// new connection.
func presented(address string, config *tls.Config) (*big.Int, error) {
	dialer := &tls.Dialer{Config: config}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, net.UnknownNetworkError("not a TLS connection")
	}
	return tlsConn.ConnectionState().PeerCertificates[0].SerialNumber, nil
}

func TestTLS(t *testing.T) {
	ca := newAuthority(t)
	server := ca.issue(t, x509.ExtKeyUsageServerAuth)
	dir := t.TempDir()
	install(t, dir, server, ca)
	address := serveTLS(t, dir)
	client := ca.issue(t, x509.ExtKeyUsageClientAuth)

	t.Run("a client with a certificate from the authority gets through, and sees tls.crt", func(t *testing.T) {
		require.NoError(t, getInfo(address, clientConfig(ca, &client)))
		serial, err := presented(address, clientConfig(ca, &client))
		require.NoError(t, err)
		require.Equal(t, server.serial, serial)
	})
	t.Run("a client without a certificate is refused", func(t *testing.T) {
		err := getInfo(address, clientConfig(ca, nil))
		require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
	})
	t.Run("a client with a certificate from another authority is refused", func(t *testing.T) {
		stranger := newAuthority(t).issue(t, x509.ExtKeyUsageClientAuth)
		err := getInfo(address, clientConfig(ca, &stranger))
		require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
	})
}

func TestTLSFilesAreLoadedAgainWhenTheyChange(t *testing.T) {
	ca := newAuthority(t)
	first := ca.issue(t, x509.ExtKeyUsageServerAuth)
	dir := t.TempDir()
	install(t, dir, first, ca)
	address := serveTLS(t, dir)
	client := ca.issue(t, x509.ExtKeyUsageClientAuth)
	sees := func(serial *big.Int, config *tls.Config) func() bool {
		return func() bool {
			got, err := presented(address, config)
			return err == nil && got.Cmp(serial) == 0
		}
	}
	require.Eventually(t, sees(first.serial, clientConfig(ca, &client)), wait, reload)

	// A renewed certificate, from the same authority.
	second := ca.issue(t, x509.ExtKeyUsageServerAuth)
	install(t, dir, second, ca)
	require.Eventually(t, sees(second.serial, clientConfig(ca, &client)), wait, reload,
		"a new connection sees the new server certificate")
	require.NoError(t, getInfo(address, clientConfig(ca, &client)))

	// Files that don't load leave the server with the ones it has: a certificate without its key.
	third := ca.issue(t, x509.ExtKeyUsageServerAuth)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tls.crt"), third.certPEM, 0o600))
	require.Never(t, func() bool { return !sees(second.serial, clientConfig(ca, &client))() }, 10*reload, reload)
	require.NoError(t, getInfo(address, clientConfig(ca, &client)))

	// A new authority: its clients get through, and the old one's are refused.
	newCA := newAuthority(t)
	install(t, dir, newCA.issue(t, x509.ExtKeyUsageServerAuth), newCA)
	newClient := newCA.issue(t, x509.ExtKeyUsageClientAuth)
	require.Eventually(t, func() bool { return getInfo(address, clientConfig(newCA, &newClient)) == nil }, wait, reload)
	err := getInfo(address, clientConfig(newCA, &client))
	require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
}

func TestTLSFilesAreCheckedWithin30Seconds(t *testing.T) {
	require.Positive(t, collector.ReloadInterval)
	require.LessOrEqual(t, collector.ReloadInterval, 30*time.Second)
}
