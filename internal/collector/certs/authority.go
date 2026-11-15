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

// Package certs keeps the certificate authority of the collectors, and issues and renews the
// certificates that the operator and its collectors talk with.
//
// The operator calls its collectors over mutual TLS, as Crossplane calls its functions. The authority
// lives in the Secret vexplain-collector-ca of the operator's namespace, with its certificate under
// ca.crt and its key under ca.key. The first process of the operator creates it, and every later one
// loads it, so a restart issues no collector's certificate again. A process makes a new authority
// there, as the first did, when the Secret holds none that it can use, and when the authority has 90
// days left.
//
// The key goes into no other Secret, and into no log line, event, error or status. A collector that may
// get Secrets in the operator's namespace by name could read it, as the scanner may get any Secret by
// name, for the pull secrets across the cluster, and RBAC can't keep a grant across the cluster out of
// one namespace. With the key, a collector could sign a client certificate and call every other
// collector. Where the cluster encrypts Secrets at rest, the key is encrypted on disk.
//
// The authority gives each collector a server certificate in the Secret vexplain-collector-<name>-tls,
// beside the authority's own certificate, and the collector's Deployment mounts it. It gives the
// operator a client certificate, which the operator holds in memory. A new authority issues every
// collector's certificate again, and a collector loads its new files once its mounted Secret has
// changed.
//
// Every key is ECDSA on P-256. The authority is valid for 10 years, and the certificates that it issues
// for 90 days. Each certificate is renewed once it has 30 days left, and the authority is replaced once
// it has 90 days left, so that no certificate outlives it. A collector's certificate is for a server
// only, and the operator's for a client only: a collector's server requires a client certificate for
// a client, so no collector can use its own certificate to call another.
package certs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// CASecretName is the name of the authority's Secret, in the operator's namespace.
	CASecretName = "vexplain-collector-ca"
	// caName is the name in the authority's certificate.
	caName = "vexplain-collector-ca"
	// caCertKey is the key under which a collector's Secret holds the authority's certificate, beside
	// its own certificate and key, as the authority's Secret does. The collector's server requires a
	// client certificate that the authority signed.
	caCertKey = "ca.crt"
	// caKeyKey is the key under which the authority's Secret holds the authority's key.
	caKeyKey = "ca.key"
	// clientName is the name in the operator's client certificate.
	clientName = "vexplain"
)

const (
	// caYears is how many years the authority is valid.
	caYears = 10
	// leafValidity is how long a certificate that the authority issues is valid.
	leafValidity = 90 * 24 * time.Hour
	// renewBefore is how long before it expires a certificate is renewed.
	renewBefore = 30 * 24 * time.Hour
	// backdate is how long before its issue a certificate is valid from, so that a node whose clock is
	// a little behind accepts it at once. client-go's certificate helpers allow an hour too.
	backdate = time.Hour
)

// The Authority reads its own Secret and the collectors' TLS Secrets through the API reader, because
// the manager's cache holds only the Secrets of the LLM keys, and creates and updates them in the
// operator's namespace. Markers generate no bindings: config/rbac/manager_secrets_rolebinding.yaml
// binds the Role.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;create;update,namespace=vexplain-system

// Authority is the certificate authority of the collectors, which a process of the operator loads
// from its Secret. It keeps the TLS Secret of each collector, and the operator's client certificate in
// memory.
//
// Its methods are safe for concurrent use: the collector client asks for its TLS at each connection,
// while the deployer ensures the Secrets of the collectors.
type Authority struct {
	// writer creates and updates the Secrets, and reader reads them.
	writer    client.Client
	reader    client.Reader
	namespace string
	// now is the clock of every decision about validity.
	now func() time.Time

	// mu guards ca and clientCert.
	mu sync.Mutex
	// ca is the authority, which the first call of EnsureCA, EnsureServer or ClientTLS loads, and a
	// call loads again once it has 90 days left.
	ca *keyPair
	// clientCert is the operator's client certificate; nil until ClientTLS first issues it.
	clientCert *tls.Certificate
}

// keyPair is a certificate with its key, and the certificate in PEM, as a Secret holds it.
type keyPair struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// NewAuthority returns the Authority of the collectors in namespace, the operator's. reader is the
// manager's API reader, which reads the TLS Secrets of the collectors, and c writes them. now is the
// clock that every decision about validity reads: time.Now, except in tests.
func NewAuthority(c client.Client, reader client.Reader, namespace string, now func() time.Time) *Authority {
	return &Authority{writer: c, reader: reader, namespace: namespace, now: now}
}

// ServerName returns the name under which the collector client reaches a collector and checks its
// certificate: vexplain-collector-<name>.<namespace>.svc, the DNS name of the collector's Service.
func ServerName(collector, namespace string) string {
	return ServiceName(collector) + "." + namespace + ".svc"
}

// SecretName returns the name of a collector's TLS Secret, vexplain-collector-<name>-tls, which
// EnsureServer writes and the collector's Deployment mounts.
func SecretName(collector string) string {
	return ServiceName(collector) + "-tls"
}

// ServiceName returns the name of a collector's Service, vexplain-collector-<name>, which the deployer
// gives its Deployment and its service account too. Every name of what the operator makes for a collector
// comes from here. It is a DNS-1035 label, since a Collector's name has at most 44 characters: a label has
// at most 63, and the prefix takes 19.
func ServiceName(collector string) string {
	return "vexplain-collector-" + collector
}

// serverNames returns the names of a collector's server certificate: the DNS name of its Service, and
// the same name in the cluster's domain.
func serverNames(collector, namespace string) []string {
	name := ServerName(collector, namespace)
	return []string{name, name + ".cluster.local"}
}

// EnsureCA loads the authority from its Secret, or makes it there, at its first call, and again once
// the authority has 90 days left. EnsureServer and ClientTLS do as much, so EnsureCA serves to have the
// authority before either.
func (a *Authority) EnsureCA(ctx context.Context) error {
	_, err := a.ensureCA(ctx)
	return err
}

// ensureCA returns the authority. It loads it from its Secret at the first call, and again once the
// one in memory has 90 days left, since another process may have replaced it already.
func (a *Authority) ensureCA(ctx context.Context) (*keyPair, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.ca != nil && caCurrent(a.ca.cert, now) {
		return a.ca, nil
	}
	ca, err := a.loadCA(ctx, now)
	if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
		// Another process wrote the Secret after this one read it, as two that start at once do: this
		// one takes the authority that the Secret holds now.
		ca, err = a.loadCA(ctx, now)
	}
	if err != nil {
		return nil, err
	}
	a.ca = ca
	return ca, nil
}

// loadCA returns the authority that its Secret holds. It makes a new one and writes it there instead
// when the Secret is missing, holds no authority that it can use, or holds one with 90 days left. What
// it logs names the Secret, and never what the Secret holds. When another process wrote the Secret
// first, its error is the API server's AlreadyExists or Conflict.
func (a *Authority) loadCA(ctx context.Context, now time.Time) (*keyPair, error) {
	key := client.ObjectKey{Namespace: a.namespace, Name: CASecretName}
	log := logf.FromContext(ctx).WithValues("secret", key.String())
	var secret corev1.Secret
	err := a.reader.Get(ctx, key, &secret)
	found := err == nil
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("read the Secret %s: %w", key, err)
	}
	// why says why the authority of a Secret that exists is replaced.
	var why string
	if found {
		loaded, err := parseCA(secret.Data)
		if err == nil && caCurrent(loaded.cert, now) {
			log.Info("Loaded the certificate authority of the collectors from its Secret", "notAfter", loaded.cert.NotAfter)
			return loaded, nil
		}
		why = "the authority is in its last 90 days"
		if err != nil {
			why = "the Secret holds no authority that can be used: " + err.Error()
		}
	}

	ca, err := issue(&x509.Certificate{
		Subject:               pkix.Name{CommonName: caName},
		NotBefore:             now.UTC().Add(-backdate),
		NotAfter:              now.UTC().AddDate(caYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// It signs the certificates of servers and of the client, and no other authority's.
		MaxPathLenZero: true,
	}, nil)
	if err != nil {
		return nil, err
	}
	keyPEM, err := ca.keyPEM()
	if err != nil {
		return nil, err
	}
	data := map[string][]byte{caCertKey: ca.certPEM, caKeyKey: keyPEM}
	if !found {
		if err := a.writer.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			Type:       corev1.SecretTypeOpaque,
			Data:       data,
		}); err != nil {
			return nil, fmt.Errorf("create the Secret %s: %w", key, err)
		}
		log.Info("Created the certificate authority of the collectors in its Secret; " +
			"the collectors' certificates are issued from it")
		return ca, nil
	}
	secret.Data = data
	if err := a.writer.Update(ctx, &secret); err != nil {
		return nil, fmt.Errorf("update the Secret %s: %w", key, err)
	}
	log.Info("Replaced the certificate authority of the collectors in its Secret; "+
		"the collectors' certificates are issued again from it", "reason", why)
	return ca, nil
}

// parseCA returns the authority that data, the authority's Secret, holds: the certificate of an
// authority under ca.crt, and its ECDSA key under ca.key. Its errors say what is wrong, and never what
// data holds.
func parseCA(data map[string][]byte) (*keyPair, error) {
	pair, err := parsePair(data[caCertKey], data[caKeyKey])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("its key isn't an ECDSA key")
	}
	if !pair.Leaf.IsCA {
		return nil, errors.New("its certificate isn't an authority's")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Leaf.Raw})
	return &keyPair{cert: pair.Leaf, key: key, certPEM: certPEM}, nil
}

// caCurrent says whether the authority of cert may still issue certificates at now: whether it has more
// than 90 days left, so that every certificate that it issues ends before it does.
func caCurrent(cert *x509.Certificate, now time.Time) bool {
	return now.Before(cert.NotAfter.Add(-leafValidity))
}

// EnsureServer writes the Secret vexplain-collector-<name>-tls of the collector, or renews what it
// holds: under tls.crt, a server certificate for the names vexplain-collector-<name>.<namespace>.svc
// and .svc.cluster.local; under tls.key, its key; and under ca.crt, the authority's certificate. It
// loads the authority first, as EnsureCA does.
//
// It issues a new certificate, with a new key, unless the Secret holds one that the authority would
// issue now and that has more than 30 days left. So a restart of the operator issues none again, and a
// new authority every one. renewed says whether it issued one, as it does for a Secret that didn't
// exist. It creates a Secret that doesn't exist, and otherwise changes the data only, so the labels and
// the owner that the deployer set stay.
func (a *Authority) EnsureServer(ctx context.Context, collector string) (renewed bool, err error) {
	ca, err := a.ensureCA(ctx)
	if err != nil {
		return false, err
	}
	key := client.ObjectKey{Namespace: a.namespace, Name: SecretName(collector)}
	var secret corev1.Secret
	err = a.reader.Get(ctx, key, &secret)
	found := err == nil
	if err != nil && !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("read the Secret %s: %w", key, err)
	}
	now := a.now()
	names := serverNames(collector, a.namespace)
	if found && serverCurrent(secret.Data, ca, names, now) {
		return false, nil
	}

	server, err := issue(leafTemplate(ServiceName(collector), x509.ExtKeyUsageServerAuth, names, now), ca)
	if err != nil {
		return false, err
	}
	keyPEM, err := server.keyPEM()
	if err != nil {
		return false, err
	}
	data := map[string][]byte{
		corev1.TLSCertKey:       server.certPEM,
		corev1.TLSPrivateKeyKey: keyPEM,
		caCertKey:               ca.certPEM,
	}
	if !found {
		if err := a.writer.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			Type:       corev1.SecretTypeTLS,
			Data:       data,
		}); err != nil {
			return false, fmt.Errorf("create the Secret %s: %w", key, err)
		}
		return true, nil
	}
	secret.Data = data
	if err := a.writer.Update(ctx, &secret); err != nil {
		return false, fmt.Errorf("update the Secret %s: %w", key, err)
	}
	return true, nil
}

// serverCurrent says whether data, a collector's Secret, holds a server certificate for names that
// needs no renewal at now, with its key, and the certificate of ca as ca.crt.
func serverCurrent(data map[string][]byte, ca *keyPair, names []string, now time.Time) bool {
	if !bytes.Equal(data[caCertKey], ca.certPEM) {
		return false
	}
	pair, err := parsePair(data[corev1.TLSCertKey], data[corev1.TLSPrivateKeyKey])
	return err == nil && current(pair.Leaf, ca, x509.ExtKeyUsageServerAuth, names, now)
}

// current says whether cert needs no renewal at now: ca signed it for usage alone and for names
// exactly, as it issues certificates now, and it has more than 30 days left.
//
// It doesn't check when cert became valid, so a clock that steps back after the issue renews
// nothing.
func current(cert *x509.Certificate, ca *keyPair, usage x509.ExtKeyUsage, names []string, now time.Time) bool {
	return cert.CheckSignatureFrom(ca.cert) == nil &&
		slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{usage}) &&
		slices.Equal(cert.DNSNames, names) &&
		now.Before(cert.NotAfter.Add(-renewBefore))
}

// ClientTLS returns the TLS configuration of the operator's client side, for a new connection to a
// collector: TLS 1.3, the authority as its only root, the operator's client certificate, and the
// Authority's clock to check certificates at. It holds the certificate in memory, and issues a new one
// when it has 30 days left. The caller sets the server name, from ServerName.
//
// It loads the authority first, as EnsureCA does, since a client may ask before the deployer's first
// check, as the streams of a new process do. Each call returns a new configuration with the certificate
// current at the call, so a client asks for one at each connection.
func (a *Authority) ClientTLS(ctx context.Context) (*tls.Config, error) {
	if _, err := a.ensureCA(ctx); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.clientCert == nil || !current(a.clientCert.Leaf, a.ca, x509.ExtKeyUsageClientAuth, nil, now) {
		issued, err := issue(leafTemplate(clientName, x509.ExtKeyUsageClientAuth, nil, now), a.ca)
		if err != nil {
			return nil, err
		}
		a.clientCert = &tls.Certificate{Certificate: [][]byte{issued.cert.Raw}, PrivateKey: issued.key, Leaf: issued.cert}
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.ca.cert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{*a.clientCert},
		// The client checks a collector's certificate at the Authority's clock, which issued the
		// certificate and decides when it is renewed.
		Time: a.now,
	}, nil
}

// leafTemplate returns the template of a certificate that the authority issues at now, under the
// name, for usage alone and for dnsNames: valid for 90 days, and no authority.
func leafTemplate(name string, usage x509.ExtKeyUsage, dnsNames []string, now time.Time) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              dnsNames,
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}
}

// issue returns a new key, and a certificate for it from template, signed by ca. A nil ca makes the
// certificate sign itself, as the authority's does. CreateCertificate draws the serial number at
// random, as RFC 5280 asks, since the template has none.
func issue(template *x509.Certificate, ca *keyPair) (*keyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate a key for %s: %w", template.Subject.CommonName, err)
	}
	parent, signer := template, key
	if ca != nil {
		parent, signer = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("issue the certificate of %s: %w", template.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse the certificate of %s: %w", template.Subject.CommonName, err)
	}
	return &keyPair{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// keyPEM returns the key of p in PEM, as a collector's Secret holds the collector's key, and the
// authority's Secret the authority's.
func (p *keyPair) keyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		return nil, fmt.Errorf("encode the key of %s: %w", p.cert.Subject.CommonName, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// parsePair parses a PEM certificate and its PEM key, and checks that they belong together. Its errors
// are those of tls.X509KeyPair, which name the types of PEM blocks and never what a block holds.
func parsePair(certPEM, keyPEM []byte) (tls.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	if pair.Leaf == nil {
		// GODEBUG x509keypairleaf=0 leaves the certificate unparsed.
		if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return tls.Certificate{}, err
		}
	}
	return pair, nil
}
