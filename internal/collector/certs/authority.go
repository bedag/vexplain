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
// The operator calls its collectors over mutual TLS, as Crossplane calls its functions. It keeps an
// authority in the Secret vexplain-collector-ca of its namespace. It gives each collector a server
// certificate in the Secret vexplain-collector-<name>-tls, which the collector's Deployment mounts,
// and itself a client certificate, which it holds in memory.
//
// Every key is ECDSA on P-256. The authority is valid for 10 years, and the certificates that it issues
// for 90 days; each is renewed once it has 30 days left. A collector's certificate is for a server
// only, and the operator's for a client only: a collector's server requires a client certificate for
// a client, so no collector can use its own certificate to call another.
package certs

import (
	"bytes"
	"context"
	"crypto"
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
	// caSecret is the Secret of the authority, in the operator's namespace. It holds the authority's
	// certificate and key under the keys of a TLS Secret.
	caSecret = "vexplain-collector-ca"
	// caCertKey is the key under which a collector's Secret holds the authority's certificate, beside
	// its own certificate and key. The collector's server requires a client certificate that the
	// authority signed.
	caCertKey = "ca.crt"
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

// The Authority reads its Secrets through the API reader, because the manager's cache holds only the
// Secrets of the LLM keys, and creates and updates them in the operator's namespace. Markers generate
// no bindings: config/rbac/manager_secrets_rolebinding.yaml binds the Role.
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;create;update,namespace=vexplain-system

// Authority is the certificate authority of the collectors. It keeps the Secrets of the authority and
// of each collector's server certificate, and the operator's client certificate in memory.
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

	// ensuring is held while EnsureCA or EnsureServer reads and writes the Secrets, so that they create
	// no second authority, and each issues from the authority that it has just read.
	ensuring sync.Mutex

	// mu guards ca and clientCert, which ClientTLS reads while the Secrets are ensured.
	mu sync.Mutex
	// ca is the authority that was loaded or created last; nil before the first time.
	ca *keyPair
	// clientCert is the operator's client certificate; nil until ClientTLS first issues it.
	clientCert *tls.Certificate
}

// keyPair is a certificate with its key. certPEM and keyPEM are their PEM encodings, as a Secret holds
// them; keyPEM is empty for an authority that was loaded, since its Secret already holds it.
type keyPair struct {
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM []byte
	keyPEM  []byte
}

// NewAuthority returns the Authority of the collectors in namespace, the operator's. reader is the
// manager's API reader, which reads the Secrets of the authority and of the collectors, and c writes
// them. now is the clock that every decision about validity reads: time.Now, except in tests.
func NewAuthority(c client.Client, reader client.Reader, namespace string, now func() time.Time) *Authority {
	return &Authority{writer: c, reader: reader, namespace: namespace, now: now}
}

// ServerName returns the name under which the collector client reaches a collector and checks its
// certificate: vexplain-collector-<name>.<namespace>.svc, the DNS name of the collector's Service.
func ServerName(collector, namespace string) string {
	return serviceName(collector) + "." + namespace + ".svc"
}

// serviceName returns the name of a collector's Service. It is a DNS label, since a Collector's name
// has at most 44 characters.
func serviceName(collector string) string {
	return "vexplain-collector-" + collector
}

// serverNames returns the names of a collector's server certificate: the DNS name of its Service, and
// the same name in the cluster's domain.
func serverNames(collector, namespace string) []string {
	name := ServerName(collector, namespace)
	return []string{name, name + ".cluster.local"}
}

// EnsureCA loads the authority from the Secret vexplain-collector-ca, or creates it when the Secret
// doesn't exist.
//
// A Secret that holds no authority that the operator can use, such as one that expired, is reported
// and left as it is, and the authority loaded before stays in memory: every collector's certificate
// rests on the authority, so only an admin who deletes the Secret makes way for a new one. EnsureServer
// loads the authority as well, so the deployer creates a deleted authority again at its next pass, and
// issues every collector's certificate again from it.
func (a *Authority) EnsureCA(ctx context.Context) error {
	a.ensuring.Lock()
	defer a.ensuring.Unlock()
	_, err := a.ensureCA(ctx)
	return err
}

// ensureCA is EnsureCA, for a caller that holds ensuring. It returns the authority.
func (a *Authority) ensureCA(ctx context.Context) (*keyPair, error) {
	key := client.ObjectKey{Namespace: a.namespace, Name: caSecret}
	var secret corev1.Secret
	err := a.reader.Get(ctx, key, &secret)
	if apierrors.IsNotFound(err) {
		ca, createErr := a.createCA(ctx, key)
		if createErr == nil {
			a.setCA(ca)
			return ca, nil
		}
		if !apierrors.IsAlreadyExists(createErr) {
			return nil, createErr
		}
		// Another replica of the operator created it first: the authority is the one that it created.
		err = a.reader.Get(ctx, key, &secret)
	}
	if err != nil {
		return nil, fmt.Errorf("read the Secret %s: %w", key, err)
	}
	ca, err := loadCA(&secret, a.now())
	if err != nil {
		return nil, fmt.Errorf("the Secret %s holds no certificate authority that the operator can use, and is left "+
			"as it is (%w); deleting it makes the operator create a new authority, and issue every collector's "+
			"certificate again", key, err)
	}
	a.setCA(ca)
	return ca, nil
}

// createCA creates a new authority, valid for 10 years, in the Secret that key names.
func (a *Authority) createCA(ctx context.Context, key client.ObjectKey) (*keyPair, error) {
	now := a.now().UTC()
	ca, err := issue(&x509.Certificate{
		Subject:               pkix.Name{CommonName: caSecret},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.AddDate(caYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// It signs the certificates of servers and of the client, and no other authority's.
		MaxPathLenZero: true,
	}, nil)
	if err != nil {
		return nil, err
	}
	if err := a.writer.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{corev1.TLSCertKey: ca.certPEM, corev1.TLSPrivateKeyKey: ca.keyPEM},
	}); err != nil {
		return nil, fmt.Errorf("create the Secret %s: %w", key, err)
	}
	logf.FromContext(ctx).Info("Created the certificate authority of the collectors", "secret", key.String())
	return ca, nil
}

// loadCA returns the authority that secret holds, if the operator can use it at now: the certificate
// of an authority, with its key, that hasn't expired. A certificate from an authority that expired
// verifies nowhere.
func loadCA(secret *corev1.Secret, now time.Time) (*keyPair, error) {
	certPEM := secret.Data[corev1.TLSCertKey]
	pair, err := parsePair(certPEM, secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return nil, err
	}
	cert := pair.Leaf
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, errors.New("its certificate is not an authority's")
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("its certificate expired at %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("its key can't sign")
	}
	return &keyPair{cert: cert, key: signer, certPEM: certPEM}, nil
}

// setCA makes ca the authority that ClientTLS trusts and issues from.
func (a *Authority) setCA(ca *keyPair) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ca = ca
}

// EnsureServer writes the Secret vexplain-collector-<name>-tls of the collector, or renews what it
// holds: under tls.crt, a server certificate for the names vexplain-collector-<name>.<namespace>.svc
// and .svc.cluster.local; under tls.key, its key; and under ca.crt, the authority's certificate. It
// loads the authority first, as EnsureCA does.
//
// It issues a new certificate, with a new key, unless the Secret holds one that the authority would
// issue now and that has more than 30 days left. renewed says whether it issued one, as it does for a
// Secret that didn't exist. It creates a Secret that doesn't exist, and otherwise changes the data
// only, so the labels and the owner that the deployer set stay.
func (a *Authority) EnsureServer(ctx context.Context, collector string) (renewed bool, err error) {
	a.ensuring.Lock()
	defer a.ensuring.Unlock()
	ca, err := a.ensureCA(ctx)
	if err != nil {
		return false, err
	}
	key := client.ObjectKey{Namespace: a.namespace, Name: serviceName(collector) + "-tls"}
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

	server, err := issue(leafTemplate(serviceName(collector), x509.ExtKeyUsageServerAuth, names, now), ca)
	if err != nil {
		return false, err
	}
	data := map[string][]byte{
		corev1.TLSCertKey:       server.certPEM,
		corev1.TLSPrivateKeyKey: server.keyPEM,
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
// It doesn't check when cert became valid, so a clock that is behind the clock of the replica that
// issued cert renews nothing.
func current(cert *x509.Certificate, ca *keyPair, usage x509.ExtKeyUsage, names []string, now time.Time) bool {
	return cert.CheckSignatureFrom(ca.cert) == nil &&
		slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{usage}) &&
		slices.Equal(cert.DNSNames, names) &&
		now.Before(cert.NotAfter.Add(-renewBefore))
}

// ClientTLS returns the TLS configuration of the operator's client side, for a new connection to a
// collector: TLS 1.3, the authority that was loaded last as its only root, and the operator's client
// certificate. It holds the certificate in memory, and issues a new one when it has 30 days left, or
// when the authority changed. The caller sets the server name, from ServerName.
//
// Each call returns a new configuration with the authority and the certificate current at the call,
// so a client asks for one at each connection. It fails until EnsureCA or EnsureServer has loaded an
// authority.
func (a *Authority) ClientTLS() (*tls.Config, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ca == nil {
		return nil, errors.New("the certificate authority of the collectors isn't loaded yet")
	}
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
	parent, signer := template, crypto.Signer(key)
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
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode the key of %s: %w", template.Subject.CommonName, err)
	}
	return &keyPair{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
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
