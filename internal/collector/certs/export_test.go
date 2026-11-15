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

package certs

import (
	"crypto/x509"
	"errors"
)

// CAKeyPEM returns the private key of the authority in PEM, as its Secret holds it, or nil before the
// Authority has loaded it. The tests of package certs_test take it from here to compare it with the
// authority's Secret, and to look for it where it must not be: in another Secret, or in a log line.
func (a *Authority) CAKeyPEM() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ca == nil {
		return nil
	}
	keyPEM, err := a.ca.keyPEM()
	if err != nil {
		panic(err)
	}
	return keyPEM
}

// Issue returns a certificate from template that the authority signs, and its new key, both in PEM, so
// that a test can put a certificate in a Secret that the authority signed but wouldn't issue.
func (a *Authority) Issue(template *x509.Certificate) (certPEM, keyPEM []byte, err error) {
	a.mu.Lock()
	ca := a.ca
	a.mu.Unlock()
	if ca == nil {
		return nil, nil, errors.New("the authority isn't loaded yet")
	}
	pair, err := issue(template, ca)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = pair.keyPEM()
	return pair.certPEM, keyPEM, err
}
