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

package collector

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/credentials"
)

// The files of a collector's TLS Secret, which vexplain's deployer mounts in Options.TLSDir.
const (
	// certFile is the server's certificate, which the server presents.
	certFile = "tls.crt"
	// keyFile is its key.
	keyFile = "tls.key"
	// caFile is the certificate of vexplain's authority, which must have signed a client's
	// certificate.
	caFile = "ca.crt"
)

// certificates are the server's TLS files. They are loaded again when they change, as when vexplain
// renews the server's certificate or replaces its authority, and each new connection gets the files
// that loaded last.
type certificates struct {
	dir    string
	config atomic.Pointer[tls.Config]
	// loaded is what the files held when they last loaded. One goroutine at a time loads them.
	loaded [][]byte
}

// load reads the files, and loads them when they differ from those that loaded last. It reports
// whether it loaded them. Files that don't load leave the server with the ones it has: a Secret's
// volume changes its files one by one, so a certificate can meet the key of the one before.
func (c *certificates) load() (bool, error) {
	files := make([][]byte, 0, 3)
	for _, name := range []string{certFile, keyFile, caFile} {
		content, err := os.ReadFile(filepath.Join(c.dir, name))
		if err != nil {
			return false, err
		}
		files = append(files, content)
	}
	if slices.EqualFunc(files, c.loaded, bytes.Equal) {
		return false, nil
	}
	pair, err := tls.X509KeyPair(files[0], files[1])
	if err != nil {
		return false, fmt.Errorf("%s and %s: %w", certFile, keyFile, err)
	}
	authority := x509.NewCertPool()
	if !authority.AppendCertsFromPEM(files[2]) {
		return false, fmt.Errorf("%s holds no certificate", caFile)
	}
	c.config.Store(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    authority,
	})
	c.loaded = files
	return true, nil
}

// wait loads the files, and tries again every interval, until they load or ctx ends.
func (c *certificates) wait(ctx context.Context, every time.Duration) error {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		_, err := c.load()
		if err == nil {
			return nil
		}
		slog.Error("Could not load the TLS files; serving once they load", "dir", c.dir, "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// watch loads the files again every interval when they changed, until ctx ends.
func (c *certificates) watch(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		switch changed, err := c.load(); {
		case err != nil:
			slog.Warn("Could not load the changed TLS files; keeping the ones that loaded last", "dir", c.dir, "error", err)
		case changed:
			slog.Info("Loaded the changed TLS files", "dir", c.dir)
		}
	}
}

// transport returns the credentials of the gRPC server. They give each new connection the files that
// loaded last: the server presents its certificate, and requires one from the client that vexplain's
// authority signed.
func (c *certificates) transport() credentials.TransportCredentials {
	return credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return c.config.Load(), nil
		},
	})
}
