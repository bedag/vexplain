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

package scan_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/bedag/vexplain/internal/controller/scan"
)

// logLimit is the most of a scan pod's log that the reader reads: 8 MiB.
const logLimit = 8 << 20

// logServer is an API server that serves one pod log, and records the request for it.
type logServer struct {
	*httptest.Server
	mu    sync.Mutex
	path  string
	query url.Values
}

// newLogServer serves body, with status, as the log of every pod.
func newLogServer(t *testing.T, status int, body string) *logServer {
	t.Helper()
	s := &logServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.path, s.query = r.URL.Path, r.URL.Query()
		s.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

// reader returns a LogReader that reads through a clientset of the server.
func (s *logServer) reader(t *testing.T) scan.LogReader {
	t.Helper()
	clientset, err := kubernetes.NewForConfig(&rest.Config{Host: s.URL})
	require.NoError(t, err)
	return scan.NewLogReader(clientset)
}

// A scan pod has one container, and the reader asks the API server for its log alone, and for no
// more than the limit, which the API server passes to the kubelet.
func TestLogReaderReadsTheLogOfTheScannerContainer(t *testing.T) {
	server := newLogServer(t, http.StatusOK, "scanner: resolving the image\nvexplain-scan-error v1 NotFound\n")

	log, err := server.reader(t).ScanLog(t.Context(), "vexplain-system", "scan-0123456789ab-x2k4p")

	require.NoError(t, err)
	require.Equal(t, "scanner: resolving the image\nvexplain-scan-error v1 NotFound\n", log)
	require.Equal(t, "/api/v1/namespaces/vexplain-system/pods/scan-0123456789ab-x2k4p/log", server.path)
	require.Equal(t, url.Values{"container": {scannerContainer}, "limitBytes": {"8388608"}}, server.query)
}

// The limit holds even when the server sends more: the reader never reads past it.
func TestLogReaderReadsNoMoreThanTheLimit(t *testing.T) {
	server := newLogServer(t, http.StatusOK, strings.Repeat("x", logLimit+1024))

	log, err := server.reader(t).ScanLog(t.Context(), "vexplain-system", "scan-0123456789ab-x2k4p")

	require.NoError(t, err)
	require.Len(t, log, logLimit)
}

// A log that can't be read is an error, and never an empty log.
func TestLogReaderReturnsAFailedRead(t *testing.T) {
	server := newLogServer(t, http.StatusNotFound,
		`{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)

	_, err := server.reader(t).ScanLog(t.Context(), "vexplain-system", "scan-0123456789ab-x2k4p")

	require.Error(t, err)
}
