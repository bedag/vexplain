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

package docker_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/hack/internal/docker"
)

// fakeDocker puts a docker of the script first on the PATH, so that the test runs no docker of the machine.
func fakeDocker(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\n"+script+"\n"), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRunReturnsWhatDockerPrinted(t *testing.T) {
	fakeDocker(t, `echo "args: $*"; echo "a warning" >&2`)

	output, err := docker.Run(context.Background(), "push", "localhost:5001/a:b")

	require.NoError(t, err)
	require.Equal(t, "args: push localhost:5001/a:b\na warning\n", output)
}

// A failed build or push can print a lot, and its cause is at the end.
func TestRunFailsWithTheEndOfWhatDockerPrinted(t *testing.T) {
	fakeDocker(t, `i=0; while [ $i -lt 3000 ]; do printf x; i=$((i+1)); done; echo; echo "the cause"; exit 3`)

	_, err := docker.Run(context.Background(), "build", ".")

	require.ErrorContains(t, err, "docker build: exit status 3")
	require.ErrorContains(t, err, "...")
	require.ErrorContains(t, err, "the cause")
	require.Less(t, len(err.Error()), 2100, "the error carries the end of the output, not all of it")
}
