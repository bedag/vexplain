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

// Package docker runs the docker CLI for the tools in hack/ that build and push images, or read a kind node.
package docker

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// tailBytes is how much of the end of the output an error carries: the cause of a failed build or push is at the end.
const tailBytes = 2000

// Run runs the docker CLI with the arguments, and returns what it printed, its standard output and error together. An
// error carries the end of that output.
func Run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		tail := output.String()
		if len(tail) > tailBytes {
			tail = "..." + tail[len(tail)-tailBytes:]
		}
		return "", fmt.Errorf("docker %s: %w\n%s", args[0], err, tail)
	}
	return output.String(), nil
}
