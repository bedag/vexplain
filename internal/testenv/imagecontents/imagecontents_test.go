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

package imagecontents_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bedag/vexplain/internal/testenv/imagecontents"
)

// goldenDir holds the golden files of the scanner's evidence, which the scanner's own tests hold its Manifest to.
var goldenDir = filepath.Join("..", "..", "..", "collectors", "scanner", "internal", "result", "testdata")

// The types of this package write the JSON of the scanner's Manifest: every field under its name, and what is left
// out when empty, as the golden files of the scanner hold them. A field that the scanner adds, renames or drops fails
// here once its golden files follow it.
func TestTheTypesWriteTheJSONOfTheScannersManifest(t *testing.T) {
	for _, file := range []string{"manifest-every-field.json", "manifest-no-field.json"} {
		t.Run(file, func(t *testing.T) {
			golden, err := os.ReadFile(filepath.Join(goldenDir, file))
			require.NoError(t, err)
			var mirrored imagecontents.Manifest
			decoder := json.NewDecoder(bytes.NewReader(golden))
			decoder.DisallowUnknownFields()
			require.NoError(t, decoder.Decode(&mirrored), "every field of the golden file is one of Manifest's")

			raw, err := json.Marshal(mirrored)
			require.NoError(t, err)
			require.JSONEq(t, string(golden), string(raw), "and Manifest writes it back as it was")
		})
	}
}

// The coverage of the scanner's evidence is the share of the ELF files that packages own, rounded down, and 100 for
// a filesystem without any.
func TestCompletenessIsTheShareOfTheELFFilesThatPackagesOwn(t *testing.T) {
	for _, tc := range []struct {
		elf  imagecontents.ELFSummary
		want int32
	}{
		{imagecontents.ELFSummary{Total: 4, Owned: 3}, 75},
		{imagecontents.ELFSummary{Total: 3, Owned: 2}, 66},
		{imagecontents.ELFSummary{}, 100},
		{imagecontents.ELFSummary{Total: 1, Owned: 2}, 0},
	} {
		require.Equal(t, tc.want, imagecontents.Manifest{ELF: tc.elf}.Completeness(), "%+v", tc.elf)
	}
}
