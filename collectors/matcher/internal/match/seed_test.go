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

package match

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// databaseFile is where a database that Grype calls valid keeps its content, under the database directory.
const databaseFile = "6/vulnerability.db"

// seedTree writes a tree like the one `grype db update` leaves in its cache directory.
func seedTree(t *testing.T) string {
	t.Helper()
	seed := filepath.Join(t.TempDir(), "grype-db")
	require.NoError(t, os.MkdirAll(filepath.Join(seed, "6"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(seed, databaseFile), []byte("database"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(seed, "6", "import.json"), []byte(`{"digest": "x"}`), 0o640))
	return seed
}

func TestSeedDatabaseCopiesTheTree(t *testing.T) {
	seed := seedTree(t)
	dir := filepath.Join(t.TempDir(), "db")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, seedDatabase(seed, dir))

	got, err := os.ReadFile(filepath.Join(dir, databaseFile))
	require.NoError(t, err)
	require.Equal(t, "database", string(got))
	got, err = os.ReadFile(filepath.Join(dir, "6", "import.json"))
	require.NoError(t, err)
	require.JSONEq(t, `{"digest": "x"}`, string(got))
	info, err := os.Stat(filepath.Join(dir, "6", "import.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm())

	// The seed is a copy's source, and stays as it is. No temporary file is left in the target.
	require.FileExists(t, filepath.Join(seed, databaseFile))
	entries, err := os.ReadDir(filepath.Join(dir, "6"))
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

func TestSeedDatabaseCreatesTheTargetAndReplacesWhatIsThere(t *testing.T) {
	seed := seedTree(t)
	// A target that doesn't exist yet, and a database in it that an earlier copy left half-written.
	dir := filepath.Join(t.TempDir(), "new", "db")
	require.NoError(t, seedDatabase(seed, dir))
	require.NoError(t, os.WriteFile(filepath.Join(dir, databaseFile), []byte("half"), 0o644))
	require.NoError(t, seedDatabase(seed, dir))
	got, err := os.ReadFile(filepath.Join(dir, databaseFile))
	require.NoError(t, err)
	require.Equal(t, "database", string(got))
}

func TestSeedDatabaseFails(t *testing.T) {
	dir := t.TempDir()
	t.Run("no seed", func(t *testing.T) {
		require.Error(t, seedDatabase(filepath.Join(t.TempDir(), "missing"), dir))
	})
	t.Run("a seed that is a file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "seed")
		require.NoError(t, os.WriteFile(file, []byte("database"), 0o644))
		target := filepath.Join(t.TempDir(), "db")
		require.Error(t, seedDatabase(file, target))
		require.NoFileExists(t, target)
	})
	t.Run("a seed that holds a link", func(t *testing.T) {
		seed := seedTree(t)
		require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(seed, "6", "link")))
		require.Error(t, seedDatabase(seed, filepath.Join(t.TempDir(), "db")))
	})
	t.Run("a target that can't be written", func(t *testing.T) {
		blocked := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(blocked, nil, 0o644))
		require.Error(t, seedDatabase(seedTree(t), filepath.Join(blocked, "db")))
	})
	t.Run("a failed copy leaves no temporary file", func(t *testing.T) {
		seed := seedTree(t)
		target := t.TempDir()
		// A directory where the file should go: the rename fails after the copy.
		require.NoError(t, os.MkdirAll(filepath.Join(target, databaseFile), 0o755))
		require.Error(t, seedDatabase(seed, target))
		entries, err := os.ReadDir(filepath.Join(target, "6"))
		require.NoError(t, err)
		for _, e := range entries {
			require.NotContains(t, e.Name(), ".seed", "left behind: %s", e.Name())
		}
	})
}
