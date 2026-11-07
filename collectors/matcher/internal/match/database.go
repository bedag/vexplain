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
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/bedag/vexplain/sdk/collector"
)

// Load asks Grype for the status of the database that is in its directory. When the status is valid, the matcher has
// that database. An error leaves it as it was.
func (m *Matcher) Load(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	db, err := m.opts.Grype.Status(ctx)
	if err != nil {
		return err
	}
	m.db.Store(&db)
	logf.FromContext(ctx).Info("Loaded the vulnerability database", "version", db.Version, "built", db.Built)
	return nil
}

// update updates the database. It waits for the matches that run, and holds the next ones back until it is done. A
// failed update keeps the database that was in use, and so does one whose status can't be read afterwards: the version
// then stays the old one, which is never newer than the files.
func (m *Matcher) update(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.opts.Grype.Update(ctx); err != nil {
		return err
	}
	db, err := m.opts.Grype.Status(ctx)
	if err != nil {
		return fmt.Errorf("reading the status after the update: %w", err)
	}
	old := m.db.Swap(&db)
	log := logf.FromContext(ctx)
	if old != nil && old.Version == db.Version {
		log.Info("The vulnerability database is up to date", "version", db.Version)
	} else {
		log.Info("Updated the vulnerability database", "version", db.Version, "built", db.Built)
	}
	return nil
}

// Watch sends an empty snapshot, which no evidence belongs to, and then keeps the database as the settings say, until
// ctx ends. It says SourceChanged, with no subjects, whenever the version of the database is one that no Watch has said
// yet: at the first Watch of the process, which can't know what the hub matched on, and after each update that changed
// the database. A Watch that opens again after a break or for new settings says nothing of a version that was said.
//
// The snapshot comes first and at once, so that a download of the database, which can take minutes, holds nothing up:
// a match asked for before it is done fails with NotReady.
func (m *Matcher) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	set, problems := settingsOf(req.Settings)
	if len(problems) > 0 {
		return status.Error(codes.InvalidArgument, "the settings: "+problems[0])
	}
	if err := sink.SnapshotStart(); err != nil {
		return err
	}
	if err := sink.SnapshotEnd(); err != nil {
		return err
	}
	return m.maintain(ctx, set, sink)
}

// maintain gives the matcher its database, and keeps it current, until ctx ends. It gets the database in this order:
//  1. It loads the one that the database directory holds.
//  2. When there is none, and a seed is set, it copies the seed into the directory, and loads it. The image built with
//     its database holds one for this: a volume at /db would hide one baked there.
//  3. When there is still none, and the matcher is online, it updates, through the proxy of its environment.
//
// Then it updates every interval. Offline means no update at all: not at start, and not on the interval. A failed
// update keeps the old database.
func (m *Matcher) maintain(ctx context.Context, set settings, sink collector.Sink) error {
	log := logf.FromContext(ctx)
	loaded := true
	if err := m.Load(ctx); err != nil {
		loaded = m.db.Load() != nil
		if !loaded {
			log.Info("The database directory holds no valid vulnerability database", "dir", m.opts.DBDir,
				"reason", err.Error())
		}
	}
	if !loaded && set.SeedDatabase != "" {
		loaded = m.seed(ctx, set.SeedDatabase)
	}
	if loaded {
		if err := m.notify(sink); err != nil {
			return err
		}
	}

	if set.DatabaseUpdates == updatesOffline {
		if loaded {
			log.Info("The matcher is offline: it never updates the vulnerability database")
		} else {
			log.Error(errors.New("no database"), "The matcher is offline and has no vulnerability database, "+
				"so every match fails with NotReady", "dir", m.opts.DBDir)
		}
		<-ctx.Done()
		return nil
	}

	if !loaded {
		if err := m.updateAndNotify(ctx, sink); err != nil {
			return err
		}
	}
	interval := time.Duration(set.UpdateIntervalSeconds) * time.Second
	for {
		wait := interval
		if m.db.Load() == nil {
			// Without a database the matcher can't serve, so it doesn't wait for the interval, which is hours.
			wait = min(wait, m.opts.RetryDelay)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-m.opts.After(wait):
		}
		if err := m.updateAndNotify(ctx, sink); err != nil {
			return err
		}
	}
}

// updateAndNotify updates the database, and says SourceChanged when its version is new. A failed update is logged,
// and keeps what there was. It returns an error only for a sink that broke.
func (m *Matcher) updateAndNotify(ctx context.Context, sink collector.Sink) error {
	log := logf.FromContext(ctx)
	log.Info("Updating the vulnerability database")
	if err := m.update(ctx); err != nil {
		if ctx.Err() == nil { // a stop is not a failure
			log.Error(err, "Could not update the vulnerability database")
		}
		return nil
	}
	return m.notify(sink)
}

// notify says SourceChanged when the database's version is not the one that was said last.
func (m *Matcher) notify(sink collector.Sink) error {
	db := m.db.Load()
	if db == nil {
		return nil
	}
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	if m.notified == db.Version {
		return nil
	}
	if err := sink.SourceChanged(); err != nil {
		return err
	}
	m.notified = db.Version
	return nil
}

// seed copies the seed into the database directory, and loads it. It reports whether the matcher has a database now.
func (m *Matcher) seed(ctx context.Context, seed string) bool {
	log := logf.FromContext(ctx)
	log.Info("Seeding the database directory", "seed", seed, "dir", m.opts.DBDir)
	if err := seedDatabase(seed, m.opts.DBDir); err != nil {
		log.Error(err, "Could not seed the database directory", "seed", seed, "dir", m.opts.DBDir)
		return false
	}
	if err := m.Load(ctx); err != nil {
		log.Error(err, "The seeded database is not valid", "seed", seed)
		return false
	}
	return true
}

// seedDatabase copies the tree under seed into dir. A seed holds directories and regular files, as Grype leaves them in
// its cache directory, and nothing else: a link or any other entry is an error. Each file appears under its name only
// when it is complete, so that a copy that is cut off doesn't leave a database that looks whole.
func seedDatabase(seed, dir string) error {
	info, err := os.Stat(seed)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("the seed is not a directory")
	}
	return filepath.WalkDir(seed, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(seed, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dir, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type().IsRegular():
			return copyFile(path, target)
		default:
			return fmt.Errorf("the seed holds %q, which is neither a file nor a directory", rel)
		}
	})
}

// copyFile copies the file src to dst, with its permissions, through a temporary file beside dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.CreateTemp(filepath.Dir(dst), ".seed-*")
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(out.Name())
		}
	}()
	_, err = io.Copy(out, in)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(out.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Rename(out.Name(), dst); err != nil {
		return err
	}
	renamed = true
	return nil
}
