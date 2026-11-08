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

	"github.com/bedag/vexplain/collectors/vulnerabilities/internal/grype"
	"github.com/bedag/vexplain/sdk/collector"
)

// Load asks Grype for the status of the database that is in its directory. When the status is valid, the vulnerabilities collector has
// that database. An error leaves it as it was.
func (m *Collector) Load(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	db, err := m.opts.Grype.Status(ctx)
	if err != nil {
		return err
	}
	m.setDatabase(db)
	logf.FromContext(ctx).Info("Loaded the vulnerability database", "version", db.Version, "built", db.Built)
	return nil
}

// setDatabase makes db the database in use, and wakes the Watches, which say SourceChanged when its version is one that
// they have not said. The caller holds mu.
func (m *Collector) setDatabase(db grype.Database) *grype.Database {
	old := m.db.Swap(&db)
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	close(m.wake)
	m.wake = make(chan struct{})
	return old
}

// update updates the database. It waits for the matches that run, and holds the next ones back until it is done. A
// failed update keeps the database that was in use, and so does one whose status can't be read afterwards: the version
// then stays the old one, which is never newer than the files.
func (m *Collector) update(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.opts.Grype.Update(ctx); err != nil {
		return err
	}
	db, err := m.opts.Grype.Status(ctx)
	if err != nil {
		return fmt.Errorf("reading the status after the update: %w", err)
	}
	old := m.setDatabase(db)
	log := logf.FromContext(ctx)
	if old != nil && old.Version == db.Version {
		log.Info("The vulnerability database is up to date", "version", db.Version)
	} else {
		log.Info("Updated the vulnerability database", "version", db.Version, "built", db.Built)
	}
	return nil
}

// Sources reports the vulnerability database, with its version and the time it was built, once one is loaded: vexplain
// shows its age, and matches the manifests again when its version changes.
func (m *Collector) Sources() []collector.Source {
	db := m.db.Load()
	if db == nil {
		return nil
	}
	return []collector.Source{{Name: sourceName, Version: db.Version, BuiltTime: db.Built}}
}

// Watch sends an empty snapshot, which no evidence belongs to, and then says SourceChanged, with no subjects, whenever
// the database has a version that this Watch has not said, until ctx ends. Every open Watch says each new version. A
// Watch that opens when the database has a version that an earlier Watch said, says nothing of it, but the first Watch
// of the process says the version that it finds, since it can't know what the hub matched on.
//
// It only reports: the maintainer keeps the database (Maintain). The snapshot comes first and at once, so that a
// download of the database, which can take minutes, holds nothing up: a match asked for before it is done fails with
// NotReady.
func (m *Collector) Watch(ctx context.Context, req collector.WatchRequest, sink collector.Sink) error {
	set, problems := settingsOf(req.Settings)
	if len(problems) > 0 {
		return status.Error(codes.InvalidArgument, "the settings: "+problems[0])
	}
	m.useSettings(set)
	if err := sink.SnapshotStart(); err != nil {
		return err
	}
	if err := sink.SnapshotEnd(); err != nil {
		return err
	}
	seen, first := "", true
	for {
		m.notifyMu.Lock()
		wake, db := m.wake, m.db.Load()
		say := db != nil && db.Version != seen && (!first || db.Version != m.notified)
		if db != nil {
			seen, m.notified = db.Version, db.Version
		}
		m.notifyMu.Unlock()
		first = false
		if say {
			if err := sink.SourceChanged(); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-wake:
		}
	}
}

// useSettings makes set the settings that the maintainer and Fire follow, and wakes the maintainer when they changed.
// The latest request's settings count.
func (m *Collector) useSettings(set settings) {
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	if m.known && m.set == set {
		return
	}
	m.set, m.known = set, true
	close(m.settingsChanged)
	m.settingsChanged = make(chan struct{})
}

// currentSettings returns the latest settings, whether there are any, and the channel that closes when they change.
func (m *Collector) currentSettings() (set settings, known bool, changed <-chan struct{}) {
	m.settingsMu.Lock()
	defer m.settingsMu.Unlock()
	return m.set, m.known, m.settingsChanged
}

// Fire runs the schedule database: it starts an update in the background and returns, since an update takes minutes.
// Offline it does nothing, and a fire while an update runs does nothing either.
func (m *Collector) Fire(ctx context.Context, req collector.FireRequest) error {
	set, problems := settingsOf(req.Settings)
	if len(problems) > 0 {
		return status.Error(codes.InvalidArgument, "the settings: "+problems[0])
	}
	m.useSettings(set)
	log := logf.FromContext(ctx)
	if set.DatabaseUpdates == updatesOffline {
		log.Info("The vulnerabilities collector is offline: it doesn't update the vulnerability database")
		return nil
	}
	m.runMu.Lock()
	defer m.runMu.Unlock()
	if m.runCtx == nil {
		return status.Error(codes.Unavailable, "the vulnerabilities collector is not maintaining its database")
	}
	if !m.updating.CompareAndSwap(false, true) {
		log.Info("The vulnerability database is being updated: this fire does nothing")
		return nil
	}
	run := m.runCtx
	m.updates.Go(func() {
		defer m.updating.Store(false)
		m.updateOnce(run)
	})
	return nil
}

// updateOnce updates the database. A failed update is logged, and keeps what there was.
func (m *Collector) updateOnce(ctx context.Context) {
	log := logf.FromContext(ctx)
	log.Info("Updating the vulnerability database")
	if err := m.update(ctx); err != nil {
		if ctx.Err() == nil { // a stop is not a failure
			log.Error(err, "Could not update the vulnerability database")
		}
	}
}

// Maintain gives the vulnerabilities collector its database until ctx ends, and waits for the update that runs then.
// It loads the database that the database directory holds at once, which a volume keeps across restarts. It learns the
// settings only from the first request, so what needs them waits for it:
//  1. When there is still no database, and a seed is set, it copies the seed into the directory, and loads it. The
//     image built with its database holds one for this: a volume at /db would hide one baked there.
//  2. When there is still none, and the vulnerabilities collector is online, it updates, through the proxy of its
//     environment, and again after RetryDelay until it has one.
//
// Later updates are Fire's, on the schedule of spec.triggers. Offline means no update at all. A failed update keeps the
// old database.
func (m *Collector) Maintain(ctx context.Context) error {
	m.runMu.Lock()
	m.runCtx = ctx
	m.runMu.Unlock()
	defer func() {
		// No fire starts an update from here on, so the wait is for the ones that run.
		m.runMu.Lock()
		m.runCtx = nil
		m.runMu.Unlock()
		m.updates.Wait()
	}()

	log := logf.FromContext(ctx)
	if err := m.Load(ctx); err != nil {
		log.Info("The database directory holds no valid vulnerability database", "dir", m.opts.DBDir, "reason", err.Error())
	}
	reported, seeded := false, ""
	for {
		set, known, changed := m.currentSettings()
		var retry <-chan time.Time
		if known && m.db.Load() == nil {
			if set.SeedDatabase != "" && set.SeedDatabase != seeded {
				seeded = set.SeedDatabase
				m.seed(ctx, set.SeedDatabase)
			}
			switch {
			case m.db.Load() != nil:
			case set.DatabaseUpdates == updatesOffline:
				if !reported {
					log.Error(errors.New("no database"), "The vulnerabilities collector is offline and has no vulnerability database, "+
						"so every match fails with NotReady", "dir", m.opts.DBDir)
					reported = true
				}
			default:
				// A fire that updates holds the flag, and this waits out the retry delay instead.
				if m.updating.CompareAndSwap(false, true) {
					m.updateOnce(ctx)
					m.updating.Store(false)
				}
				if m.db.Load() == nil {
					// Without a database the vulnerabilities collector can't serve, so it doesn't wait for a schedule.
					retry = m.opts.After(m.opts.RetryDelay)
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-changed:
		case <-retry:
		}
	}
}

// seed copies the seed into the database directory, and loads it.
func (m *Collector) seed(ctx context.Context, seed string) {
	log := logf.FromContext(ctx)
	log.Info("Seeding the database directory", "seed", seed, "dir", m.opts.DBDir)
	if err := seedDatabase(seed, m.opts.DBDir); err != nil {
		log.Error(err, "Could not seed the database directory", "seed", seed, "dir", m.opts.DBDir)
		return
	}
	if err := m.Load(ctx); err != nil {
		log.Error(err, "The seeded database is not valid", "seed", seed)
	}
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
