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

// Command matcher is the hub's one vulnerability database, behind a small HTTP API (0022). It runs
// the Grype CLI for each SBOM that the hub sends, and answers with the matches. It runs as a
// Deployment of its own next to the operator.
//
//	matcher [--listen :8080] [--grype /usr/local/bin/grype] [--db-dir /db] [--offline]
//	        [--seed-db /opt/grype-db] [--update-interval 6h] [--max-concurrent 2]
//
// The matcher answers 503 until it has a database. It gets one in this order:
//  1. It loads the one that --db-dir holds.
//  2. When there is none, and --seed-db is set, it copies that directory into --db-dir, and loads it.
//     The image built with WITH_DB=true holds a database at /opt/grype-db for this: a volume at
//     /db would hide one baked there.
//  3. When there is still none, and the matcher is not offline, it updates, through the proxy of its
//     environment.
//
// Then it updates every --update-interval. --offline means no update at all: not at start, and
// not on the interval. A failed update keeps the old database, and the matcher stays ready.
//
// Nothing that Grype writes goes into a response or an error: its stderr is logged at debug level
// (--zap-log-level=debug) and nowhere else, because it can hold text from an image's SBOM.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/bedag/vexplain/internal/matchapi"
	"github.com/bedag/vexplain/internal/matcher"
)

// The defaults of the flags.
const (
	defaultListen         = ":8080"
	defaultGrype          = "/usr/local/bin/grype"
	defaultDBDir          = "/db"
	defaultUpdateInterval = 6 * time.Hour
	// defaultMaxConcurrent is as many matches as the hub's verdicts controller asks for at once
	// (matchWorkers in internal/controller/hub). A change of one calls for a change of the other.
	defaultMaxConcurrent = 2
)

const (
	// retryDelay is how long the matcher waits to update again when it has no database. Without one it
	// can't serve, so it doesn't wait for the interval, which is hours.
	retryDelay = time.Minute

	// The timeouts of the HTTP server.
	//
	// readHeaderTimeout stops a client that never finishes its headers.
	readHeaderTimeout = 10 * time.Second
	// readTimeout covers the request, which is up to 64 MiB and comes from inside the cluster. The
	// handler reads it at once, so a request that then waits for a slot has been read.
	readTimeout = time.Minute
	// writeTimeout counts from the end of the headers, so it covers the read, the wait for a slot
	// and the match. A large SBOM takes a minute to match, and the client waits for
	// matchapi.DefaultTimeout, so the server must not give up on the answer before the client does.
	writeTimeout = matchapi.DefaultTimeout + time.Minute
	idleTimeout  = 2 * time.Minute
	// shutdownTimeout is how long a stopped matcher lets the requests that run finish.
	shutdownTimeout = 30 * time.Second
)

// The exit codes.
const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

// errUsage is the error of options that parse but don't make sense. The reason has been printed.
var errUsage = errors.New("invalid options")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stderr)
	stop() // os.Exit doesn't run deferred calls.
	os.Exit(code)
}

// options are what the flags say.
type options struct {
	listen         string
	grype          string
	dbDir          string
	seedDB         string
	offline        bool
	updateInterval time.Duration
	maxConcurrent  int
	// retryDelay is not a flag. The tests shorten it.
	retryDelay time.Duration
	logOptions zap.Options
}

// parseOptions reads the flags. It prints the reason of a refusal, and the usage, to output.
func parseOptions(args []string, output io.Writer) (options, error) {
	opts := options{retryDelay: retryDelay}
	flags := flag.NewFlagSet("matcher", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&opts.listen, "listen", defaultListen, "The address the HTTP server listens on.")
	flags.StringVar(&opts.grype, "grype", defaultGrype, "The Grype CLI.")
	flags.StringVar(&opts.dbDir, "db-dir", defaultDBDir, "The directory of the vulnerability database.")
	flags.BoolVar(&opts.offline, "offline", false,
		"Use the database that --db-dir holds, and never update it: not at start, and not on the interval.")
	flags.StringVar(&opts.seedDB, "seed-db", "",
		"A directory that holds a database, such as the one an image built with WITH_DB=true has. At start, "+
			"when --db-dir holds no database, it is copied into --db-dir before the database is loaded.")
	flags.DurationVar(&opts.updateInterval, "update-interval", defaultUpdateInterval,
		"How often the database is updated. It has no effect with --offline.")
	flags.IntVar(&opts.maxConcurrent, "max-concurrent", defaultMaxConcurrent,
		"How many SBOMs are matched at once. A request that finds them all busy waits for one.")
	opts.logOptions.BindFlags(flags)
	// An error here has a fixed text and is logged where it happens, so a stack trace adds a screenful
	// to each failed match and nothing else. The flag still turns it on.
	if err := flags.Set("zap-stacktrace-level", "panic"); err != nil {
		return options{}, err
	}
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}

	var problem string
	switch {
	case flags.NArg() > 0:
		problem = "unexpected arguments"
	case opts.listen == "":
		problem = "--listen must not be empty"
	case opts.grype == "":
		problem = "--grype must not be empty"
	case opts.dbDir == "":
		problem = "--db-dir must not be empty"
	case opts.updateInterval <= 0:
		problem = "--update-interval must be positive"
	case opts.maxConcurrent < 1:
		problem = "--max-concurrent must be at least 1"
	}
	if problem != "" {
		_, _ = fmt.Fprintln(output, "matcher:", problem)
		flags.Usage()
		return options{}, errUsage
	}
	return opts, nil
}

// run is the matcher. It takes what main takes from the process, so that a test can start it and stop
// it, and returns the exit code. It runs until ctx ends, or until the HTTP server fails.
func run(ctx context.Context, args []string, stderr io.Writer) int {
	opts, err := parseOptions(args, stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case err != nil:
		return exitUsage
	}
	logger := zap.New(zap.UseFlagOptions(&opts.logOptions), zap.WriteTo(stderr))
	ctx, stop := context.WithCancel(logf.IntoContext(ctx, logger))
	defer stop()

	// A missing Grype is the one thing that every call would fail on, and its error says nothing.
	// So say it at the start.
	if _, err := exec.LookPath(opts.grype); err != nil {
		logger.Error(err, "Cannot run Grype", "grype", opts.grype)
		return exitFailed
	}
	listener, err := net.Listen("tcp", opts.listen)
	if err != nil {
		logger.Error(err, "Cannot listen", "address", opts.listen)
		return exitFailed
	}

	srv := matcher.NewServer(matcher.NewGrype(opts.grype, opts.dbDir), opts.maxConcurrent)
	httpServer := newHTTPServer(ctx, opts.listen, srv.Handler())
	var maintained sync.WaitGroup
	maintained.Go(func() { maintain(ctx, srv, opts) })
	served := make(chan error, 1)
	go func() { served <- httpServer.Serve(listener) }()
	logger.Info("Serving the matcher API", "address", listener.Addr().String(), "offline", opts.offline)

	code := exitOK
	select {
	case <-ctx.Done():
	case err := <-served:
		logger.Error(err, "The HTTP server stopped")
		code = exitFailed
	}

	stop()
	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdown); err != nil {
		logger.Error(err, "Could not stop the HTTP server in time")
		code = exitFailed
	}
	maintained.Wait()
	return code
}

// newHTTPServer returns the server for the handler, with the timeouts. Its requests carry the values
// of ctx, such as its logger, but not its cancellation: when the matcher is stopped, Shutdown gives
// the matches that run time to finish.
func newHTTPServer(ctx context.Context, addr string, handler http.Handler) *http.Server {
	base := context.WithoutCancel(ctx)
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		BaseContext:       func(net.Listener) context.Context { return base },
	}
}

// maintain gives the server its database, and keeps it current, until ctx ends. See the package
// documentation for the order.
func maintain(ctx context.Context, srv *matcher.Server, opts options) {
	log := logf.FromContext(ctx)

	loaded := true
	if err := srv.Load(ctx); err != nil {
		loaded = false
		log.Info("The database directory holds no valid vulnerability database", "dir", opts.dbDir,
			"reason", err.Error())
	}
	if !loaded && opts.seedDB != "" {
		loaded = seed(ctx, srv, opts)
	}

	if opts.offline {
		if loaded {
			log.Info("The matcher is offline: it never updates the vulnerability database")
		} else {
			log.Error(errors.New("no database"),
				"The matcher is offline and has no vulnerability database, so it stays not ready", "dir", opts.dbDir)
		}
		return
	}

	if !loaded {
		loaded = update(ctx, srv)
	}
	for {
		wait := opts.updateInterval
		if !loaded {
			wait = min(wait, opts.retryDelay)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if update(ctx, srv) {
			loaded = true
		}
	}
}

// seed copies the seed database into the database directory, and loads it. It reports whether the
// server has a database now.
func seed(ctx context.Context, srv *matcher.Server, opts options) bool {
	log := logf.FromContext(ctx)
	log.Info("Seeding the database directory", "seed", opts.seedDB, "dir", opts.dbDir)
	if err := seedDatabase(opts.seedDB, opts.dbDir); err != nil {
		log.Error(err, "Could not seed the database directory", "seed", opts.seedDB, "dir", opts.dbDir)
		return false
	}
	if err := srv.Load(ctx); err != nil {
		log.Error(err, "The seeded database is not valid", "seed", opts.seedDB)
		return false
	}
	return true
}

// update updates the database, and reports whether it worked. A failure is logged, and the server
// keeps the database it has.
func update(ctx context.Context, srv *matcher.Server) bool {
	log := logf.FromContext(ctx)
	log.Info("Updating the vulnerability database")
	if err := srv.Update(ctx); err != nil {
		if ctx.Err() == nil { // a stop is not a failure
			log.Error(err, "Could not update the vulnerability database")
		}
		return false
	}
	return true
}

// seedDatabase copies the tree under seed into dir. A seed holds directories and regular files, as
// Grype leaves them in its cache directory, and nothing else: a link or any other entry is an error.
// Each file appears under its name only when it is complete, so that a copy that is cut off doesn't
// leave a database that looks whole.
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
