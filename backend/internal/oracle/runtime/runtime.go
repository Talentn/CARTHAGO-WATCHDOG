// Package runtime runs the Oracle analyst's local language model: a llama.cpp server
// process that the gateway starts when a case is waiting and stops again when the
// analyst has been idle. Studios do not install or operate it; they see the Oracle.
//
// The process is kept out of the way of whatever else the machine is doing, because a
// small studio's gateway often shares a PC with a game server or, in a test, the game:
//
//   - it listens on loopback only, on a port chosen at start, behind a random key that
//     exists only in this process and the child's environment;
//   - it runs with a capped number of threads and below-normal priority, so the game and
//     the gateway's own work are scheduled first;
//   - it answers one request at a time;
//   - it is not running at all between cases: the model's memory is only held while the
//     analyst works, and for a short idle period after.
//
// The runtime directory (binaries and model weights) is outside the repository and any
// web root. Nothing in it is served.
package runtime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"carthago/backend/internal/oracle/analyst"
)

// niceness is the scheduling priority the model runs at where the system has nice values:
// below everything interactive. On Windows the process runs in the below-normal class.
const niceness = 10

// ErrNotInstalled means the runtime directory lacks the server binary or the model.
var ErrNotInstalled = errors.New("local analyst runtime is not installed")

type Config struct {
	// Dir is the runtime directory: the llama.cpp server somewhere below it and the
	// model under models/.
	Dir string
	// ModelFile is the model's file name under Dir/models; ModelSHA256 its expected hash
	// ("" skips the check, for a privately tuned model without a published hash).
	ModelFile   string
	ModelSHA256 string
	// ModelID is the name verdicts record for the model.
	ModelID string
	// Threads caps the CPU threads the model uses. Default: half the CPUs, at most 4.
	Threads       int
	ContextTokens int
	// IdleStop is how long the server is kept after its last case. Default 90 s.
	IdleStop     time.Duration
	StartTimeout time.Duration
	Log          *slog.Logger
}

// DefaultThreads is the thread cap used when none is configured.
func DefaultThreads() int { return max(1, min(4, goruntime.NumCPU()/2)) }

// DefaultDir is where the fetch script puts the runtime: a per-user directory outside
// any repository.
func DefaultDir() string {
	if goruntime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "Carthago", "oracle-runtime")
		}
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "carthago", "oracle-runtime")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".local", "share", "carthago", "oracle-runtime")
	}
	return "oracle-runtime"
}

// Runtime owns the server process. It implements analyst.Provider.
type Runtime struct {
	cfg    Config
	server string
	model  string

	mu       sync.Mutex // held for the length of a request: one case at a time
	cmd      *exec.Cmd
	exited   chan struct{}
	local    *analyst.OpenAI
	verified bool
	idle     *time.Timer
	closed   bool
}

var _ analyst.Provider = (*Runtime)(nil)

func serverName() string {
	if goruntime.GOOS == "windows" {
		return "llama-server.exe"
	}
	return "llama-server"
}

// findServer looks for the server binary in dir and up to three levels below it, which
// covers how the release archives unpack.
func findServer(dir string) (string, error) {
	var found string
	root := filepath.Clean(dir)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil
		}
		if d.IsDir() {
			if rel, _ := filepath.Rel(root, p); countSep(rel) >= 3 {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == serverName() {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil || found == "" {
		return "", fmt.Errorf("%w: no %s under %s", ErrNotInstalled, serverName(), dir)
	}
	return found, nil
}

func countSep(rel string) int {
	n := 0
	for _, c := range filepath.ToSlash(rel) {
		if c == '/' {
			n++
		}
	}
	return n
}

// New checks that the runtime is installed. It starts nothing.
func New(cfg Config) (*Runtime, error) {
	if cfg.ModelFile == "" || cfg.ModelFile != filepath.Base(cfg.ModelFile) {
		return nil, fmt.Errorf("%w: the bundle names no local model file", ErrNotInstalled)
	}
	server, err := findServer(cfg.Dir)
	if err != nil {
		return nil, err
	}
	model := filepath.Join(cfg.Dir, "models", cfg.ModelFile)
	if st, err := os.Stat(model); err != nil || st.IsDir() {
		return nil, fmt.Errorf("%w: no model %s under %s", ErrNotInstalled, cfg.ModelFile, filepath.Join(cfg.Dir, "models"))
	}
	if cfg.Threads <= 0 {
		cfg.Threads = DefaultThreads()
	}
	if cfg.ContextTokens <= 0 {
		cfg.ContextTokens = 4096
	}
	if cfg.IdleStop <= 0 {
		cfg.IdleStop = 90 * time.Second
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = 3 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.ModelID == "" {
		cfg.ModelID = cfg.ModelFile
	}
	return &Runtime{cfg: cfg, server: server, model: model}, nil
}

func (r *Runtime) Name() string   { return "local" }
func (r *Runtime) Model() string  { return r.cfg.ModelID }
func (r *Runtime) External() bool { return false }
func (r *Runtime) Threads() int   { return r.cfg.Threads }

// Complete runs one request, starting the server first if it is not running.
func (r *Runtime) Complete(ctx context.Context, req analyst.Request) (analyst.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return analyst.Response{}, errors.New("runtime closed")
	}
	if r.idle != nil {
		r.idle.Stop()
	}
	defer func() {
		r.idle = time.AfterFunc(r.cfg.IdleStop, r.stopIdle)
	}()
	if err := r.ensure(ctx); err != nil {
		return analyst.Response{}, err
	}
	return r.local.Complete(ctx, req)
}

func (r *Runtime) stopIdle() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil {
		r.cfg.Log.Debug("Carthago Oracle analyst runtime stopped after idling")
	}
	r.stop()
}

// Close stops the server.
func (r *Runtime) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.idle != nil {
		r.idle.Stop()
	}
	r.stop()
}

// Pid is the running server's process id, or 0. For measurements.
func (r *Runtime) Pid() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil || r.cmd.Process == nil {
		return 0
	}
	return r.cmd.Process.Pid
}

func (r *Runtime) stop() {
	if r.cmd == nil {
		return
	}
	_ = r.cmd.Process.Kill()
	<-r.exited
	r.cmd, r.local = nil, nil
}

func (r *Runtime) running() bool {
	if r.cmd == nil {
		return false
	}
	select {
	case <-r.exited:
		r.cmd, r.local = nil, nil
		return false
	default:
		return true
	}
}

// childEnv is the gateway's environment without its own settings: the model server has no
// use for them, and one of them may be the key of a hosted analyst.
func childEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(strings.ToUpper(kv), "CARTHAGO_") {
			out = append(out, kv)
		}
	}
	return out
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ensure starts the server and waits until it has loaded the model.
func (r *Runtime) ensure(ctx context.Context) error {
	if r.running() {
		return nil
	}
	if !r.verified && r.cfg.ModelSHA256 != "" {
		got, err := fileSHA256(r.model)
		if err != nil {
			return err
		}
		if got != r.cfg.ModelSHA256 {
			return errors.New("the local model file does not match the hash in the bundle")
		}
	}
	r.verified = true

	// A free loopback port: taken, released and handed to the child.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	var kb [24]byte
	if _, err := rand.Read(kb[:]); err != nil {
		return err
	}
	key := hex.EncodeToString(kb[:])
	threads := strconv.Itoa(r.cfg.Threads)
	cmd := exec.Command(r.server,
		"-m", r.model, "--host", "127.0.0.1", "--port", strconv.Itoa(port),
		"-c", strconv.Itoa(r.cfg.ContextTokens), "-t", threads, "-tb", threads,
		// One slot and no cache of earlier prompts: memory stays at the model plus one
		// context, whatever the number of cases reviewed.
		"-np", "1", "--cache-ram", "0", "--no-webui", "--offline")
	dir := filepath.Dir(r.server)
	cmd.Dir = dir
	// The key travels in the environment, not on the command line, where any local user
	// could read it from the process list.
	cmd.Env = append(childEnv(os.Environ()), "LLAMA_API_KEY="+key, "LD_LIBRARY_PATH="+dir+string(os.PathListSeparator)+os.Getenv("LD_LIBRARY_PATH"))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	lowPriority(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the analyst runtime: %w", err)
	}
	afterStart(cmd)
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	r.cmd, r.exited = cmd, exited

	endpoint := "http://127.0.0.1:" + strconv.Itoa(port)
	deadline := time.Now().Add(r.cfg.StartTimeout)
	client := &http.Client{Timeout: 2 * time.Second}
	start := time.Now()
	for {
		select {
		case <-exited:
			r.cmd = nil
			return errors.New("the analyst runtime exited while starting")
		case <-ctx.Done():
			r.stop()
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			r.stop()
			return errors.New("the analyst runtime did not become ready in time")
		}
		resp, err := client.Get(endpoint + "/health")
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			break
		}
	}
	afterReady(cmd)
	local, err := analyst.NewLocal(endpoint+"/v1", key, r.cfg.ModelID)
	if err != nil {
		r.stop()
		return err
	}
	r.local = local
	r.cfg.Log.Debug("Carthago Oracle analyst runtime started", "threads", r.cfg.Threads, "load", time.Since(start).Round(100*time.Millisecond))
	return nil
}
