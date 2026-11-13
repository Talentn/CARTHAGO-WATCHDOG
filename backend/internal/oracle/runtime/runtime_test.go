package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"carthago/backend/internal/oracle/analyst"
)

// The tests run the runtime against a stand-in for the model server: this test binary,
// copied into a runtime directory under the server's name. It accepts the same arguments,
// answers /health and /v1/chat/completions, and writes down how it was started.

type fakeRecord struct {
	Args      []string `json:"args"`
	Key       bool     `json:"key"`
	Carthago  []string `json:"carthago_env"`
	Nice      int      `json:"nice"`
	Requests  int      `json:"requests"`
	MaxAtOnce int      `json:"max_at_once"`
	Unauth    int      `json:"unauthorised"`
}

func TestMain(m *testing.M) {
	if strings.HasPrefix(filepath.Base(os.Args[0]), "llama-server") {
		fakeServer()
		return
	}
	os.Exit(m.Run())
}

func fakeServer() {
	rec := fakeRecord{Args: os.Args[1:], Key: os.Getenv("LLAMA_API_KEY") != ""}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "CARTHAGO_") {
			rec.Carthago = append(rec.Carthago, kv)
		}
	}
	rec.Nice = niceOf(os.Getpid())
	port := ""
	for i, a := range os.Args {
		if a == "--port" && i+1 < len(os.Args) {
			port = os.Args[i+1]
		}
	}
	var mu sync.Mutex
	save := func() {
		if path := os.Getenv("FAKE_LLAMA_RECORD"); path != "" {
			b, _ := json.Marshal(rec)
			_ = os.WriteFile(path+".tmp", b, 0o600)
			_ = os.Rename(path+".tmp", path)
		}
	}
	save()
	if os.Getenv("FAKE_LLAMA_EXIT") == "1" {
		os.Exit(3)
	}
	var inflight atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"status":"ok"}`) })
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		n := int(inflight.Add(1))
		defer inflight.Add(-1)
		mu.Lock()
		rec.Requests++
		rec.MaxAtOnce = max(rec.MaxAtOnce, n)
		ok := r.Header.Get("Authorization") == "Bearer "+os.Getenv("LLAMA_API_KEY")
		if !ok {
			rec.Unauth++
		}
		save()
		mu.Unlock()
		if !ok {
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		time.Sleep(30 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]string{"content": os.Getenv("FAKE_LLAMA_REPLY")}}},
			"usage":   map[string]int{"prompt_tokens": 700, "completion_tokens": 60},
		})
	})
	_ = http.ListenAndServe("127.0.0.1:"+port, mux)
}

// install builds a runtime directory holding the stand-in server and a model file.
func install(t *testing.T) (dir, record string) {
	t.Helper()
	dir = t.TempDir()
	bin := filepath.Join(dir, "llama-b1", serverName())
	if err := os.MkdirAll(filepath.Join(dir, "models"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, self, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "models", "model.gguf"), []byte("not a real model"), 0o644); err != nil {
		t.Fatal(err)
	}
	record = filepath.Join(t.TempDir(), "record.json")
	t.Setenv("FAKE_LLAMA_RECORD", record)
	t.Setenv("FAKE_LLAMA_REPLY", `{"ok":true}`)
	return dir, record
}

func readRecord(t *testing.T, path string) fakeRecord {
	t.Helper()
	var rec fakeRecord
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &rec) != nil {
		t.Fatalf("the server left no record: %v", err)
	}
	return rec
}

func alive(pid int) bool {
	if goruntime.GOOS == "windows" {
		return true
	}
	p, err := os.FindProcess(pid)
	return err == nil && p.Signal(syscall.Signal(0)) == nil
}

func TestNotInstalled(t *testing.T) {
	empty := t.TempDir()
	if _, err := New(Config{Dir: empty, ModelFile: "model.gguf"}); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("empty directory: %v", err)
	}
	if _, err := New(Config{Dir: filepath.Join(empty, "missing"), ModelFile: "model.gguf"}); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("missing directory: %v", err)
	}
	dir, _ := install(t)
	if _, err := New(Config{Dir: dir, ModelFile: "other.gguf"}); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("missing model: %v", err)
	}
	// A bundle cannot point the runtime at a file outside its models directory.
	for _, name := range []string{"", "../model.gguf", "models/model.gguf", filepath.Join(dir, "models", "model.gguf")} {
		if _, err := New(Config{Dir: dir, ModelFile: name}); !errors.Is(err, ErrNotInstalled) {
			t.Errorf("model file %q: %v", name, err)
		}
	}
	if _, err := New(Config{Dir: dir, ModelFile: "model.gguf"}); err != nil {
		t.Fatalf("installed runtime: %v", err)
	}
}

func TestStartsOnDemandCappedAndLowPriority(t *testing.T) {
	dir, record := install(t)
	t.Setenv("CARTHAGO_ORACLE_API_KEY", "hosted-key-that-must-not-leak")
	rt, err := New(Config{Dir: dir, ModelFile: "model.gguf", ModelID: "oracle-test", Threads: 2, ContextTokens: 2048})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if rt.Name() != "local" || rt.External() || rt.Model() != "oracle-test" || rt.Threads() != 2 {
		t.Fatalf("identity: %s %v %s %d", rt.Name(), rt.External(), rt.Model(), rt.Threads())
	}
	// Nothing runs until a case arrives.
	if rt.Pid() != 0 {
		t.Fatal("the server was started before any case")
	}
	if _, err := os.Stat(record); err == nil {
		t.Fatal("the server was started before any case")
	}
	out, err := rt.Complete(context.Background(), analyst.Request{System: "s", User: "u", MaxTokens: 10})
	if err != nil {
		t.Fatal(err)
	}
	if out.Text != `{"ok":true}` || out.TokensIn != 700 || out.TokensOut != 60 {
		t.Fatalf("answer: %+v", out)
	}
	pid := rt.Pid()
	if pid == 0 || !alive(pid) {
		t.Fatal("the server is not running after a case")
	}
	rec := readRecord(t, record)
	args := " " + strings.Join(rec.Args, " ") + " "
	for _, want := range []string{" --host 127.0.0.1 ", " -t 2 ", " -tb 2 ", " -np 1 ", " -c 2048 ", " --cache-ram 0 ", " --no-webui ", " --offline ",
		" -m " + filepath.Join(dir, "models", "model.gguf") + " "} {
		if !strings.Contains(args, want) {
			t.Errorf("server arguments lack %q: %s", want, args)
		}
	}
	// The key is in the child's environment, never on its command line; the gateway's
	// own settings are not passed on.
	if !rec.Key || strings.Contains(args, "api-key") {
		t.Errorf("key handling: env %v, args %s", rec.Key, args)
	}
	if len(rec.Carthago) != 0 {
		t.Errorf("the gateway's settings reached the model server: %v", rec.Carthago)
	}
	if rec.Unauth != 0 {
		t.Error("the runtime did not present its key")
	}
	if goruntime.GOOS == "linux" && niceOf(pid) != niceness {
		t.Errorf("server priority: nice %d, want %d", niceOf(pid), niceness)
	}

	// One case at a time, however many are asked for at once.
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := rt.Complete(context.Background(), analyst.Request{System: "s", User: "u"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if rec = readRecord(t, record); rec.Requests != 7 || rec.MaxAtOnce != 1 {
		t.Fatalf("requests %d, at once %d", rec.Requests, rec.MaxAtOnce)
	}
	if rt.Pid() != pid {
		t.Error("the server was restarted between cases")
	}
	rt.Close()
	if rt.Pid() != 0 || goruntime.GOOS != "windows" && alive(pid) {
		t.Fatal("Close left the server running")
	}
}

func TestStopsWhenIdleAndStartsAgain(t *testing.T) {
	dir, _ := install(t)
	rt, err := New(Config{Dir: dir, ModelFile: "model.gguf", IdleStop: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if _, err := rt.Complete(context.Background(), analyst.Request{}); err != nil {
		t.Fatal(err)
	}
	first := rt.Pid()
	deadline := time.Now().Add(5 * time.Second)
	for rt.Pid() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rt.Pid() != 0 {
		t.Fatal("the idle server was not stopped")
	}
	if goruntime.GOOS != "windows" && alive(first) {
		t.Fatal("the idle server's process is still there")
	}
	if _, err := rt.Complete(context.Background(), analyst.Request{}); err != nil {
		t.Fatal(err)
	}
	if second := rt.Pid(); second == 0 || second == first {
		t.Fatalf("no new server for the next case: %d then %d", first, second)
	}
}

func TestModelHashIsChecked(t *testing.T) {
	dir, record := install(t)
	rt, err := New(Config{Dir: dir, ModelFile: "model.gguf", ModelSHA256: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if _, err := rt.Complete(context.Background(), analyst.Request{}); err == nil {
		t.Fatal("a model with the wrong hash was served")
	}
	if _, err := os.Stat(record); err == nil || rt.Pid() != 0 {
		t.Fatal("the server was started with a model that failed its hash")
	}
	sum, err := fileSHA256(filepath.Join(dir, "models", "model.gguf"))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := New(Config{Dir: dir, ModelFile: "model.gguf", ModelSHA256: sum})
	if err != nil {
		t.Fatal(err)
	}
	defer ok.Close()
	if _, err := ok.Complete(context.Background(), analyst.Request{}); err != nil {
		t.Fatalf("matching hash: %v", err)
	}
}

func TestServerThatDiesIsReported(t *testing.T) {
	dir, _ := install(t)
	t.Setenv("FAKE_LLAMA_EXIT", "1")
	rt, err := New(Config{Dir: dir, ModelFile: "model.gguf", StartTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	start := time.Now()
	if _, err := rt.Complete(context.Background(), analyst.Request{}); err == nil {
		t.Fatal("no error from a server that exits at start")
	}
	if time.Since(start) > 4*time.Second || rt.Pid() != 0 {
		t.Fatal("a dead server was waited for")
	}
	// A case's own deadline also ends the wait.
	t.Setenv("FAKE_LLAMA_EXIT", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rt.Complete(ctx, analyst.Request{}); err == nil {
		t.Fatal("a cancelled case was answered")
	}
	if rt.Pid() != 0 {
		t.Fatal("the server was left running after a cancelled start")
	}
}

func TestChildEnvDropsGatewaySettings(t *testing.T) {
	got := childEnv([]string{"PATH=/bin", "CARTHAGO_ORACLE_API_KEY=k", "carthago_oracle_model=m", "HOME=/h"})
	if strings.Join(got, ",") != "PATH=/bin,HOME=/h" {
		t.Fatalf("%v", got)
	}
}

func TestDefaults(t *testing.T) {
	if n := DefaultThreads(); n < 1 || n > 4 || n > max(1, goruntime.NumCPU()/2) {
		t.Fatalf("default thread cap %d on %d CPUs", n, goruntime.NumCPU())
	}
	if d := DefaultDir(); d == "" || !filepath.IsAbs(d) && d != "oracle-runtime" {
		t.Fatalf("default directory %q", d)
	}
}
