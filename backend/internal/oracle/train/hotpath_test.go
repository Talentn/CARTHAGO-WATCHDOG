package train

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "carthago/backend/gen/carthago/v1"
	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/oracle"
	"carthago/backend/internal/oracle/analyst"
	"carthago/backend/internal/pipeline"
	"carthago/backend/internal/store"
)

// hotPath is a gateway's ingest side as it runs in production: the pipeline on a SQLite
// store, with or without the Oracle observing it. The Oracle here is complete (behaviour
// model, engine, stub analyst), so its scoring and its writes compete for the same store.
type hotPath struct {
	st     *store.SQLite
	pl     *pipeline.Pipeline
	people []person
	stop   func()
	// settle waits until the Oracle has finished everything it was told about.
	settle func()
}

func newHotPath(b *testing.B, withOracle bool, queue int) *hotPath {
	b.Helper()
	dir := b.TempDir()
	st, err := store.OpenSQLite(filepath.Join(dir, "gateway.db"))
	if err != nil {
		b.Fatal(err)
	}
	h := &hotPath{st: st, settle: func() {}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := pipeline.Config{QueueSize: queue}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	close(done)
	if withOracle {
		m, err := Fit(handRows(1200, 1), DefaultParams())
		if err != nil {
			b.Fatal(err)
		}
		data, _ := m.Encode()
		pr := analyst.DefaultPrompts()
		if _, err := oracle.WriteBundle(filepath.Join(dir, "oracle"), oracle.Contents{Model: data, Thresholds: oracle.Thresholds{Watch: 0.2, Review: 0.6},
			PromptVersion: pr.Version, SchemaVersion: analyst.VerdictSchema, SystemPrompt: pr.System, CasePrompt: pr.Case}); err != nil {
			b.Fatal(err)
		}
		bundle, err := oracle.LoadBundle(filepath.Join(dir, "oracle"))
		if err != nil {
			b.Fatal(err)
		}
		an, err := analyst.New(analyst.Config{Provider: analyst.Stub{}, Prompts: pr, Usage: st})
		if err != nil {
			b.Fatal(err)
		}
		eng, err := oracle.New(oracle.Config{Bundle: bundle, Analyst: an, PseudonymKey: []byte("0123456789abcdef0123456789abcdef")}, st, log)
		if err != nil {
			b.Fatal(err)
		}
		done = make(chan struct{})
		go func() {
			eng.Run(ctx)
			close(done)
		}()
		cfg.Observer = eng
		h.settle = func() { eng.Flush(ctx) }
	}
	h.pl = pipeline.New(cfg, st, st, nil, log)
	h.stop = func() {
		h.pl.Close()
		cancel()
		<-done
		st.Close()
	}
	r := &rng{s: 42}
	for i := range 10 {
		p := draw(r, Honest, true)
		p.slot = uint32(i + 1)
		at := time.Now().UTC()
		p.sess = store.Session{SessionID: fmt.Sprintf("%032x", i+1), TenantID: Tenant, PlayerHash: fmt.Sprintf("bench-%d", i),
			DeviceID: fmt.Sprintf("dev-%d", i), TrustLevel: p.trust, State: store.SessionActive, CreatedAt: at, ExpiresAt: at.Add(24 * time.Hour), LastHeartbeat: at}
		if err := st.UpsertDevice(context.Background(), &store.Device{DeviceID: p.sess.DeviceID, TenantID: Tenant, KeyAlg: 1, PublicKey: []byte{1}, FirstSeen: at, LastSeen: at}); err != nil {
			b.Fatal(err)
		}
		if err := st.PutSession(context.Background(), &p.sess); err != nil {
			b.Fatal(err)
		}
		h.people = append(h.people, p)
	}
	return h
}

// BenchmarkHeartbeat is the pipeline's whole work for one client heartbeat, store writes
// included, from the moment the gateway hands it over until the worker is done with it.
func BenchmarkHeartbeat(b *testing.B) {
	for _, with := range []bool{false, true} {
		name := "oracle_off"
		if with {
			name = "oracle_on"
		}
		b.Run(name, func(b *testing.B) {
			h := newHotPath(b, with, b.N+16)
			hbs := make([]*pb.Heartbeat, b.N)
			for i := range hbs {
				hbs[i] = h.people[i%len(h.people)].client.heartbeat(i/len(h.people), time.Duration(i/len(h.people))*15*time.Second)
			}
			b.ResetTimer()
			for i, hb := range hbs {
				h.pl.Heartbeat(h.people[i%len(h.people)].sess, hb)
			}
			h.pl.Close() // returns once the worker has handled every queued heartbeat
			b.StopTimer()
			if h.pl.Dropped() != 0 {
				b.Fatalf("%d heartbeats dropped", h.pl.Dropped())
			}
			h.stop()
		})
	}
}

// BenchmarkHeartbeatHandOff is the part of a heartbeat the client's connection waits
// for: handing it to the pipeline. The Oracle adds nothing here by construction. The
// number of hand-offs is fixed, because every one of them is real work for the worker
// afterwards; read the ns/handoff column.
func BenchmarkHeartbeatHandOff(b *testing.B) {
	const n = 20000
	for _, with := range []bool{false, true} {
		name := "oracle_off"
		if with {
			name = "oracle_on"
		}
		b.Run(name, func(b *testing.B) {
			h := newHotPath(b, with, n+16)
			hb := h.people[0].client.heartbeat(0, 0)
			b.ResetTimer()
			start := time.Now()
			for range n {
				h.pl.Heartbeat(h.people[0].sess, hb)
			}
			spent := time.Since(start)
			b.StopTimer()
			b.ReportMetric(float64(spent.Nanoseconds())/n, "ns/handoff")
			h.stop()
		})
	}
}

// BenchmarkGameplayBatch is one second of a ten-player match from the game server:
// received, stored, analysed and acknowledged. Each iteration is a whole 120 s match.
// Three numbers come out of it:
//
//   - µs/batch: an ordinary batch, which the Oracle never sees;
//   - µs/last-batch: the batch that ends the match, where the pipeline also hands the
//     match's summaries to the Oracle;
//   - oracle-ms/match: what the Oracle then does on its own goroutine (ten sessions
//     scored and stored), after the game server has its acknowledgement.
func BenchmarkGameplayBatch(b *testing.B) {
	const seconds = 120
	for _, with := range []bool{false, true} {
		name := "oracle_off"
		if with {
			name = "oracle_on"
		}
		b.Run(name, func(b *testing.B) {
			h := newHotPath(b, with, 0)
			players := synth.DefaultPlayers(pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, 1, nil)
			for i := range players {
				players[i].SessionID, players[i].PlayerHash, players[i].MMR = h.people[i].sess.SessionID, h.people[i].sess.PlayerHash, h.people[i].mmr
			}
			template := synth.Batches(synth.Spec{MatchID: "bench", Mode: pb.GameMode_GAME_MODE_COMPETITIVE_SHOOTER, TickRate: 64, Seconds: seconds, Seed: 7, Players: players, Decoys: true})
			ctx := context.Background()
			var ordinary, last, own time.Duration
			batches := 0
			b.ResetTimer()
			for n := range b.N {
				b.StopTimer()
				match := make([]*pb.GameplayBatch, len(template))
				for i, t := range template {
					match[i] = proto.Clone(t).(*pb.GameplayBatch)
					match[i].MatchId = fmt.Sprintf("bench-%d", n)
				}
				b.StartTimer()
				for i, batch := range match {
					start := time.Now()
					if _, _, err := h.pl.Gameplay(ctx, Tenant, batch); err != nil {
						b.Fatal(err)
					}
					if i == len(match)-1 {
						last += time.Since(start)
					} else {
						ordinary += time.Since(start)
						batches++
					}
				}
				b.StopTimer()
				start := time.Now()
				h.settle()
				own += time.Since(start)
				b.StartTimer()
			}
			b.StopTimer()
			b.ReportMetric(float64(ordinary.Microseconds())/float64(batches), "µs/batch")
			b.ReportMetric(float64(last.Microseconds())/float64(b.N), "µs/last-batch")
			b.ReportMetric(float64(own.Microseconds())/1000/float64(b.N), "oracle-ms/match")
			h.stop()
		})
	}
}
