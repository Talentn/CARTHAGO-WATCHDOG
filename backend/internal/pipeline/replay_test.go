package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"carthago/backend/internal/knowledge/synth"
	"carthago/backend/internal/replay"
	"carthago/backend/internal/store"
)

func TestMatchWithPositionsIsRecorded(t *testing.T) {
	p, st, _ := newTest(t, Config{})
	ctx := context.Background()
	spec := leakMatch("rec-1", 60)
	// Slot 1 has a verified session; the other slots name sessions the gateway does not know.
	sess := session(st, spec.Players[0].SessionID, "t1", "verified-name")
	bs := synth.Batches(spec)
	feed(t, p, "t1", bs[:len(bs)-1])
	if _, err := st.GetMatchReplay(ctx, "t1", "rec-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("recording written before the flush interval or the end of the match: %v", err)
	}
	feed(t, p, "t1", bs[len(bs)-1:])

	rec, err := st.GetMatchReplay(ctx, "t1", "rec-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Players) != len(spec.Players) || rec.Samples == 0 || rec.Truncated || rec.DurationMs < 59_000 || rec.DurationMs > 60_000 {
		t.Fatalf("recording: %d players, %d samples, %d ms, truncated %v", len(rec.Players), rec.Samples, rec.DurationMs, rec.Truncated)
	}
	if got := rec.Players[0]; got.Slot != spec.Players[0].Slot || got.PlayerHash != "verified-name" || got.SessionID != sess.SessionID {
		t.Fatalf("the verified session does not name its slot: %+v", got)
	}
	if got := rec.Players[1]; got.PlayerHash != spec.Players[1].PlayerHash || got.SessionID != "" {
		t.Fatalf("a slot without a verified session: %+v", got)
	}
	d, err := replay.Decode(rec.Data)
	if err != nil {
		t.Fatal(err)
	}
	// Four positions a second per player, however many the game server sent.
	if want := len(spec.Players) * 60 * 1000 / replay.StepMs; rec.Samples < want*9/10 || rec.Samples > want+len(spec.Players) {
		t.Fatalf("samples = %d, want about %d", rec.Samples, want)
	}
	if len(d.Players) != len(spec.Players) || d.Players[0].Name != "verified-name" || d.Players[0].Team == 0 || len(d.Batches) != len(bs) {
		t.Fatalf("decoded: %d players, first %q team %d, %d batches", len(d.Players), d.Players[0].Name, d.Players[0].Team, len(d.Batches))
	}
	if d.Bounds[2] <= d.Bounds[0] || d.Bounds[3] <= d.Bounds[1] {
		t.Fatalf("bounds: %v", d.Bounds)
	}
	if _, err := st.GetMatchReplay(ctx, "t2", "rec-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another tenant reads the recording: %v", err)
	}
	if rows, _ := st.ListMatchReplays(ctx, "t1", store.ReplayFilter{SessionID: sess.SessionID}); len(rows) != 1 {
		t.Fatalf("the session's recordings: %+v", rows)
	}
}

func TestMatchInProgressIsRecordedEveryFlush(t *testing.T) {
	p, st, _ := newTest(t, Config{ReplayFlush: time.Nanosecond})
	bs := synth.Batches(leakMatch("rec-live", 30))
	feed(t, p, "t1", bs[:3])
	rec, err := st.GetMatchReplay(context.Background(), "t1", "rec-live")
	if err != nil || rec.Samples == 0 {
		t.Fatalf("a match in progress has no recording: %+v %v", rec, err)
	}
}

func TestMatchWithoutPositionsIsNotRecorded(t *testing.T) {
	p, st, _ := newTest(t, Config{})
	if ok, w, err := p.Gameplay(context.Background(), "t1", cheaterBatch(1, nil, true)); !ok || w != "" || err != nil {
		t.Fatalf("v1 batch: %v %q %v", ok, w, err)
	}
	flush(p)
	if rows, _ := st.ListMatchReplays(context.Background(), "t1", store.ReplayFilter{}); len(rows) != 0 {
		t.Fatalf("a match without positions was recorded: %+v", rows)
	}
}
