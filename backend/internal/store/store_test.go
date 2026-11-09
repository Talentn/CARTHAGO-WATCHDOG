package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func exercise(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := s.GetDevice(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetDevice missing: %v", err)
	}
	d := &Device{DeviceID: "dev1", TenantID: "t", KeyAlg: 2, PublicKey: []byte{4, 1, 2}, FirstSeen: now, LastSeen: now}
	if err := s.UpsertDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	bound := *d
	bound.AKPublic, bound.BoundVia, bound.EKCertMatches, bound.LastSeen, bound.FirstSeen = []byte{9, 9}, "ek-certify", true, later, later
	if err := s.UpsertDevice(ctx, &bound); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDevice(ctx, "dev1")
	if err != nil || string(got.AKPublic) != "\x09\x09" || !got.EKCertMatches || !got.FirstSeen.Equal(now) || !got.LastSeen.Equal(later) {
		t.Fatalf("device after upsert: %+v %v", got, err)
	}

	x := &Session{SessionID: "s1", TenantID: "t", PlayerHash: "p", DeviceID: "dev1", TrustLevel: 3, AttestFlags: 1<<63 | 5,
		State: SessionActive, CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute), LastHeartbeat: now}
	if err := s.PutSession(ctx, x); err != nil {
		t.Fatal(err)
	}
	x.State, x.KickReason, x.Heartbeats = SessionKicked, "heartbeat_timeout", 7
	if err := s.PutSession(ctx, x); err != nil {
		t.Fatal(err)
	}
	gs, err := s.GetSession(ctx, "s1")
	if err != nil || gs.State != SessionKicked || gs.KickReason != "heartbeat_timeout" || gs.Heartbeats != 7 || gs.AttestFlags != 1<<63|5 || !gs.ExpiresAt.Equal(x.ExpiresAt) {
		t.Fatalf("session: %+v %v", gs, err)
	}
	if err := s.AddAttestation(ctx, &Attestation{SessionID: "s1", DeviceID: "dev1", VerifiedAt: now, QuoteOK: true, CodeIntegrity: "enabled"}); err != nil {
		t.Fatal(err)
	}
}

func TestMemory(t *testing.T) { exercise(t, NewMemory()) }

func TestSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gw.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, s)
	s.Close()
	s, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.GetDevice(context.Background(), "dev1"); err != nil {
		t.Fatalf("not persisted: %v", err)
	}
}
