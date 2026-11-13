package store

import (
	"context"
	"sync"
)

type Memory struct {
	mu           sync.Mutex
	auth         *memAuth
	devices      map[string]Device
	sessions     map[string]Session
	attestations []Attestation
	evid         *memEvidence
	play         *memGameplay
	oracle       *memOracle
	bans         *memBans
}

func NewMemory() *Memory {
	return &Memory{devices: map[string]Device{}, sessions: map[string]Session{}}
}

func (m *Memory) GetDevice(_ context.Context, id string) (*Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &d, nil
}

func (m *Memory) UpsertDevice(_ context.Context, d *Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.devices[d.DeviceID]; ok && !old.FirstSeen.IsZero() {
		d.FirstSeen = old.FirstSeen
	}
	m.devices[d.DeviceID] = *d
	return nil
}

func (m *Memory) PutSession(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.SessionID] = *s
	return nil
}

func (m *Memory) GetSession(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return &s, nil
}

func (m *Memory) AddAttestation(_ context.Context, a *Attestation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attestations = append(m.attestations, *a)
	return nil
}

func (m *Memory) Close() error { return nil }
