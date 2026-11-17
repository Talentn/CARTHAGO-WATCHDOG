package review

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"carthago/backend/internal/outline"
	"carthago/backend/internal/replay"
	"carthago/backend/internal/store"
)

// SuspectSlot is the slot the suspect has in every recording a reviewer is given.
const SuspectSlot = 1

// Recording is the match of a case as a reviewer gets it: the positions, views and shots
// of the stored recording, and nothing that says who played or when. The suspect is slot
// 1 and named "Suspect"; the other players get the slots after it in an order made up
// for the case, and are named by that number. The match id, the map name, the players'
// accounts and sessions and the times the gateway received the match are left out.
func (s *Service) Recording(ctx context.Context, c *store.ReviewCase) ([]byte, error) {
	rec, err := s.st.GetMatchReplay(ctx, c.TenantID, c.MatchID)
	if err != nil {
		return nil, err
	}
	d, err := replay.Decode(rec.Data)
	if err != nil {
		return nil, err
	}
	suspect := int64(-1)
	for _, p := range rec.Players {
		if p.PlayerHash == c.Suspect {
			suspect = int64(p.Slot)
		}
	}
	if suspect < 0 {
		return nil, errors.New("review: the suspect is not in the recording")
	}
	// The order of the other players: by a hash of the case and the slot, so it says
	// nothing about the game's own numbering.
	type slotKey struct {
		slot uint32
		key  [32]byte
	}
	var others []slotKey
	for _, p := range d.Players {
		if int64(p.Slot) != suspect {
			others = append(others, slotKey{p.Slot, sha256.Sum256(fmt.Appendf(nil, "%x\x00%d\x00%d", s.cfg.Key, c.ID, p.Slot))})
		}
	}
	sort.Slice(others, func(i, j int) bool { return string(others[i].key[:]) < string(others[j].key[:]) })
	slots := map[uint32]uint32{uint32(suspect): SuspectSlot}
	for i, o := range others {
		slots[o.slot] = uint32(i) + SuspectSlot + 1
	}
	out := replay.Data{V: d.V, TickRate: d.TickRate, StepMs: d.StepMs, DurationMs: d.DurationMs, Bounds: d.Bounds, Truncated: d.Truncated, Players: make([]replay.Player, 0, len(d.Players))}
	teams := map[uint32]uint32{}
	for _, p := range d.Players {
		n := slots[p.Slot]
		q := replay.Player{Slot: n, Name: fmt.Sprintf("Player %d", n), Bot: p.Bot, T: p.T, X: p.X, Y: p.Y, Yaw: p.Yaw}
		if n == SuspectSlot {
			q.Name = "Suspect"
		}
		out.Players = append(out.Players, q)
	}
	sort.Slice(out.Players, func(i, j int) bool { return out.Players[i].Slot < out.Players[j].Slot })
	// Teams are numbered in the order they appear, with the suspect's team first.
	old := map[uint32]uint32{}
	for _, p := range d.Players {
		old[slots[p.Slot]] = p.Team
	}
	for i := range out.Players {
		t := old[out.Players[i].Slot]
		if t == 0 {
			continue
		}
		if _, ok := teams[t]; !ok {
			teams[t] = uint32(len(teams)) + 1
		}
		out.Players[i].Team = teams[t]
	}
	for _, sh := range d.Shots {
		from, ok := slots[uint32(sh[1])]
		if sh[1] < 0 || !ok {
			continue
		}
		target := int32(-1)
		if to, ok := slots[uint32(sh[2])]; ok && sh[2] >= 0 {
			target = int32(to)
		}
		out.Shots = append(out.Shots, replay.Shot{sh[0], int32(from), target, sh[3], sh[4]})
	}
	return out.Encode()
}

// Outline is the outline of the case's map, when the studio registered one, for the
// review page to draw under the players: the wall lines, or the picture. The map's name
// is not passed on, and no shot is pointed out.
func (s *Service) Outline(ctx context.Context, c *store.ReviewCase) (*store.MapOutline, [][4]int32, error) {
	rec, err := s.st.GetMatchReplay(ctx, c.TenantID, c.MatchID)
	if err != nil {
		return nil, nil, err
	}
	d, err := replay.Decode(rec.Data)
	if err != nil {
		return nil, nil, err
	}
	if d.Map == "" {
		return nil, nil, store.ErrNotFound
	}
	o, err := s.st.GetMapOutline(ctx, c.TenantID, d.Map)
	if err != nil {
		return nil, nil, err
	}
	lines, err := outline.StoredLines(o)
	return o, lines, err
}
