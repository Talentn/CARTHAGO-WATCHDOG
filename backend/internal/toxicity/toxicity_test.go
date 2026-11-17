package toxicity

import (
	"strings"
	"testing"

	pb "carthago/backend/gen/carthago/v1"
)

// The test game runs at 4 ticks a second with four players: slots 1 and 2 are team 1,
// slots 3 and 4 team 2. Every player walks 2 m a second and turns unless a test says
// otherwise.
const rate = 4

type game struct {
	t       *testing.T
	m       *Match
	found   []Finding
	sec     uint32
	still   map[uint32]bool // slots that neither move nor turn
	absent  map[uint32]bool // slots the game server sends nothing for
	players []*pb.MatchPlayer
}

func newGame(t *testing.T, lim Limits) *game {
	g := &game{t: t, m: NewMatch(lim), still: map[uint32]bool{}, absent: map[uint32]bool{}}
	for slot := uint32(1); slot <= 4; slot++ {
		g.players = append(g.players, &pb.MatchPlayer{Slot: slot, Team: (slot + 1) / 2})
	}
	return g
}

// play sends seconds of the match, one batch a second, with the shots of each second.
func (g *game) play(seconds uint32, shots func(sec uint32) []*pb.ShotEvent) {
	for range seconds {
		b := &pb.GameplayBatch{MatchId: "m", BatchSeq: uint64(g.sec + 1), TickRate: rate}
		if g.sec == 0 {
			b.Players = g.players
		}
		first := g.sec * rate
		for slot := uint32(1); slot <= 4; slot++ {
			if g.absent[slot] {
				continue
			}
			mt := &pb.MotionTrack{Slot: slot, FirstTick: first}
			at := &pb.AimTrack{Slot: slot, FirstTick: first}
			for i := range uint32(rate) {
				tick := first + i
				x, yaw := int32(slot)*10_000+int32(tick)*50, float32(tick%90)*4
				if g.still[slot] {
					x, yaw = int32(slot)*10_000, 45
				}
				if i == 0 {
					mt.XCm = append(mt.XCm, x)
				} else if g.still[slot] {
					mt.XCm = append(mt.XCm, 0)
				} else {
					mt.XCm = append(mt.XCm, 50)
				}
				mt.YCm = append(mt.YCm, 0)
				at.Yaw, at.Pitch = append(at.Yaw, yaw), append(at.Pitch, 0)
			}
			b.Motion, b.Aim = append(b.Motion, mt), append(b.Aim, at)
		}
		if shots != nil {
			b.Shots = shots(g.sec)
		}
		g.found = append(g.found, g.m.Add(b)...)
		g.sec++
	}
}

func (g *game) finish() { g.found = append(g.found, g.m.Finish()...) }

func (g *game) want(kinds ...string) {
	g.t.Helper()
	var got []string
	for _, f := range g.found {
		got = append(got, f.Kind+"@"+string(rune('0'+f.Slot)))
	}
	if strings.Join(got, " ") != strings.Join(kinds, " ") {
		g.t.Fatalf("findings = %v, want %v", got, kinds)
	}
}

func hit(sec, from uint32, target int32, kill bool) *pb.ShotEvent {
	return &pb.ShotEvent{Slot: from, Tick: sec * rate, TargetSlot: target, Hit: true, Kill: kill}
}

func TestAnHonestMatchHasNoFindings(t *testing.T) {
	g := newGame(t, Defaults())
	g.play(300, func(sec uint32) []*pb.ShotEvent {
		if sec%20 != 0 {
			return nil
		}
		// Both teams trade kills; a stray hit on a teammate now and then.
		out := []*pb.ShotEvent{hit(sec, 1, 3, true), hit(sec, 3, 2, true), hit(sec, 2, 4, true), hit(sec, 4, 1, true)}
		if sec == 100 {
			out = append(out, hit(sec, 1, 2, false))
		}
		return out
	})
	g.finish()
	g.want()
}

func TestTeamDamageAndTeamKills(t *testing.T) {
	g := newGame(t, Defaults())
	g.play(150, func(sec uint32) []*pb.ShotEvent {
		switch {
		case sec >= 10 && sec < 16:
			return []*pb.ShotEvent{hit(sec, 1, 2, sec == 12 || sec == 15)}
		case sec == 20:
			// Missed shots, shots at enemies and at nobody are not team damage.
			return []*pb.ShotEvent{{Slot: 3, Tick: sec * rate, TargetSlot: 4}, hit(sec, 3, 1, false), {Slot: 3, Tick: sec * rate, TargetSlot: -1, Hit: true}}
		}
		return nil
	})
	g.finish()
	g.want("team_damage@1", "team_kill@1")
	if f := g.found[0]; f.Count != 6 || f.Tick != 15*rate {
		t.Fatalf("team damage: %+v", f)
	}
	if f := g.found[1]; f.Count != 2 || f.Tick != 15*rate || !strings.Contains(f.Summary, "Killed 2 teammates") {
		t.Fatalf("team kill: %+v", f)
	}
}

func TestPlayersWithoutTeamsCannotTeamKill(t *testing.T) {
	g := newGame(t, Defaults())
	for _, p := range g.players {
		p.Team = 0
	}
	g.play(150, func(sec uint32) []*pb.ShotEvent { return []*pb.ShotEvent{hit(sec, 1, 2, false)} })
	g.finish()
	g.want()
}

func TestIdle(t *testing.T) {
	g := newGame(t, Defaults())
	g.play(30, nil)
	g.still[2] = true
	g.play(89, nil)
	g.want()
	g.play(3, nil)
	g.want("afk@2")
	if f := g.found[0]; f.Count != 90 || f.Tick/rate < 29 || f.Tick/rate > 30 || !strings.Contains(f.Summary, "for 90 s from 00:") {
		t.Fatalf("idle: %+v", f)
	}
	// Once per match, however long it lasts.
	g.play(200, nil)
	g.finish()
	g.want("afk@2")
}

func TestAPlayerWithoutDataIsNotIdle(t *testing.T) {
	g := newGame(t, Defaults())
	g.still[3] = true
	g.play(60, nil)
	// Dead for a while: the game server sends nothing, then the player is back and still.
	g.absent[3] = true
	g.play(60, nil)
	g.absent[3] = false
	g.play(60, nil)
	g.finish()
	g.want()
}

func TestLeftEarly(t *testing.T) {
	g := newGame(t, Defaults())
	g.play(200, nil)
	g.absent[4] = true
	g.play(100, nil)
	g.finish()
	g.want("left_early@4")
	if f := g.found[0]; f.Count != 33 || f.Tick/rate != 199 || !strings.Contains(f.Summary, "Left at 03:19 with 33%") {
		t.Fatalf("left early: %+v", f)
	}

	// Leaving in the last quarter is not early, and a short match is not judged.
	g = newGame(t, Defaults())
	g.play(240, nil)
	g.absent[4] = true
	g.play(60, nil)
	g.finish()
	g.want()
	g = newGame(t, Defaults())
	g.play(30, nil)
	g.absent[4] = true
	g.play(60, nil)
	g.finish()
	g.want()
}

func TestFeeding(t *testing.T) {
	feed := func(killsOfTwo int, mateKills bool) *game {
		g := newGame(t, Defaults())
		g.play(300, func(sec uint32) []*pb.ShotEvent {
			var out []*pb.ShotEvent
			if sec%20 == 0 && sec < 240 { // twelve deaths of slot 2
				from := uint32(3)
				if mateKills {
					from = 1
				}
				out = append(out, hit(sec, from, 2, true))
			}
			if sec%100 == 50 { // the others die three times each
				out = append(out, hit(sec, 3, 1, true), hit(sec, 1, 3, true), hit(sec, 1, 4, true))
			}
			if int(sec/30) < killsOfTwo && sec%30 == 7 {
				out = append(out, hit(sec, 2, 3, true))
			}
			return out
		})
		g.finish()
		return g
	}
	g := feed(0, false)
	g.want("feeding@2")
	if f := g.found[0]; f.Count != 12 || f.Tick/rate != 220 || !strings.Contains(f.Summary, "Died 12 times with 0 kills") {
		t.Fatalf("feeding: %+v", f)
	}
	feed(2, false).want("feeding@2") // two kills for twelve deaths is still feeding
	feed(3, false).want()            // a player who fights back is having a bad match
	// Twelve deaths at the hands of a teammate are that teammate's doing.
	feed(0, true).want("team_kill@1", "team_damage@1")
}

func TestLimitsOfAStudio(t *testing.T) {
	off := Limits{}
	g := newGame(t, off)
	g.still[2] = true
	g.play(200, func(sec uint32) []*pb.ShotEvent { return []*pb.ShotEvent{hit(sec, 1, 2, true), hit(sec, 3, 4, true)} })
	g.absent[4] = true
	g.play(200, nil)
	g.finish()
	g.want()

	strict := Limits{TeamDamageHits: 1, TeamKills: 1, AFKSeconds: 10, LeftEarlyPercent: 5, FeedingDeaths: 2}
	g = newGame(t, strict)
	g.still[2] = true
	g.play(120, func(sec uint32) []*pb.ShotEvent {
		if sec == 5 {
			return []*pb.ShotEvent{hit(sec, 1, 2, true)}
		}
		return nil
	})
	g.absent[4] = true
	g.play(20, nil)
	g.finish()
	g.want("team_damage@1", "team_kill@1", "afk@2", "left_early@4")

	for stored, want := range map[string]Limits{
		"":                  Defaults(),
		`{"team_kills":5}`:  {TeamDamageHits: 6, TeamKills: 5, AFKSeconds: 90, LeftEarlyPercent: 25, FeedingDeaths: 10},
		`{"afk_seconds":0}`: {TeamDamageHits: 6, TeamKills: 2, AFKSeconds: 0, LeftEarlyPercent: 25, FeedingDeaths: 10},
		strict.Encode():     strict,
		Defaults().Encode(): Defaults(),
		Limits{}.Encode():   {},
	} {
		if got, err := Parse(stored); err != nil || got != want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", stored, got, err, want)
		}
	}
	for _, bad := range []string{`{"team_kills":-1}`, `{"left_early_percent":100}`, `{"afk_seconds":1000000}`, `not json`} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	if d := Defaults().Describe(); !strings.Contains(d, "team kills from 2") || !strings.Contains((Limits{}).Describe(), "team kills off") {
		t.Errorf("Describe: %q", d)
	}
}
