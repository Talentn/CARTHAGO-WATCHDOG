# Behaviour findings

The gateway notices five ways a player spoils a match for the others, from the events a
game server already sends. It reads no chat, no voice and no text, and uses no model. What
it finds is advice for a studio's community team. It is not anti-cheat evidence.

## What it does

One finding per player, kind and match, raised when the studio's limit is reached:

| Kind | Raised when, in one match | Default limit |
| --- | --- | --- |
| `team_damage` | the player hit teammates this many times | 6 hits |
| `team_kill` | the player killed this many teammates | 2 |
| `afk` | the player, while in play, neither moved (1 m) nor turned (2°) for this long | 90 s |
| `left_early` | the player's data stopped with more than this share of the match still to play | 25% |
| `feeding` | the player died this many times, with at most one kill per five deaths and at least twice the deaths of the lobby's median player | 10 deaths |

- **Fair to the player.** A death at a teammate's hands counts against the teammate, not
  the one who died. A player the game server sends nothing for (dead, not spawned) is not
  idle: the idle time starts again when their data does. Leaving early and feeding are
  judged only when the match is over and lasted two minutes or more; feeding needs a lobby
  of four or more.
- **Advisory only.** Findings are kept in a table of their own (`toxicity_findings`), not
  with the evidence. The code that computes risk, feeds the Oracle and its baseline, sends
  notices, kicks, bans or fills the shadow pool reads the evidence table and never this
  one. A behaviour finding cannot do any of those.
- **Player page.** A "Behaviour" card shows, for the last 30 days, in how many matches each
  kind was found, and lists the findings with a link to the replay at that moment.
- **Replay.** The findings of a match are grey marks on its timeline and rows in the table
  under it (`docs/match-replay.md`).
- **Limits per studio.** Each studio has its own limits; 0 turns a kind off. A change
  applies to matches that start after it and is written to the audit log.
- **Per studio.** Findings and limits are stored per studio; another studio sees neither.
- **Retention.** A finding is deleted after 90 days.

## What the game server must send

Nothing new. The rules use telemetry v2 on `/v1/ingest` (`GameplayBatch`, see
`proto/carthago/v1/gameserver.proto`):

| Field | Used for |
| --- | --- |
| `players` with `team` (not 0) | who is whose teammate; without teams there is no team damage or team kill |
| `shots` with `target_slot`, `hit`, `kill` | team damage, team kills, deaths and kills for feeding |
| `motion` and/or `aim` | standing idle; the last tick with data is when the player left |
| `match_over` | judges leaving early and feeding at once (otherwise when the match goes idle) |

## See it

```
cd backend
go run ./cmd/carthago-demo
```

Chapter 8 plays an 8-minute match in which the simulated game server reports `walid`
feeding, shooting teammates, standing idle and leaving. Sign in with the demo login and open

```
http://127.0.0.1:8791/players/walid
http://127.0.0.1:8791/matches/casual-yard-0002?player=walid
```

A studio's limits, shown and changed (with the gateway running or not):

```
go run ./cmd/carthago-gateway toxicity limits -tenant demo
go run ./cmd/carthago-gateway toxicity limits -tenant demo -team-kills 1 -afk-seconds 0
go run ./cmd/carthago-gateway toxicity limits -tenant demo -defaults
```

Tests: `go test ./internal/toxicity ./internal/store ./internal/pipeline ./internal/dashboard ./cmd/carthago-gateway`.

## Limits and what is untested

- The only spoiled match ever judged is the simulator's, with events written to trip each
  rule. No real game server and no real players: the default limits are a starting point,
  not measured on real matches.
- The limits are set on the command line only. There is no form in the dashboard, and the
  one-command demo runs on the defaults.
- The count is on the player's page only. The players list has no behaviour column and
  there is no list of all behaviour findings.
- The rules assume a match where players respawn or stay to the end. In a mode where a dead
  player's data stops for the rest of the match (battle royale, one life per match), a
  player who dies early looks like one who left early: set `-left-early-percent 0` there.
- A player who reconnects under another slot is two players to these rules.
- Damage amounts are not sent, so team damage counts hits, not health lost. Friendly-fire
  modes where hitting teammates is part of the game need `-team-damage 0 -team-kills 0`.
- Idle needs positions or view angles for the player; a game server that sends neither
  gets no idle findings and no leaving early.
- A match in progress when the gateway restarts loses its counts so far.
