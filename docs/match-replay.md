# Match replay

A reviewer can watch a match from above in the dashboard: every player as a dot with the
direction they look, the shots, and a timeline with everything the gateway found in that
match. It is a picture for review. No rule reads it and it changes nothing about a player.

## What it does

- **Recording.** When a game server sends player positions, the gateway keeps one position
  and view direction per player every quarter second, and every shot. A 25-minute match of
  ten players is about 180 KB in the database.
- **Size cap.** One match keeps at most 400,000 positions (ten players for eleven hours),
  40,000 shots and 256 players, and at most 6 MB. A match that runs past a cap keeps what
  was recorded up to there and says so on the page.
- **The page** `/matches/<match id>` plays the match: play, pause, a scrubber, speed from
  0.5× to 16×. Team one is a filled dot, team two a ring. A player with a medium mark is
  amber, with a high mark red. The frame is the area the players covered; no map is drawn.
- **Timeline marks.** Each mark is listed under the replay with its match time and placed
  as a tick under the scrubber. Clicking either one jumps to two seconds before it and
  highlights the player. Marked are:
  - gameplay findings of the match, at the batch that raised them;
  - each moment an information-leak or decoy finding lists, at its own time;
  - client findings of a player's session made while the match was being received;
  - the Oracle's score of a player's session for this match, when it is Watch or Review;
  - behaviour findings of the match (`docs/toxicity.md`), in grey: they are advice and do
    not colour the player.
- **Links.** A player's page and a session's page list their recorded matches with a
  "Watch replay" link. `?t=<milliseconds>` opens the page at a moment and
  `?player=<player>` highlights a player.
- **Access.** The same sign-in and roles as the session pages: every signed-in user of the
  studio can watch, nobody from another studio can. Recordings are stored per studio.
- **Retention.** A recording is deleted 30 days after its last batch.
- **Browser policy.** The match page is the only page of the dashboard that runs a script:
  one file served by the dashboard itself. Nothing inline, nothing from another host. Every
  other page still allows no script at all.

## What the game server must send

Nothing new. The replay uses what telemetry v2 already carries on `/v1/ingest`
(`GameplayBatch`, see `proto/carthago/v1/gameserver.proto`):

| Field | Used for |
| --- | --- |
| `motion` (`MotionTrack`: slot, first tick, x and y in centimetres) | positions |
| `aim` (`AimTrack`: yaw in degrees, 0 along +X, 90 along +Y) | view direction |
| `shots` (`ShotEvent`: slot, tick, target slot, hit, kill) | shots |
| `players` (slot, session id, player hash, team, bot) | names, teams, links |
| `match_over` | closes the recording at once |

With the server SDK (`carthago-server`) these are `player`, `player_profile`, `motion`,
`aim` and `shot` on the batch recorder. The coordinates can be any game's: only x and y are
drawn, and the frame is taken from the data.

A game server that sends no positions gets no recording and no replay links. Everything
else works as before.

## See it

```
cd backend
go run ./cmd/carthago-demo
```

The demo streams a 25-minute match of ten players in which `sami` is flagged for
`information_leak`. When it prints the dashboard address, sign in with the demo login and
open

```
http://127.0.0.1:8791/matches/ranked-yard-0001?player=sami
```

or go to Players, `sami`, "Watch replay". Click a mark in the table, then Play.

Tests: `go test ./internal/replay ./internal/store ./internal/pipeline ./internal/dashboard`.

## Limits and what is untested

- The demo's match comes from the gateway's own match simulator. No real game server and
  no real game has sent a match to the replay.
- The player was run in headless Chrome on Linux only: load, play, pause, speed, scrub and
  jumping to a mark. Firefox, Safari, Edge, touch screens and a real person using it are
  untested.
- A match of more than about ten players, or one that reaches the size cap, was tested in
  the recorder only, not watched in the browser.
- Height is not recorded: two floors of a building are drawn on top of each other.
- A player the game server sends no position for (dead, not spawned) disappears after two
  seconds. Deaths are not marked apart from the × of a killing shot.
- The Oracle scores a session over a whole match, so its mark stands at the end of the
  match, not at a moment. A gameplay finding stands at the batch that raised it, which for
  rules scored at the end of the match is also the end.
- A client finding is placed by the time the gateway received it. If the game server sends
  the match late or in one piece, client findings fall outside the match and are not marked.
- The recording of a match in progress is written every 30 seconds, so a live match is
  behind by up to that.
- There is no switch to turn recording off for a studio that sends positions, and no list
  of all recorded matches: a match is reached from a player or a session.
