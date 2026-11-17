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
  amber, with a high mark red. The frame is the area the players covered. A map is drawn when the studio
  registered an outline for it (see Map outline below); otherwise none is.
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

## Map outline

Without an outline the players move on an empty field. A studio can register one outline
per map, and the replay of every match on that map draws it under the players. An outline
belongs to one studio; another studio with a map of the same name does not see it.

A match names its map in the telemetry it already sends: `GameplayBatch.map.map_id` (or
the `map_id` of `map_geometry`). The first name a match gives is kept with its recording.
No new field was needed. A match recorded before this change has no map name and is drawn
as before, as is a match whose map has no outline.

Two forms, in the coordinates of the match's positions (centimetres, +X right, +Y up):

**Wall lines** (preferred). A JSON document with the map's walls as line segments,
`[x0, y0, x1, y1]` each:

```json
{"map": "de_dust2", "lines": [[-2200, 800, -2200, 2400], [-2200, 2400, -900, 2400], [-900, 2400, -900, 1700]]}
```

At most 5000 lines and 512 KB, whole numbers within ±10 000 000 cm, no line of zero
length, no other field.

**A picture.** A PNG of the map seen from above, with the world rectangle it covers as
`min_x,min_y,max_x,max_y` in centimetres. The picture's top edge is max y:

```
POST /v1/maps?map=de_dust2&rect=-2500,-1200,1800,3300      Content-Type: image/png
```

At most 2 MB, 4096 pixels on a side and 4 megapixels. Only PNG: the file must start with
the PNG signature and decode as one. The gateway decodes it and writes the pixels out
again as its own PNG, and that copy is what it stores and serves, so text chunks, colour
profiles and anything appended to the file are gone. JPEG, SVG and everything else are
refused.

### How to upload

From the game server, under the server key, like the other game-server calls:

```sh
# wall lines
curl -X POST https://gateway.example/v1/maps \
  -H "Authorization: Bearer $SERVER_KEY" -H "Content-Type: application/json" \
  --data-binary @de_dust2.lines.json

# a picture
curl -X POST "https://gateway.example/v1/maps?map=de_dust2&rect=-2500,-1200,1800,3300" \
  -H "Authorization: Bearer $SERVER_KEY" -H "Content-Type: image/png" \
  --data-binary @de_dust2.png
```

The answer is `201 {"map","kind","segments" or "width","height","rect"}`; 400 with the
reason for an outline it does not take, 413 past the size cap, 415 for any other content
type, 401 for an unknown key. `GET /v1/maps` lists the studio's outlines and
`DELETE /v1/maps?map=de_dust2` removes one. An upload replaces the map's previous outline;
a studio keeps at most 200.

From the dashboard: Maps (in the navigation for an admin, and linked under every replay).
Uploading and removing need the admin role, go through the same CSRF check as every other
form and are written to the audit log (`map.outline`, `map.outline_remove`), refused
uploads included. Every role can see the list.

### Shots across a wall line

With wall lines, the replay also points out shots at a player whose line crosses a wall:
they are drawn dashed and stay on screen longer, each has a short grey tick on the
timeline, and a table under the replay lists them (first 200) with a jump to each.

This is an aid for the person watching and nothing else. It is worked out when the match
page is opened and stored nowhere: it makes no finding, has no score, does not touch risk,
bans, the shadow pool or the Oracle, and does not count among the match's marks. A test
opens such a match and checks that no evidence, ban, shadow-pool entry or report appeared
and that the match still shows 0 marks.

How a shot is tested: the straight line from the shooter to the player the game server
says was shot at, at the positions the recording has for that moment, leaving out the 40 cm
at both ends. It counts when that line and the two lines 80 cm to either side of it all
cross the same wall line. The 80 cm stand for a player's width, the part of a target that
shows round a corner and the quarter second between two kept positions.

What that means in practice:

- A shot through a wall closer than 80 cm to the wall's end, or through a wall or pillar
  narrower than 1.6 m, is not listed.
- The outline is flat. A shot over a low wall, through a window or from a floor above is
  listed although nothing was in the way. Leave out of the lines what a standing player
  sees over.
- A shot at nobody (a miss with no target) has no line to test.
- Many games let bullets pass thin walls. The list does not know the game's rules.
- In the demo's 25-minute match of ten simulated players 14 of 17 675 shots at a player
  are listed, over eight players; six of them are sami's, the simulated wallhack user. The simulator has no player who shoots through
  walls and only fires at a target it can see, so these 14 are the aid's false alarms:
  targets at a corner or a doorway, 80 to 100 cm from the wall's end (with 100 cm instead
  of 80 one or two remain, with none 822 are listed). The demo shows the outline and the
  aid, not a caught wallbang.

A picture has no lines, so with a picture alone no shots are pointed out.

### See it

`carthago-demo` registers the outline of its map (`carthago-yard`, 92 wall lines) through
`POST /v1/maps` in chapter 2. Open the match of chapter 2 and the Maps page:

```
http://127.0.0.1:8791/matches/ranked-yard-0001?player=sami
http://127.0.0.1:8791/maps
```

Tests: `go test ./internal/outline ./internal/replay ./internal/store ./internal/gateway ./internal/dashboard`.

### What is untested

- No real map. The only outline drawn so far is the simulator's test map, and one
  hand-made PNG. Nobody has exported wall lines from a real game's map file; there is no
  exporter for any map format.
- The browser side (drawing lines, drawing the picture, dashed shots, the ticks) was looked
  at in headless Chrome on Linux only. The dashboard's upload forms are covered by Go tests
  that post the form; nobody has clicked them in a browser.
- A large outline (thousands of lines) or a picture at the size cap was checked in the
  validation tests, not watched in the browser.
- Pictures with unusual PNG features (16-bit, interlaced, palette with transparency) rely on
  Go's decoder; only 8-bit RGBA was tried.
- The outline is not versioned: `MapRef.version` is ignored, and a replay is drawn with the
  outline the map has today, not the one it had when the match was played.
- The geometry a game server may already upload for the information-leak rule
  (`map_geometry`) is not turned into an outline; the two are separate uploads.
- No preview of an outline on the Maps page: open a match on that map to see it.

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
