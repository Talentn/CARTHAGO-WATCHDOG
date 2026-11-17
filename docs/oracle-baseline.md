# Oracle baseline: learning from a studio's own players

The behaviour model of the Carthago Oracle is trained before it ships, on simulated play.
The baseline is a second opinion that is not trained at all. It looks at the sessions one
studio (one tenant) has already scored and answers one question: how far does this player
sit outside what this studio's own players do?

It needs no cheat labels and no outside data. One tenant's baseline is built from that
tenant's score rows only.

## What it does

- **Learning.** For every gameplay signal (aim snaps, headshot rate against rating, reaction
  time, reaction time against the lobby, command rate, trigger rhythm, information-leak score,
  decoy score, fire timing, aim on opponents out of sight, aim ready where opponents appear)
  the baseline takes the middle of the tenant's sessions and the edge that 95% of them lie
  inside, on the suspicious side of the signal. The distance between the two is one *spread*.
  At most 5 sessions of one player are learned from, so one account that plays all day cannot
  move what is normal. A signal that fewer than 100 sessions report is left out.
- **From the clean majority.** Cheaters play in every studio, and an edge at 95% moves as
  soon as a twentieth of the sessions cheat in one signal. So the baseline learns in two
  passes. The first takes, for every signal, the middle and the quartile on the suspicious
  side, and leaves out every session that lies more than 4.45 quartile distances past the
  middle in any signal (three standard deviations of a bell curve). The second learns the
  edges from the sessions that are left. The first pass holds while fewer than a quarter of
  the sessions cheat in the same signal.
- **Never from known cheaters.** A session that carries a finding of the certain tier (the
  engine marks its score row) and every session of a banned player, lifted bans included,
  is scored like any other and never learned from.
- **Starting baseline.** Below 200 sessions with gameplay a studio has no baseline of its
  own. Its players are measured against a fixed starting baseline: an edge and a spread for
  each signal, set by hand from what the signal means, so that a session is outside normal
  only near where the rules themselves stand or where no person gets (a reaction of 30 ms,
  five standard deviations of headshot rate, two thirds of the fire delays quick and
  alike). It is wide and finds less than a studio's own baseline. It is learned from no
  data, and it has no value for the two sight signals, which depend on a game's maps. The
  dashboard says which baseline a studio is on.
- **Session distance.** For every signal, the number of spreads the session lies past the
  edge, capped at 10 per signal and added up. Inside the edge is 0.
- **Player score.** The mean distance of the player's three most suspicious sessions in the
  last 30 days. A session counts for at most 8, and a session the player has not played
  counts as 0. From 3 the player is *outside normal*, from 8 *far outside*; the dashboard
  shows it as 0 to 100 (8 is 100). The ordinary sessions of somebody who cheats now and then
  do not pull the score down, and one extraordinary match alone leaves a player inside
  normal: it takes two sessions outside to be outside, and three far outside to be far
  outside.
- **Dashboard.** The players list has a column "Against own players" and puts players who are
  outside normal first, the furthest first; everybody else follows by rule risk as before.
  The flagged list also takes in players who are outside normal and have no rule evidence. A
  player's page has a card with the score, the band, the number of sessions and the names of
  the signals that stand out. No value, edge or spread is shown.

The baseline is advice for a reviewer, like the rest of the Oracle. It is computed on read
from `oracle_scores` (the latest 5,000 rows of the tenant, cached for a minute). It writes
nothing and has no code path to a kick, a ban or a client notice. It needs the Oracle engine
to be on, because the engine is what stores the score rows.

The numbers above are constants in `backend/internal/oracle/baseline.go`. The smallest spread
of each signal and the starting baseline are set by hand from what the signal means. Nothing
is fitted on any data set.

## Measuring it with the simulator

```
carthago-oracle baseline -matches 100 -seed 1
```

The simulated sessions are one studio's history. The baseline learns from them with the
labels hidden, then every session is scored and the labels are used to count. The simulator
is built to train a model, so about a third of its sessions cheat; the studio measured keeps
every honest session and 3% cheating ones (`-cheat-share`). A second table shows what the
baseline finds when it learns from the whole simulated mix instead, and a third what the
starting baseline finds with nothing learned. Honest players with good game sense (they hold
the angles opponents come from, follow footsteps, follow a teammate's call) have their own
line, `honest_sense`, because they are who the sight signals could flag by mistake.

## Fire timing: the signal for trigger bots

A trigger bot fires for the player the moment the crosshair is on an enemy, at a set delay.
A person's fire follows later and at a different delay each time. The signal is the largest
share of a player's fire delays that are both under 100 ms and within 32 ms of each other,
from matches with at least 12 delays. A delay is the time from the crosshair arriving on an
enemy to the player's next shot, hit or miss, within one second; a player who was already
firing in the half second before gives no sample.

**Integration requirement.** The gateway cannot see the crosshair. The game server has to
report it: `MatchRecorder::crosshair(slot, target, tick)` (`CrosshairEvent` in
`GameplayBatch.crosshair`), once each time the trace along a player's view direction first
meets an enemy's body, not on every tick it stays there. A game server traces the view for
its own hit detection, so it has this. Without these events the signal is unknown and
everything else works as before.

Fire timing is a signal of the baseline only. It is stored beside the model's features in a
score row (`fire_timing`), and the behaviour model does not read it: a new model feature
would mean a new feature version and a new model for every deployment.

## Sight: the signals for wallhacks

A wallhack shows where opponents are behind walls, and the aim follows them. Two signals
measure that from what the game server already knows, with no map on the gateway:

- **Aim on opponents out of sight** (`hidden_aim`): of the moments with an opponent within
  40 m whom the player cannot see and has no word of, the share in which the crosshair stayed
  within 4 degrees of such an opponent for two samples running (8 samples a second). Needs
  30 seconds of such moments in a match.
- **Aim ready where opponents appear** (`pre_aim`): of the opponents who came into view
  unannounced, the share the crosshair was already on. Needs 8 of them in a match.

A player has honest ways to know where a hidden opponent is, and those moments are left out,
for two seconds each: the player has just seen the opponent, a teammate sees the opponent
(and says so), the game marked the opponent for the team (`TeamInfo`), or the opponent made
a sound the game says the player could hear (`SoundEvent`). The time from an opponent
becoming visible to the first hit is not new: it is the reaction-time signal.

**Integration requirement.** All of it is optional, and a game server that sends none of it
keeps working unchanged, with the two signals unknown:

- *Who can see whom.* `MatchRecorder::visible_now(observer, tick, &opponents)` with the whole
  list of opponents the server's own line-of-sight test finds for the observer, a few times a
  second or more; the recorder sends only the changes. A server that tracks the changes
  itself calls `visibility(observer, target, tick, visible)` instead. Either way it is
  `VisibilityEvent` in `GameplayBatch.visibility`, the same events the reaction-time signal
  uses. The two sight signals do not exist without it.
- *Where players are.* `motion(...)` (telemetry v2), with `MatchPlayer.team` set for team
  games. The two sight signals do not exist without it.
- *What players could hear.* `sound(...)` with the game's own audible radius. Without it a
  player who follows footsteps looks like one who sees through walls, and the signals flag
  honest players.

Like fire timing, these are signals of the baseline only, stored beside the model's features
in a score row. They overlap with the information-leak score, which needs the map geometry
and is more careful; they are for integrations that do not send a map.

## Two changes that came with it

- **`angle_snap` is low severity.** Real honest players produce snap-and-lock aim movements
  too, so the rule alone no longer flags a player. It still counts together with
  `headshot_rate` or `time_to_damage` for the client notice, and the aim-snap rate is still a
  signal of the behaviour model and of the baseline.
- **`MatchRecorder::view_reset(slot)`** in the game-server crate. When the game itself sets a
  player's view (a spawn, a teleport, a forced camera), the integration calls it before `aim`
  for the tick the new view first shows in. That one sample is left out, the aim track ends
  there, and the jump is not measured as the player's own aim movement. An integration that
  builds batches without the crate must do the same: leave a gap of one tick in the aim
  track.

## Limits

- The baseline finds what is far from the studio's own players. Cheating that stays inside
  the normal range is not found by it.
- If a quarter or more of a studio's sessions cheat in the same way, that cheating still
  becomes part of what is normal. Below that, quiet cheating that the first pass cannot tell
  from the honest tail still widens the edges a little.
- The starting baseline cannot know a game it has never seen. It finds less of the quiet
  cheating, and it is not free of false flags: the headshot rate against rating has a long
  honest tail, and on the simulator about 3% of honest sessions lie past the starting line
  for it. A studio's own baseline measures that tail.
- The sight signals know the honest sources of knowledge listed above and no others. A
  player who knows the map, counts the opponents' timing or is told by a dead teammate has
  aim on hidden opponents that the signals cannot explain. Honest players are not measured
  against zero but against the studio's other players, which is what keeps this in bounds.
- Only the gameplay signals are used; the client integrity signals stay with the rules and
  the behaviour model.
- The player score needs two sessions outside normal. Many sessions that are each a little
  inside the edge do not add up.
- The simulator's fire delays, of people and of trigger bots, are assumptions. They were not
  measured on players. Its wallhack player prefers opponents nobody has heard or seen, which
  is the easiest case for the sight signals.
