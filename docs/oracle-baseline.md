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
  decoy score, fire timing) the baseline takes the middle of the tenant's sessions and the
  edge that 95% of them lie inside, on the suspicious side of the signal. The distance between
  the two is one *spread*. At most 5 sessions of one player are learned from, so one account
  that plays all day cannot move what is normal.
- **Watch-only first.** Below 200 sessions with gameplay the baseline scores nobody. A signal
  that fewer than 100 sessions report is left out.
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
of each signal is set by hand from what the signal means. Nothing is fitted on any data set.

## Measuring it with the simulator

```
carthago-oracle baseline -matches 100 -seed 1
```

The simulated sessions are one studio's history. The baseline learns from them with the
labels hidden, then every session is scored and the labels are used to count. The simulator
is built to train a model, so about a third of its sessions cheat; the studio measured keeps
every honest session and 3% cheating ones (`-cheat-share`). A last line shows what the
baseline finds when it learns from the whole simulated mix instead.

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
- If many of a studio's sessions cheat, the cheating becomes part of what is normal.
- Only the gameplay signals are used; the client integrity signals stay with the rules and
  the behaviour model.
- The player score needs two sessions outside normal. Many sessions that are each a little
  inside the edge do not add up.
- The simulator's fire delays, of people and of trigger bots, are assumptions. They were not
  measured on players.
