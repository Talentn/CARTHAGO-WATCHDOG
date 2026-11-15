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
  decoy score) the baseline takes the middle of the tenant's sessions and the edge that 95% of
  them lie inside, on the suspicious side of the signal. The distance between the two is one
  *spread*. At most 5 sessions of one player are learned from, so one account that plays all
  day cannot move what is normal.
- **Watch-only first.** Below 200 sessions with gameplay the baseline scores nobody. A signal
  that fewer than 100 sessions report is left out.
- **Session distance.** For every signal, the number of spreads the session lies past the
  edge, capped at 10 per signal and added up. Inside the edge is 0.
- **Player score.** The mean distance of the player's sessions in the last 30 days, pulled
  toward 0 while the sessions are few (`mean × n / (n + 1)`). From 3 the player is *outside
  normal*, from 8 *far outside*. The dashboard shows it as 0 to 100 (8 is 50).
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
- The player score is a mean. It does not yet add up many small deviations of one player.
