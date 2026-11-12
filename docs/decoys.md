# Decoys

A decoy is a fake enemy that the game server replicates to one player (or a few chosen
players) only while none of them could see or hear it. An honest client culls it like any
other hidden enemy: nothing reaches the screen or the speakers. A client that reads hidden
entity state sees one more enemy that nobody else knows about. The gateway's `decoy_reaction`
rule tests whether a player's aim and shots follow those decoys more often than their own
habits explain.

Decoy evidence is **flag-only**. It is never integrity evidence, it never triggers an
automatic kick, and it is a separate evidence family from `information_leak`.

## How a decoy is reported

Each decoy goes through four phases. Report all of them with `carthago-server`'s
`MatchRecorder`:

| Phase | SDK call | Sent to clients |
| --- | --- | --- |
| Created; the decoy walks for a pre-roll of at least `DECOY_ROLL_MIN_S` (12.5 s) | `decoy_create(id, team, recipients, cloned_from)`, then `decoy_motion` every tick | no |
| Replicated to its recipients | `decoy_replicated(id, tick)`, then `decoy_motion` | to recipients only |
| No longer replicated; the decoy walks on for a post-roll of the same length | `decoy_unreplicated(id, tick)`, then `decoy_motion` | no |
| Ended | `decoy_end(id)` | no |

The pre-roll and post-roll positions are never sent to anyone. They let the gateway compare
aim at the replicated decoy with aim at where the same decoy was 5, 8 and 12 seconds earlier
or later, under the same validity rule. These are the same time-shifted controls the
information-leak scorer uses. A single coincidence therefore cannot flag, and a flag also
needs reactions to at least two different decoys.

On the wire, each decoy is a `DecoyTrack` in `GameplayBatch.decoys`. See the proto README.

## Integration rules

A studio must follow these rules. Each one either keeps decoys invisible to honest players
or keeps the statistics fair.

**Replication and placement** (`DecoyPlanner`, using the same map geometry as the gateway):

1. Replicate a decoy only to its recipients, and only while `DecoyPlanner::keep` holds:
   - every recipient is 20–40 m away;
   - no recipient has line of sight to the decoy's eye or chest point, in any direction,
     including from 1.5 m to either side of their eye (a peek);
   - no real enemy is within 7 m of it.

   Start replicating only when `can_replicate` holds, which additionally needs 10 m from real
   enemies and from anything shared with the team in the last few seconds (pings, spots,
   radar). Stop replicating on the tick the check fails, before that tick's move is sent.
2. **Move the decoy independently of its recipients.** Use the game's own bot navigation
   toward goals of its own, with player-like speeds and pauses (`cloned_from` names the
   player whose movement it imitates). Never steer it by what its recipient does: no
   seeking cover from them, no waiting at the edge of their sight. A decoy placed by its
   recipient's behaviour makes its own positions at other times an unfair control. In our
   simulation, honest players then scored route z values of 2 to 3.6 against decoys they
   never saw.
3. Report the full pre-roll and post-roll, and motion in every phase.

**Rendering, audio and netcode:**

4. Cull decoys exactly like hidden enemies: no outline, no wall-hack-proof highlight, no
   minimap or radar dot, no kill-feed entry, no hit marker, no scoreboard row, no name tag.
5. Play no sound for a decoy: no footsteps, no gunfire, no voice lines, and no client-side
   animation sound events. If footsteps are driven by animation notifies on the client,
   strip them from the decoy's animation set. The 20 m minimum distance is beyond footstep
   range as a second line of defence, not a substitute.
6. Never let a decoy be spotted, pinged, revealed by an ability, tagged by a utility, or
   damaged. Bullets pass through it, and it never fires.
7. Replicate a decoy with the same relevancy, priority and update rate as a real hidden enemy
   at that distance, under the same entity class and component layout. A decoy that is the
   only entity sent at an unusual rate is easy to filter (see "Limits").
8. Never replicate a decoy to a spectator, a replay or killcam stream, or a teammate who is
   not a recipient. Teammates' clients never see it.

Our simulation and the gateway apply rules 1 to 3. Rules 4 to 8 belong to the game client
and engine; Carthago cannot check them, and a studio should test them with its own
debug views before shipping.

## What the gateway scores

- **`decoy_aim`:** crosshair within 7° of a replicated decoy, compared with the controls.
- **`decoy_shots`:** shots within 5° of a decoy while no visible enemy was being engaged.
- **`decoy_route`:** moving toward a decoy. It is reported with its moments but not
  combined into the score, because a decoy is replicated for too short a time for route
  changes to separate from where players go anyway.

A sample is set aside when:

- the decoy was in sight of a recipient ("exposed"). This only removes evidence and never
  creates it;
- a real enemy was within 7 m of it;
- a visible enemy was within 14° of its bearing;
- something the team was told about was near it.

Samples where the team just heard an enemy in the decoy's direction still count toward the
rates, because the controls are tested the same way. They are never shown as moments or
counted as reactions, so a reviewer is only shown reactions that nothing the player knew
could explain.

Thresholds are per segment (game mode × input device): z ≥ 4.0 for mouse, 4.5 for
controller and 5.0 as the fallback, with a minimum excess over the controls. They target 1
false flag per 1,000 honest player-matches. A synthetic calibration can show zero false
flags, but it can bound the false-flag rate at 1e-3 (95%) only after about 3,000 honest
player-matches per segment. Re-calibrate on each game's real matches before relying on
the threshold.

## Limits: what a cheat author can do, and what it costs them

Decoys raise the cost of using leaked information. They do not make it impossible. The
known counters, and their costs:

- **Filter entities that make no sound.** This works only if the game lets decoys stay
  silent where real players would not. With rule 5 and the 20 m distance, a real enemy that
  far away is also silent, so the filter hides real enemies too.
- **Filter short-lived or briefly replicated entities.** Real enemies also flicker in and
  out of relevancy at range. Filtering by lifetime delays the cheat's own information by
  that lifetime.
- **Cross-check against server-authoritative state the cheat can also read**, such as the
  scoreboard, player count or team roster. A decoy that is "extra" can be spotted by
  counting. Mitigations: clone a real player (`cloned_from`), and do not replicate a decoy
  while its cloned player is relevant to the recipient. Counting attacks remain the
  strongest counter, and studios with exposed rosters should treat decoys as a deterrent
  rather than proof.
- **Fingerprint behaviour**, such as decoys that never shoot or never take damage, or paths
  that differ from human ones. The cheat has to see an entity long enough to classify it,
  which delays reactions to real enemies by the same amount. Bot navigation that imitates a
  real player (`cloned_from`) raises the cost further.
- **Detect netcode differences**, such as an entity class, component layout, update rate or
  replication priority that only decoys use. These are integration bugs that rule 7
  forbids.
- **React only to enemies that are also visible on radar or reported by teammates.** At
  that point the cheat no longer uses leaked information.

In every case, a cheat that filters decoys also filters, or delays, some real hidden enemies.
That reduces the cheat's value, and the `information_leak` rule keeps scoring the real
enemies independently.

## Calibration status

See the decoy table printed by `carthago-sim -calibrate N -decoys`. On synthetic matches,
honest players (including noisy prefire, sound and team-call players) never reached a decoy
score of 2.6. Informed players are caught in the shooter segments. In the extraction
segments, where informed players spend most of their time looting on a large map, recall is
low. These numbers are synthetic and will move on real games.
