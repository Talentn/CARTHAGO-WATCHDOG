# Shadow pool

A studio can keep the players it has caught playing with each other, unaware, for a set
period before the ban takes effect. During that period the gateway keeps collecting what
they do and what they load. It is off by default: off, a ban on certain evidence is
immediate, as before.

## What it does

- **The period** is a setting of the studio, in hours or days, at most 90 days. An admin
  sets it on the dashboard's Shadow pool page or with
  `carthago-gateway shadow period -tenant ID -hours N` (`-days N`, `-off`).
- **Entry.** With a period set, evidence that would ban automatically (certain evidence:
  see `analyzer/tiers.go`, and the impossible values of the economy ledger) puts the
  player in the pool instead. The entry is the ban itself, on the account and the device
  key, with its effect put off by the period. A ban a reviewer makes is never put off.
- **Other accounts on the PC.** An account that signs in with the device key of a player
  in the pool joins the pool at the handshake, with the same end. It does not have to be
  caught itself.
- **Collection.** From entry, the player's sessions are labelled "confirmed cheat" with
  source `shadow` and the entry's reference (the session of the detection, the last 30
  days before it, and every session started in the pool), the files they load count
  toward proposed known cheats, and the money they trade or drop is marked dirty in the
  economy ledger. For an account that came in through the device key this starts at the
  session it joined with.
- **End.** When the period is over the ban takes effect by itself: the sessions are ended,
  and the account and the device key are refused from then on. The gateway also checks
  every 15 seconds, so a period that ended while the gateway was down ends at the next
  start.
- **Ban now** makes the ban take effect at once. **Release** returns the player to normal
  and removes the labels and dirty marks the entry caused, as lifting a ban does; the
  proposals are worked out from the standing bans, so they follow. On the player who was
  caught, both also apply to the accounts that came in from the same PC; on such an
  account they apply to that account alone. A reviewer's "Ban player" on a player in the
  pool is Ban now. Entry, joining, the end, Ban now, Release and a change of the period
  are in the audit log.
- A change of the period applies to players caught from then on. Those in the pool keep
  their end.

## What the studio's matchmaking must call

The pool does nothing by itself: the studio's matchmaking has to ask who is in it and
match those players with each other. The calls are plain HTTP with JSON on the gateway,
under the tenant's server key (`Authorization: Bearer <key>`), like `/v1/economy`.

| Call | Answer |
| --- | --- |
| `GET /v1/shadow/status?player=<id>` | `{"player":"<id>","status":"normal"}` or `"shadow"` |
| `POST /v1/shadow/status` with `{"players":["a","b"]}` (1 to 500) | `{"players":[{"player":"a","status":"normal"},{"player":"b","status":"shadow"}]}`, in the order asked |
| `GET /v1/shadow/pool` | `{"players":[{"player":"b","since_ms":...,"until_ms":...}]}`, the entry that ends first first |

- Ask when a player queues, and again before a match starts: a player can enter the pool
  in the middle of a session.
- The only answers are `normal` and `shadow`. A player the gateway has never seen is
  `normal`; so is a banned one, who has no session to match.
- On an error (401 without the key, 400 for a bad request, 500 when the pool cannot be
  read) ask again. Do not match on a guess.
- While the studio's unattested pool is on (`docs/driver-list.md`), each answer of the
  status call also carries `"attestation": "attested"` or `"unattested"`. It is a separate
  answer, worked out without the shadow pool, and the same for a player in it as for any
  other.
- The server key must stay on the studio's servers. Do not pass the status on to any
  client, and do not let it show: no separate queue name, no different wait message.
- When few players are in the pool their matches are short. Whether to fill them with
  bots, or let them wait, is the studio's choice.
- The economy calls answer `"shadow": true` next to `"banned"` while the ban waits, so the
  game server does not act on it in sight of the player.

## What the player can and cannot see

Nothing the gateway sends to a player in the pool differs from what a normal player
gets: the handshake, the session, the token and its renewals, the heartbeat answers. No
alert or ban notice is sent and the session is not ended, whatever is found during the
period. An account that joins through the device key gets a session like anybody. A test
runs two clients through the same messages, one of them caught, and compares what they
receive.

When the period ends the player is banned like anybody else: the session ends, and the
next handshake is refused with the ban's reference and no reason.

What the player can still notice is outside the gateway: who they are matched with, how
long a match takes to fill, and anything the studio's own servers show.

## Simulated matchmaker

`carthago-shadow-sim` starts a gateway of its own on this PC and runs five scenes with
simulated players over the real client protocol and the real `/v1/shadow` calls: honest
players matched normally, caught players matched only with each other, a second account
on a caught player's PC, a released player matched normally again, and the ban taking
effect when the period ends. Then it keeps its dashboard up with three players in the
pool.

```bat
cd /d "C:\Users\Ala Ghabi\anticheat\backend" && go run .\cmd\carthago-shadow-sim
```

`-period 20s` is the period of the run, `-admin` prints a one-time link for an admin
account (the period setting needs it), `-exit` stops after the scenes.

## Limits

- The pool only separates players if the studio's matchmaking calls the API. Nothing in
  the game is changed.
- A pooled player's handshake and first certain finding do one or two more database
  writes than a normal player's. The difference in answer time was not measured, and
  not shown to be invisible.
- A released player whose client still reports the same thing is caught again by the
  next report.
- Labels of source `shadow` stay after the ban takes effect; they go when the ban is
  lifted.
- An account that was released from a PC's entry does not join that entry again by
  signing in; it has to be caught itself.
- The Shadow pool page counts sessions and files from the stored evidence each time it
  is opened. That was not measured on a large database.
- One studio's pool is that studio's. Nothing is shared between studios.
