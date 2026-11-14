# Economy ledger

For games where the studio runs the game servers. The game servers tell the gateway about
every change of a player's money or items, and now and then what a player has. The gateway
keeps its own ledger per player and currency and catches money that should not exist:
money a modder gave themself shows up as a balance the reports do not add up to.

Nothing here runs on the player's PC, and the ledger does not look into the game.

## What a game server must report

Every call carries the studio's server key, the same one as for `/v1/gs`:
`Authorization: Bearer <server key>`. Bodies and answers are JSON. A call reads and writes
the ledger of the key's studio only.

| Call | What it does |
| --- | --- |
| `POST /v1/economy/events` | Reports 1 to 500 changes: `{"events":[...]}` |
| `POST /v1/economy/balances` | Reports 1 to 500 balances: `{"balances":[...]}` |
| `GET /v1/economy/dirty` (`?player=` for one) | Lists dirty money per player and currency |
| `GET /v1/economy/status?player=` | One player's ban, ledger balances and flags |

One change:

```json
{"event_id": "srv3-88121", "player": "account-id", "currency": "money", "amount": 1500,
 "source": "robbery", "counterparty": "", "at_ms": 1794619938275}
```

| Field | Meaning |
| --- | --- |
| `event_id` | The game server's own id of the change, unique in the studio. Sending an id again changes nothing, so a failed call can simply be repeated. |
| `player` | The player's account: the same player id hash the anti-cheat client and `/v1/gs` use for the player, so a ban reaches the player's sessions. |
| `currency` | `money` when left out. An item is a currency of its own, counted in pieces, for example `item:lockpick`. |
| `amount` | Whole number in the smallest unit. Positive: received. Negative: spent or given away. |
| `source` | Where it came from or went: `job`, `robbery`, `trade`, `drop`, `purchase`, `sale`, `admin_grant`, or a source of your own that has a limit on the Economy page. |
| `counterparty` | For `trade`: the other player. For `drop`: who dropped what this player picked up. |
| `at_ms` | The game server's time of the change, Unix milliseconds. |

One balance: `{"player": "account-id", "currency": "money", "balance": 1900, "at_ms": ...}`.

Rules for reporting:

- Report every change. A trade is two events: a negative one for the giver and a positive
  one for the receiver, each naming the other as `counterparty`.
- Report the changes before the balance that includes them. The ledger compares a balance
  with the changes up to the balance's `at_ms`.
- The first balance reported for a player is taken as the start and is never judged, so
  players who had money before the integration are not banned.
- The answer has one result per event or balance, in order: `recorded`, `duplicate` or
  `rejected` for an event; `ok`, `opened`, `mismatch` or `short` for a balance; with the
  flags it raised, the ban reference if it banned, and how much of a credit is dirty.

## What bans and what only flags

| Rule | When | Result |
| --- | --- | --- |
| `economy_balance_mismatch` | A reported balance is above the ledger by more than the tolerance | Certain: automatic ban |
| `economy_no_source` | Money received with no source | Certain: automatic ban |
| `economy_unknown_source` | Money received from a source the studio does not have | Certain: automatic ban |
| `economy_over_limit` | Earnings from one source go over the studio's limit per hour or per day | Flag for review, never a ban |
| `economy_balance_short` | A reported balance is below the ledger: a spend was not reported | Flag for review, never a ban |

Bans go through the normal ban path: the account, and the device key of the player's
latest session if there is one, with a reference on the Bans page, where a reviewer can
lift it. With `-auto-ban=false` on the gateway the certain rules flag and mark the money
and ban nobody. Spending never bans, whatever its source.

The tolerance (default 0) and the limits per source and currency are set on the dashboard's
Economy page by an admin; the changes are in the audit log.

## Dirty money

Money that should not exist is marked dirty so the studio can remove it:

- in the cheater's own ledger: the unexplained part of the balance, or the money without a
  known source;
- on what others received from a banned player by `trade` or `drop`: what they received in
  the 30 days before the ban, and everything after it.

A receiver is never banned or flagged for it. The game server reads the amounts from
`GET /v1/economy/dirty`, takes the money back in the game, and reports that as an event
with a negative amount and the source `dirty_removal`, which clears the marks, oldest
first. Lifting a ban clears the marks it caused.

## Dashboard

The Economy page shows the flags, the dirty money list, the limits and tolerance, and a
player's ledger (click a player, or enter the account at the bottom).

## Try it

`carthago-econ-sim` plays a game server through four scenarios over the real API and prints
the outcome of each: honest play, injected money, farming over the limit, and a banned
player passing money on. With no flags it starts a gateway of its own on this PC with a
scratch database that is deleted when it stops; it touches nothing else.

```bat
cd /d "C:\Users\Ala Ghabi\anticheat\backend" && go run .\cmd\carthago-econ-sim
```

The last lines should be `RESULT: 4 of 4 scenarios passed` and the address of the
dashboard: `http://127.0.0.1:8761`, studio `demo`, key `demo-dashboard-key`, page Economy.
Ctrl+C stops it.

The demo key signs in as a reviewer, who sees everything and cannot change the limits. To
try changing them as an admin, run it with `-admin` and open the one-time link it prints:

```bat
cd /d "C:\Users\Ala Ghabi\anticheat\backend" && go run .\cmd\carthago-econ-sim -admin
```

Against a gateway that is already running (set a limit for `robbery` of 5 000 per hour on
its Economy page first, or scenario 3 reports a failure):

```bat
cd /d "C:\Users\Ala Ghabi\anticheat\backend" && go run .\cmd\carthago-econ-sim -gateway https://127.0.0.1:8750 -key demo-server-key
```

## Limits

- The ledger trusts the game server. It catches money that appears in a balance or arrives
  without a source; it cannot catch a game server that reports a false source.
- Dirty money is marked one step from the banned player. Money the receiver passed on
  again is not followed.
- Duplicated items show only as a balance above the ledger for that item's currency.
