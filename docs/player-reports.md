# Player reports

A game with a report button can pass each report on to the gateway. The dashboard collects
them in a queue for reviewers, counts them per player and links each one to the replay at
the moment it is about. A report is what one player said about another: it is advice for a
reviewer and decides nothing.

## What it does

- **A report** names the reporter, the reported player, the match, optionally the moment,
  a reason from a fixed list (`cheating`, `toxic_behaviour`, `griefing`, `other`) and an
  optional note of at most 280 characters.
- **No spam.** A reporter has one report per reported player and match: sending it again
  changes nothing and is answered as a duplicate. A reporter may make 6 reports an hour and
  20 a day; more are refused with HTTP 429. A report with anything the gateway does not
  expect (unknown field, reason outside the list, note too long, control characters) is
  refused whole, never cut to fit.
- **Queue.** Reports, in the dashboard's navigation: tabs Open, Reviewed and Dismissed. A
  reviewer marks a report reviewed, dismisses it or opens it again; each change is in the
  audit log (`report.review`, `report.dismiss`, `report.reopen`). Read-only users can
  look; changing needs the reviewer role.
- **Counts.** The player's page has a "Reports by players" card and the players list a
  "Reports" column: reports in the last 30 days and how many different players made them.
  Dismissed reports are not counted.
- **Replay.** When the match was recorded (`docs/match-replay.md`), the report links to
  the replay at the reported moment with the reported player highlighted.
- **Reporter weight.** Next to each report: how the reporter's earlier reports turned out,
  as (confirmed + 1) / (confirmed + dismissed + 2). Confirmed means the reported player has
  a standing ban or a session a reviewer labelled a confirmed cheat. A new reporter starts
  at 0.50; reports without an outcome yet do not count either way. The weight is shown, not
  used: it does not sort, hide or auto-dismiss anything.
- **Advisory only.** Reports are kept in a table of their own (`player_reports`) that only
  the dashboard reads. The code that computes risk, runs the rules, bans, fills the shadow
  pool, and the Oracle and its baseline never read it, and setting a report's state changes
  the report and the audit log and nothing else.
- **Per studio.** The server key decides the studio a report belongs to. Another studio
  can neither see nor change it.

## The note is personal data

The note is free text typed by a player, and the report ties two player identifiers to
each other. Treat both as personal data of the studio's players:

- the note is stored as sent (whitespace collapsed), shown to signed-in dashboard users of
  that studio only, and never written to the gateway's log or the audit log;
- a report is deleted 90 days after it was received (when the next report arrives);
- there is no command yet to delete or export one player's reports on request: until
  there is, that is a manual `DELETE` on `player_reports` in the gateway's database.

## What the game server must send

One HTTP call per report, to the same address and with the same server key as the other
game-server calls (`/v1/ingest`, `/v1/shadow`, `/v1/economy`):

```
curl -X POST http://127.0.0.1:8790/v1/reports \
  -H "Authorization: Bearer $CARTHAGO_SERVER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reporter":"chiraz","reported":"sami","match":"ranked-yard-0001","tick":41280,"tick_rate":64,"reason":"cheating","note":"he was already aiming at the corner before I came round it"}'
```

| Field | |
| --- | --- |
| `reporter`, `reported` | the player identifiers the game server uses everywhere else (1 to 128 bytes); they must differ |
| `match` | the `match_id` of the match's telemetry |
| `tick` with `tick_rate` | the moment, as in the match's telemetry; or |
| `time_ms` | the moment in milliseconds from tick 0 of the match. Leave both out for a report about no particular moment |
| `reason` | `cheating`, `toxic_behaviour`, `griefing` or `other` |
| `note` | optional, at most 280 characters |

Answers: `201 {"id":7,"status":"accepted"}`; `200 {"id":7,"status":"duplicate"}` for a
repeat; `400 {"error":"..."}` for a report it does not take; `401` without the server
key; `429` with `Retry-After` (seconds) when the reporter has made too many.

## See it

```
cd backend
go run ./cmd/carthago-demo
```

Chapter 9: the simulated game server sends two reports about `sami` (the wallhack suspect
of chapter 2), one about `walid` (the player of chapter 8) and one about `zied` (banned in
chapter 3, which gives its reporter a weight of 0.67). Sign in with the demo login and open

```
http://127.0.0.1:8791/reports
http://127.0.0.1:8791/players/sami
```

Click "Replay at" on a report, or Reviewed or Dismiss. While the demo runs you can send
your own (the demo's server key is `demo-server-key`, its API on port 8790).

Tests: `go test ./internal/reports ./internal/store ./internal/gateway ./internal/dashboard`.

## Limits and what is untested

- No real game has sent a report. The demo's reports come from its simulated game server.
  The Windows sample game is a client only and has no report button.
- The gateway trusts the game server about who the reporter is, as it does for every
  game-server call. It does not check that either player was in the match, or that the
  match exists.
- The weight looks at the newest 1000 bans and 1000 labels of the studio and at up to 1000
  reports of the reporter. A report counts as confirmed when the reported player is banned
  for any reason at any time, not only for what was reported.
- The players list shows players with sessions or evidence; a player known only from a
  report is reached from the queue. The list is not sorted by reports.
- The queue shows the newest 100 reports of a tab, without paging or search.
- The limits (6 an hour, 20 a day, 280 characters, 90 days) are fixed in the code, not
  settings of the studio.
- There is one report per call; there is no batch call and no way to withdraw a report.
- Deleting or exporting one player's reports on request is manual (see above).
- Tried in headless Chrome on Linux only; not on Windows, not by a person.
