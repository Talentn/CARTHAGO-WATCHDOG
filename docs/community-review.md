# Community review

A prototype. Players of the studio's game watch the recording of a suspicious match and
say what they saw. Several players review each case; when enough of them agree, the case
goes to the studio's own reviewers as advice. A player who reviews well earns levels and
badges, which the game server can read and reward.

It is off for every studio until an admin turns it on, and it decides nothing by itself: a
community verdict never bans, never ends a session, never puts anyone in the shadow pool
and is never something the Oracle learns from.

## How it works

**Cases.** A case is one player (the suspect) in one recorded match. With the feature on,
the gateway makes cases of what it already holds:

| Source | When |
| --- | --- |
| Oracle review flag | A session's Oracle score is in the Review band and names a match |
| Gameplay finding | Evidence from the server-side rules about the match, severity medium or above, not about a bot |
| Player reports | The open reports of the last 30 days about one player in one match, with the reporters' weights added up, reach the studio's threshold (default 1.0: two new reporters) |

A case needs the match to be recorded (`docs/match-replay.md`) with the suspect in it,
because the recording is all a reviewer gets. There is one case per match and suspect.
Cases are made when a game server asks for a link and when the Community page is opened.

**Reviewers are players, not dashboard users.** The gateway has no player accounts. The
studio's game server decides which player may review (account age, hours played, rank:
the studio's rule) and asks the gateway for a link for that player. The player opens the
link in a browser. The page is served by the gateway's game-server listener under
`/review/`, not by the dashboard: it shares no session, no cookie and no page with it.

**What the reviewer sees.** The match from above, in the same player the dashboard uses,
with play, pause, scrub and speed, and the map outline when the studio registered one.
The suspect is named "Suspect" and ringed. Everyone else is "Player 2", "Player 3" and so
on, in an order made up for that case. The page and the recording it loads hold no
account, session or device id, no match id, no map name, no wall-clock time, no finding,
no score, no report and no hint of why the match was picked. Bots stay marked as bots.

**Verdicts.** One of five, once per link, not changeable:

| Verdict | Counts as |
| --- | --- |
| Cheating: aim | cheating |
| Cheating: sees through walls | cheating |
| Cheating: something else | cheating |
| Toxic behaviour | toxic |
| Not enough evidence | insufficient |

**Assignment.** The gateway picks the case; the call takes a player and nothing else. A
reviewer is never handed:

- a match they played in, or a case where they are the suspect;
- a suspect they reported, in any match;
- a suspect they were handed before, or the same case twice.

Among the cases left, the one closest to its quorum goes first, then the oldest. A
reviewer who asks again before giving a verdict gets the same case again, with a new
expiry. A reviewer is handed at most 6 cases an hour and 20 a day.

**Closing.** A case closes when a set number of reviewers have given a verdict (default
5). Each verdict counts with the reviewer's weight at that moment. If the answer with the
most weight behind it (cheating, toxic or insufficient) has at least the agreement
threshold of the total weight (default 70%), the case is **decided** with that answer;
otherwise it is **undecided**. For a cheating answer the kind with the most weight is
shown too.

**The studio decides.** A decided case appears on the Community page of the dashboard with
the vote split and a link to the full replay (with names and findings, for the studio's
reviewer). The reviewer presses Confirm or Dismiss. That records the studio's conclusion
in the audit log and scores the players who voted. It does nothing to the suspect: a ban
stays the reviewer's own action on the player's page, as before.

**Standing.** A verdict is scored when its answer is known:

- on a real case, when the studio confirms or dismisses it. Confirmed: those who gave the
  case's answer were right, the others wrong. Dismissed: those who gave the case's answer
  were wrong, those who said "not enough evidence" were right, the rest are not scored;
- on a **calibration case**, at once. A calibration case is a recorded match and a player
  whose answer the studio already knows. It looks like any other case and is handed out
  among the real ones: a reviewer's first case is one, then about one in four, and every
  case of a reviewer whose weight is below 0.50. Calibration cases never close and never
  reach the studio's queue.

Accuracy is correct / scored. Weight is (correct + 1) / (scored + 2): a new reviewer
starts at 0.50, three right answers in a row give 0.80, three wrong ones 0.20. A reviewer
whose weight is below 0.25 with at least 3 scored verdicts is **not eligible**: the
gateway hands them no more cases. Undecided cases score nobody.

**Levels and badges** come from the number of correct verdicts:

| Correct verdicts | Level | Badge |
| --- | --- | --- |
| 1 | Reviewer | `first_correct_verdict` |
| 5 | Investigator | `investigator` |
| 25 | Senior investigator | `senior_investigator` |
| 100 | Veteran | `veteran` |

## Turning it on

Community page of the dashboard, Settings card (admin role): the switch, how many verdicts
close a case (3 to 25), the agreement that decides it (50 to 100%), and the report weight
that makes a case (0.5 to 20). The change is in the audit log (`community.settings`).

Add calibration cases on the Calibration tab of the same page (reviewer role): the match
id as on its replay page, the player, and the known answer. Add cases of both kinds:
players you know cheated or spoiled a match, and players you know played fairly. With
only fair players as calibration cases, a reviewer who always answers "not enough
evidence" passes every one of them.

On the gateway, `-review-url https://ac.example.com` sets the public address review links
start with (without it, links use the address the game server called), and
`-review-link-ttl` how long a link works (default 30 minutes). The key that signs links
is `review.key` in the gateway's data folder, created on first start and separate from
every other key.

## The game-server calls

All four carry the studio's server key, `Authorization: Bearer <server key>`, and read
and write that studio only. Bodies and answers are JSON; an unknown field is refused.

### Ask for a review link

```bash
curl -X POST -H "Authorization: Bearer $SERVER_KEY" \
  -d '{"player":"account-id"}' https://ac.example.com/v1/review/links
```

```json
{"status":"assigned","url":"https://ac.example.com/review/v1.ZGVtbw.f.toogwb.jFlGvEcg__uT48lAc1z9Yf28rjzTz9__An_8jfL6XDE","expires_ms":1794971531780}
```

`player` is the same player id the anti-cheat client and `/v1/gs` use. Show the `url` to
that player only (a button that opens the browser). The answer never says which match or
player the link is about.

| Answer | Meaning |
| --- | --- |
| 201 `"status":"assigned"` | A link for that player |
| 200 `"status":"none"` | No case this player may review right now |
| 403 `"status":"off"` | The studio has community review off |
| 403 `"status":"not_eligible"` | The player's verdicts were wrong too often |
| 429 with `Retry-After` | The player was handed 6 cases this hour or 20 today |
| 400 | No player, or a body that is not what the call takes |

### Read a player's standing

```bash
curl -H "Authorization: Bearer $SERVER_KEY" \
  "https://ac.example.com/v1/review/standing?player=account-id"
```

```json
{"player":"lina","verdicts":2,"scored":1,"correct":1,"accuracy":1,"weight":0.6666666666666666,
 "level":1,"level_name":"Reviewer","eligible":true,
 "badges":[{"badge":"first_correct_verdict","earned_ms":1794928192268,"new":false}]}
```

A player who never reviewed has weight 0.5, level 0 ("New") and no badges.

### Read the badges not rewarded yet

```bash
curl -H "Authorization: Bearer $SERVER_KEY" https://ac.example.com/v1/review/badges
```

```json
{"badges":[{"player":"lina","badge":"first_correct_verdict","earned_ms":1794928192268,"new":true}]}
```

The badges the game server has not acknowledged, oldest first, at most 500. Poll it, for
example once a minute.

### Acknowledge badges

```bash
curl -X POST -H "Authorization: Bearer $SERVER_KEY" \
  -d '{"player":"lina","badges":["first_correct_verdict"]}' \
  https://ac.example.com/v1/review/badges/ack
```

```json
{"acknowledged":1}
```

After this the badge is no longer listed as new. A badge acknowledged before counts as 0,
so the call can be sent again after a failure.

## Rewards and the economy ledger

The gateway grants nothing in the game. The studio decides what a badge is worth (a
title, a skin, currency) and its game server grants it.

If the reward is money or an item and the studio uses the economy ledger
(`docs/economy-ledger.md`), the grant must be reported like every other change, or the
ledger will see a balance it cannot explain and ban the reviewer:

1. Once, on the Economy page: give the source `review_reward` a limit per hour and per
   day. A source without a limit is unknown to the ledger, and money from an unknown
   source is certain evidence (`economy_unknown_source`).
2. For each new badge, grant the reward in the game and report it, with an event id made
   from the badge so that a repeated call changes nothing:

```json
{"events":[{"event_id":"review-badge:lina:first_correct_verdict","player":"lina",
  "currency":"money","amount":500,"source":"review_reward","at_ms":1794928200000}]}
```

3. Then acknowledge the badge. If the game server stops between 2 and 3, it reads the
   badge as new again, sends the same event id (answered `duplicate`) and acknowledges.

This order has not been run end to end against the ledger; the demo acknowledges badges
without granting anything.

## Privacy

- **Players see other players' matches.** A reviewer watches the positions, view
  directions and shots of every player of a match, with the names replaced. The studio's
  EULA and privacy notice must say that recordings of matches may be shown, without
  names, to other players for review. Without that, do not turn this on.
- Names are hidden, not the play. A reviewer who was told about the match, who knows the
  map and the suspect's habits, or who recognises a friend's style can still guess who it
  is. The recording is the whole match, not an excerpt.
- The gateway keeps, per studio: which player was handed which case and when, the
  verdict, and the badges. That ties a reviewer's player id to a suspect's. It is shown
  to signed-in dashboard users of that studio only. Nothing deletes it yet: there is no
  retention period and no command to delete or export one player's reviews; until there
  is, that is a manual `DELETE` on `review_assignments` and `review_badges`.
- The suspect is not told that a case exists, and reviewers are not told how a case
  ended.
- The link holds the studio's id at the gateway (encoded, not encrypted) and the number of
  the assignment. A player who decodes it learns those two things and nothing about the
  case.

## Security

- **The link is the key.** It names one assignment (one reviewer, one case), is signed
  with HMAC-SHA-256 under `review.key`, and carries its expiry inside the signature. It
  opens that case's page and recording, takes one verdict, and nothing else. After the
  verdict, after the expiry, after the case closed or after the studio turned the feature
  off it shows a message and no recording.
- **Nothing to enumerate.** There is no list, no search and no case or match number in
  any address. Every address under `/review/` that is not a valid link gets the same 404
  page, whether the link was forged, cut, expired or never existed.
- **Strict CSP**, as on the match page: `default-src 'none'`, scripts, styles and
  pictures from the page's own origin only, no inline script or style, `form-action
  'self'`, `frame-ancestors 'none'`. Also `Referrer-Policy: no-referrer` (the link must
  not travel to another site), `Cache-Control: no-store`, `X-Robots-Tag: noindex`, and no
  cookie at all.
- **Verdict form.** A post that the browser marks as coming from another site is refused.
- **Per studio.** The link's studio is part of what is signed; cases, assignments,
  standing and badges are read and written under the studio of the server key or the
  dashboard session. Another studio's admin cannot see or decide a case.
- **Dashboard.** Read-only users see both pages. Confirm, Dismiss and adding a
  calibration case need the reviewer role; the settings need the admin role. Each change
  is in the audit log: `community.settings`, `community.confirmed`,
  `community.dismissed`, `community.calibration`.
- **Serve it over HTTPS.** Anyone who sees the link can give that reviewer's verdict.

## Abuse it covers

| Abuse | What stops it |
| --- | --- |
| Choosing which case to judge (a rival, a friend) | The gateway assigns; the call and the page take no case or match |
| Judging a match you played, a player you reported, or the same player again | Never assigned |
| Voting many times | One verdict per link; a second is refused; one assignment per reviewer and case |
| Flooding with verdicts from one account | 6 cases an hour, 20 a day |
| Forged, altered, reused or old links | Signature, expiry, single verdict, one 404 for all |
| Looking for other cases or matches from the page | Nothing to list; no ids in addresses |
| A careless reviewer, or one who convicts everyone | Calibration cases: weight drops with each wrong answer, the next cases are calibration cases only, then no more cases |
| A new account outvoting experienced reviewers | A new reviewer weighs 0.50, the first case is a calibration case, and agreement is by weight, not by head count |
| Judging by reputation instead of play | Names, ids, findings, scores and reports are not shown |
| A community verdict becoming a punishment | It is a row on a dashboard page. Nothing that bans, kicks, pools or trains reads it |

## Abuse it does not cover

- **Groups voting together.** Five friends with good standing can each ask for a link
  until they hold the same case, and agree on an answer. The gateway does not know who
  plays with whom. The studio's reviewer confirming each case is the only check, and the
  studio should not ask for links for the party or clan of a suspect or reporter.
- **Many accounts of one person.** Eligibility is the studio's: the gateway accepts any
  player id the game server names.
- **Passing the link on.** The link is not tied to the player's game session or device.
  Whoever opens it gives the verdict.
- **Learning the calibration cases.** They never close and every reviewer gets them from
  the same pool, so players who compare notes can learn the answers. The same match can
  also come up twice with a different suspect. Rotating the pool is manual.
- **Recognising the players** from the map, the positions or the style of play, as said
  under Privacy.
- **Always answering "not enough evidence"** costs weight only on cases the studio
  confirms and on calibration cases of cheaters.
- **A reviewer with a grudge the gateway cannot see**: someone the suspect reported, a
  former teammate, a banned player. Only "reported the suspect" and "played in the match"
  are checked.
- **The studio's own mistakes.** Standing follows what the studio's reviewers decide. A
  studio that confirms everything teaches reviewers to convict.

## See it

```bash
cd backend && go run ./cmd/carthago-demo
```

Chapter 10 turns the feature on for the demo studio. sami's match from chapter 2 is a
case; a second report about walid makes another. karim, who calls everyone a cheater,
answers three calibration cases wrong (weight 0.50, 0.33, 0.25, 0.20) and is refused a
fourth link. Five other players each answer a calibration case right and then review
sami's match: three say sees through walls, one aim, one not enough evidence, and the
case closes as decided with 80% agreement. Nothing happens to sami. The demo then prints
a review link for a player called "ala" to open in a browser, and the `curl` line for the
next one. The decided case waits on `/community` for Confirm or Dismiss; the reviewers are
on `/community/reviewers`.

The reviewers of the demo are simulated: the demo asks for their links, loads the page
and the recording over HTTP and posts the verdicts. No person watched anything.

## Limits and what is untested

- No real game has asked for a link and no real player has reviewed a match. Whether
  players can judge a top-down replay of a whole match, and how long they will watch, is
  unknown. The replay cannot be cut to an excerpt or point at a moment.
- The page was opened in headless Chrome on Linux only: not on Windows, not on a phone,
  not by a person.
- "Toxic behaviour" means what the play shows. There is no chat or voice in a recording.
- More reviewers than the quorum can hold the same case at once. Those who answer after
  it closed are told the review is closed and their time is lost.
- A case is made only from a recorded match. Sessions flagged on client evidence alone
  have nothing to watch and never become cases.
- Votes arriving at the same moment were not tested against SQLite under load.
- The rate limits (6 an hour, 20 a day), the weight below which a reviewer is not
  eligible (0.25 after 3 scored verdicts), the calibration share (one in four) and the
  levels are fixed in the code, not settings.
- Changing the quorum or the threshold applies to open cases at their next verdict.
- An undecided case cannot be decided by the studio from the Community page and scores
  nobody. A decision can be changed (confirmed to dismissed and back); the reviewers are
  scored again each time, but a badge once earned stays.
- The Community page lists the newest 200 cases of a tab, without paging, search or a
  page per case showing each verdict.
- Deleting `review.key` makes every outstanding link invalid. There is no key rotation.
- Review data has no retention period (see Privacy).
- The reward path through the economy ledger is described above and not run.

What the tests check (`go test ./internal/review ./internal/gateway ./internal/dashboard
./internal/store`): the three case sources and the switch; every assignment rule and the
rate limit; quorum, weighted agreement, decided and undecided; scoring on confirm and on
dismiss; calibration taking a careless reviewer's eligibility; forged, altered, expired
and reused links; that the page and the recording hold no player, session, match or map
name, finding or report text; the CSP and the other headers; roles, form token, audit
entries and studio isolation on the dashboard and the API; and that a full review, a
confirmation and a dismissal leave bans, the shadow pool, evidence, Oracle scores and
Oracle labels exactly as they were.
