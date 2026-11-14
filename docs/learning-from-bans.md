# Learning from bans

Every ban on certain evidence teaches the product two things: which sessions were a
cheater's, for the Oracle's training data, and which files only cheaters load, for the list
of known cheats. Both stay inside one studio. Nothing here bans anybody by itself, and no
file is put on the list without a reviewer.

## Ban labels

When a ban is placed on a certain finding, the session it was made from and the banned
account's other sessions of the last 30 days get the label "confirmed cheat" in the same
store as the reviewer labels, with the source `ban` and the ban's reference. On the session
page the label card shows it as set by `ban CW-XXXX-XXXX`.

- An automatic ban always labels: it is only ever made on a rule of the certain tier.
- A ban a person makes on the dashboard labels when the session it was made from holds
  certain evidence (a certain-tier integrity finding of high severity). A ban on judgement
  alone labels nothing; the reviewer can label the session by hand.
- A session that already has a label keeps it. A label a reviewer sets later replaces the
  ban's and is the reviewer's from then on.
- Lifting the ban, on the dashboard or with `carthago-gateway bans lift`, removes the labels
  that ban made and no others. Every change is in the label history of the session.
- There are no automatic "clean" labels. A session is only called clean by a reviewer.

## Training on real labels

`carthago-oracle export` writes the labelled sessions of a studio, from reviewers and from
bans, and `carthago-oracle train -labelled` adds them to the synthetic sessions and says how
many it used (here on a small trial run, `-matches 8`):

```
real labels used: 6 (6 from bans, 0 from reviewers): 6 cheating, 0 clean, next to 96 synthetic sessions (behaviour.jsonl)
```

The bundle's manifest records the same. `carthago-oracle eval -labelled` checks a bundle on
them. The export no longer needs the Oracle to have run first: if the data directory has no
pseudonym key yet, it creates the one the Oracle will use.

## Proposed known cheats

From the file hashes the sessions already report, the gateway works out which files only
banned accounts load. A file is proposed when all of this holds:

- it is not validly signed (not signed, changed after signing, untrusted signer or expired
  certificate);
- it is outside the Windows folder (files under it are not in this evidence at all);
- at least N distinct accounts with a standing ban loaded it; N is the studio's setting,
  2 by default;
- no account without a standing ban loaded it, in any session;
- it is not on the list of known cheats and was not dismissed.

Proposals are on the dashboard's Known cheats page under "Proposed", with the names the
file was loaded under and the counts. A reviewer approves one (it is added to the list
under the name the reviewer gives, with the counts in its note) or dismisses it (it is not
proposed again). Both are in the audit log. An admin sets N on the same page.

On the command line, against the gateway's data directory, running or not:

```
carthago-gateway cheats proposed -tenant demo -data <dir>
carthago-gateway cheats propose-after -tenant demo -accounts 1 -data <dir>
```

In the CS 1.6 kit, `-ProposeAfter 1` sets N for the local test gateway.

With a shadow period set, a caught player is not banned at once and the same learning
starts at entry into the pool, with labels of source `shadow`. See `docs/shadow-pool.md`.

## Limits

- A ban says the account cheated, not that every one of its sessions of the last 30 days
  shows it. Labels from bans are noisier than a reviewer's, and they are all "cheating":
  the clean side of the training data is still the simulator and the reviewers.
- While no account that is not banned has reported its files, the game's own unsigned
  files look like a cheat's: only banned accounts load them. The page says so in red. With
  one PC and one test account, expect the whole unsigned part of the game on the list.
- A cheat that is validly signed, or sits under the Windows folder, is never proposed.
- The proposals are worked out from the stored module evidence each time the page is
  opened. That is fine for a test and for a small studio; a large one needs it kept as a
  table.
