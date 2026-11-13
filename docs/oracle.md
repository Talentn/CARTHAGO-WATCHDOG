# Carthago Oracle

Carthago Oracle is the gateway's own AI detection engine. It runs on the gateway host only.
Nothing of it is in the client, the SDK or the game server, and no message to a client or a
game server changes because of it.

It has three parts:

1. **Behaviour model.** A learned model that scores every session from 0 to 100 using the
   numbers the pipeline already computes: aim, reaction and input statistics of the session's
   matches, the information-leak and decoy scores, the client integrity evidence and the trust
   level. Inference is a few table lookups in pure Go.
2. **Analyst.** For a session the rules or the model flag, the Oracle builds a compact case
   file and asks a small language model, running on the gateway host, for a structured
   opinion: the likely kind of cheat, a confidence, the evidence rows it relies on, a
   recommended action and a one-paragraph summary.
3. **Reviewer labels.** A reviewer marks a session as confirmed cheat, cleared or unsure on
   the dashboard. Labels are the ground truth the two models can later be tuned on.

**The Oracle is advisory.** It writes scores, opinions and labels to the store and the
dashboard shows them beside the hard evidence. It cannot add evidence, change a player's risk,
kick, ban or send anything to a client: the pipeline hands it copies of its numbers through a
one-way observer, and the engine holds no reference to the kick channel. A label never kicks
or bans either.

## Quick start

```bash
# 1. Train a behaviour model on synthetic sessions and write a bundle (about 8 minutes on 4 cores).
cd backend
go run ./cmd/carthago-oracle train -seed <a number of your own> -out ../oracle-bundle

# 2. Optional: fetch the analyst's runtime and model (1.2 GB) to a per-user folder outside the repository.
../tools/carthago-oracle-fetch.sh                        # Linux
powershell -ExecutionPolicy Bypass -File ..\tools\carthago-oracle-fetch.ps1   # Windows

# 3. Run the gateway with the bundle.
go run ./cmd/carthago-gateway -oracle-dir ../oracle-bundle
#   level=INFO msg="Carthago Oracle ready" bundle=cb-… behaviour_model=cob-… analyst=local …
```

Without a bundle the gateway runs exactly as before and logs `Carthago Oracle off: no
bundle`. With a bundle but without the fetched runtime it scores sessions and logs `Carthago
Oracle analyst off: sessions are scored, no opinions are written`, with the reason.
`-oracle-analyst stub` gives a deterministic rule-based analyst that needs no model and no
network; the tests and the check script use it.

`tools/carthago-oracle-check.sh` runs the whole thing end to end on Linux with synthetic
traffic (about three minutes; add `--local` to use the fetched model instead of the stub).

## How a session is handled

1. The pipeline analyses heartbeats and gameplay as before and stores its evidence.
2. After each heartbeat and each finished match it tells the Oracle through
   `pipeline.Observer`. That call is a non-blocking send on a bounded queue (4,096 entries);
   when the queue is full the event is dropped and counted, and the pipeline carries on.
3. On its own goroutine the Oracle builds the session's feature vector, scores it, and stores
   the score, its band (`clear`, `watch`, `review`) and the five signals that moved the score
   most. A session is scored when its match ends, when new evidence arrives, and at most once
   a minute otherwise.
4. A session becomes a **case** when the rules stored evidence of medium severity or above,
   or when the model puts it in the review band. By default the case waits until the session
   has ended (kicked, closed, or silent for two minutes; `-oracle-ended-after`), because the
   gateway may share a PC with the game. `-oracle-review-live` reviews connected sessions too.
   (The gateway records a session whose client stopped sending heartbeats as "kicked" with
   the reason `heartbeat_timeout`. That is its ordinary end-of-session record and was there
   before the Oracle; it is not an Oracle action.)
5. Cases are reviewed one at a time. The verdict is checked, stored and shown on the
   session page as "Analyst opinion" with links to the evidence rows it cites. A case that
   could not be judged is stored with the reason, and the evidence stands on its own.

## The bundle

Everything the Oracle decides with lives in one directory, the bundle:

| File | Content |
| --- | --- |
| `manifest.json` | Bundle id; behaviour-model id, feature version and SHA-256; the watch and review thresholds; analyst prompt version, schema version and SHA-256 of both prompts; the local analyst model's id, file name, SHA-256 and context size; how the model was trained |
| `behaviour-model.json` | The behaviour model: one curve per signal |
| `prompts/system.txt`, `prompts/case.txt` | The analyst's instructions and the case template |

The gateway verifies every hash at startup and refuses a bundle that does not match its
manifest (`Carthago Oracle off: the bundle failed its checks`). The startup line names the
bundle id, the behaviour-model id, the feature version, the analyst and the prompt version, so
an operator can tell from the log which Oracle is running. The dashboard shows the same ids.

`carthago-oracle info -bundle DIR` prints a bundle. `carthago-oracle set -bundle DIR …`
changes its thresholds, its prompt version or the analyst model it names and rewrites the
manifest. The model path and the prompt version are configuration, not code.

## Behaviour model

**Form.** An additive model: one monotone step curve per signal, summed and passed through a
logistic function. A signal declared "more is more suspicious" can only raise the score, so a
player cannot lower a score by producing more of it. A signal that is unknown (a session that
played no match) has a value of its own instead of an assumed average. The contribution of
each signal to a score is exact, which is what the dashboard's "Top signals" shows.

**Signals** (feature version 1): aim snaps per minute, headshot rate against the player's
rating, reaction time and reaction time against the lobby, command rate, trigger rhythm,
information-leak score, decoy-reaction score, client integrity findings and their worst
severity, clock evidence, injected-input share, other client findings, scanner gaps, trust
level. The four signals that describe the player's PC rather than what the player did (trust
level, other client findings, injected input, scanner gaps) are capped at ±0.3 log-odds each:
they can shade a score and never decide it, so a player without a TPM is not flagged for that.

**Training.** `carthago-oracle train` simulates matches with the repository's simulator, runs
them through the real pipeline, and fits the model by gradient boosting of one-cut trees
(300 rounds). Sessions are split by match: three fifths to fit, one fifth to choose the
thresholds, one fifth to test. The watch and review thresholds are the scores that 5% and
0.5% of the held-out honest sessions reach. The same seed gives the same bundle bit for bit on
the same CPU architecture.

**Evaluation of the reference model** (seed 1, 500 synthetic matches, 6,000 sessions; numbers
are for the 1,200 held-out sessions, 827 honest and 373 cheating):

| Measure | Value |
| --- | --- |
| AUC | 0.9965 |
| Brier score, log loss | 0.0273, 0.1067 |
| Honest sessions in the review band | 6 of 827 (0.7%; 95% upper bound 1.4%) |
| Honest sessions in the watch band or above | 33 of 827 (4.0%; bound 5.3%) |
| Honest sessions with rule evidence of medium severity or above | 17 of 827 (2.1%; bound 3.1%) |
| Cheating sessions in the review band | 323 of 373 (86.6%) |
| Cheating sessions in the watch band or above | 98.1% |
| Cheating sessions the rules alone flag | 80.4% |
| Cheating sessions in review or flagged by the rules | 90.9% |
| Sessions without a match: honest in review, cheating in review | 0 of 141, 57 of 59 |

Share of each cheating profile in the review band: blatant aim 100%, subtle aim 74%, trigger
100%, information 100%, subtle information 89%, speed 100%, subtle speed 26%, macro 100%,
subtle macro 69%, tampering 95%, clock 83%, mixed 100%.

**What these numbers do not show.** Every session above is synthetic. The honest players and
the cheats are distributions written by hand in `internal/oracle/train/dataset.go`, and the
model learns exactly those. The numbers show that the model and the pipeline work together
and how the model trades recall for false flags on that data. They say nothing certain about
real players, real cheats or a real game, and the false-flag bounds are bounds on synthetic
honest players only. An earlier version of the synthetic players all took about 625 ms to land
a first hit; the model trained on them put an ordinary player with a 280 ms reaction in the
review band. The current data gives every honest player a reaction time and a clock drift of
their own, and that case is now in the check script. Expect more such gaps until the model is
tuned on labelled sessions of the actual game. Until then, treat a score as a reason to look,
never as proof.

## Analyst

**Case file.** JSON, schema version 1, built by the gateway from the store: pseudonyms for
the session and the player, the model's score, band and top signals, the trust level, and the
16 most severe evidence rows (the rest are counted), each with an id (`E1`, `E2`, …), the rule's name, its family, severity,
confidence, a weight (`strong`, `weak` or `context`) and, for cheat families, the kind of
cheat it points to. Every string in a case file comes from a fixed vocabulary in the gateway.

**What never enters a case file.** Player names, chat, player ids, device ids, IP addresses,
file paths, module names, window titles and any other string a client supplied. The player
and session ids are replaced by pseudonyms (`P-…`, `S-…`), an HMAC under a key that stays on
the gateway (`<data>/oracle-pseudonym.key`, mode 0600). The gateway checks each case against
the vocabulary before it is sent and refuses one that fails (`case_rejected`). This is the
defence against prompt injection: a cheater controls what the client reports, and none of it
reaches the model as text. A test fills every client-supplied field with instructions
("ignore all previous…", "recommend a ban", a URL) and checks that nothing of it is in what
the provider is sent. The summary that comes back is checked and HTML-escaped before it is
shown, so a model cannot inject markup into the dashboard either.

**Verdict.** The model must answer with one JSON object: `cheat_type` (none, aim assistance,
wallhack or other hidden information, input automation, speed or clock manipulation, client
tampering, mixed, inconclusive), `confidence` (0 to 100), `cited_evidence` (ids from the case
file), `recommended_action` (none, monitor, manual review, priority review) and `summary`. The gateway
parses it strictly: unknown fields, unknown values, an id that is not in the case, a named
cheat without cited evidence, or "priority review" for "none" all fail the check. The summary
is reduced to letters, digits and plain punctuation and capped in length. One retry, then the
case is stored as `invalid_output`. With the local runtime the
output is also constrained to the schema while it is generated.

**Limits per studio.** 30 cases an hour, 200 cases a day and 400,000 tokens a day by default
(`-oracle-cases-per-hour`, `-oracle-cases-per-day`, `-oracle-tokens-per-day`); two minutes per
case (`-oracle-timeout`). A verdict is cached under the hash of the case, the prompt version
and the model, so an unchanged session is never judged twice. A failed case is retried after
ten minutes at the earliest.

**Providers** (`-oracle-analyst`):

| Value | What runs | Data leaves the host |
| --- | --- | --- |
| `auto` (default) | `local` when the runtime and model are installed, otherwise off | No |
| `local` | The fetched model under llama.cpp, started and stopped by the gateway | No |
| `stub` | Deterministic rules over the case file; no model | No |
| `openai` | Any OpenAI-compatible HTTP endpoint | Yes |
| `anthropic` | The Anthropic Messages API | Yes |
| `off` | Nothing; sessions are still scored | No |

The hosted providers are off unless `CARTHAGO_ORACLE_API_KEY` is set, and the key, the
endpoint (`CARTHAGO_ORACLE_ENDPOINT`) and the model name (`CARTHAGO_ORACLE_MODEL`) are read
from the environment only. Sending case files to a hosted provider is an opt-in per studio:
`-oracle-external-tenant <id>`. Without it that studio's cases are stored as
`external_not_allowed` and nothing is sent.

## The local model

**Runtime.** The gateway owns the life cycle of a `llama-server` process (llama.cpp, MIT):

- started on demand when the first case arrives, stopped after 90 s without one, so it uses
  no CPU and no memory while nothing is under review;
- bound to 127.0.0.1 on a free port, with a random API key per start passed in the
  environment, no web UI, no network access for the model;
- the model file's SHA-256 is checked against the bundle before each start;
- a thread cap (`-oracle-threads`; default half the CPUs, at most 4) and below-normal
  priority (nice 10 on Linux, `BELOW_NORMAL_PRIORITY_CLASS` on Windows), so the game and the
  gateway's own work always come first;
- one case at a time, from a queue of 64; a full queue leaves cases for a later sweep;
- the child's environment carries none of the gateway's `CARTHAGO_*` settings, and it dies
  with the gateway (parent-death signal on Linux, kill-on-close job on Windows).

**Choice of model.** Six openly licensed small models were run on the same 56 synthetic case
files (36 flagged cheating sessions, three of each profile; 16 honest sessions the rules or
the model flagged by mistake; 4 honest sessions with nothing against them), with the same
prompt, on 3 threads of a 4-vCPU Xeon without a GPU. The cases come from the calibration
split, which was not looked at while the prompt was written.

| Analyst | Licence | File | Answers that passed the check | Kind right | Cheating kept for review | Honest flagged, accused | Honest clean, accused | Median time per case | Peak memory |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Stub (rules, no model) | – | – | 56/56 | 30/36 | 36/36 | 8/16 | 0/4 | under 1 ms | – |
| Qwen2.5-0.5B-Instruct | Apache-2.0 | 0.49 GB | 45/56 | 17/36 | 27/36 | 13/16 | 2/4 | 3.2 s | 0.75 GB |
| **Qwen2.5-1.5B-Instruct** | Apache-2.0 | 1.12 GB | 56/56 | 29/36 | 35/36 | 10/16 | 1/4 | 4.9 s | 2.05 GB |
| Granite 3.3 2B Instruct | Apache-2.0 | 1.55 GB | 55/56 | 27/36 | 35/36 | 13/16 | 1/4 | 12.2 s | 3.24 GB |
| Phi-3.5-mini-instruct | MIT | 2.39 GB | 0/56 | – | – | – | – | – | 5.98 GB |
| Phi-4-mini-instruct | MIT | 2.49 GB | 55/56 | 25/36 | 32/36 | 8/16 | 1/4 | 11.7 s | 5.32 GB |
| Qwen3-4B | Apache-2.0 | 2.50 GB | 56/56 | 31/36 | 33/36 | 9/16 | 1/4 | 12.0 s | 5.40 GB |

All model files are 4-bit quantisations (`Q4_K_M`); sources and revisions are in
`THIRD-PARTY-NOTICES.md`. Phi-3.5-mini failed every request: this llama.cpp release cannot
build the output grammar for that file ("Failed to initialize samplers"), which says nothing
about the model itself. Qwen2.5-3B-Instruct was not measured because its licence does not
allow commercial use. Other work ran on the machine during parts of the run, so read the
times as accurate to about a fifth.

"Kind right" counts the true kind, and also client tampering or mixed when the case holds
tampering evidence of high or critical severity, since a synthetic aim cheat that also left a
loader is correctly described either way. "Honest flagged, accused" is a session the rules
flagged by mistake for which the analyst still named a cheat. Memory is the peak resident
size of the runtime on the test machine (see the note under Performance).

**Winner: Qwen2.5-1.5B-Instruct (4-bit GGUF, Apache-2.0).** It is within two cases of the
most accurate candidate at 40% of its time and memory, and every answer passed the output
check. It is the model the fetch scripts download and new bundles name. Qwen3-4B is the
alternative for a gateway on its own machine: `carthago-oracle set -bundle DIR
-local-model-id … -local-model-file … -local-model-sha256 …` switches a bundle to it.

The table above was measured on case files from the first version of the synthetic data. The
winner and the stub were measured again on the reference bundle's final data (again 56 cases
from the calibration split), at the default thread cap of this machine (2 threads) and with
nothing else running:

| Analyst | Answers that passed the check | Kind right | Cheating kept for review | Honest flagged, accused | Honest clean, accused | Median, 90th percentile, first case | Peak memory |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Stub (rules, no model) | 56/56 | 25/36 | 36/36 | 7/16 | 0/4 | under 1 ms | – |
| Qwen2.5-1.5B-Instruct | 56/56 | 21/36 | 36/36 | 9/16 | 0/4 | 6.7 s, 8.4 s, 11.9 s | 2.05 GB |

A case is about 1,030 tokens in and 70 out. The first case includes loading the model.

**What the benchmark also shows.** The deterministic stub names the kind of cheat at least as
well as the small models: 30 of 36 against 17 to 31 in the six-model run, and 25 of 36
against the winner's 21 on the final data. It also accuses fewer honest sessions than most.
Out of the box the language model adds the written summary, not accuracy, and it sometimes
words a summary more firmly than the evidence supports. That is why the opinion is advisory,
why every opinion lists the evidence rows it cites, and why the path below exists to tune the
model on a studio's own reviewed cases. About half of the honest-but-flagged sessions are
"accused" by every analyst including the stub: the analyst reads the evidence the rules
produced, and when a rule is wrong the opinion repeats the mistake. An analyst opinion is not
a second, independent detection.

Carthago did not train the language model. See `THIRD-PARTY-NOTICES.md`.

## Performance

The game client is unchanged: `git diff carthago-dev..ai-engine -- client proto sdk` is
empty, and so is the diff of the gateway's connection code (`backend/internal/gateway`,
`backend/internal/attest`). In the pipeline the Oracle adds one non-blocking channel send per
heartbeat and one hand-over of the match summaries when a match ends. Everything else runs on
the Oracle's own goroutine or in the analyst's process.

**Handshake, heartbeat and telemetry ingest, before and after** (4-vCPU Xeon VM, SQLite
store; `go test ./internal/oracle/train -run xxx -bench 'Heartbeat|Gameplay'`, medians of 3
to 5 runs; the handshake row is the gateway's own `handshake_ms` over 108 handshakes, 18 at a
time, measured twice):

| Path | Oracle off | Oracle on |
| --- | --- | --- |
| Handshake, gateway side (median of 108, two measurements) | 14 ms, 13 ms | 13 ms, 12 ms |
| Heartbeat hand-off: what the client's connection waits for | 0.21 µs | 0.24 µs |
| Heartbeat, full processing on the pipeline worker, store writes included | 61.3 µs | 60.1 µs (57.8 to 76.9) |
| Gameplay batch: one second of a ten-player match, received to acknowledged | 2.93 ms | 2.87 ms |
| The batch that ends a match | 17.4 ms | 17.8 ms |
| The Oracle's own work per finished match (ten sessions scored and stored, after the acknowledgement, on its own goroutine) | – | 3.0 ms |

The differences in the first five rows are inside the run-to-run spread.

**Gateway CPU and memory** (the check script's traffic: 18 sessions with a heartbeat every
two seconds, two replayed matches, six flagged sessions; sampled once a second):

| Phase | Gateway, Oracle off | Gateway, Oracle on | Analyst runtime |
| --- | --- | --- | --- |
| No sessions | 0.0% of one core, 24.6 MB | 0.0%, 24.4 MB | not running: no CPU, no memory |
| 18 sessions connected | 0.31% of one core, 40.1 MB | 0.34%, 41.5 MB | not running |
| Sessions ended, analyst reviewing six cases | – | 0.75% of one core, 38.5 MB | 2 threads busy for 43 s in all, at nice 10; 2.08 GB resident |
| 90 s after the last case | – | 0.0% | stopped: no CPU, no memory |

The six cases took 12.5 s for the first (with the model load) and 5.8 to 7.0 s for each of
the others. The gateway's 0.75% while reviewing includes hashing the 1.1 GB model file before
the start.

**Memory on other CPUs.** The test machine's CPU has AMX, and llama.cpp's AMX code keeps a
second copy of the weights, so the runtime's resident size here is about twice the model
file: 1.2 GB private plus 0.9 GB of the mapped file. On a CPU without AMX, which is nearly
every gaming PC, expect roughly the size of the file plus half a gigabyte. That figure is an
expectation from how llama.cpp maps a model; it has not been measured on such a machine.

**On the same PC as the game.** By default the analyst does not run while a session is
connected, runs at below-normal priority, uses at most half the cores (at most 4), handles
one case at a time and exits 90 s after the last one. A case took 4.9 s on 3 threads and
6.7 s on 2; `-oracle-threads 1` was not measured. `-oracle-analyst off` or `stub` removes the
runtime entirely and keeps the scores.

## What stays secret

**Kept on the gateway host only:** the bundle (behaviour-model curves, thresholds, prompts,
the name and hash of the analyst model), feature vectors, case files, and the pseudonym key.

- The bundle is loaded from a path outside the dashboard's static directory. The dashboard
  embeds its static files at build time and has no route that reads from disk; its package
  does not import the Oracle. The check script requests the bundle's files through the
  dashboard and the client port and expects none to be served.
- The dashboard shows, to a signed-in studio and for its own sessions only: the score, the
  band, the labels of the top signals with the direction and relative size of their effect,
  the analyst's opinion and the ids of the bundle and models. It never shows a threshold, a
  feature value, a curve, a prompt or a case file.
- Nothing is sent to a client or a game server. The client protocol has no Oracle message.
- The log at the default level carries the bundle and model ids and, for a case that could
  not be judged, the session id and a reason code. Verdict text, case files, feature values
  and provider errors never appear at the default level.
- The gateway warns at startup when the bundle directory is readable by other users.

**What an attacker can still learn.**

- The source is in this repository. Which signals exist and how they are computed is public,
  and so is the reference prompt. What is secret in a deployment is the studio's bundle:
  train it with a private seed, and later on private labelled data, and replace the prompts.
  A bundle trained with the public defaults and a known seed can be reproduced by anyone.
- A cheater who gets banned or reviewed learns that some combination of behaviour was
  noticed. With many accounts and slow changes they can estimate where a threshold lies.
  Scores are never shown to players, enforcement is a human decision, and the Oracle never
  acts in real time, so each probe costs a reviewed account and returns one bit, late.
- Anyone with read access to the gateway host or the store reads everything. The Oracle adds
  no protection against a compromised host.
- A studio employee with dashboard access sees scores and top-signal labels of that studio's
  players, and could infer roughly which behaviour raises a score.

## Reviewer labels and private tuning

**Labelling.** Every session page has a "Reviewer label" card: confirmed cheat, cleared or
unsure, an optional kind of cheat, a note of up to 280 characters and the reviewer's name. A
label can be changed or removed; every change is appended to an audit table with who, when
and from which address. The form carries a per-login token and the request must be
same-origin, like the login form. A session with client integrity evidence of high or
critical severity shows a suggested label ("Confirmed cheat · Client tampering") that the
reviewer accepts with one click; the suggestion is never applied by itself. Labelling works
for sessions that have integrity evidence but never joined a match, which is the case when a
game is watched from outside without match data.

The dashboard has one key per studio and no user accounts, so the reviewer's name is what the
reviewer typed. Treat it as a note, not as proof of who labelled.

**Export.** `carthago-oracle export -data <gateway data dir> -tenant <studio> -out <dir>`
writes two files, readable by the owner only:

- `behaviour.jsonl`: one line per labelled session with the label, the kind of cheat, the
  feature vector and pseudonyms for the player and the session. No player id, session id,
  device id, note or reviewer name.
- `analyst.jsonl`: one chat example per labelled session in the common fine-tuning format
  (`messages` with system, user and assistant turns): the bundle's prompt, the pseudonymised
  case file, and the verdict the label implies.

It prints how many sessions of each class it found and what is still missing.

**How many labels before retraining is worth it.** From the learning curves on synthetic
sessions (`carthago-oracle curve`; honest and cheating sessions in the proportion 70:30,
measured on the same 1,200 held-out sessions):

| Training sessions (honest + cheating) | AUC | Cheating sessions in review |
| --- | --- | --- |
| 35 + 15 | 0.836 | 33% |
| 140 + 60 | 0.954 | 54% |
| 280 + 120 | 0.978 | 62% |
| 560 + 240 | 0.989 | 65% |
| 1,120 + 480 | 0.996 | 84% |
| 2,460 + 1,140 | 0.997 | 87% |

With all honest sessions and only 100 cheating ones the model sends 37% of cheating sessions
to review; with 400 it sends 77%. Honest sessions matter less: 400 are enough for the fit.
The tool therefore reports a label set as ready from:

- **400 confirmed cheating sessions**, and **100 of each kind** the model should recognise
  (fewer cannot measure that kind's recall to within about ten points);
- **600 cleared sessions**. The fit needs fewer, but 600 held-out cleared sessions with none
  in review is the least that bounds the honest review rate at 0.5% with 95% confidence. A
  studio that holds out one fifth for that test needs 3,000 cleared sessions in all;
- **50 distinct players**, so the model learns behaviour and not a few people's habits.

Real play is noisier than the simulator, so read these as lower bounds. Below them, use
labels to check the model (`carthago-oracle eval -labelled behaviour.jsonl`), not to retrain
it.

**Retraining the behaviour model.** `carthago-oracle train -labelled behaviour.jsonl
-labelled-repeat N -seed … -out <new bundle>` adds the labelled sessions to the synthetic
ones (each counted N times) and writes a new bundle with a new id. Point the gateway at it and
restart.

**Tuning the analyst.** `analyst.jsonl` is the training file for a LoRA or full fine-tune of
the base model with any standard trainer (for example llama.cpp's or Hugging Face's tools).
This repository does not run the fine-tune: it needs a GPU and a set of reviewed cases that
does not exist yet. After tuning, convert the result to GGUF, put the file in the runtime's
`models` folder and run `carthago-oracle set -bundle DIR -local-model-id <name>
-local-model-file <file> -local-model-sha256 <hash> -prompt-version <version>`. The gateway
then refuses to start the analyst on any other file.

**How this keeps a studio's model secret.** The tuned weights, the prompts and the labelled
data never leave the studio's gateway host: training happens on the studio's own machine from
its own export, the bundle names the model by hash, and no part of it is published, embedded
in a client or sent to another studio. Two studios running the same Carthago release
therefore run different Oracles.

## Limits

- Synthetic data only, as described above. No real player data was used anywhere.
- The Oracle sees a session only through the pipeline's summaries. A cheat that the rules'
  statistics cannot express is invisible to it.
- Scores of one session are independent of the player's other sessions. The player page lists
  them; nothing aggregates them yet.
- The analyst reads the same evidence as the reviewer. It summarises; it does not detect.
- The local runtime is tested with the real model on Linux x86-64. The Windows start, stop,
  priority and thread-cap code is tested with a stand-in server under Wine only; the real
  `llama-server.exe` has not been run by these tests (it crashes under Wine), and the
  PowerShell fetch script was run under PowerShell 7 on Linux, not under Windows PowerShell 5.1.
- Model files are bit-identical for the same seed on the same CPU architecture only.
