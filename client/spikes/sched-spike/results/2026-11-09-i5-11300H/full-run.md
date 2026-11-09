# Scheduler spike report

CPU: 11th Gen Intel(R) Core(TM) i5-11300H @ 3.10GHz, 8 logical processors. TSC 3.092 cycles/ns. Budget config: gameplay bucket 0.8% of one core (cap 6 ms), slice target 2 ms, hard cap 3 ms, worker below-normal + EcoQoS, ideal CPU = last in affinity mask.

Intrinsic `tick()` cost (2M back-to-back calls, no game load): **31.9 ns/call**. Per-frame tick samples below include two QPC reads (~100 ns resolution).

System-wide Toolhelp thread snapshot (what a naive thread audit would call, not sliceable): median 5.61 ms, max 6.38 ms. The spike uses per-process `NtGetNextThread` instead.

Hashing: one `text_hash` pass covers 39.5 MiB (executable sections of all loaded images + 32 MiB simulated game `.text`). BLAKE3 over 64 KiB chunks, sustained: 6305 MB/s on a normal thread, 3180 MB/s with EcoQoS; in scheduler-like 2 ms bursts after 100 ms idle (EcoQoS, per CPU-second): 3069 MB/s. In-job rates are in each profile's per-job table. At the gameplay share (0.4 x 0.8% = 0.32% of a core) and the bursty rate, a full pass needs ≈ 4 s of wall time.

## Profile `desktop`

this PC, all logical CPUs, 144 fps target, main + 3 game workers at 30% of frame (single-thread calibrated; ~60-70% of frame once 4 threads share the memory system)

Affinity mask `0xff`, EcoQoS off, game work rate calibrated under this profile's load: 50246 units/ms (100% of desktop), 8 pairs x 8 s blocks (ABBA order).

| Budget (G2) | Target | Measured | Result |
|---|---|---|---|
| `tick()` cost | p99 ≤ 20 µs | p50 0.90 µs, p99 4.80 µs, p99.9 16.70 µs, max 89.2 µs (8773 ticks) | PASS |
| Background CPU (worker thread, cycle-accurate) | ≤ 1% of one core | 0.379% (GetThreadTimes: 0.220%, charged to buckets: 0.340%) | PASS |
| Scan slice | ≤ 3 ms | CPU max 1.02 ms; wall max 7.84 ms, wall p99 ≤ 7.84 ms; 0 / 871 slices over 3 ms CPU, 9 over 3 ms wall | PASS |
| Memory | ≤ 25 MB (whole SDK) | scheduler+jobs heap peak 32.2 KiB (35 allocs); private bytes delta on 0.09 MiB vs off 0.00 MiB; working-set delta 4.80 MiB | PASS |
| Frame time p99 delta | ≤ 1% | off p99 25.130 ms → on 14.828 ms (-41.00%); mean 5.870 → 4.986 ms (-15.06%); median per-block p99 27.840 → 13.212 ms (-52.54%); A/A noise p99 0.75%, mean 2.43% | PASS |
| Frame attribution (same ON blocks) | slice-overlapped frames ≈ clean frames | 436 frames overlapped a slice (5.0%): mean 6.388 ms, p50 4.943, p99 33.960; 8337 clean: mean 4.913, p50 4.326, p99 14.060 (mean +30.03%, p50 +14.26%, p99 +141.53%) | info |
| Frame attribution, unbiased (frame started while a slice ran) | ≈ other frames | 64 frames: mean 4.962 ms, p50 4.501; 8709 others: mean 4.986, p50 4.344 (mean -0.48%, p50 +3.61%) | info |
| Init | ≤ 50 ms, off main thread | main-thread `start()` 0.27 ms; worker init 0.64 ms wall (0.17 ms CPU, rest is waiting at below-normal priority) | PASS |

Frames: off 8136 (p50 4.633 ms, p99.9 67.606 ms, max 225.14 ms, missed deadline 15.81%), on 8773 (p50 4.346 ms, p99.9 34.664 ms, max 105.53 ms, missed deadline 8.00%). Process CPU (whole sim, % of one core): off 201.4%, on 206.5%. Hitch-guard deferrals: 116. Findings delivered via `tick()`: 16.

Per-job stats (last ON block, 8 s):

| Job | Passes | Steps | Last pass CPU | Last pass wall | CPU % of core | Max step | Overruns | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|---|
| module_inventory | 2 | 6 | 0.16 ms | 0.2 ms | 0.0051% | 136 µs | 0 | 0 | 0 |
| memory_region_walk | 2 | 6 | 0.65 ms | 0.8 ms | 0.0168% | 478 µs | 0 | 0 | 0 |
| thread_audit | 2 | 2 | 0.11 ms | 0.1 ms | 0.0023% | 115 µs | 0 | 0 | 0 |
| text_hash | 0 | 216 | 0.00 ms | 0.0 ms | 0.3551% | 579 µs | 0 | 0 | 69 |

In-job `text_hash` rate: ≈ 498 MB/s per CPU-second (216 steps x ≤ 64 KiB in 28.4 ms CPU, 132 µs/step).

## Profile `lowend-2c`

simulated low-end laptop: 2 physical cores (CPU 4,6, no SMT siblings), process EcoQoS (lower clocks), 60 fps, main + 1 worker at 40% of frame, background load 2 threads x 25% duty in another process

Affinity mask `0x50`, EcoQoS on, game work rate calibrated under this profile's load: 21134 units/ms (42% of desktop), 8 pairs x 8 s blocks (ABBA order).

| Budget (G2) | Target | Measured | Result |
|---|---|---|---|
| `tick()` cost | p99 ≤ 20 µs | p50 1.00 µs, p99 6.70 µs, p99.9 45.60 µs, max 171.7 µs (3727 ticks) | PASS |
| Background CPU (worker thread, cycle-accurate) | ≤ 1% of one core | 0.369% (GetThreadTimes: 0.390%, charged to buckets: 0.329%) | PASS |
| Scan slice | ≤ 3 ms | CPU max 1.04 ms; wall max 12.74 ms, wall p99 ≤ 12.74 ms; 0 / 913 slices over 3 ms CPU, 20 over 3 ms wall | PASS |
| Memory | ≤ 25 MB (whole SDK) | scheduler+jobs heap peak 32.2 KiB (35 allocs); private bytes delta on 0.17 MiB vs off 0.00 MiB; working-set delta 0.04 MiB | PASS |
| Frame time p99 delta | ≤ 1% | off p99 26.516 ms → on 26.673 ms (+0.59%); mean 9.224 → 9.306 ms (+0.88%); median per-block p99 21.519 → 23.081 ms (+7.26%); A/A noise p99 28.77%, mean 4.30% | NO DETECTABLE IMPACT (delta inside 28.8% A/A noise) |
| Frame attribution (same ON blocks) | slice-overlapped frames ≈ clean frames | 288 frames overlapped a slice (7.7%): mean 10.960 ms, p50 9.082, p99 39.894; 3439 clean: mean 9.167, p50 8.536, p99 25.309 (mean +19.56%, p50 +6.40%, p99 +57.63%) | info |
| Frame attribution, unbiased (frame started while a slice ran) | ≈ other frames | 19 frames: mean 14.776 ms, p50 8.153; 3708 others: mean 9.278, p50 8.573 (mean +59.26%, p50 -4.90%) | info |
| Init | ≤ 50 ms, off main thread | main-thread `start()` 0.34 ms; worker init 10.70 ms wall (0.19 ms CPU, rest is waiting at below-normal priority) | PASS |

Frames: off 3714 (p50 8.494 ms, p99.9 87.107 ms, max 134.89 ms, missed deadline 2.88%), on 3727 (p50 8.566 ms, p99.9 59.773 ms, max 159.68 ms, missed deadline 3.25%). Process CPU (whole sim, % of one core): off 72.4%, on 76.8%. Hitch-guard deferrals: 59. Findings delivered via `tick()`: 16.

Per-job stats (last ON block, 8 s):

| Job | Passes | Steps | Last pass CPU | Last pass wall | CPU % of core | Max step | Overruns | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|---|
| module_inventory | 2 | 6 | 0.19 ms | 0.3 ms | 0.0046% | 111 µs | 0 | 0 | 0 |
| memory_region_walk | 1 | 5 | 0.47 ms | 0.5 ms | 0.0185% | 863 µs | 1 | 0 | 0 |
| thread_audit | 2 | 2 | 0.10 ms | 0.1 ms | 0.0023% | 96 µs | 0 | 0 | 0 |
| text_hash | 0 | 198 | 0.00 ms | 0.0 ms | 0.3119% | 707 µs | 0 | 0 | 78 |

In-job `text_hash` rate: ≈ 519 MB/s per CPU-second (198 steps x ≤ 64 KiB in 25.0 ms CPU, 126 µs/step).

## Profile `lowend-1c`

worst case: 1 logical CPU (CPU 6), process EcoQoS, 60 fps, main thread only at 40% of frame, background load 1 thread x 20% duty

Affinity mask `0x40`, EcoQoS on, game work rate calibrated under this profile's load: 27637 units/ms (55% of desktop), 8 pairs x 8 s blocks (ABBA order).

| Budget (G2) | Target | Measured | Result |
|---|---|---|---|
| `tick()` cost | p99 ≤ 20 µs | p50 1.00 µs, p99 5.70 µs, p99.9 18.40 µs, max 89.0 µs (3617 ticks) | PASS |
| Background CPU (worker thread, cycle-accurate) | ≤ 1% of one core | 0.376% (GetThreadTimes: 0.415%, charged to buckets: 0.336%) | PASS |
| Scan slice | ≤ 3 ms | CPU max 1.26 ms; wall max 78.66 ms, wall p99 ≤ 78.66 ms; 0 / 824 slices over 3 ms CPU, 33 over 3 ms wall | PASS |
| Memory | ≤ 25 MB (whole SDK) | scheduler+jobs heap peak 32.2 KiB (35 allocs); private bytes delta on 0.17 MiB vs off 0.06 MiB; working-set delta 0.11 MiB | PASS |
| Frame time p99 delta | ≤ 1% | off p99 20.776 ms → on 28.936 ms (+39.28%); mean 9.007 → 9.397 ms (+4.33%); median per-block p99 18.744 → 26.534 ms (+41.56%); A/A noise p99 0.62%, mean 0.04% | FAIL |
| Frame attribution (same ON blocks) | slice-overlapped frames ≈ clean frames | 33 frames overlapped a slice (0.9%): mean 10.170 ms, p50 8.000, p99 30.939; 3584 clean: mean 9.390, p50 8.643, p99 28.380 (mean +8.30%, p50 -7.44%, p99 +9.02%) | info |
| Frame attribution, unbiased (frame started while a slice ran) | ≈ other frames | 23 frames: mean 10.614 ms, p50 8.266; 3594 others: mean 9.390, p50 8.637 (mean +13.04%, p50 -4.29%) | info |
| Init | ≤ 50 ms, off main thread | main-thread `start()` 1.09 ms; worker init 212.27 ms wall (0.40 ms CPU, rest is waiting at below-normal priority) | PASS |

Frames: off 3703 (p50 8.632 ms, p99.9 31.865 ms, max 61.29 ms, missed deadline 2.27%), on 3617 (p50 8.632 ms, p99.9 62.363 ms, max 76.82 ms, missed deadline 3.98%). Process CPU (whole sim, % of one core): off 41.6%, on 39.9%. Hitch-guard deferrals: 109. Findings delivered via `tick()`: 16.

Per-job stats (last ON block, 8 s):

| Job | Passes | Steps | Last pass CPU | Last pass wall | CPU % of core | Max step | Overruns | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|---|
| module_inventory | 2 | 6 | 0.18 ms | 0.2 ms | 0.0046% | 121 µs | 0 | 0 | 0 |
| memory_region_walk | 2 | 6 | 0.76 ms | 0.9 ms | 0.0206% | 598 µs | 0 | 0 | 0 |
| thread_audit | 2 | 2 | 0.05 ms | 0.1 ms | 0.0016% | 75 µs | 0 | 0 | 0 |
| text_hash | 0 | 184 | 0.00 ms | 0.0 ms | 0.2787% | 846 µs | 0 | 0 | 54 |

In-job `text_hash` rate: ≈ 540 MB/s per CPU-second (184 steps x ≤ 64 KiB in 22.3 ms CPU, 121 µs/step).

## Throttling demo (30 s, desktop game load)

Standard jobs with `text_hash` made continuous (always due), plus two misbehaving modules: `misbehaving_spin_hog` declares 200 µs steps but spins 8 ms per step; `misbehaving_greedy` declares share 0.3 and a 30 ms per-pass cap but never finishes and is always due.

| Check | Expected | Measured | Result |
|---|---|---|---|
| Spin hog | backed off, quarantined after 3 strikes | overruns 3, steps 3, quarantined true, total CPU 23.1 ms | PASS |
| Greedy | ≤ its share (0.3 x 0.8% = 0.24% of a core), pass cut at 30 ms | 0.249% of a core, 2 run-budget aborts, share-throttled 482 times | PASS |
| Whole worker | ≤ 1% of one core | 0.730% (charged 0.671%; global bucket throttled 153 times) | PASS |
| Other jobs still progress | text_hash keeps hashing | text_hash 0 passes, ~34 MiB hashed, 0.324% of a core | PASS |

Slices over 3 ms CPU: 3 of 946 (the hog's overrunning steps; a cooperative step cannot be preempted, so each overrun costs one full step before the strike lands). Frame p99 during demo: 6.184 ms, tick p99 5.20 µs.

| Job | Passes | CPU % of core | Max step | Overruns | Strikes | Quarantined | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|
| module_inventory | 7 | 0.0053% | 172 µs | 0 | 0 | false | 0 | 0 |
| memory_region_walk | 6 | 0.0140% | 701 µs | 0 | 0 | false | 0 | 0 |
| thread_audit | 6 | 0.0016% | 107 µs | 0 | 0 | false | 0 | 0 |
| text_hash | 0 | 0.3235% | 662 µs | 0 | 0 | false | 0 | 356 |
| misbehaving_spin_hog | 0 | 0.0770% | 7928 µs | 3 | 3 | true | 0 | 2 |
| misbehaving_greedy | 0 | 0.2493% | 175 µs | 0 | 0 | false | 2 | 482 |

