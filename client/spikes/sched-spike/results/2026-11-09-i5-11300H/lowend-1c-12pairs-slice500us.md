# Scheduler spike report

CPU: 11th Gen Intel(R) Core(TM) i5-11300H @ 3.10GHz, 8 logical processors. TSC 3.077 cycles/ns. Budget config: gameplay bucket 0.8% of one core (cap 6 ms), slice target 500 µs, hard cap 3 ms, worker below-normal + EcoQoS, ideal CPU = last in affinity mask.

Intrinsic `tick()` cost (2M back-to-back calls, no game load): **34.5 ns/call**. Per-frame tick samples below include two QPC reads (~100 ns resolution).

System-wide Toolhelp thread snapshot (what a naive thread audit would call, not sliceable): median 6.15 ms, max 6.67 ms. The spike uses per-process `NtGetNextThread` instead.

Hashing: one `text_hash` pass covers 39.5 MiB (executable sections of all loaded images + 32 MiB simulated game `.text`). BLAKE3 over 64 KiB chunks, sustained: 5703 MB/s on a normal thread, 3588 MB/s with EcoQoS; in scheduler-like 2 ms bursts after 100 ms idle (EcoQoS, per CPU-second): 3446 MB/s. In-job rates are in each profile's per-job table. At the gameplay share (0.4 x 0.8% = 0.32% of a core) and the bursty rate, a full pass needs ≈ 4 s of wall time.

## Profile `lowend-1c`

worst case: 1 logical CPU (CPU 6), process EcoQoS, 60 fps, main thread only at 40% of frame, background load 1 thread x 20% duty

Affinity mask `0x40`, EcoQoS on, game work rate calibrated under this profile's load: 23490 units/ms (2348962% of desktop), 12 pairs x 8 s blocks (ABBA order).

| Budget (G2) | Target | Measured | Result |
|---|---|---|---|
| `tick()` cost | p99 ≤ 20 µs | p50 1.20 µs, p99 3.20 µs, p99.9 17.60 µs, max 68.3 µs (5553 ticks) | PASS |
| Background CPU (worker thread, cycle-accurate) | ≤ 1% of one core | 0.381% (GetThreadTimes: 0.358%, charged to buckets: 0.337%) | PASS |
| Scan slice | ≤ 3 ms | CPU max 0.79 ms; wall max 14.59 ms, wall p99 ≤ 11.60 ms; 0 / 2537 slices over 3 ms CPU, 29 over 3 ms wall | PASS |
| Memory | ≤ 25 MB (whole SDK) | scheduler+jobs heap peak 32.2 KiB (35 allocs); private bytes delta on 0.07 MiB vs off 0.00 MiB; working-set delta 4.66 MiB | PASS |
| Frame time p99 delta | ≤ 1% | off p99 14.242 ms → on 14.912 ms (+4.70%); mean 8.446 → 8.472 ms (+0.31%); median per-block p99 13.746 → 13.239 ms (-3.69%); A/A noise p99 1.79%, mean 5.70% | FAIL |
| Frame attribution (same ON blocks) | slice-overlapped frames ≈ clean frames | 37 frames overlapped a slice (0.7%): mean 8.639 ms, p50 8.998, p99 12.330; 5516 clean: mean 8.471, p50 8.356, p99 14.991 (mean +1.98%, p50 +7.69%, p99 -17.75%) | info |
| Frame attribution, unbiased (frame started while a slice ran) | ≈ other frames | 16 frames: mean 8.792 ms, p50 9.230; 5537 others: mean 8.471, p50 8.356 (mean +3.79%, p50 +10.46%) | info |
| Init | ≤ 50 ms, off main thread | main-thread `start()` 0.18 ms; worker init 7.10 ms wall (0.24 ms CPU, rest is waiting at below-normal priority) | PASS |

Frames: off 5582 (p50 8.468 ms, p99.9 33.380 ms, max 121.06 ms, missed deadline 0.43%), on 5553 (p50 8.357 ms, p99.9 44.581 ms, max 109.07 ms, missed deadline 0.70%). Process CPU (whole sim, % of one core): off 39.7%, on 39.7%. Hitch-guard deferrals: 73. Findings delivered via `tick()`: 24.

Per-job stats (last ON block, 8 s):

| Job | Passes | Steps | Last pass CPU | Last pass wall | CPU % of core | Max step | Overruns | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|---|
| module_inventory | 2 | 6 | 0.34 ms | 66.6 ms | 0.0077% | 148 µs | 0 | 0 | 0 |
| memory_region_walk | 2 | 6 | 0.54 ms | 0.5 ms | 0.0141% | 376 µs | 0 | 0 | 0 |
| thread_audit | 2 | 2 | 0.05 ms | 0.0 ms | 0.0013% | 55 µs | 0 | 0 | 0 |
| text_hash | 0 | 213 | 0.00 ms | 0.0 ms | 0.3468% | 464 µs | 0 | 0 | 77 |

In-job `text_hash` rate: ≈ 502 MB/s per CPU-second (213 steps x ≤ 64 KiB in 27.8 ms CPU, 130 µs/step).

## Throttling demo (1 s, desktop game load)

Standard jobs with `text_hash` made continuous (always due), plus two misbehaving modules: `misbehaving_spin_hog` declares 200 µs steps but spins 8 ms per step; `misbehaving_greedy` declares share 0.3 and a 30 ms per-pass cap but never finishes and is always due.

| Check | Expected | Measured | Result |
|---|---|---|---|
| Spin hog | backed off, quarantined after 3 strikes | overruns 1, steps 1, quarantined false, total CPU 6.9 ms | FAIL |
| Greedy | ≤ its share (0.3 x 0.8% = 0.24% of a core), pass cut at 30 ms | 0.440% of a core, 0 run-budget aborts, share-throttled 13 times | FAIL |
| Whole worker | ≤ 1% of one core | 1.748% (charged 1.680%; global bucket throttled 6 times) | FAIL |
| Other jobs still progress | text_hash keeps hashing | text_hash 0 passes, ~9 MiB hashed, 0.521% of a core | PASS |

Slices over 3 ms CPU: 1 of 173 (the hog's overrunning steps; a cooperative step cannot be preempted, so each overrun costs one full step before the strike lands). Frame p99 during demo: 5.372 ms, tick p99 4.10 µs.

| Job | Passes | CPU % of core | Max step | Overruns | Strikes | Quarantined | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|
| module_inventory | 1 | 0.0204% | 94 µs | 0 | 0 | false | 0 | 0 |
| memory_region_walk | 0 | 0.0000% | 0 µs | 0 | 0 | false | 0 | 0 |
| thread_audit | 1 | 0.0074% | 74 µs | 0 | 0 | false | 0 | 0 |
| text_hash | 0 | 0.5214% | 613 µs | 0 | 0 | false | 0 | 7 |
| misbehaving_spin_hog | 0 | 0.6916% | 6926 µs | 1 | 1 | false | 0 | 0 |
| misbehaving_greedy | 0 | 0.4396% | 215 µs | 0 | 0 | false | 0 | 13 |

