# Scheduler spike report

CPU: 11th Gen Intel(R) Core(TM) i5-11300H @ 3.10GHz, 8 logical processors. TSC 3.107 cycles/ns. Budget config: gameplay bucket 0.8% of one core (cap 6 ms), slice target 2 ms, hard cap 3 ms, worker below-normal + EcoQoS, ideal CPU = last in affinity mask.

Intrinsic `tick()` cost (2M back-to-back calls, no game load): **31.8 ns/call**. Per-frame tick samples below include two QPC reads (~100 ns resolution).

System-wide Toolhelp thread snapshot (what a naive thread audit would call, not sliceable): median 5.57 ms, max 6.52 ms. The spike uses per-process `NtGetNextThread` instead.

Hashing: one `text_hash` pass covers 39.5 MiB (executable sections of all loaded images + 32 MiB simulated game `.text`). BLAKE3 over 64 KiB chunks, sustained: 6090 MB/s on a normal thread, 4353 MB/s with EcoQoS; in scheduler-like 2 ms bursts after 100 ms idle (EcoQoS, per CPU-second): 3753 MB/s. In-job rates are in each profile's per-job table. At the gameplay share (0.4 x 0.8% = 0.32% of a core) and the bursty rate, a full pass needs ≈ 3 s of wall time.

## Profile `lowend-1c`

worst case: 1 logical CPU (CPU 6), process EcoQoS, 60 fps, main thread only at 40% of frame, background load 1 thread x 20% duty

Affinity mask `0x40`, EcoQoS on, game work rate calibrated under this profile's load: 28338 units/ms (2833825% of desktop), 12 pairs x 8 s blocks (ABBA order).

| Budget (G2) | Target | Measured | Result |
|---|---|---|---|
| `tick()` cost | p99 ≤ 20 µs | p50 1.00 µs, p99 6.00 µs, p99.9 86.60 µs, max 4584.1 µs (5365 ticks) | PASS |
| Background CPU (worker thread, cycle-accurate) | ≤ 1% of one core | 0.374% (GetThreadTimes: 0.309%, charged to buckets: 0.335%) | PASS |
| Scan slice | ≤ 3 ms | CPU max 1.16 ms; wall max 64.16 ms, wall p99 ≤ 64.16 ms; 0 / 1359 slices over 3 ms CPU, 60 over 3 ms wall | PASS |
| Memory | ≤ 25 MB (whole SDK) | scheduler+jobs heap peak 32.2 KiB (35 allocs); private bytes delta on 0.07 MiB vs off 0.00 MiB; working-set delta 4.64 MiB | PASS |
| Frame time p99 delta | ≤ 1% | off p99 30.813 ms → on 34.189 ms (+10.96%); mean 10.030 → 10.010 ms (-0.19%); median per-block p99 26.974 → 31.880 ms (+18.19%); A/A noise p99 32.04%, mean 6.82% | NO DETECTABLE IMPACT (delta inside 32.0% A/A noise) |
| Frame attribution (same ON blocks) | slice-overlapped frames ≈ clean frames | 70 frames overlapped a slice (1.3%): mean 14.854 ms, p50 11.405, p99 77.715; 5295 clean: mean 9.946, p50 8.958, p99 33.903 (mean +49.35%, p50 +27.32%, p99 +129.23%) | info |
| Frame attribution, unbiased (frame started while a slice ran) | ≈ other frames | 48 frames: mean 12.190 ms, p50 11.163; 5317 others: mean 9.991, p50 8.968 (mean +22.01%, p50 +24.48%) | info |
| Init | ≤ 50 ms, off main thread | main-thread `start()` 1.26 ms; worker init 22.89 ms wall (0.29 ms CPU, rest is waiting at below-normal priority) | PASS |

Frames: off 5391 (p50 9.052 ms, p99.9 61.692 ms, max 71.85 ms, missed deadline 6.21%), on 5365 (p50 8.981 ms, p99.9 115.204 ms, max 276.32 ms, missed deadline 4.81%). Process CPU (whole sim, % of one core): off 41.0%, on 41.5%. Hitch-guard deferrals: 159. Findings delivered via `tick()`: 24.

Per-job stats (last ON block, 8 s):

| Job | Passes | Steps | Last pass CPU | Last pass wall | CPU % of core | Max step | Overruns | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|---|
| module_inventory | 2 | 6 | 0.17 ms | 0.2 ms | 0.0059% | 168 µs | 0 | 0 | 0 |
| memory_region_walk | 2 | 6 | 0.82 ms | 0.8 ms | 0.0157% | 481 µs | 0 | 0 | 0 |
| thread_audit | 2 | 2 | 0.05 ms | 0.1 ms | 0.0016% | 76 µs | 0 | 0 | 0 |
| text_hash | 0 | 204 | 0.00 ms | 0.0 ms | 0.3358% | 834 µs | 0 | 0 | 77 |

In-job `text_hash` rate: ≈ 498 MB/s per CPU-second (204 steps x ≤ 64 KiB in 26.9 ms CPU, 132 µs/step).

## Throttling demo (1 s, desktop game load)

Standard jobs with `text_hash` made continuous (always due), plus two misbehaving modules: `misbehaving_spin_hog` declares 200 µs steps but spins 8 ms per step; `misbehaving_greedy` declares share 0.3 and a 30 ms per-pass cap but never finishes and is always due.

| Check | Expected | Measured | Result |
|---|---|---|---|
| Spin hog | backed off, quarantined after 3 strikes | overruns 1, steps 1, quarantined false, total CPU 6.4 ms | FAIL |
| Greedy | ≤ its share (0.3 x 0.8% = 0.24% of a core), pass cut at 30 ms | 0.359% of a core, 0 run-budget aborts, share-throttled 4 times | FAIL |
| Whole worker | ≤ 1% of one core | 1.430% (charged 1.382%; global bucket throttled 12 times) | FAIL |
| Other jobs still progress | text_hash keeps hashing | text_hash 0 passes, ~9 MiB hashed, 0.385% of a core | PASS |

Slices over 3 ms CPU: 1 of 28 (the hog's overrunning steps; a cooperative step cannot be preempted, so each overrun costs one full step before the strike lands). Frame p99 during demo: 13.421 ms, tick p99 5.00 µs.

| Job | Passes | CPU % of core | Max step | Overruns | Strikes | Quarantined | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|
| module_inventory | 0 | 0.0000% | 0 µs | 0 | 0 | false | 0 | 0 |
| memory_region_walk | 0 | 0.0000% | 0 µs | 0 | 0 | false | 0 | 0 |
| thread_audit | 0 | 0.0000% | 0 µs | 0 | 0 | false | 0 | 0 |
| text_hash | 0 | 0.3851% | 527 µs | 0 | 0 | false | 0 | 3 |
| misbehaving_spin_hog | 0 | 0.6375% | 6410 µs | 1 | 1 | false | 0 | 0 |
| misbehaving_greedy | 0 | 0.3592% | 170 µs | 0 | 0 | false | 0 | 4 |

