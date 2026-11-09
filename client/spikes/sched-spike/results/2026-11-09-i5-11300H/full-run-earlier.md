# Scheduler spike report

CPU: 11th Gen Intel(R) Core(TM) i5-11300H @ 3.10GHz, 8 logical processors. TSC 3.108 cycles/ns. Budget config: gameplay bucket 0.8% of one core (cap 6 ms), slice target 2 ms, hard cap 3 ms, worker below-normal + EcoQoS, ideal CPU = last in affinity mask.

Intrinsic `tick()` cost (2M back-to-back calls, no game load): **30.6 ns/call**. Per-frame tick samples below include two QPC reads (~100 ns resolution).

System-wide Toolhelp thread snapshot (what a naive thread audit would call, not sliceable): median 4.00 ms, max 4.87 ms. The spike uses per-process `NtGetNextThread` instead.

Hashing: one `text_hash` pass covers 39.5 MiB (executable sections of all loaded images + 32 MiB simulated game `.text`). BLAKE3 over 64 KiB chunks: 6924 MB/s on a normal thread, 3413 MB/s with EcoQoS. At the gameplay share (0.4 x 0.8% = 0.32% of a core) a full pass needs ≈ 4 s of wall time (EcoQoS rate) — expensive passes belong in menu/loading (3% budget) or on server challenge.

## Profile `desktop`

this PC, all logical CPUs, 144 fps target, main + 3 game workers at 30% of frame (single-thread calibrated; ~60-70% of frame once 4 threads share the memory system)

Affinity mask `0xff`, EcoQoS off, game work rate calibrated under this profile's load: 56741 units/ms (100% of desktop), 8 pairs x 8 s blocks (ABBA order).

| Budget (G2) | Target | Measured | Result |
|---|---|---|---|
| `tick()` cost | p99 ≤ 20 µs | p50 0.90 µs, p99 2.70 µs, p99.9 11.40 µs, max 39.9 µs (9159 ticks) | PASS |
| Background CPU (worker thread, cycle-accurate) | ≤ 1% of one core | 0.380% (GetThreadTimes: 0.317%, charged to buckets: 0.341%) | PASS |
| Scan slice | ≤ 3 ms | CPU max 1.07 ms; wall max 4.09 ms, wall p99 ≤ 1.80 ms; 0 / 1013 slices over 3 ms CPU, 2 over 3 ms wall | PASS |
| Memory | ≤ 25 MB (whole SDK) | scheduler+jobs heap peak 32.2 KiB (35 allocs); private bytes delta on 0.09 MiB vs off 0.00 MiB; working-set delta 4.78 MiB | PASS |
| Frame time p99 delta | ≤ 1% | off p99 8.269 ms → on 6.580 ms (-20.43%); mean 4.260 → 4.158 ms (-2.38%); median per-block p99 4.729 → 5.123 ms (+8.34%); A/A noise p99 124.90%, mean 10.74% | NO DETECTABLE IMPACT (delta inside 124.9% A/A noise) |
| Frame attribution (same ON blocks) | slice-overlapped frames ≈ clean frames | 494 frames overlapped a slice (5.4%): mean 4.277 ms, p50 4.139, p99 7.045; 8665 clean: mean 4.152, p50 4.099, p99 6.474 (mean +3.01%, p50 +0.98%, p99 +8.82%) | info |
| Frame attribution, unbiased (frame started while a slice ran) | ≈ other frames | 94 frames: mean 4.082 ms, p50 4.093; 9065 others: mean 4.159, p50 4.101 (mean -1.86%, p50 -0.18%) | info |
| Init | ≤ 50 ms, off main thread | main-thread `start()` 0.19 ms; worker init 0.02 ms wall (0.15 ms CPU, rest is waiting at below-normal priority) | PASS |

Frames: off 9105 (p50 4.120 ms, p99.9 21.188 ms, max 29.84 ms, missed deadline 1.67%), on 9159 (p50 4.100 ms, p99.9 13.750 ms, max 28.94 ms, missed deadline 0.81%). Process CPU (whole sim, % of one core): off 221.8%, on 219.2%. Hitch-guard deferrals: 21. Findings delivered via `tick()`: 16.

Per-job stats (last ON block, 8 s):

| Job | Passes | Steps | Last pass CPU | Last pass wall | CPU % of core | Max step | Overruns | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|---|
| module_inventory | 2 | 6 | 0.21 ms | 0.2 ms | 0.0055% | 157 µs | 0 | 0 | 0 |
| memory_region_walk | 2 | 6 | 0.67 ms | 0.7 ms | 0.0161% | 474 µs | 0 | 0 | 0 |
| thread_audit | 2 | 2 | 0.06 ms | 0.1 ms | 0.0013% | 64 µs | 0 | 0 | 0 |
| text_hash | 0 | 203 | 0.00 ms | 0.0 ms | 0.3339% | 537 µs | 0 | 0 | 100 |

## Profile `lowend-2c`

simulated low-end laptop: 2 physical cores (CPU 4,6, no SMT siblings), process EcoQoS (lower clocks), 60 fps, main + 1 worker at 40% of frame, background load 2 threads x 25% duty in another process

Affinity mask `0x50`, EcoQoS on, game work rate calibrated under this profile's load: 31143 units/ms (55% of desktop), 8 pairs x 8 s blocks (ABBA order).

| Budget (G2) | Target | Measured | Result |
|---|---|---|---|
| `tick()` cost | p99 ≤ 20 µs | p50 1.10 µs, p99 7.50 µs, p99.9 28.30 µs, max 214.5 µs (3674 ticks) | PASS |
| Background CPU (worker thread, cycle-accurate) | ≤ 1% of one core | 0.385% (GetThreadTimes: 0.390%, charged to buckets: 0.343%) | PASS |
| Scan slice | ≤ 3 ms | CPU max 1.22 ms; wall max 36.24 ms, wall p99 ≤ 36.24 ms; 0 / 1009 slices over 3 ms CPU, 43 over 3 ms wall | PASS |
| Memory | ≤ 25 MB (whole SDK) | scheduler+jobs heap peak 32.2 KiB (35 allocs); private bytes delta on 0.07 MiB vs off 0.00 MiB; working-set delta 0.04 MiB | PASS |
| Frame time p99 delta | ≤ 1% | off p99 24.080 ms → on 27.971 ms (+16.16%); mean 14.293 → 14.479 ms (+1.30%); median per-block p99 20.455 → 21.393 ms (+4.59%); A/A noise p99 25.56%, mean 1.82% | NO DETECTABLE IMPACT (delta inside 25.6% A/A noise) |
| Frame attribution (same ON blocks) | slice-overlapped frames ≈ clean frames | 430 frames overlapped a slice (11.7%): mean 15.379 ms, p50 14.474, p99 39.452; 3244 clean: mean 14.359, p50 14.187, p99 27.202 (mean +7.10%, p50 +2.02%, p99 +45.03%) | info |
| Frame attribution, unbiased (frame started while a slice ran) | ≈ other frames | 36 frames: mean 14.185 ms, p50 14.097; 3638 others: mean 14.482, p50 14.223 (mean -2.05%, p50 -0.89%) | info |
| Init | ≤ 50 ms, off main thread | main-thread `start()` 0.16 ms; worker init 12.77 ms wall (0.22 ms CPU, rest is waiting at below-normal priority) | PASS |

Frames: off 3743 (p50 14.371 ms, p99.9 40.476 ms, max 55.98 ms, missed deadline 14.53%), on 3674 (p50 14.222 ms, p99.9 54.492 ms, max 274.99 ms, missed deadline 16.36%). Process CPU (whole sim, % of one core): off 130.3%, on 126.1%. Hitch-guard deferrals: 47. Findings delivered via `tick()`: 15.

Per-job stats (last ON block, 8 s):

| Job | Passes | Steps | Last pass CPU | Last pass wall | CPU % of core | Max step | Overruns | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|---|
| module_inventory | 2 | 6 | 0.28 ms | 0.3 ms | 0.0068% | 148 µs | 0 | 0 | 0 |
| memory_region_walk | 2 | 6 | 1.18 ms | 1.2 ms | 0.0236% | 778 µs | 0 | 0 | 0 |
| thread_audit | 2 | 2 | 0.09 ms | 0.1 ms | 0.0022% | 89 µs | 0 | 0 | 0 |
| text_hash | 0 | 192 | 0.00 ms | 0.0 ms | 0.3019% | 711 µs | 0 | 0 | 81 |

## Profile `lowend-1c`

worst case: 1 logical CPU (CPU 6), process EcoQoS, 60 fps, main thread only at 40% of frame, background load 1 thread x 20% duty

Affinity mask `0x40`, EcoQoS on, game work rate calibrated under this profile's load: 18574 units/ms (33% of desktop), 8 pairs x 8 s blocks (ABBA order).

| Budget (G2) | Target | Measured | Result |
|---|---|---|---|
| `tick()` cost | p99 ≤ 20 µs | p50 1.20 µs, p99 7.00 µs, p99.9 17.40 µs, max 77.1 µs (3767 ticks) | PASS |
| Background CPU (worker thread, cycle-accurate) | ≤ 1% of one core | 0.389% (GetThreadTimes: 0.488%, charged to buckets: 0.347%) | PASS |
| Scan slice | ≤ 3 ms | CPU max 1.05 ms; wall max 20.15 ms, wall p99 ≤ 20.15 ms; 0 / 974 slices over 3 ms CPU, 11 over 3 ms wall | PASS |
| Memory | ≤ 25 MB (whole SDK) | scheduler+jobs heap peak 32.2 KiB (35 allocs); private bytes delta on 0.16 MiB vs off 0.06 MiB; working-set delta 0.09 MiB | PASS |
| Frame time p99 delta | ≤ 1% | off p99 11.935 ms → on 11.477 ms (-3.84%); mean 7.438 → 7.351 ms (-1.17%); median per-block p99 11.425 → 10.761 ms (-5.81%); A/A noise p99 0.61%, mean 2.35% | PASS |
| Frame attribution (same ON blocks) | slice-overlapped frames ≈ clean frames | 9 frames overlapped a slice (0.2%): mean 6.918 ms, p50 7.783, p99 10.196; 3758 clean: mean 7.352, p50 7.597, p99 11.477 (mean -5.91%, p50 +2.45%, p99 -11.16%) | info |
| Frame attribution, unbiased (frame started while a slice ran) | ≈ other frames | 7 frames: mean 6.240 ms, p50 6.778; 3760 others: mean 7.353, p50 7.598 (mean -15.13%, p50 -10.79%) | info |
| Init | ≤ 50 ms, off main thread | main-thread `start()` 0.18 ms; worker init 8.07 ms wall (0.20 ms CPU, rest is waiting at below-normal priority) | PASS |

Frames: off 3755 (p50 7.675 ms, p99.9 16.296 ms, max 203.80 ms, missed deadline 0.11%), on 3767 (p50 7.597 ms, p99.9 12.710 ms, max 22.71 ms, missed deadline 0.03%). Process CPU (whole sim, % of one core): off 37.1%, on 39.8%. Hitch-guard deferrals: 36. Findings delivered via `tick()`: 16.

Per-job stats (last ON block, 8 s):

| Job | Passes | Steps | Last pass CPU | Last pass wall | CPU % of core | Max step | Overruns | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|---|
| module_inventory | 2 | 6 | 0.14 ms | 0.1 ms | 0.0053% | 154 µs | 0 | 0 | 0 |
| memory_region_walk | 2 | 6 | 0.92 ms | 0.9 ms | 0.0197% | 684 µs | 0 | 0 | 0 |
| thread_audit | 2 | 2 | 0.09 ms | 0.1 ms | 0.0022% | 93 µs | 0 | 0 | 0 |
| text_hash | 0 | 205 | 0.00 ms | 0.0 ms | 0.3501% | 742 µs | 0 | 0 | 76 |

## Throttling demo (30 s, desktop game load)

Standard jobs with `text_hash` made continuous (always due), plus two misbehaving modules: `misbehaving_spin_hog` declares 200 µs steps but spins 8 ms per step; `misbehaving_greedy` declares share 0.3 and a 30 ms per-pass cap but never finishes and is always due.

| Check | Expected | Measured | Result |
|---|---|---|---|
| Spin hog | backed off, quarantined after 3 strikes | overruns 3, steps 3, quarantined true, total CPU 23.1 ms | PASS |
| Greedy | ≤ its share (0.3 x 0.8% = 0.24% of a core), pass cut at 30 ms | 0.249% of a core, 2 run-budget aborts, share-throttled 479 times | PASS |
| Whole worker | ≤ 1% of one core | 0.725% (charged 0.670%; global bucket throttled 148 times) | PASS |
| Other jobs still progress | text_hash keeps hashing | text_hash 0 passes, ~32 MiB hashed, 0.324% of a core | PASS |

Slices over 3 ms CPU: 3 of 925 (the hog's overrunning steps; a cooperative step cannot be preempted, so each overrun costs one full step before the strike lands). Frame p99 during demo: 5.082 ms, tick p99 8.30 µs.

| Job | Passes | CPU % of core | Max step | Overruns | Strikes | Quarantined | Run-budget aborts | Share-throttled |
|---|---|---|---|---|---|---|---|---|
| module_inventory | 6 | 0.0041% | 151 µs | 0 | 0 | false | 0 | 0 |
| memory_region_walk | 5 | 0.0125% | 773 µs | 0 | 0 | false | 0 | 0 |
| thread_audit | 6 | 0.0026% | 275 µs | 0 | 0 | false | 0 | 0 |
| text_hash | 0 | 0.3242% | 1670 µs | 0 | 0 | false | 0 | 330 |
| misbehaving_spin_hog | 0 | 0.0772% | 7965 µs | 3 | 3 | true | 0 | 2 |
| misbehaving_greedy | 0 | 0.2492% | 321 µs | 0 | 0 | false | 2 | 479 |

