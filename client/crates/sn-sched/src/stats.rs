/// Fixed-size linear histogram (no allocation on the worker): 50 µs buckets up to 4 ms,
/// plus an overflow bucket.
#[derive(Debug, Clone)]
pub struct Histogram {
    buckets: [u32; Self::N + 1],
    pub count: u64,
    pub sum_ns: u64,
    pub max_ns: u64,
}

impl Histogram {
    const N: usize = 80;
    const WIDTH_NS: u64 = 50_000;

    pub fn record(&mut self, ns: u64) {
        let i = ((ns / Self::WIDTH_NS) as usize).min(Self::N);
        self.buckets[i] += 1;
        self.count += 1;
        self.sum_ns += ns;
        self.max_ns = self.max_ns.max(ns);
    }

    /// Upper bound of the bucket holding the p-th percentile (exact max for p = 100).
    pub fn percentile_ns(&self, p: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let target = ((p / 100.0) * self.count as f64).ceil().max(1.0) as u64;
        let mut seen = 0u64;
        for (i, &c) in self.buckets.iter().enumerate() {
            seen += c as u64;
            if seen >= target {
                return if i == Self::N { self.max_ns } else { ((i as u64 + 1) * Self::WIDTH_NS).min(self.max_ns) };
            }
        }
        self.max_ns
    }

    pub fn count_above(&self, ns: u64) -> u64 {
        let first = (ns / Self::WIDTH_NS) as usize;
        self.buckets[first.min(Self::N)..].iter().map(|&c| c as u64).sum()
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self { buckets: [0; Self::N + 1], count: 0, sum_ns: 0, max_ns: 0 }
    }
}

#[derive(Debug, Clone, Default)]
pub struct JobStats {
    pub name: &'static str,
    pub runs_completed: u64,
    /// Passes cut off because they exceeded `max_cpu_per_run`.
    pub runs_aborted_budget: u64,
    /// Steps that exceeded the declared `max_step` (with grace) or the slice hard cap.
    pub overruns: u64,
    pub strikes: u32,
    pub quarantined: bool,
    /// Times this job was due but held back by its own share bucket.
    pub share_throttled: u64,
    pub steps: u64,
    pub slices: u64,
    pub cpu_ns: u64,
    pub max_step_cpu_ns: u64,
    pub last_pass_cpu_ns: u64,
    pub last_pass_wall_ns: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SchedStats {
    pub slices: u64,
    pub slice_wall: Histogram,
    pub slice_cpu: Histogram,
    /// CPU charged to buckets (sum of slice CPU).
    pub charged_cpu_ns: u64,
    /// Worker thread cycles since start, converted to ns (includes idle-loop bookkeeping).
    pub worker_cpu_ns: u64,
    pub wakeups: u64,
    pub hitch_deferrals: u64,
    pub global_throttled: u64,
    pub findings_dropped: u64,
    pub cycles_per_ns: f64,
    /// Worker-side startup (thread config + cycle calibration), wall and CPU.
    pub worker_init_ns: u64,
    pub worker_init_cpu_ns: u64,
    pub jobs: Vec<JobStats>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles() {
        let mut h = Histogram::default();
        for i in 0..100 {
            h.record(i * 10_000);
        }
        h.record(10_000_000);
        assert_eq!(h.percentile_ns(100.0), 10_000_000);
        assert_eq!(h.percentile_ns(50.0), 550_000);
        assert_eq!(h.count_above(3_000_000), 1);
    }
}
