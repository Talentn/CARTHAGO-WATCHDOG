/// CPU token bucket measured in nanoseconds of CPU time.
///
/// Charges are applied after the fact and may drive the bucket negative: an overrun becomes
/// debt that must be repaid before the next slice, so the long-run average holds even when a
/// single step blows its budget.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last_ns: u64,
}

impl TokenBucket {
    /// `rate` is CPU-ns granted per wall-ns (0.01 = 1% of one core).
    pub fn new(rate: f64, capacity_ns: f64, now_ns: u64) -> Self {
        Self { rate, capacity: capacity_ns, tokens: capacity_ns, last_ns: now_ns }
    }

    pub fn refill(&mut self, now_ns: u64) {
        let dt = now_ns.saturating_sub(self.last_ns) as f64;
        self.tokens = (self.tokens + dt * self.rate).min(self.capacity);
        self.last_ns = now_ns;
    }

    pub fn charge(&mut self, cpu_ns: u64) {
        self.tokens -= cpu_ns as f64;
    }

    pub fn tokens(&self) -> f64 {
        self.tokens
    }

    pub fn is_full(&self) -> bool {
        self.tokens >= self.capacity
    }

    pub fn set_rate(&mut self, rate: f64) {
        self.rate = rate;
    }

    /// Wall nanoseconds until the bucket holds at least `level` tokens.
    pub fn ns_until(&self, level: f64) -> u64 {
        if self.tokens >= level {
            0
        } else if self.rate <= 0.0 {
            u64::MAX
        } else {
            ((level - self.tokens) / self.rate).ceil() as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refills_at_rate_and_caps() {
        let mut b = TokenBucket::new(0.01, 3_000_000.0, 0);
        b.charge(3_000_000);
        assert_eq!(b.tokens(), 0.0);
        b.refill(100_000_000);
        assert!((b.tokens() - 1_000_000.0).abs() < 1.0);
        b.refill(10_000_000_000);
        assert_eq!(b.tokens(), 3_000_000.0);
    }

    #[test]
    fn overrun_becomes_debt() {
        let mut b = TokenBucket::new(0.01, 3_000_000.0, 0);
        b.charge(13_000_000);
        assert_eq!(b.tokens(), -10_000_000.0);
        assert_eq!(b.ns_until(0.0), 1_000_000_000);
    }
}
