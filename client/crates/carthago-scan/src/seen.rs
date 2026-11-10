//! Bounded "already reported" set, so a scanner reports each observation once per session
//! instead of once per pass (keeps heartbeats under the network budget).

pub fn fnv1a(parts: &[&[u8]]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for p in parts {
        for &b in *p {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

pub struct Seen {
    keys: Vec<u64>,
    cap: usize,
}

impl Seen {
    pub fn new(cap: usize) -> Self {
        Self { keys: Vec::with_capacity(cap.min(64)), cap }
    }

    /// True the first time a key is seen. When full, the oldest key is forgotten, so a
    /// long-lived observation can be reported again (the server deduplicates too).
    pub fn first(&mut self, key: u64) -> bool {
        if self.keys.contains(&key) {
            return false;
        }
        if self.keys.len() == self.cap {
            self.keys.remove(0);
        }
        self.keys.push(key);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_once_and_evicts_oldest() {
        let mut s = Seen::new(2);
        assert!(s.first(1));
        assert!(!s.first(1));
        assert!(s.first(2));
        assert!(s.first(3));
        assert!(s.first(1), "1 was evicted");
        assert!(!s.first(3));
    }

    #[test]
    fn hash_separates_parts() {
        assert_ne!(fnv1a(&[b"ab", b"c"]), fnv1a(&[b"a", b"bc"]));
        assert_eq!(fnv1a(&[b"x"]), fnv1a(&[b"x"]));
    }
}
