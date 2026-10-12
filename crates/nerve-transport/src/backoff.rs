//! Reconnect waits (docs/dev/spec/protocol.md §4.6): 1 s doubling to 60 s, up to
//! a tenth taken off at random so many nodes do not dial in step, reset once a
//! link lasted 60 s.

use std::time::Duration;

pub const FIRST: Duration = Duration::from_secs(1);
pub const MAX: Duration = Duration::from_secs(60);
/// A link that lasted this long resets the backoff.
pub const STABLE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Backoff {
        Backoff { next: FIRST }
    }
}

impl Backoff {
    /// The wait before the next attempt; doubles the one after it.
    pub fn next_wait(&mut self) -> Duration {
        let base = self.next;
        self.next = (self.next * 2).min(MAX);
        let r = crate::keys::random_bytes(2);
        let frac = u16::from_be_bytes([r[0], r[1]]) as u64; // 0..65535
        let cut = base.as_millis() as u64 * frac / 65535 / 10;
        base - Duration::from_millis(cut)
    }

    /// Called when a link ends after it lasted `lasted`.
    pub fn link_ended(&mut self, lasted: Duration) {
        if lasted >= STABLE {
            self.next = FIRST;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_with_jitter_and_resets() {
        let mut b = Backoff::default();
        let waits: Vec<Duration> = (0..9).map(|_| b.next_wait()).collect();
        for (w, base) in waits.iter().zip([1u64, 2, 4, 8, 16, 32, 60, 60, 60]) {
            let base = Duration::from_secs(base);
            assert!(*w <= base && *w >= base - base / 10, "{w:?} vs {base:?}");
        }
        b.link_ended(Duration::from_secs(5));
        assert!(b.next_wait() > Duration::from_secs(50));
        b.link_ended(Duration::from_secs(61));
        assert!(b.next_wait() <= FIRST);
    }
}
