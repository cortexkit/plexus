//! Exponential backoff for retry loops.
//!
//! Callers choose their own base, how many doublings count, and the cap: a
//! subscription poll, a reconnect and a reconciliation retry back off over
//! very different time scales. The doubling arithmetic, and keeping it from
//! overflowing, lives here once.

/// `base_ms` doubled once per failure, counting at most `max_doublings`
/// failures, and never more than `cap_ms`. Saturates instead of overflowing,
/// so any failure count is safe.
pub fn doubling_ms(base_ms: u64, failures: u32, max_doublings: u32, cap_ms: u64) -> u64 {
    let factor = 1u64
        .checked_shl(failures.min(max_doublings))
        .unwrap_or(u64::MAX);
    base_ms.saturating_mul(factor).min(cap_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_per_failure_up_to_the_doubling_limit_and_the_cap() {
        let steps: Vec<u64> = (0..10).map(|n| doubling_ms(5, n, 4, 60)).collect();
        assert_eq!(
            steps,
            [5, 10, 20, 40, 60, 60, 60, 60, 60, 60],
            "backoff step"
        );
        let steps: Vec<u64> = (0..10).map(|n| doubling_ms(1, n, 3, 1_000)).collect();
        assert_eq!(steps, [1, 2, 4, 8, 8, 8, 8, 8, 8, 8]);
        // Exponents past the width of u64 and products past u64::MAX saturate.
        assert_eq!(doubling_ms(3, 63, 63, u64::MAX), u64::MAX);
        assert_eq!(doubling_ms(1, 63, 63, u64::MAX), 1 << 63);
        assert_eq!(doubling_ms(1, 64, 64, u64::MAX), u64::MAX);
        assert_eq!(doubling_ms(u64::MAX, u32::MAX, u32::MAX, 7), 7);
        assert_eq!(doubling_ms(0, 10, 10, 7), 0);
    }
}
