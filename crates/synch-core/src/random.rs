//! A cheap non-cryptographic random source, for jitter and tiebreaks.
//!
//! Nothing here is a secret: the values order providers and spread timers, so
//! predictability costs nothing and a real generator would buy nothing. One
//! implementation serves every caller.

/// Seeds the generator from the clock.
pub fn xorshift_seed() -> u64 {
    (crate::now_ns() as u64) ^ 0x9e37_79b9_7f4a_7c15
}

/// Advances the state (xorshift64*) and returns the new value.
pub fn xorshift_next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sequence_advances() {
        let mut state = xorshift_seed();
        let a = xorshift_next(&mut state);
        let b = xorshift_next(&mut state);
        assert_ne!(a, b);
    }
}
