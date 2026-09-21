//! Randomness. Only the OS CSPRNG is used, and only where genuine randomness
//! is required: the root secret and release identifiers. Everything that has to
//! be reproducible (which sites get picked, which variant encodes them) is
//! derived from keys instead — see `swp-embedding`.

use swp_core::error::{ErrorCode, SwpError};

/// Fill `buf` from the operating system CSPRNG (`BCryptGenRandom` on Windows,
/// `getrandom(2)` on Unix).
fn fill(buf: &mut [u8]) -> Result<(), SwpError> {
    getrandom::fill(buf).map_err(|e| {
        SwpError::new(
            ErrorCode::SecretUnavailable,
            format!("the operating system random source failed: {e}"),
        )
    })
}

pub fn random_array<const N: usize>() -> Result<[u8; N], SwpError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

pub fn random_vec(len: usize) -> Result<Vec<u8>, SwpError> {
    let mut out = vec![0u8; len];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn outputs_differ_across_calls() {
        let a = random_array::<32>().unwrap();
        let b = random_array::<32>().unwrap();
        assert_ne!(a, b, "two CSPRNG draws were identical");
        assert_ne!(random_vec(16).unwrap(), random_vec(16).unwrap());
    }

    #[test]
    fn draws_have_no_obvious_structure() {
        // 256 independent 32-byte draws: all distinct, and each byte position
        // should show plenty of variety. A stubbed or time-seeded generator
        // fails this immediately.
        let mut seen = BTreeSet::new();
        let mut zeros = 0usize;
        for _ in 0..256 {
            let d = random_array::<32>().unwrap();
            assert!(seen.insert(d));
            zeros += d.iter().filter(|b| **b == 0).count();
        }
        assert_eq!(seen.len(), 256);
        // 8192 bytes at 1/256 per value expects ~32 zeros with σ≈5.7, so this
        // band is >5σ wide on both sides: it catches an all-zero, all-same or
        // small-alphabet generator without being flaky.
        assert!(zeros > 4 && zeros < 200, "unexpected zero density: {zeros}");
    }

    #[test]
    fn zero_length_is_fine() {
        assert_eq!(random_vec(0).unwrap().len(), 0);
    }
}
