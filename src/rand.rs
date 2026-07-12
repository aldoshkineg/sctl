//! Cryptographically-secure random secret generation.

use rand::Rng;
use rand::rng;
use zeroize::Zeroizing;

/// Generate `len` cryptographically-secure random bytes, returned in a
/// `Zeroizing` container so the buffer is wiped on drop.
pub fn random_secret(len: usize) -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    rng().fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_secret_length_and_uniqueness() {
        let a = random_secret(32);
        assert_eq!(a.len(), 32);
        // Zero probability of collision for 32 random bytes.
        let b = random_secret(32);
        assert_ne!(a.as_slice(), b.as_slice());
    }
}
