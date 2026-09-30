use crate::crypto::error::CryptoError;
use rand::rngs::SysRng;
use rand::TryRng;

/// Generate cryptographically secure random bytes.
pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; len];

    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_requested_number_of_bytes() {
        let bytes = random_bytes(32).unwrap();

        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn generates_different_random_values() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();

        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn supports_zero_length_request() {
        let bytes = random_bytes(0).unwrap();

        assert!(bytes.is_empty());
    }
}
