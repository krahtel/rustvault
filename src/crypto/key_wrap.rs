use crate::crypto::encryption::{decrypt, encrypt, EncryptedData};
use crate::crypto::error::CryptoError;

pub const WRAPPING_KEY_LEN: usize = 32;

pub type WrappingKey = [u8; WRAPPING_KEY_LEN];

pub type DocumentKey = [u8; WRAPPING_KEY_LEN];

/// Wrap a document encryption key using the vault's
/// document key-encryption key (KEK).
pub fn wrap_document_key(
    wrapping_key: &WrappingKey,
    document_key: &DocumentKey,
) -> Result<EncryptedData, CryptoError> {
    encrypt(wrapping_key, document_key)
}

/// Unwrap a document encryption key using the vault's
/// document key-encryption key (KEK).
pub fn unwrap_document_key(
    wrapping_key: &WrappingKey,
    wrapped_key: &EncryptedData,
) -> Result<DocumentKey, CryptoError> {
    let plaintext = decrypt(wrapping_key, wrapped_key)?;

    if plaintext.len() != WRAPPING_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }

    let mut document_key = [0u8; WRAPPING_KEY_LEN];

    document_key.copy_from_slice(&plaintext);

    Ok(document_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::document::generate_document_key;

    fn generate_wrapping_key() -> WrappingKey {
        generate_document_key().unwrap()
    }

    #[test]
    fn document_key_wrap_unwrap_roundtrip() {
        let wrapping_key = generate_wrapping_key();
        let document_key = generate_document_key().unwrap();

        let wrapped = wrap_document_key(&wrapping_key, &document_key).unwrap();

        let unwrapped = unwrap_document_key(&wrapping_key, &wrapped).unwrap();

        assert_eq!(document_key, unwrapped);
    }

    #[test]
    fn wrong_wrapping_key_cannot_unwrap_document_key() {
        let wrapping_key = generate_wrapping_key();
        let wrong_wrapping_key = generate_wrapping_key();
        let document_key = generate_document_key().unwrap();

        let wrapped = wrap_document_key(&wrapping_key, &document_key).unwrap();

        let result = unwrap_document_key(&wrong_wrapping_key, &wrapped);

        assert!(result.is_err());
    }

    #[test]
    fn wrapped_keys_use_different_nonces() {
        let wrapping_key = generate_wrapping_key();
        let document_key = generate_document_key().unwrap();

        let wrapped1 = wrap_document_key(&wrapping_key, &document_key).unwrap();

        let wrapped2 = wrap_document_key(&wrapping_key, &document_key).unwrap();

        assert_ne!(wrapped1.nonce, wrapped2.nonce);
    }

    #[test]
    fn modified_wrapped_key_fails() {
        let wrapping_key = generate_wrapping_key();
        let document_key = generate_document_key().unwrap();

        let mut wrapped = wrap_document_key(&wrapping_key, &document_key).unwrap();

        wrapped.ciphertext[0] ^= 0x01;

        let result = unwrap_document_key(&wrapping_key, &wrapped);

        assert!(result.is_err());
    }

    #[test]
    fn different_document_keys_produce_different_wrapped_keys() {
        let wrapping_key = generate_wrapping_key();

        let document_key1 = generate_document_key().unwrap();
        let document_key2 = generate_document_key().unwrap();

        let wrapped1 = wrap_document_key(&wrapping_key, &document_key1).unwrap();

        let wrapped2 = wrap_document_key(&wrapping_key, &document_key2).unwrap();

        assert_ne!(wrapped1.ciphertext, wrapped2.ciphertext);
    }
}
