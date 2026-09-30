use crate::crypto::encryption::{decrypt, encrypt, EncryptedData};
use crate::crypto::error::CryptoError;
use crate::crypto::random::random_bytes;

pub const DOCUMENT_KEY_LEN: usize = 32;

/// A randomly generated AES-256 key used exclusively
/// for one document.
pub type DocumentKey = [u8; DOCUMENT_KEY_LEN];

/// Generate a fresh random AES-256 key for a document.
pub fn generate_document_key() -> Result<DocumentKey, CryptoError> {
    let bytes = random_bytes(DOCUMENT_KEY_LEN)?;

    let mut key = [0u8; DOCUMENT_KEY_LEN];
    key.copy_from_slice(&bytes);

    Ok(key)
}

/// Encrypt a document using its dedicated document key.
pub fn encrypt_document(
    document_key: &DocumentKey,
    plaintext: &[u8],
) -> Result<EncryptedData, CryptoError> {
    encrypt(document_key, plaintext)
}

/// Decrypt a document using its dedicated document key.
pub fn decrypt_document(
    document_key: &DocumentKey,
    encrypted: &EncryptedData,
) -> Result<Vec<u8>, CryptoError> {
    decrypt(document_key, encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_document_key_has_correct_length() {
        let key = generate_document_key().unwrap();

        assert_eq!(key.len(), DOCUMENT_KEY_LEN);
    }

    #[test]
    fn generated_document_keys_are_different() {
        let key1 = generate_document_key().unwrap();
        let key2 = generate_document_key().unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn document_encryption_roundtrip() {
        let key = generate_document_key().unwrap();

        let plaintext = b"This is a secret RustVault document.";

        let encrypted = encrypt_document(&key, plaintext).unwrap();

        let decrypted = decrypt_document(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_document_key_cannot_decrypt() {
        let key = generate_document_key().unwrap();
        let wrong_key = generate_document_key().unwrap();

        let plaintext = b"Highly confidential document.";

        let encrypted = encrypt_document(&key, plaintext).unwrap();

        let result = decrypt_document(&wrong_key, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn different_documents_use_different_keys() {
        let key1 = generate_document_key().unwrap();
        let key2 = generate_document_key().unwrap();

        assert_ne!(key1, key2);
    }
}
