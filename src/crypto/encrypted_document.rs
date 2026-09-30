use crate::crypto::document::{decrypt_document, encrypt_document, generate_document_key};
use crate::crypto::encryption::EncryptedData;
use crate::crypto::error::CryptoError;
use crate::crypto::key_wrap::{unwrap_document_key, wrap_document_key, WrappingKey};
use serde::{Deserialize, Serialize};

pub const ENCRYPTED_DOCUMENT_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedDocument {
    pub version: u8,
    pub content: EncryptedData,
    pub wrapped_document_key: EncryptedData,
}

impl EncryptedDocument {
    pub fn encrypt(wrapping_key: &WrappingKey, plaintext: &[u8]) -> Result<Self, CryptoError> {
        let document_key = generate_document_key()?;

        let content = encrypt_document(&document_key, plaintext)?;

        let wrapped_document_key = wrap_document_key(wrapping_key, &document_key)?;

        Ok(Self {
            version: ENCRYPTED_DOCUMENT_VERSION,
            content,
            wrapped_document_key,
        })
    }

    pub fn decrypt(&self, wrapping_key: &WrappingKey) -> Result<Vec<u8>, CryptoError> {
        let document_key = unwrap_document_key(wrapping_key, &self.wrapped_document_key)?;

        decrypt_document(&document_key, &self.content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::document::generate_document_key;

    #[test]
    fn encrypted_document_roundtrip() {
        let wrapping_key = generate_document_key().expect("key generation should succeed");

        let plaintext = b"secret document";

        let encrypted = EncryptedDocument::encrypt(&wrapping_key, plaintext)
            .expect("encryption should succeed");

        let decrypted = encrypted
            .decrypt(&wrapping_key)
            .expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypted_document_has_correct_version() {
        let wrapping_key = generate_document_key().expect("key generation should succeed");

        let encrypted = EncryptedDocument::encrypt(&wrapping_key, b"secret")
            .expect("encryption should succeed");

        assert_eq!(encrypted.version, ENCRYPTED_DOCUMENT_VERSION);
    }

    #[test]
    fn different_documents_have_different_content_nonces() {
        let wrapping_key = generate_document_key().expect("key generation should succeed");

        let document1 = EncryptedDocument::encrypt(&wrapping_key, b"same plaintext")
            .expect("encryption should succeed");

        let document2 = EncryptedDocument::encrypt(&wrapping_key, b"same plaintext")
            .expect("encryption should succeed");

        assert_ne!(document1.content.nonce, document2.content.nonce);
    }

    #[test]
    fn different_documents_have_different_wrapping_nonces() {
        let wrapping_key = generate_document_key().expect("key generation should succeed");

        let document1 = EncryptedDocument::encrypt(&wrapping_key, b"same plaintext")
            .expect("encryption should succeed");

        let document2 = EncryptedDocument::encrypt(&wrapping_key, b"same plaintext")
            .expect("encryption should succeed");

        assert_ne!(
            document1.wrapped_document_key.nonce,
            document2.wrapped_document_key.nonce
        );
    }

    #[test]
    fn wrong_wrapping_key_fails() {
        let wrapping_key = generate_document_key().expect("key generation should succeed");

        let wrong_key = generate_document_key().expect("key generation should succeed");

        let encrypted = EncryptedDocument::encrypt(&wrapping_key, b"secret")
            .expect("encryption should succeed");

        let result = encrypted.decrypt(&wrong_key);

        assert!(result.is_err());
    }

    #[test]
    fn modified_document_ciphertext_fails() {
        let wrapping_key = generate_document_key().expect("key generation should succeed");

        let mut encrypted = EncryptedDocument::encrypt(&wrapping_key, b"secret")
            .expect("encryption should succeed");

        encrypted.content.ciphertext[0] ^= 0x01;

        let result = encrypted.decrypt(&wrapping_key);

        assert!(result.is_err());
    }

    #[test]
    fn modified_wrapped_key_fails() {
        let wrapping_key = generate_document_key().expect("key generation should succeed");

        let mut encrypted = EncryptedDocument::encrypt(&wrapping_key, b"secret")
            .expect("encryption should succeed");

        encrypted.wrapped_document_key.ciphertext[0] ^= 0x01;

        let result = encrypted.decrypt(&wrapping_key);

        assert!(result.is_err());
    }
}
