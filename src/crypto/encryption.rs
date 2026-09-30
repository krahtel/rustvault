use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::rngs::SysRng;
use rand::TryRng;

use crate::crypto::error::CryptoError;

pub const NONCE_LEN: usize = 12;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
    let key = Key::<Aes256Gcm>::try_from(key_bytes.as_slice())
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; NONCE_LEN];

    SysRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;

    let nonce =
        Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::InvalidNonceLength)?;

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptedData {
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn decrypt(key_bytes: &[u8; 32], encrypted: &EncryptedData) -> Result<Vec<u8>, CryptoError> {
    let key = Key::<Aes256Gcm>::try_from(key_bytes.as_slice())
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    let cipher = Aes256Gcm::new(&key);

    let nonce =
        Nonce::try_from(encrypted.nonce.as_slice()).map_err(|_| CryptoError::InvalidNonceLength)?;

    cipher
        .decrypt(&nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)
}
