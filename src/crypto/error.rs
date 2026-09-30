use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidNonceLength,
    EncryptionFailed,
    DecryptionFailed,
    RandomGenerationFailed,
    KdfFailed,
    HkdfFailed,
    VaultNotUnlocked,
    DocumentNotFound,
    StorageUnavailable,
    IpfsConnectionFailed,
    IpfsOperationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeyLength => {
                write!(f, "Invalid cryptographic key length")
            }

            CryptoError::InvalidNonceLength => {
                write!(f, "Invalid cryptographic nonce length")
            }

            CryptoError::EncryptionFailed => {
                write!(f, "Encryption failed")
            }

            CryptoError::DecryptionFailed => {
                write!(f, "Decryption failed")
            }

            CryptoError::RandomGenerationFailed => {
                write!(f, "Secure random generation failed")
            }

            CryptoError::KdfFailed => {
                write!(f, "Key derivation failed")
            }

            CryptoError::HkdfFailed => {
                write!(f, "HKDF key derivation failed")
            }

            CryptoError::VaultNotUnlocked => {
                write!(f, "Vault is locked")
            }

            CryptoError::DocumentNotFound => {
                write!(f, "Document not found")
            }

            CryptoError::StorageUnavailable => {
                write!(f, "Vault storage is unavailable")
            }
            CryptoError::IpfsConnectionFailed => {
                write!(f, "Failed to connect to IPFS")
            }

            CryptoError::IpfsOperationFailed => {
                write!(f, "IPFS operation failed")
            }
        }
    }
}

impl std::error::Error for CryptoError {}
