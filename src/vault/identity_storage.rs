use crate::crypto::encryption::{decrypt, encrypt, EncryptedData};
use crate::crypto::error::CryptoError;
use crate::crypto::key_derivation::KEY_LEN;
use crate::crypto::signing::{MlDsaSigningKey, MlDsaVerifyingKey, SigningKeyPair};
pub struct ProtectedVaultIdentity {
    encrypted_seed: EncryptedData,
    verifying_key: Vec<u8>,
}

impl ProtectedVaultIdentity {
    pub fn protect(key: &[u8; KEY_LEN], identity: &SigningKeyPair) -> Result<Self, CryptoError> {
        let seed = identity.signing_key.to_seed();

        let encrypted_seed = encrypt(key, seed.as_ref())?;

        let verifying_key = identity.verifying_key.encode().to_vec();

        Ok(Self {
            encrypted_seed,
            verifying_key,
        })
    }

    pub fn encrypted_seed(&self) -> &EncryptedData {
        &self.encrypted_seed
    }

    pub fn verifying_key_bytes(&self) -> &[u8] {
        &self.verifying_key
    }

    pub fn unlock_signing_key(&self, key: &[u8; KEY_LEN]) -> Result<MlDsaSigningKey, CryptoError> {
        let seed = decrypt(key, &self.encrypted_seed)?;

        let seed: ml_dsa::Seed = seed
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;

        Ok(MlDsaSigningKey::from_seed(&seed))
    }

    pub fn verifying_key(&self) -> Result<MlDsaVerifyingKey, CryptoError> {
        Ok(MlDsaVerifyingKey::decode(
            self.verifying_key
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeyLength)?,
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::key_derivation::KEY_LEN;
    use crate::crypto::signing::{generate_keypair, verify};

    use ml_dsa::Keypair;

    fn test_key() -> [u8; KEY_LEN] {
        [0x42u8; KEY_LEN]
    }

    fn different_key() -> [u8; KEY_LEN] {
        [0x24u8; KEY_LEN]
    }

    #[test]
    fn identity_can_be_protected() {
        let identity = generate_keypair();
        let key = test_key();

        let protected = ProtectedVaultIdentity::protect(&key, &identity)
            .expect("identity protection should succeed");

        assert!(!protected.encrypted_seed().ciphertext.is_empty());
        assert!(!protected.verifying_key_bytes().is_empty());
    }

    #[test]
    fn protected_identity_can_be_unlocked() {
        let identity = generate_keypair();
        let key = test_key();

        let protected = ProtectedVaultIdentity::protect(&key, &identity)
            .expect("identity protection should succeed");

        let restored_signing_key = protected
            .unlock_signing_key(&key)
            .expect("identity should unlock");

        let restored_verifying_key = restored_signing_key.verifying_key();

        assert_eq!(
            restored_verifying_key.encode(),
            identity.verifying_key.encode()
        );
    }

    #[test]
    fn wrong_key_cannot_unlock_identity() {
        let identity = generate_keypair();
        let key = test_key();
        let wrong_key = different_key();

        let protected = ProtectedVaultIdentity::protect(&key, &identity)
            .expect("identity protection should succeed");

        assert!(protected.unlock_signing_key(&wrong_key).is_err());
    }

    #[test]
    fn tampered_encrypted_seed_cannot_unlock_identity() {
        let identity = generate_keypair();
        let key = test_key();

        let mut protected = ProtectedVaultIdentity::protect(&key, &identity)
            .expect("identity protection should succeed");

        protected.encrypted_seed.ciphertext[0] ^= 0x01;

        assert!(protected.unlock_signing_key(&key).is_err());
    }

    #[test]
    fn restored_signing_key_can_sign() {
        let identity = generate_keypair();
        let key = test_key();

        let protected = ProtectedVaultIdentity::protect(&key, &identity)
            .expect("identity protection should succeed");

        let restored_signing_key = protected
            .unlock_signing_key(&key)
            .expect("identity should unlock");

        let message = b"RustVault identity test";

        let signature = crate::crypto::signing::sign(&restored_signing_key, message)
            .expect("restored signing key should sign");

        assert!(!signature.is_empty());
    }

    #[test]
    fn restored_signing_key_matches_original_identity() {
        let identity = generate_keypair();
        let key = test_key();

        let protected = ProtectedVaultIdentity::protect(&key, &identity)
            .expect("identity protection should succeed");

        let restored_signing_key = protected
            .unlock_signing_key(&key)
            .expect("identity should unlock");

        let message = b"RustVault identity verification";

        let signature = crate::crypto::signing::sign(&restored_signing_key, message)
            .expect("restored signing key should sign");

        verify(&identity.verifying_key, message, &signature)
            .expect("original verifying key should verify restored signature");
    }

    #[test]
    fn different_identities_have_different_protected_seeds() {
        let identity_a = generate_keypair();
        let identity_b = generate_keypair();
        let key = test_key();

        let protected_a = ProtectedVaultIdentity::protect(&key, &identity_a)
            .expect("identity A protection should succeed");

        let protected_b = ProtectedVaultIdentity::protect(&key, &identity_b)
            .expect("identity B protection should succeed");

        assert_ne!(
            protected_a.encrypted_seed().ciphertext,
            protected_b.encrypted_seed().ciphertext
        );

        assert_ne!(
            protected_a.verifying_key_bytes(),
            protected_b.verifying_key_bytes()
        );
    }

    #[test]
    fn verifying_key_can_be_restored() {
        let identity = generate_keypair();
        let key = test_key();

        let protected = ProtectedVaultIdentity::protect(&key, &identity)
            .expect("identity protection should succeed");

        let restored_verifying_key = protected
            .verifying_key()
            .expect("verifying key should restore");

        assert_eq!(
            restored_verifying_key.encode(),
            identity.verifying_key.encode()
        );
    }
}
