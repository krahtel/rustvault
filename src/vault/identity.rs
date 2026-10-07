use crate::crypto::error::CryptoError;
use crate::crypto::signing::{
    generate_keypair, MlDsaSigningKey, MlDsaVerifyingKey, SigningKeyPair,
};

pub struct VaultIdentity {
    signing_key: MlDsaSigningKey,
    verifying_key: MlDsaVerifyingKey,
}

impl VaultIdentity {
    pub fn generate() -> Self {
        let keypair: SigningKeyPair = generate_keypair();

        Self::from_keypair(keypair)
    }

    pub fn from_keypair(keypair: SigningKeyPair) -> Self {
        Self {
            signing_key: keypair.signing_key,
            verifying_key: keypair.verifying_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        crate::crypto::signing::sign(&self.signing_key, message)
    }

    pub fn verifying_key(&self) -> &MlDsaVerifyingKey {
        &self.verifying_key
    }

    pub fn signing_key(&self) -> &MlDsaSigningKey {
        &self.signing_key
    }

    pub fn signing_key_pair(&self) -> SigningKeyPair {
        SigningKeyPair {
            signing_key: self.signing_key.clone(),
            verifying_key: self.verifying_key.clone(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_generates_successfully() {
        let identity = VaultIdentity::generate();

        assert!(!identity.verifying_key().encode().is_empty());
    }

    #[test]
    fn identity_can_sign_and_verify() {
        let identity = VaultIdentity::generate();
        let message = b"RustVault authenticated vault root";

        let signature = identity.sign(message).expect("signing should succeed");

        assert!(!signature.is_empty());

        crate::crypto::signing::verify(identity.verifying_key(), message, &signature)
            .expect("signature verification should succeed");
    }

    #[test]
    fn identity_signature_fails_for_modified_message() {
        let identity = VaultIdentity::generate();

        let message = b"RustVault authenticated vault root";
        let modified_message = b"Modified RustVault authenticated vault root";

        let signature = identity.sign(message).expect("signing should succeed");

        assert!(crate::crypto::signing::verify(
            identity.verifying_key(),
            modified_message,
            &signature,
        )
        .is_err());
    }

    #[test]
    fn different_identities_have_different_verifying_keys() {
        let identity_a = VaultIdentity::generate();
        let identity_b = VaultIdentity::generate();

        assert_ne!(
            identity_a.verifying_key().encode(),
            identity_b.verifying_key().encode()
        );
    }
}
