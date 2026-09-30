use ml_dsa::{
    Generate, Keypair, MlDsa65, Signature, SignatureEncoding, Signer, SigningKey, Verifier,
    VerifyingKey,
};

use crate::crypto::error::CryptoError;

pub type MlDsaSigningKey = SigningKey<MlDsa65>;
pub type MlDsaVerifyingKey = VerifyingKey<MlDsa65>;
pub type MlDsaSignature = Signature<MlDsa65>;

pub struct SigningKeyPair {
    pub signing_key: MlDsaSigningKey,
    pub verifying_key: MlDsaVerifyingKey,
}

impl SigningKeyPair {
    pub fn generate() -> Self {
        let signing_key = MlDsaSigningKey::generate();
        let verifying_key = signing_key.verifying_key().clone();

        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature = self
            .signing_key
            .try_sign(message)
            .map_err(|_| CryptoError::SigningFailed)?;

        Ok(signature.to_vec())
    }

    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<(), CryptoError> {
        let signature =
            MlDsaSignature::try_from(signature_bytes).map_err(|_| CryptoError::InvalidSignature)?;

        self.verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

pub fn generate_keypair() -> SigningKeyPair {
    SigningKeyPair::generate()
}

pub fn sign(signing_key: &MlDsaSigningKey, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature = signing_key
        .try_sign(message)
        .map_err(|_| CryptoError::SigningFailed)?;

    Ok(signature.to_vec())
}

pub fn verify(
    verifying_key: &MlDsaVerifyingKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), CryptoError> {
    let signature =
        MlDsaSignature::try_from(signature_bytes).map_err(|_| CryptoError::InvalidSignature)?;

    verifying_key
        .verify(message, &signature)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_creates_signing_and_verifying_keys() {
        let keypair = generate_keypair();

        let message = b"RustVault ML-DSA test message";

        let signature = keypair.sign(message).expect("failed to sign message");

        assert!(!signature.is_empty());
    }

    #[test]
    fn valid_signature_verifies() {
        let keypair = generate_keypair();

        let message = b"RustVault authentication test";

        let signature = keypair.sign(message).expect("failed to sign message");

        keypair
            .verify(message, &signature)
            .expect("valid signature failed verification");
    }

    #[test]
    fn modified_message_fails_verification() {
        let keypair = generate_keypair();

        let message = b"original vault root";
        let modified_message = b"modified vault root";

        let signature = keypair.sign(message).expect("failed to sign message");

        let result = keypair.verify(modified_message, &signature);

        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn modified_signature_fails_verification() {
        let keypair = generate_keypair();

        let message = b"RustVault signed data";

        let mut signature = keypair.sign(message).expect("failed to sign message");

        signature[0] ^= 0x01;

        let result = keypair.verify(message, &signature);

        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed) | Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn wrong_verifying_key_fails_verification() {
        let keypair_a = generate_keypair();
        let keypair_b = generate_keypair();

        let message = b"RustVault protected message";

        let signature = keypair_a.sign(message).expect("failed to sign message");

        let result = keypair_b.verify(message, &signature);

        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn empty_signature_is_rejected() {
        let keypair = generate_keypair();

        let message = b"RustVault message";

        let result = keypair.verify(message, &[]);

        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn standalone_sign_and_verify_work() {
        let keypair = generate_keypair();

        let message = b"standalone signing API";

        let signature = sign(&keypair.signing_key, message).expect("failed to sign message");

        verify(&keypair.verifying_key, message, &signature).expect("failed to verify signature");
    }
}
