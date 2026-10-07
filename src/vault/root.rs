use ml_dsa::Keypair;
use serde::{Deserialize, Serialize};

use crate::crypto::error::CryptoError;
use crate::crypto::signing::{sign, verify, MlDsaSigningKey, MlDsaVerifyingKey};
use crate::vault::identity::VaultIdentity;

pub const VAULT_ROOT_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultRoot {
    pub version: u8,
    pub manifest_cid: String,
    pub identity_cid: String,
    pub vault_id: String,

    /// ML-DSA-65 public verification key.
    pub verifying_key: Vec<u8>,

    /// ML-DSA signature over the root contents.
    pub signature: Vec<u8>,
}

/// Only these fields are signed.
///
/// The signature and public key are deliberately excluded from the
/// signed payload.
#[derive(Debug, Clone, Serialize)]
struct SignableVaultRoot<'a> {
    version: u8,
    manifest_cid: &'a str,
    identity_cid: &'a str,
    vault_id: &'a str,
}

impl VaultRoot {
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn identity_cid(&self) -> &str {
        &self.identity_cid
    }

    pub fn create_from_identity(
        vault_id: impl Into<String>,
        manifest_cid: impl Into<String>,
        identity_cid: impl Into<String>,
        identity: &VaultIdentity,
    ) -> Result<Self, CryptoError> {
        let vault_id = vault_id.into();
        let manifest_cid = manifest_cid.into();
        let identity_cid = identity_cid.into();

        if vault_id.trim().is_empty()
            || manifest_cid.trim().is_empty()
            || identity_cid.trim().is_empty()
        {
            return Err(CryptoError::InvalidVaultRoot);
        }

        let signable = SignableVaultRoot {
            version: VAULT_ROOT_VERSION,
            manifest_cid: &manifest_cid,
            identity_cid: &identity_cid,
            vault_id: &vault_id,
        };

        let signable_bytes =
            serde_json::to_vec(&signable).map_err(|_| CryptoError::InvalidVaultRoot)?;

        let signature = identity.sign(&signable_bytes)?;

        let verifying_key = identity.verifying_key().encode().to_vec();

        Ok(Self {
            version: VAULT_ROOT_VERSION,
            manifest_cid,
            identity_cid,
            vault_id,
            verifying_key,
            signature,
        })
    }

    pub fn new(
        vault_id: impl Into<String>,
        manifest_cid: impl Into<String>,
        identity_cid: impl Into<String>,
        signing_key: &MlDsaSigningKey,
    ) -> Result<Self, CryptoError> {
        let vault_id = vault_id.into();
        let manifest_cid = manifest_cid.into();
        let identity_cid = identity_cid.into();

        if vault_id.trim().is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        if manifest_cid.trim().is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        if identity_cid.trim().is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        let signable = SignableVaultRoot {
            version: VAULT_ROOT_VERSION,
            manifest_cid: &manifest_cid,
            identity_cid: &identity_cid,
            vault_id: &vault_id,
        };

        let signable_bytes =
            serde_json::to_vec(&signable).map_err(|_| CryptoError::InvalidVaultRoot)?;

        let signature = sign(signing_key, &signable_bytes)?;

        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            version: VAULT_ROOT_VERSION,
            manifest_cid,
            identity_cid,
            vault_id,
            verifying_key: verifying_key.encode().to_vec(),
            signature,
        })
    }

    fn signable_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let signable = SignableVaultRoot {
            version: self.version,
            manifest_cid: &self.manifest_cid,
            identity_cid: &self.identity_cid,
            vault_id: &self.vault_id,
        };

        serde_json::to_vec(&signable).map_err(|_| CryptoError::InvalidVaultRoot)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        self.validate()?;

        serde_json::to_vec(self).map_err(|_| CryptoError::InvalidVaultRoot)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, CryptoError> {
        let root: Self = serde_json::from_slice(data).map_err(|_| CryptoError::InvalidVaultRoot)?;

        root.validate()?;

        Ok(root)
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.version != VAULT_ROOT_VERSION {
            return Err(CryptoError::InvalidVaultRoot);
        }

        if self.vault_id.trim().is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        if self.manifest_cid.trim().is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        if self.identity_cid.trim().is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        if self.verifying_key.is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        if self.signature.is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        let verifying_key = MlDsaVerifyingKey::decode(
            self.verifying_key
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidVaultRoot)?,
        );

        let signable_bytes = self.signable_bytes()?;

        verify(&verifying_key, &signable_bytes, &self.signature)?;

        Ok(())
    }

    pub fn update_manifest_cid(
        &mut self,
        manifest_cid: String,
        signing_key: &MlDsaSigningKey,
    ) -> Result<(), CryptoError> {
        if manifest_cid.is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        self.manifest_cid = manifest_cid;

        let message = self.signable_bytes()?;

        let signature = crate::crypto::signing::sign(signing_key, &message)?;

        self.signature = signature;

        Ok(())
    }

    pub fn update_identity_cid(
        &mut self,
        identity_cid: impl Into<String>,
        signing_key: &MlDsaSigningKey,
    ) -> Result<(), CryptoError> {
        let identity_cid = identity_cid.into();

        if identity_cid.trim().is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        self.identity_cid = identity_cid;

        let signable_bytes = self.signable_bytes()?;

        self.signature = sign(signing_key, &signable_bytes)?;

        Ok(())
    }

    pub fn verifying_key(&self) -> Result<MlDsaVerifyingKey, CryptoError> {
        let encoded_key = self
            .verifying_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidVaultRoot)?;

        Ok(MlDsaVerifyingKey::decode(encoded_key))
    }
}

impl Default for VaultRoot {
    fn default() -> Self {
        panic!("VaultRoot requires an authenticated signing key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::signing::generate_keypair;

    #[test]
    fn new_root_has_correct_version() {
        let keypair = generate_keypair();

        let root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        assert_eq!(root.version, VAULT_ROOT_VERSION);
    }

    #[test]
    fn root_can_be_created_from_vault_identity() {
        let identity = VaultIdentity::generate();

        let root = VaultRoot::create_from_identity(
            "test-vault",
            "bafy-test-manifest",
            "bafy-test-identity",
            &identity,
        )
        .expect("root creation should succeed");

        assert_eq!(root.vault_id(), "test-vault");
        assert_eq!(root.manifest_cid, "bafy-test-manifest");
        assert_eq!(root.identity_cid(), "bafy-test-identity");

        root.validate().expect("root signature should validate");
    }

    #[test]
    fn root_created_from_identity_detects_tampering() {
        let identity = VaultIdentity::generate();

        let mut root = VaultRoot::create_from_identity(
            "test-vault",
            "bafy-test-manifest",
            "bafy-test-identity",
            &identity,
        )
        .expect("root creation should succeed");

        root.manifest_cid = "bafy-modified-manifest".to_string();

        assert!(root.validate().is_err());
    }

    #[test]
    fn identity_cid_is_stored_in_root() {
        let keypair = generate_keypair();

        let root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        assert_eq!(root.identity_cid, "QmIdentity123");
    }

    #[test]
    fn new_root_stores_vault_id_and_manifest_cid() {
        let keypair = generate_keypair();

        let root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        assert_eq!(root.vault_id, "vault-001");
        assert_eq!(root.manifest_cid, "QmManifest123");
    }

    #[test]
    fn root_serialization_roundtrip() {
        let keypair = generate_keypair();

        let root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        let serialized = root.serialize().expect("failed to serialize vault root");

        let restored =
            VaultRoot::deserialize(&serialized).expect("failed to deserialize vault root");

        assert_eq!(restored, root);
    }

    #[test]
    fn empty_vault_id_is_rejected() {
        let keypair = generate_keypair();

        let result = VaultRoot::new("", "QmManifest123", "QmIdentity123", &keypair.signing_key);

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn whitespace_vault_id_is_rejected() {
        let keypair = generate_keypair();

        let result = VaultRoot::new(
            "   ",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        );

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn empty_manifest_cid_is_rejected() {
        let keypair = generate_keypair();

        let result = VaultRoot::new("vault-001", "", "QmIdentity123", &keypair.signing_key);

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn whitespace_manifest_cid_is_rejected() {
        let keypair = generate_keypair();

        let result = VaultRoot::new("vault-001", "   ", "QmIdentity123", &keypair.signing_key);

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn empty_identity_cid_is_rejected() {
        let keypair = generate_keypair();

        let result = VaultRoot::new("vault-001", "QmManifest123", "", &keypair.signing_key);

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn whitespace_identity_cid_is_rejected() {
        let keypair = generate_keypair();

        let result = VaultRoot::new("vault-001", "QmManifest123", "   ", &keypair.signing_key);

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn invalid_version_is_rejected() {
        let keypair = generate_keypair();

        let root = VaultRoot {
            version: 99,
            vault_id: "vault-001".to_string(),
            manifest_cid: "QmManifest123".to_string(),
            identity_cid: "QmIdentity123".to_string(),
            verifying_key: keypair.verifying_key.encode().to_vec(),
            signature: Vec::new(),
        };

        let result = root.validate();

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn malformed_serialized_root_is_rejected() {
        let result = VaultRoot::deserialize(b"not valid json");

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn serialized_root_with_invalid_version_is_rejected() {
        let data = br#"{
            "version": 99,
            "manifest_cid": "QmManifest123",
            "identity_cid": "QmIdentity123",
            "vault_id": "vault-001",
            "verifying_key": [],
            "signature": []
        }"#;

        let result = VaultRoot::deserialize(data);

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn manifest_cid_can_be_updated() {
        let keypair = generate_keypair();

        let mut root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        root.update_manifest_cid("QmManifest456".to_string(), &keypair.signing_key)
            .expect("failed to update manifest CID");

        assert_eq!(root.manifest_cid, "QmManifest456");

        root.validate()
            .expect("updated root signature failed validation");
    }

    #[test]
    fn empty_updated_manifest_cid_is_rejected() {
        let keypair = generate_keypair();

        let mut root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        let result = root.update_manifest_cid("".to_string(), &keypair.signing_key);
        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));

        assert_eq!(root.manifest_cid, "QmManifest123");
    }

    #[test]
    fn identity_cid_can_be_updated() {
        let keypair = generate_keypair();

        let mut root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        root.update_identity_cid("QmIdentity456", &keypair.signing_key)
            .expect("failed to update identity CID");

        assert_eq!(root.identity_cid, "QmIdentity456");

        root.validate()
            .expect("updated root signature failed validation");
    }

    #[test]
    fn empty_updated_identity_cid_is_rejected() {
        let keypair = generate_keypair();

        let mut root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        let result = root.update_identity_cid("", &keypair.signing_key);

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));

        assert_eq!(root.identity_cid, "QmIdentity123");
    }

    #[test]
    fn valid_root_signature_verifies() {
        let keypair = generate_keypair();

        let root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        root.validate()
            .expect("valid root signature failed validation");
    }

    #[test]
    fn modified_manifest_cid_fails_validation() {
        let keypair = generate_keypair();

        let mut root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        root.manifest_cid = "QmAttackerManifest".to_string();

        let result = root.validate();

        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn modified_identity_cid_fails_validation() {
        let keypair = generate_keypair();

        let mut root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        root.identity_cid = "QmAttackerIdentity".to_string();

        let result = root.validate();

        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn modified_vault_id_fails_validation() {
        let keypair = generate_keypair();

        let mut root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        root.vault_id = "attacker-vault".to_string();

        let result = root.validate();

        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn modified_version_fails_validation() {
        let keypair = generate_keypair();

        let root = VaultRoot {
            version: 99,
            vault_id: "vault-001".to_string(),
            manifest_cid: "QmManifest123".to_string(),
            identity_cid: "QmIdentity123".to_string(),
            verifying_key: keypair.verifying_key.encode().to_vec(),
            signature: Vec::new(),
        };

        let result = root.validate();

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn wrong_verifying_key_fails_validation() {
        let keypair_a = generate_keypair();
        let keypair_b = generate_keypair();

        let mut root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair_a.signing_key,
        )
        .expect("failed to create vault root");

        root.verifying_key = keypair_b.verifying_key.encode().to_vec();

        let result = root.validate();

        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn modified_signature_fails_validation() {
        let keypair = generate_keypair();

        let mut root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        root.signature[0] ^= 0x01;

        let result = root.validate();

        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed) | Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn manifest_cid_update_resigns_root() {
        let keypair = generate_keypair();

        let mut root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        let original_signature = root.signature.clone();

        root.update_manifest_cid("QmManifest456".to_string(), &keypair.signing_key)
            .expect("failed to update manifest CID");

        assert_eq!(root.manifest_cid, "QmManifest456");

        assert_ne!(root.signature, original_signature);

        root.validate().expect("re-signed root failed validation");
    }

    #[test]
    fn identity_cid_update_resigns_root() {
        let keypair = generate_keypair();

        let mut root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        let original_signature = root.signature.clone();

        root.update_identity_cid("QmIdentity456", &keypair.signing_key)
            .expect("failed to update identity CID");

        assert_eq!(root.identity_cid, "QmIdentity456");

        assert_ne!(root.signature, original_signature);

        root.validate().expect("re-signed root failed validation");
    }

    #[test]
    fn verifying_key_can_be_reconstructed() {
        let keypair = generate_keypair();

        let root = VaultRoot::new(
            "vault-001",
            "QmManifest123",
            "QmIdentity123",
            &keypair.signing_key,
        )
        .expect("failed to create vault root");

        let reconstructed_key = root
            .verifying_key()
            .expect("failed to reconstruct verifying key");

        assert_eq!(reconstructed_key.encode(), keypair.verifying_key.encode());
    }
}
