use serde::{Deserialize, Serialize};

use crate::crypto::error::CryptoError;

pub const VAULT_ROOT_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultRoot {
    pub version: u8,
    pub manifest_cid: String,
    pub vault_id: String,
}

impl VaultRoot {
    pub fn new(
        vault_id: impl Into<String>,
        manifest_cid: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        let vault_id = vault_id.into();
        let manifest_cid = manifest_cid.into();

        if vault_id.trim().is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        if manifest_cid.trim().is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        Ok(Self {
            version: VAULT_ROOT_VERSION,
            manifest_cid,
            vault_id,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
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

        Ok(())
    }

    pub fn update_manifest_cid(
        &mut self,
        manifest_cid: impl Into<String>,
    ) -> Result<(), CryptoError> {
        let manifest_cid = manifest_cid.into();

        if manifest_cid.trim().is_empty() {
            return Err(CryptoError::InvalidVaultRoot);
        }

        self.manifest_cid = manifest_cid;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_root_has_correct_version() {
        let root =
            VaultRoot::new("vault-001", "QmManifest123").expect("failed to create vault root");

        assert_eq!(root.version, VAULT_ROOT_VERSION);
    }

    #[test]
    fn new_root_stores_vault_id_and_manifest_cid() {
        let root =
            VaultRoot::new("vault-001", "QmManifest123").expect("failed to create vault root");

        assert_eq!(root.vault_id, "vault-001");
        assert_eq!(root.manifest_cid, "QmManifest123");
    }

    #[test]
    fn root_serialization_roundtrip() {
        let root =
            VaultRoot::new("vault-001", "QmManifest123").expect("failed to create vault root");

        let serialized = root.serialize().expect("failed to serialize vault root");

        let restored =
            VaultRoot::deserialize(&serialized).expect("failed to deserialize vault root");

        assert_eq!(restored, root);
    }

    #[test]
    fn empty_vault_id_is_rejected() {
        let result = VaultRoot::new("", "QmManifest123");

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn whitespace_vault_id_is_rejected() {
        let result = VaultRoot::new("   ", "QmManifest123");

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn empty_manifest_cid_is_rejected() {
        let result = VaultRoot::new("vault-001", "");

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn whitespace_manifest_cid_is_rejected() {
        let result = VaultRoot::new("vault-001", "   ");

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn invalid_version_is_rejected() {
        let root = VaultRoot {
            version: 99,
            vault_id: "vault-001".to_string(),
            manifest_cid: "QmManifest123".to_string(),
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
            "vault_id": "vault-001"
        }"#;

        let result = VaultRoot::deserialize(data);

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[test]
    fn manifest_cid_can_be_updated() {
        let mut root =
            VaultRoot::new("vault-001", "QmManifest123").expect("failed to create vault root");

        root.update_manifest_cid("QmManifest456")
            .expect("failed to update manifest CID");

        assert_eq!(root.manifest_cid, "QmManifest456");
    }

    #[test]
    fn empty_updated_manifest_cid_is_rejected() {
        let mut root =
            VaultRoot::new("vault-001", "QmManifest123").expect("failed to create vault root");

        let result = root.update_manifest_cid("");

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));

        assert_eq!(root.manifest_cid, "QmManifest123");
    }
}
