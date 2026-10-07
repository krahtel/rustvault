use crate::crypto::error::CryptoError;
use crate::vault::root::VaultRoot;

pub trait VaultRootStorage {
    fn save_root(&mut self, root: &VaultRoot) -> Result<(), CryptoError>;
    fn load_root(&self) -> Result<VaultRoot, CryptoError>;
}

#[derive(Default)]
pub struct MemoryRootStorage {
    root: Option<VaultRoot>,
}

impl MemoryRootStorage {
    pub fn new() -> Self {
        Self { root: None }
    }
}

impl VaultRootStorage for MemoryRootStorage {
    fn save_root(&mut self, root: &VaultRoot) -> Result<(), CryptoError> {
        self.root = Some(root.clone());
        Ok(())
    }

    fn load_root(&self) -> Result<VaultRoot, CryptoError> {
        self.root.clone().ok_or(CryptoError::StorageUnavailable)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::identity::VaultIdentity;

    #[test]
    fn root_storage_can_save_and_load_root() {
        let identity = VaultIdentity::generate();

        let root = VaultRoot::create_from_identity(
            "test-vault",
            "bafy-test-manifest",
            "bafy-test-identity",
            &identity,
        )
        .expect("root creation should succeed");

        let mut storage = MemoryRootStorage::new();

        storage.save_root(&root).expect("root should save");

        let loaded = storage.load_root().expect("root should load");

        assert_eq!(loaded.vault_id(), "test-vault");
        assert_eq!(loaded.manifest_cid, "bafy-test-manifest");

        loaded
            .validate()
            .expect("loaded root should remain authenticated");
    }

    #[test]
    fn root_storage_returns_error_when_empty() {
        let storage = MemoryRootStorage::new();

        let result = storage.load_root();

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));
    }

    #[test]
    fn root_storage_preserves_signature() {
        let identity = VaultIdentity::generate();

        let root = VaultRoot::create_from_identity(
            "test-vault",
            "bafy-test-manifest",
            "bafy-test-identity",
            &identity,
        )
        .expect("root creation should succeed");

        let original_signature = root.signature.clone();

        let mut storage = MemoryRootStorage::new();

        storage.save_root(&root).expect("root should save");

        let loaded = storage.load_root().expect("root should load");

        assert_eq!(loaded.signature, original_signature);
    }
}
