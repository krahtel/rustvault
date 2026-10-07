use crate::crypto::encrypted_document::EncryptedDocument;
use crate::crypto::encryption::EncryptedData;
use crate::crypto::error::CryptoError;
use crate::vault::identity_storage::IdentityStorageRecord;
use crate::vault::root::VaultRoot;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ManifestStorageRecord {
    pub cid: String,
    pub encrypted_manifest: EncryptedData,
}

#[async_trait::async_trait]
pub trait VaultStorage {
    async fn save_manifest(&mut self, manifest: &EncryptedData) -> Result<String, CryptoError>;

    async fn load_manifest(&self) -> Result<ManifestStorageRecord, CryptoError>;

    async fn save_identity(
        &mut self,
        identity: &IdentityStorageRecord,
    ) -> Result<String, CryptoError>;

    async fn load_identity(&self) -> Result<IdentityStorageRecord, CryptoError>;

    async fn store_document(&mut self, document: EncryptedDocument) -> Result<String, CryptoError>;

    async fn load_document(&self, cid: &str) -> Result<EncryptedDocument, CryptoError>;

    async fn delete_document(&mut self, cid: &str) -> Result<(), CryptoError>;
    async fn save_root(&mut self, root: &VaultRoot) -> Result<String, CryptoError>;

    async fn load_root(&self) -> Result<VaultRoot, CryptoError>;
}

#[derive(Default)]
pub struct MemoryStorage {
    manifest: Option<ManifestStorageRecord>,
    identity: Option<IdentityStorageRecord>,
    root: Option<VaultRoot>,
    documents: HashMap<String, EncryptedDocument>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            manifest: None,
            identity: None,
            root: None,
            documents: HashMap::new(),
        }
    }

    pub fn document_count(&self) -> usize {
        self.documents.len()
    }
}

#[async_trait::async_trait]
impl VaultStorage for MemoryStorage {
    async fn save_manifest(&mut self, manifest: &EncryptedData) -> Result<String, CryptoError> {
        let cid = format!("memory-manifest-{}", self.documents.len());

        self.manifest = Some(ManifestStorageRecord {
            cid: cid.clone(),
            encrypted_manifest: manifest.clone(),
        });

        Ok(cid)
    }
    async fn save_root(&mut self, root: &VaultRoot) -> Result<String, CryptoError> {
        let cid = "memory-root-0".to_string();

        self.root = Some(root.clone());

        Ok(cid)
    }

    async fn load_root(&self) -> Result<VaultRoot, CryptoError> {
        self.root.clone().ok_or(CryptoError::StorageUnavailable)
    }

    async fn load_manifest(&self) -> Result<ManifestStorageRecord, CryptoError> {
        self.manifest.clone().ok_or(CryptoError::StorageUnavailable)
    }

    async fn save_identity(
        &mut self,
        identity: &IdentityStorageRecord,
    ) -> Result<String, CryptoError> {
        let cid = format!("memory-identity-{}", self.documents.len());

        self.identity = Some(identity.clone());

        Ok(cid)
    }

    async fn load_identity(&self) -> Result<IdentityStorageRecord, CryptoError> {
        self.identity.clone().ok_or(CryptoError::StorageUnavailable)
    }

    async fn store_document(&mut self, document: EncryptedDocument) -> Result<String, CryptoError> {
        let cid = format!("memory-{}", self.documents.len() + 1);

        self.documents.insert(cid.clone(), document);

        Ok(cid)
    }

    async fn load_document(&self, cid: &str) -> Result<EncryptedDocument, CryptoError> {
        self.documents
            .get(cid)
            .cloned()
            .ok_or(CryptoError::DocumentNotFound)
    }

    async fn delete_document(&mut self, cid: &str) -> Result<(), CryptoError> {
        self.documents
            .remove(cid)
            .ok_or(CryptoError::DocumentNotFound)?;

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encryption::EncryptedData;
    use crate::vault::identity_storage::IdentityStorageRecord;

    fn sample_encrypted_seed() -> EncryptedData {
        EncryptedData {
            nonce: [1u8; 12],
            ciphertext: vec![10, 20, 30],
        }
    }

    fn sample_identity_record() -> IdentityStorageRecord {
        IdentityStorageRecord {
            encrypted_seed: sample_encrypted_seed(),
            verifying_key: vec![4, 5, 6],
        }
    }

    #[tokio::test]
    async fn save_identity_returns_cid() {
        let mut storage = MemoryStorage::new();
        let identity = sample_identity_record();

        let cid = storage
            .save_identity(&identity)
            .await
            .expect("identity should save");

        assert_eq!(cid, "memory-identity-0");
    }

    #[tokio::test]
    async fn saved_identity_can_be_loaded() {
        let mut storage = MemoryStorage::new();
        let identity = sample_identity_record();

        storage
            .save_identity(&identity)
            .await
            .expect("identity should save");

        let loaded = storage.load_identity().await.expect("identity should load");

        assert_eq!(loaded.encrypted_seed.nonce, identity.encrypted_seed.nonce);

        assert_eq!(
            loaded.encrypted_seed.ciphertext,
            identity.encrypted_seed.ciphertext
        );

        assert_eq!(loaded.verifying_key, identity.verifying_key);
    }

    #[tokio::test]
    async fn saving_identity_replaces_previous_identity() {
        let mut storage = MemoryStorage::new();

        let first = IdentityStorageRecord {
            encrypted_seed: EncryptedData {
                nonce: [1u8; 12],
                ciphertext: vec![1, 2, 3],
            },
            verifying_key: vec![4, 5, 6],
        };

        let second = IdentityStorageRecord {
            encrypted_seed: EncryptedData {
                nonce: [2u8; 12],
                ciphertext: vec![7, 8, 9],
            },
            verifying_key: vec![10, 11, 12],
        };

        storage
            .save_identity(&first)
            .await
            .expect("first identity should save");

        let cid = storage
            .save_identity(&second)
            .await
            .expect("second identity should save");

        assert_eq!(cid, "memory-identity-0");

        let loaded = storage.load_identity().await.expect("identity should load");

        assert_eq!(loaded.encrypted_seed.nonce, second.encrypted_seed.nonce);

        assert_eq!(
            loaded.encrypted_seed.ciphertext,
            second.encrypted_seed.ciphertext
        );

        assert_eq!(loaded.verifying_key, second.verifying_key);
    }
}
#[tokio::test]
async fn saved_root_can_be_loaded() {
    let mut storage = MemoryStorage::new();

    let identity = crate::vault::identity::VaultIdentity::generate();

    let root = crate::vault::root::VaultRoot::create_from_identity(
        "test-vault".to_string(),
        "memory-manifest-0".to_string(),
        "memory-identity-0".to_string(),
        &identity,
    )
    .expect("root should be created");

    let cid = storage.save_root(&root).await.expect("root should save");

    assert_eq!(cid, "memory-root-0");

    let loaded = storage.load_root().await.expect("root should load");

    assert_eq!(loaded, root);
}
