use std::collections::HashMap;

use crate::crypto::encrypted_document::EncryptedDocument;
use crate::crypto::encryption::EncryptedData;
use crate::crypto::error::CryptoError;

#[derive(Debug, Clone)]
pub struct ManifestStorageRecord {
    pub cid: String,
    pub encrypted_manifest: EncryptedData,
}

#[async_trait::async_trait]
pub trait VaultStorage {
    async fn save_manifest(
        &mut self,
        manifest: &EncryptedData,
    ) -> Result<String, CryptoError>;

    async fn load_manifest(&self) -> Result<ManifestStorageRecord, CryptoError>;

    async fn store_document(
        &mut self,
        document: EncryptedDocument,
    ) -> Result<String, CryptoError>;

    async fn load_document(
        &self,
        cid: &str,
    ) -> Result<EncryptedDocument, CryptoError>;

    async fn delete_document(
        &mut self,
        cid: &str,
    ) -> Result<(), CryptoError>;
}

#[derive(Default)]
pub struct MemoryStorage {
    manifest: Option<ManifestStorageRecord>,
    documents: HashMap<String, EncryptedDocument>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            manifest: None,
            documents: HashMap::new(),
        }
    }

    pub fn document_count(&self) -> usize {
        self.documents.len()
    }
}

#[async_trait::async_trait]
impl VaultStorage for MemoryStorage {
    async fn save_manifest(
        &mut self,
        manifest: &EncryptedData,
    ) -> Result<String, CryptoError> {
        let cid = format!("memory-manifest-{}", self.documents.len());

        self.manifest = Some(ManifestStorageRecord {
            cid: cid.clone(),
            encrypted_manifest: manifest.clone(),
        });

        Ok(cid)
    }

    async fn load_manifest(&self) -> Result<ManifestStorageRecord, CryptoError> {
        self.manifest
            .clone()
            .ok_or(CryptoError::StorageUnavailable)
    }

    async fn store_document(
        &mut self,
        document: EncryptedDocument,
    ) -> Result<String, CryptoError> {
        let cid = format!("memory-{}", self.documents.len() + 1);

        self.documents.insert(cid.clone(), document);

        Ok(cid)
    }

    async fn load_document(
        &self,
        cid: &str,
    ) -> Result<EncryptedDocument, CryptoError> {
        self.documents
            .get(cid)
            .cloned()
            .ok_or(CryptoError::DocumentNotFound)
    }

    async fn delete_document(
        &mut self,
        cid: &str,
    ) -> Result<(), CryptoError> {
        self.documents
            .remove(cid)
            .ok_or(CryptoError::DocumentNotFound)?;

        Ok(())
    }
}