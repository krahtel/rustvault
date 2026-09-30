use serde::{Deserialize, Serialize};

use crate::crypto::encryption::EncryptedData;

pub const MANIFEST_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub document_id: String,
    pub ipfs_cid: String,
    pub wrapped_document_key: EncryptedData,
    pub encrypted_metadata: EncryptedData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultManifest {
    pub version: u8,
    pub documents: Vec<ManifestEntry>,
}

impl VaultManifest {
    pub fn new() -> Self {
        Self {
            version: MANIFEST_VERSION,
            documents: Vec::new(),
        }
    }

    pub fn add_document(&mut self, entry: ManifestEntry) {
        self.documents.push(entry);
    }

    pub fn find_document(&self, document_id: &str) -> Option<&ManifestEntry> {
        self.documents
            .iter()
            .find(|entry| entry.document_id == document_id)
    }

    pub fn remove_document(&mut self, document_id: &str) -> Option<ManifestEntry> {
        let position = self
            .documents
            .iter()
            .position(|entry| entry.document_id == document_id)?;

        Some(self.documents.remove(position))
    }

    pub fn document_count(&self) -> usize {
        self.documents.len()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

impl Default for VaultManifest {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encryption::EncryptedData;

    fn test_entry() -> ManifestEntry {
        ManifestEntry {
            document_id: "doc-001".to_string(),
            ipfs_cid: "QmTestCid123".to_string(),
            wrapped_document_key: EncryptedData {
                nonce: [0u8; 12],
                ciphertext: vec![1, 2, 3],
            },
            encrypted_metadata: EncryptedData {
                nonce: [1u8; 12],
                ciphertext: vec![4, 5, 6],
            },
        }
    }

    #[test]
    fn new_manifest_has_correct_version() {
        let manifest = VaultManifest::new();

        assert_eq!(manifest.version, MANIFEST_VERSION);
    }

    #[test]
    fn new_manifest_is_empty() {
        let manifest = VaultManifest::new();

        assert_eq!(manifest.document_count(), 0);
    }

    #[test]
    fn add_document_increases_count() {
        let mut manifest = VaultManifest::new();

        manifest.add_document(test_entry());

        assert_eq!(manifest.document_count(), 1);
    }

    #[test]
    fn find_document_returns_entry() {
        let mut manifest = VaultManifest::new();

        manifest.add_document(test_entry());

        let found = manifest.find_document("doc-001");

        assert!(found.is_some());
        assert_eq!(found.unwrap().ipfs_cid, "QmTestCid123");
    }

    #[test]
    fn find_missing_document_returns_none() {
        let manifest = VaultManifest::new();

        assert!(manifest.find_document("missing").is_none());
    }

    #[test]
    fn remove_document_removes_entry() {
        let mut manifest = VaultManifest::new();

        manifest.add_document(test_entry());

        let removed = manifest.remove_document("doc-001");

        assert!(removed.is_some());
        assert_eq!(manifest.document_count(), 0);
    }

    #[test]
    fn remove_missing_document_returns_none() {
        let mut manifest = VaultManifest::new();

        assert!(manifest.remove_document("missing").is_none());
    }

    #[test]
    fn manifest_serializes() {
        let mut manifest = VaultManifest::new();

        manifest.add_document(test_entry());

        let data = manifest.serialize().expect("manifest should serialize");

        assert!(!data.is_empty());
    }

    #[test]
    fn manifest_deserializes() {
        let mut manifest = VaultManifest::new();

        manifest.add_document(test_entry());

        let data = manifest.serialize().expect("manifest should serialize");

        let restored = VaultManifest::deserialize(&data).expect("manifest should deserialize");

        assert_eq!(restored.version, MANIFEST_VERSION);
        assert_eq!(restored.document_count(), 1);
        assert!(restored.find_document("doc-001").is_some());
    }
}
