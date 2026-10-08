use crate::crypto::encrypted_document::EncryptedDocument;
use crate::crypto::encryption::EncryptedData;
use crate::crypto::error::CryptoError;
use crate::vault::identity_storage::IdentityStorageRecord;
use crate::vault::root::VaultRoot;
use crate::vault::storage::{ManifestStorageRecord, VaultStorage};
use reqwest::multipart;
use serde::Deserialize;

const DEFAULT_IPFS_API_URL: &str = "http://127.0.0.1:5001";

#[derive(Debug, Deserialize)]
struct AddResponse {
    #[serde(rename = "Name")]
    name: String,

    #[serde(rename = "Hash")]
    hash: String,

    #[serde(rename = "Size")]
    size: String,
}

pub struct IpfsStorage {
    client: reqwest::Client,
    api_url: String,
    manifest_cid: Option<String>,
    identity_cid: Option<String>,
}

impl IpfsStorage {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            api_url: DEFAULT_IPFS_API_URL.to_string(),
            manifest_cid: None,
            identity_cid: None,
        }
    }

    pub fn with_api_url(api_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_url: api_url.into(),
            manifest_cid: None,
            identity_cid: None,
        }
    }

    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    async fn add_bytes(&self, data: Vec<u8>) -> Result<String, CryptoError> {
        let part = multipart::Part::bytes(data).file_name("rustvault-data");

        let form = multipart::Form::new().part("file", part);

        let response = self
            .client
            .post(format!("{}/api/v0/add", self.api_url))
            .multipart(form)
            .send()
            .await
            .map_err(|_| CryptoError::IpfsConnectionFailed)?;

        if !response.status().is_success() {
            return Err(CryptoError::IpfsOperationFailed);
        }

        let result: AddResponse = response
            .json()
            .await
            .map_err(|_| CryptoError::IpfsOperationFailed)?;

        Ok(result.hash)
    }

    async fn get_bytes(&self, cid: &str) -> Result<Vec<u8>, CryptoError> {
        let response = self
            .client
            .post(format!("{}/api/v0/cat?arg={}", self.api_url, cid))
            .send()
            .await
            .map_err(|_| CryptoError::IpfsConnectionFailed)?;

        if !response.status().is_success() {
            return Err(CryptoError::IpfsOperationFailed);
        }

        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .map_err(|_| CryptoError::IpfsOperationFailed)
    }

    async fn add_json<T: serde::Serialize>(&self, value: &T) -> Result<String, CryptoError> {
        let data = serde_json::to_vec(value).map_err(|_| CryptoError::IpfsOperationFailed)?;

        self.add_bytes(data).await
    }

    async fn get_json<T: for<'de> serde::Deserialize<'de>>(
        &self,
        cid: &str,
    ) -> Result<T, CryptoError> {
        let data = self.get_bytes(cid).await?;

        serde_json::from_slice(&data).map_err(|_| CryptoError::IpfsOperationFailed)
    }
}

#[async_trait::async_trait]
impl VaultStorage for IpfsStorage {
    async fn save_manifest(&mut self, manifest: &EncryptedData) -> Result<String, CryptoError> {
        let cid = self.add_json(manifest).await?;

        self.manifest_cid = Some(cid.clone());

        Ok(cid)
    }
    async fn save_root(&mut self, root: &VaultRoot) -> Result<String, CryptoError> {
        let bytes = serde_json::to_vec(root).map_err(|_| CryptoError::IpfsOperationFailed)?;

        self.add_bytes(bytes).await
    }
    async fn list_manifest_cids(&self) -> Result<Vec<String>, CryptoError> {
        Err(CryptoError::StorageUnavailable)
    }

    async fn delete_manifest(&mut self, _cid: &str) -> Result<(), CryptoError> {
        Err(CryptoError::StorageUnavailable)
    }

    async fn list_document_cids(&self) -> Result<Vec<String>, CryptoError> {
        Err(CryptoError::StorageUnavailable)
    }

    async fn load_root(&self) -> Result<VaultRoot, CryptoError> {
        // Root CID persistence will be connected to the
        // vault bootstrap mechanism in the next milestone.
        Err(CryptoError::StorageUnavailable)
    }

    async fn load_manifest(&self) -> Result<ManifestStorageRecord, CryptoError> {
        let cid = self
            .manifest_cid
            .as_ref()
            .ok_or(CryptoError::StorageUnavailable)?;

        let encrypted_manifest: EncryptedData = self.get_json(cid).await?;

        Ok(ManifestStorageRecord {
            cid: cid.clone(),
            encrypted_manifest,
        })
    }

    async fn save_identity(
        &mut self,
        identity: &IdentityStorageRecord,
    ) -> Result<String, CryptoError> {
        let bytes = serde_json::to_vec(identity).map_err(|_| CryptoError::IpfsOperationFailed)?;

        let cid = self.add_bytes(bytes).await?;

        self.identity_cid = Some(cid.clone());

        Ok(cid)
    }

    async fn load_identity(&self) -> Result<IdentityStorageRecord, CryptoError> {
        let cid = self
            .identity_cid
            .as_ref()
            .ok_or(CryptoError::StorageUnavailable)?;

        self.get_json(cid).await
    }

    async fn store_document(&mut self, document: EncryptedDocument) -> Result<String, CryptoError> {
        self.add_json(&document).await
    }

    async fn load_document(&self, cid: &str) -> Result<EncryptedDocument, CryptoError> {
        self.get_json(cid).await
    }

    async fn delete_document(&mut self, _cid: &str) -> Result<(), CryptoError> {
        /*
         * IPFS content is immutable and content-addressed.
         *
         * Removing a CID from the vault manifest is sufficient
         * for logical deletion from RustVault.
         *
         * Actual IPFS garbage collection is handled separately.
         */
        Ok(())
    }
}
