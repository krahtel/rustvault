use crate::crypto::encrypted_document::EncryptedDocument;
use crate::crypto::encryption::EncryptedData;
use crate::crypto::error::CryptoError;
use crate::vault::storage::VaultStorage;
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

/// Client for communicating with a local Kubo IPFS node.
pub struct IpfsStorage {
    api_url: String,
    client: reqwest::Client,
    manifest_cid: Option<String>,
}

impl IpfsStorage {
    pub fn new(api_url: impl Into<String>) -> Self {
        Self {
            api_url: api_url.into(),
            client: reqwest::Client::new(),
            manifest_cid: None,
        }
    }
    pub fn manifest_cid(&self) -> Option<&str> {
        self.manifest_cid.as_deref()
    }

    pub fn default_local() -> Self {
        Self::new(DEFAULT_IPFS_API_URL)
    }

    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    /// Add raw bytes to IPFS and return the resulting CID.
    pub async fn add(&self, data: Vec<u8>) -> Result<String, CryptoError> {
        let url = format!("{}/api/v0/add", self.api_url);

        let part = multipart::Part::bytes(data).file_name("rustvault.bin");

        let form = multipart::Form::new().part("file", part);

        let response = self
            .client
            .post(url)
            .multipart(form)
            .send()
            .await
            .map_err(|_| CryptoError::IpfsConnectionFailed)?;

        if !response.status().is_success() {
            return Err(CryptoError::IpfsOperationFailed);
        }

        let result = response
            .json::<AddResponse>()
            .await
            .map_err(|_| CryptoError::IpfsOperationFailed)?;

        Ok(result.hash)
    }

    /// Retrieve raw bytes from IPFS using a CID.
    pub async fn cat(&self, cid: &str) -> Result<Vec<u8>, CryptoError> {
        let url = format!("{}/api/v0/cat", self.api_url);

        let response = self
            .client
            .post(url)
            .query(&[("arg", cid)])
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

    /// Serialize and store an encrypted RustVault document in IPFS.
    pub async fn add_encrypted_document(
        &self,
        document: &EncryptedDocument,
    ) -> Result<String, CryptoError> {
        let data = serde_json::to_vec(document).map_err(|_| CryptoError::IpfsOperationFailed)?;

        self.add(data).await
    }

    /// Retrieve and deserialize an encrypted RustVault document from IPFS.
    pub async fn get_encrypted_document(
        &self,
        cid: &str,
    ) -> Result<EncryptedDocument, CryptoError> {
        let data = self.cat(cid).await?;

        serde_json::from_slice(&data).map_err(|_| CryptoError::IpfsOperationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_and_cat_roundtrip() {
        let storage = IpfsStorage::default_local();

        let original = b"RustVault IPFS integration test".to_vec();

        let cid = storage
            .add(original.clone())
            .await
            .expect("failed to add data to IPFS");

        assert!(!cid.is_empty());

        let retrieved = storage
            .cat(&cid)
            .await
            .expect("failed to retrieve data from IPFS");

        assert_eq!(retrieved, original);
    }

    #[tokio::test]
    async fn encrypted_document_roundtrip() {
        let storage = IpfsStorage::default_local();

        let wrapping_key = [42u8; 32];

        let plaintext = b"This is a secret RustVault document.";

        let encrypted = EncryptedDocument::encrypt(&wrapping_key, plaintext)
            .expect("failed to encrypt document");

        let cid = storage
            .add_encrypted_document(&encrypted)
            .await
            .expect("failed to store encrypted document");

        assert!(!cid.is_empty());

        let retrieved = storage
            .get_encrypted_document(&cid)
            .await
            .expect("failed to retrieve encrypted document");

        let decrypted = retrieved
            .decrypt(&wrapping_key)
            .expect("failed to decrypt document");

        assert_eq!(decrypted, plaintext);
    }
}
#[async_trait::async_trait]
impl VaultStorage for IpfsStorage {
    async fn save_manifest(&mut self, manifest: &EncryptedData) -> Result<(), CryptoError> {
        let data = serde_json::to_vec(manifest).map_err(|_| CryptoError::IpfsOperationFailed)?;

        let cid = self.add(data).await?;

        self.manifest_cid = Some(cid);

        Ok(())
    }

    async fn load_manifest(&self) -> Result<EncryptedData, CryptoError> {
        let cid = self
            .manifest_cid
            .as_deref()
            .ok_or(CryptoError::StorageUnavailable)?;

        let data = self.cat(cid).await?;

        serde_json::from_slice(&data).map_err(|_| CryptoError::IpfsOperationFailed)
    }

    async fn store_document(&mut self, document: EncryptedDocument) -> Result<String, CryptoError> {
        self.add_encrypted_document(&document).await
    }

    async fn load_document(&self, cid: &str) -> Result<EncryptedDocument, CryptoError> {
        self.get_encrypted_document(cid).await
    }

    async fn delete_document(&mut self, _cid: &str) -> Result<(), CryptoError> {
        // IPFS content is immutable/content-addressed. Deleting a
        // local reference does not delete the content from the
        // network.
        Ok(())
    }
}
