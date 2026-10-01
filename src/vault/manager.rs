use crate::crypto::encrypted_document::EncryptedDocument;
use crate::crypto::encryption::{decrypt, encrypt, EncryptedData};
use crate::crypto::error::CryptoError;
use crate::crypto::kdf::{derive_key, generate_salt, KEY_LEN, SALT_LEN};
use crate::crypto::key_derivation::{derive_vault_keys, VaultKeySet};
use crate::vault::manifest::{ManifestEntry, VaultManifest};
use crate::vault::storage::VaultStorage;

pub struct VaultManager<S: VaultStorage> {
    salt: [u8; SALT_LEN],
    keys: VaultKeySet,
    manifest: VaultManifest,
    encrypted_manifest: EncryptedData,
    manifest_cid: String,
    storage: S,
    unlocked: bool,
}

impl<S: VaultStorage> VaultManager<S> {
    /// Create a new vault using a password and storage backend.
    pub async fn create(password: &[u8], mut storage: S) -> Result<Self, CryptoError> {
        let salt = generate_salt()?;

        let root_key = derive_key(password, &salt)?;

        let keys = derive_vault_keys(&root_key)?;

        let manifest = VaultManifest::new();

        let encrypted_manifest = Self::encrypt_manifest(&keys.manifest_key, &manifest)?;

        // Store the initial encrypted manifest and capture its CID.
        let manifest_cid = storage.save_manifest(&encrypted_manifest).await?;

        Ok(Self {
            salt,
            keys,
            manifest,
            encrypted_manifest,
            manifest_cid,
            storage,
            unlocked: true,
        })
    }

    /// Unlock an existing vault using an encrypted manifest
    /// supplied directly by the caller.
    ///
    /// The encrypted manifest acts as the password verifier.
    /// If the password is incorrect, AES-256-GCM authentication
    /// will fail.
    ///
    /// This method does not access the async storage backend,
    /// so it remains synchronous.
    pub fn unlock(
        password: &[u8],
        salt: [u8; SALT_LEN],
        encrypted_manifest: &EncryptedData,
        storage: S,
    ) -> Result<Self, CryptoError> {
        let root_key = derive_key(password, &salt)?;

        let keys = derive_vault_keys(&root_key)?;

        let manifest = Self::decrypt_manifest(&keys.manifest_key, encrypted_manifest)?;

        Ok(Self {
            salt,
            keys,
            manifest,
            encrypted_manifest: encrypted_manifest.clone(),
            manifest_cid: String::new(),
            storage,
            unlocked: true,
        })
    }

    /// Unlock an existing vault by loading the encrypted manifest
    /// directly from the storage backend.
    pub async fn unlock_from_storage(
        password: &[u8],
        salt: [u8; SALT_LEN],
        storage: S,
    ) -> Result<Self, CryptoError> {
        let encrypted_manifest = storage.load_manifest().await?;

        let root_key = derive_key(password, &salt)?;

        let keys = derive_vault_keys(&root_key)?;

        let manifest = Self::decrypt_manifest(&keys.manifest_key, &encrypted_manifest)?;

        Ok(Self {
            salt,
            keys,
            manifest,
            encrypted_manifest,
            manifest_cid: String::new(),
            storage,
            unlocked: true,
        })
    }

    /// Add an encrypted document to the vault.
    pub async fn add_document(
        &mut self,
        document_id: String,
        plaintext: &[u8],
    ) -> Result<String, CryptoError> {
        if !self.unlocked {
            return Err(CryptoError::VaultNotUnlocked);
        }

        // Generate a fresh key for this document.
        let document_key = crate::crypto::document::generate_document_key()?;

        // Encrypt the plaintext using the document-specific key.
        let encrypted_content =
            crate::crypto::document::encrypt_document(&document_key, plaintext)?;

        // Wrap the document key using the vault's document key.
        let wrapped_document_key =
            crate::crypto::key_wrap::wrap_document_key(&self.keys.document_key, &document_key)?;

        // Build the encrypted document.
        let encrypted_document = EncryptedDocument {
            version: 1,
            content: encrypted_content,
            wrapped_document_key: wrapped_document_key.clone(),
        };

        // Store the encrypted document.
        // The storage backend generates and returns the document CID.
        let cid = self.storage.store_document(encrypted_document).await?;

        // Encrypt document metadata.
        let encrypted_metadata = encrypt(&self.keys.manifest_key, document_id.as_bytes())?;

        // Add the document reference to the encrypted manifest.
        let entry = ManifestEntry {
            document_id,
            ipfs_cid: cid.clone(),
            wrapped_document_key,
            encrypted_metadata,
        };

        self.manifest.add_document(entry);

        // Persist the updated encrypted manifest.
        self.save_manifest().await?;

        Ok(cid)
    }

    /// Retrieve and decrypt a document using its CID.
    pub async fn get_document(&self, cid: &str) -> Result<Vec<u8>, CryptoError> {
        if !self.unlocked {
            return Err(CryptoError::VaultNotUnlocked);
        }

        let entry = self
            .manifest
            .documents
            .iter()
            .find(|entry| entry.ipfs_cid == cid)
            .ok_or(CryptoError::DocumentNotFound)?;

        let encrypted_document = self.storage.load_document(&entry.ipfs_cid).await?;

        encrypted_document.decrypt(&self.keys.document_key)
    }

    /// Delete a document from both storage and the manifest.
    pub async fn delete_document(&mut self, cid: &str) -> Result<(), CryptoError> {
        if !self.unlocked {
            return Err(CryptoError::VaultNotUnlocked);
        }

        let position = self
            .manifest
            .documents
            .iter()
            .position(|entry| entry.ipfs_cid == cid)
            .ok_or(CryptoError::DocumentNotFound)?;

        // Remove the encrypted document first.
        self.storage.delete_document(cid).await?;

        // Remove the corresponding manifest entry.
        self.manifest.documents.remove(position);

        // Persist the updated manifest.
        self.save_manifest().await?;

        Ok(())
    }

    fn encrypt_manifest(
        manifest_key: &[u8; KEY_LEN],
        manifest: &VaultManifest,
    ) -> Result<EncryptedData, CryptoError> {
        let data = manifest
            .serialize()
            .map_err(|_| CryptoError::EncryptionFailed)?;

        encrypt(manifest_key, &data)
    }

    fn decrypt_manifest(
        manifest_key: &[u8; KEY_LEN],
        encrypted_manifest: &EncryptedData,
    ) -> Result<VaultManifest, CryptoError> {
        let data = decrypt(manifest_key, encrypted_manifest)?;

        VaultManifest::deserialize(&data).map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Lock the vault.
    pub fn lock(&mut self) {
        self.unlocked = false;
    }

    /// Check whether the vault is unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.unlocked
    }

    /// Return the vault salt.
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// Return the current manifest CID.
    pub fn manifest_cid(&self) -> Result<&str, CryptoError> {
        if !self.unlocked {
            return Err(CryptoError::VaultNotUnlocked);
        }

        Ok(&self.manifest_cid)
    }

    /// Return the decrypted manifest.
    pub fn manifest(&self) -> Result<&VaultManifest, CryptoError> {
        if !self.unlocked {
            return Err(CryptoError::VaultNotUnlocked);
        }

        Ok(&self.manifest)
    }

    /// Return a mutable decrypted manifest.
    pub fn manifest_mut(&mut self) -> Result<&mut VaultManifest, CryptoError> {
        if !self.unlocked {
            return Err(CryptoError::VaultNotUnlocked);
        }

        Ok(&mut self.manifest)
    }

    /// Return the encrypted manifest.
    pub fn encrypted_manifest(&self) -> &EncryptedData {
        &self.encrypted_manifest
    }

    /// Return the storage backend.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Consume the vault manager and return its storage backend.
    ///
    /// This is useful when ending a vault session and creating
    /// another session using the same persistent storage backend.
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Return the document key-encryption key.
    pub fn document_key(&self) -> Result<&[u8; KEY_LEN], CryptoError> {
        if !self.unlocked {
            return Err(CryptoError::VaultNotUnlocked);
        }

        Ok(&self.keys.document_key)
    }

    /// Encrypt and save the current manifest.
    ///
    /// Saving the manifest creates a new CID in content-addressed
    /// storage. The manager therefore updates its current manifest CID.
    pub async fn save_manifest(&mut self) -> Result<(), CryptoError> {
        if !self.unlocked {
            return Err(CryptoError::VaultNotUnlocked);
        }

        self.encrypted_manifest = Self::encrypt_manifest(&self.keys.manifest_key, &self.manifest)?;

        let manifest_cid = self.storage.save_manifest(&self.encrypted_manifest).await?;

        self.manifest_cid = manifest_cid;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::storage::MemoryStorage;

    #[tokio::test]
    async fn creates_encrypted_manifest() {
        let vault = VaultManager::create(b"test-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        assert!(vault.is_unlocked());

        assert_eq!(vault.manifest().unwrap().document_count(), 0);

        assert!(!vault.manifest_cid().unwrap().is_empty());
    }

    #[test]
    fn correct_password_unlocks_vault() {
        // This test intentionally uses the synchronous unlock()
        // method because the encrypted manifest is supplied directly.
        let vault = futures_test_create_vault();

        let salt = *vault.salt();

        let encrypted_manifest = vault.encrypted_manifest().clone();

        let result = VaultManager::unlock(
            b"correct-password",
            salt,
            &encrypted_manifest,
            MemoryStorage::new(),
        );

        assert!(result.is_ok());

        let unlocked = result.unwrap();

        assert!(unlocked.is_unlocked());

        assert_eq!(unlocked.manifest().unwrap().document_count(), 0);
    }

    #[tokio::test]
    async fn wrong_password_fails_to_unlock() {
        let vault = VaultManager::create(b"correct-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        let salt = *vault.salt();

        let encrypted_manifest = vault.encrypted_manifest().clone();

        let result = VaultManager::unlock(
            b"wrong-password",
            salt,
            &encrypted_manifest,
            MemoryStorage::new(),
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn modified_manifest_fails_authentication() {
        let vault = VaultManager::create(b"correct-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        let salt = *vault.salt();

        let mut encrypted_manifest = vault.encrypted_manifest().clone();

        encrypted_manifest.ciphertext[0] ^= 0x01;

        let result = VaultManager::unlock(
            b"correct-password",
            salt,
            &encrypted_manifest,
            MemoryStorage::new(),
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn manifest_can_be_saved() {
        let mut vault = VaultManager::create(b"test-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        vault
            .save_manifest()
            .await
            .expect("manifest save should succeed");

        assert!(!vault.encrypted_manifest().ciphertext.is_empty());

        assert!(!vault.manifest_cid().unwrap().is_empty());
    }

    #[tokio::test]
    async fn locked_vault_rejects_manifest_access() {
        let mut vault = VaultManager::create(b"test-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        vault.lock();

        assert!(vault.manifest().is_err());
        assert!(vault.manifest_mut().is_err());
        assert!(vault.document_key().is_err());
        assert!(vault.manifest_cid().is_err());
    }

    #[tokio::test]
    async fn add_document_returns_cid() {
        let mut vault = VaultManager::create(b"test-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        let cid = vault
            .add_document("document-001".to_string(), b"secret document")
            .await
            .expect("document should be added");

        assert!(!cid.is_empty());
    }

    #[tokio::test]
    async fn adding_document_creates_manifest_entry() {
        let mut vault = VaultManager::create(b"test-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        let cid = vault
            .add_document("document-001".to_string(), b"secret document")
            .await
            .expect("document should be added");

        let manifest = vault.manifest().expect("manifest should be accessible");

        assert_eq!(manifest.document_count(), 1);

        let entry = manifest
            .find_document("document-001")
            .expect("document should exist");

        assert_eq!(entry.ipfs_cid, cid);
    }

    #[tokio::test]
    async fn adding_document_updates_manifest_cid() {
        let mut vault = VaultManager::create(b"test-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        let initial_cid = vault
            .manifest_cid()
            .expect("manifest CID should exist")
            .to_string();

        vault
            .add_document("document-001".to_string(), b"secret document")
            .await
            .expect("document should be added");

        let updated_cid = vault.manifest_cid().expect("manifest CID should exist");

        assert_ne!(initial_cid, updated_cid);
    }

    #[tokio::test]
    async fn document_can_be_retrieved() {
        let mut vault = VaultManager::create(b"test-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        let cid = vault
            .add_document("document-001".to_string(), b"secret document")
            .await
            .expect("document should be added");

        let plaintext = vault
            .get_document(&cid)
            .await
            .expect("document should be retrieved");

        assert_eq!(plaintext, b"secret document");
    }

    #[tokio::test]
    async fn different_documents_have_different_cids() {
        let mut vault = VaultManager::create(b"test-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        let cid1 = vault
            .add_document("document-001".to_string(), b"first secret")
            .await
            .expect("first document should be added");

        let cid2 = vault
            .add_document("document-002".to_string(), b"second secret")
            .await
            .expect("second document should be added");

        assert_ne!(cid1, cid2);
    }

    #[tokio::test]
    async fn locked_vault_cannot_add_document() {
        let mut vault = VaultManager::create(b"test-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        vault.lock();

        let result = vault
            .add_document("document-001".to_string(), b"secret")
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn locked_vault_cannot_retrieve_document() {
        let mut vault = VaultManager::create(b"test-password", MemoryStorage::new())
            .await
            .expect("vault creation should succeed");

        let cid = vault
            .add_document("document-001".to_string(), b"secret")
            .await
            .expect("document should be added");

        vault.lock();

        let result = vault.get_document(&cid).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn creating_vault_stores_encrypted_manifest() {
        let password = b"test-password";

        let vault = VaultManager::create(password, MemoryStorage::new())
            .await
            .unwrap();

        let stored_manifest = vault.storage().load_manifest().await.unwrap();

        assert_eq!(stored_manifest.nonce, vault.encrypted_manifest().nonce);

        assert_eq!(
            stored_manifest.ciphertext,
            vault.encrypted_manifest().ciphertext
        );
    }

    #[tokio::test]
    async fn adding_document_stores_document() {
        let password = b"test-password";

        let mut vault = VaultManager::create(password, MemoryStorage::new())
            .await
            .unwrap();

        let cid = vault
            .add_document("document-1".to_string(), b"secret document")
            .await
            .unwrap();

        let stored_document = vault.storage().load_document(&cid).await.unwrap();

        let plaintext = stored_document
            .decrypt(vault.document_key().unwrap())
            .unwrap();

        assert_eq!(plaintext, b"secret document");
    }

    #[tokio::test]
    async fn deleting_document_removes_it_from_storage() {
        let password = b"test-password";

        let mut vault = VaultManager::create(password, MemoryStorage::new())
            .await
            .unwrap();

        let cid = vault
            .add_document("document-1".to_string(), b"secret document")
            .await
            .unwrap();

        assert!(vault.storage().load_document(&cid).await.is_ok());

        vault.delete_document(&cid).await.unwrap();

        assert!(matches!(
            vault.storage().load_document(&cid).await,
            Err(CryptoError::DocumentNotFound)
        ));
    }

    #[tokio::test]
    async fn deleting_document_removes_manifest_entry() {
        let password = b"test-password";

        let mut vault = VaultManager::create(password, MemoryStorage::new())
            .await
            .unwrap();

        let cid = vault
            .add_document("document-1".to_string(), b"secret document")
            .await
            .unwrap();

        assert_eq!(vault.manifest().unwrap().document_count(), 1);

        vault.delete_document(&cid).await.unwrap();

        assert_eq!(vault.manifest().unwrap().document_count(), 0);

        assert!(vault.manifest().unwrap().find_document(&cid).is_none());
    }

    #[tokio::test]
    async fn deleting_missing_document_fails() {
        let password = b"test-password";

        let mut vault = VaultManager::create(password, MemoryStorage::new())
            .await
            .unwrap();

        let result = vault.delete_document("nonexistent-cid").await;

        assert!(matches!(result, Err(CryptoError::DocumentNotFound)));
    }

    #[tokio::test]
    async fn vault_can_be_reopened_from_storage() {
        let password = b"test-password";

        // Create the vault.
        let mut vault = VaultManager::create(password, MemoryStorage::new())
            .await
            .unwrap();

        // Add a document.
        let cid = vault
            .add_document("document-1".to_string(), b"secret persistent document")
            .await
            .unwrap();

        // Save the information required for a
        // new vault session.
        let salt = *vault.salt();

        // End the first vault session and recover
        // the same storage backend.
        let storage = vault.into_storage();

        // Create a completely new VaultManager using
        // the same storage backend.
        let reopened = VaultManager::unlock_from_storage(password, salt, storage)
            .await
            .expect("vault should reopen from storage");

        // The manifest should have been recovered.
        assert_eq!(reopened.manifest().unwrap().document_count(), 1);

        // The document should still be retrievable.
        let plaintext = reopened
            .get_document(&cid)
            .await
            .expect("document should be retrieved");

        assert_eq!(plaintext, b"secret persistent document");
    }

    // Helper used only by the synchronous unlock test.
    //
    // The actual vault creation is async, so this helper
    // creates the same encrypted-manifest material directly.
    fn futures_test_create_vault() -> VaultManager<MemoryStorage> {
        let salt = generate_salt().expect("salt generation should succeed");

        let root_key =
            derive_key(b"correct-password", &salt).expect("key derivation should succeed");

        let keys = derive_vault_keys(&root_key).expect("vault key derivation should succeed");

        let manifest = VaultManifest::new();

        let encrypted_manifest =
            VaultManager::<MemoryStorage>::encrypt_manifest(&keys.manifest_key, &manifest)
                .expect("manifest encryption should succeed");

        VaultManager {
            salt,
            keys,
            manifest,
            encrypted_manifest,
            manifest_cid: String::new(),
            storage: MemoryStorage::new(),
            unlocked: true,
        }
    }
}
