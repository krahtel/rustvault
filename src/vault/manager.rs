use crate::crypto::encrypted_document::EncryptedDocument;
use crate::crypto::encryption::{decrypt, encrypt, EncryptedData};
use crate::crypto::error::CryptoError;
use crate::crypto::kdf::{derive_key, generate_salt, KEY_LEN, SALT_LEN};
use crate::crypto::key_derivation::{derive_vault_keys, VaultKeySet};
use crate::crypto::random::random_bytes;
use crate::crypto::signing::generate_keypair;
use crate::vault::identity::VaultIdentity;
use crate::vault::identity_storage::{IdentityStorageRecord, ProtectedVaultIdentity};
use crate::vault::manifest::{ManifestEntry, VaultManifest};
use crate::vault::root::VaultRoot;
use crate::vault::storage::{ManifestStorageRecord, VaultStorage};
pub struct VaultManager<S: VaultStorage> {
    salt: [u8; SALT_LEN],
    keys: VaultKeySet,
    manifest: VaultManifest,
    encrypted_manifest: EncryptedData,
    manifest_cid: String,
    identity_cid: String,
    vault_root: Option<VaultRoot>,
    storage: S,
    unlocked: bool,
}

impl<S: VaultStorage> VaultManager<S> {
    /// Create a new RustVault instance.
    ///
    /// Creation performs the following steps:
    ///
    /// 1. Generate a unique password salt.
    /// 2. Derive the vault root key using Argon2id.
    /// 3. Derive the vault subkeys using HKDF.
    /// 4. Generate a fresh ML-DSA vault identity.
    /// 5. Protect the identity using the identity key.
    /// 6. Store the protected identity and obtain its CID.
    /// 7. Create and encrypt the initial manifest.
    /// 8. Store the encrypted manifest and obtain its CID.
    /// 9. Create a signed VaultRoot containing both CIDs.
    /// 10. Store the signed VaultRoot.

    pub async fn create(password: &[u8], mut storage: S) -> Result<Self, CryptoError> {
        let salt = generate_salt()?;

        let root_key = derive_key(password, &salt)?;

        let keys = derive_vault_keys(&root_key)?;

        // Generate the vault's ML-DSA identity.
        let keypair = generate_keypair();

        let identity = VaultIdentity::from_keypair(keypair);

        // Protect the identity using the password-derived identity key.
        let protected_identity =
            ProtectedVaultIdentity::protect(&keys.identity_key, &identity.signing_key_pair())?;

        let identity_record = IdentityStorageRecord::from_protected_identity(&protected_identity);

        let identity_cid = storage.save_identity(&identity_record).await?;

        // Create and encrypt the initial manifest.
        let manifest = VaultManifest::new();

        let encrypted_manifest = Self::encrypt_manifest(&keys.manifest_key, &manifest)?;

        let manifest_cid = storage.save_manifest(&encrypted_manifest).await?;

        // Generate a unique vault identifier.
        let vault_id = Self::generate_vault_id()?;

        // Create the signed VaultRoot.
        let vault_root = VaultRoot::create_from_identity(
            vault_id,
            manifest_cid.clone(),
            identity_cid.clone(),
            &identity,
        )?;

        // Persist the signed VaultRoot.
        let _root_cid = storage.save_root(&vault_root).await?;

        Ok(Self {
            salt,
            keys,
            manifest,
            encrypted_manifest,
            manifest_cid,
            identity_cid,
            vault_root: Some(vault_root),
            storage,
            unlocked: true,
        })
    }

    /// Unlock a vault using an already-loaded encrypted manifest.
    ///
    /// This method is useful when the caller already has the
    /// encrypted manifest and its CID.
    ///
    /// Identity loading is intentionally not performed here yet.
    /// Persistent VaultRoot/bootstrap integration will be added
    /// in a later milestone.
    pub fn unlock(
        password: &[u8],
        salt: [u8; SALT_LEN],
        encrypted_manifest: EncryptedData,
        storage: S,
    ) -> Result<Self, CryptoError> {
        let root_key = derive_key(password, &salt)?;

        let keys = derive_vault_keys(&root_key)?;

        let manifest = Self::decrypt_manifest(&keys.manifest_key, &encrypted_manifest)?;

        Ok(Self {
            salt,
            keys,
            manifest,
            encrypted_manifest,
            manifest_cid: String::new(),
            identity_cid: String::new(),
            vault_root: None,
            storage,
            unlocked: true,
        })
    }

    /// Unlock a vault by loading the encrypted manifest and CID
    /// from the configured storage backend.
    ///
    /// Identity loading is intentionally not performed here yet.
    /// Persistent VaultRoot/bootstrap integration will be added
    /// in a later milestone.
    pub async fn unlock_from_storage(
        password: &[u8],
        salt: [u8; SALT_LEN],
        storage: S,
    ) -> Result<Self, CryptoError> {
        // Load the signed VaultRoot first.
        let vault_root = storage.load_root().await?;

        // Validate the VaultRoot signature and required fields.
        vault_root.validate()?;

        // Load the protected identity.
        let identity_record = storage.load_identity().await?;

        // Reconstruct the protected identity so we can inspect
        // its stored ML-DSA verifying key.
        let protected_identity = identity_record.to_protected_identity();

        // The public key stored in the identity must match the
        // public key embedded in the signed VaultRoot.
        let identity_verifying_key = protected_identity.verifying_key()?.encode().to_vec();

        let root_verifying_key = vault_root.verifying_key()?.encode().to_vec();

        if identity_verifying_key != root_verifying_key {
            return Err(CryptoError::InvalidVaultRoot);
        }

        // Load the manifest referenced by the signed VaultRoot.
        let manifest_record: ManifestStorageRecord = storage.load_manifest().await?;

        // The manifest returned by storage must be the manifest
        // referenced by the signed VaultRoot.
        if vault_root.manifest_cid != manifest_record.cid {
            return Err(CryptoError::InvalidVaultRoot);
        }

        // Derive the vault root key from the supplied password.
        let root_key = derive_key(password, &salt)?;

        // Derive the vault-specific subkeys.
        let keys = derive_vault_keys(&root_key)?;

        // Decrypt the manifest.
        let manifest =
            Self::decrypt_manifest(&keys.manifest_key, &manifest_record.encrypted_manifest)?;

        Ok(Self {
            salt,
            keys,
            manifest,
            encrypted_manifest: manifest_record.encrypted_manifest,
            manifest_cid: manifest_record.cid,
            identity_cid: vault_root.identity_cid().to_string(),
            vault_root: Some(vault_root),
            storage,
            unlocked: true,
        })
    }

    /// Add an encrypted document to the vault.
    pub async fn add_document(
        &mut self,
        document_id: impl Into<String>,
        plaintext: &[u8],
    ) -> Result<String, CryptoError> {
        self.ensure_unlocked()?;

        let document_id = document_id.into();

        if self.manifest.find_document(&document_id).is_some() {
            return Err(CryptoError::DocumentNotFound);
        }

        // Generate a fresh random key for this document.
        let document_key = Self::generate_document_key()?;

        // Encrypt document content using the document-specific key.
        let encrypted_content = EncryptedDocument::encrypt(&document_key, plaintext)?;

        // Wrap the document key using the vault document key.
        let wrapped_document_key =
            crate::crypto::key_wrap::wrap_document_key(&self.keys.document_key, &document_key)?;

        // Store encrypted document in storage.
        let cid = self
            .storage
            .store_document(encrypted_content.clone())
            .await?;

        // Encrypt metadata separately.
        let encrypted_metadata = encrypt(&self.keys.document_key, document_id.as_bytes())?;

        let entry = ManifestEntry {
            document_id: document_id.clone(),
            ipfs_cid: cid.clone(),
            wrapped_document_key,
            encrypted_metadata,
        };

        self.manifest.add_document(entry);

        // The document has already been stored. If saving the manifest fails,
        // roll back both the in-memory manifest entry and the stored document.
        if let Err(error) = self.save_manifest().await {
            self.manifest.remove_document(&document_id);

            // Best-effort cleanup of the stored encrypted document.
            let _ = self.storage.delete_document(&cid).await;

            return Err(error);
        }

        Ok(cid)
    }

    /// Retrieve and decrypt a document by document ID.
    pub async fn get_document(&self, document_id: &str) -> Result<Vec<u8>, CryptoError> {
        self.ensure_unlocked()?;

        let entry = self
            .manifest
            .find_document(document_id)
            .ok_or(CryptoError::DocumentNotFound)?;

        let encrypted_document = self.storage.load_document(&entry.ipfs_cid).await?;

        let document_key = crate::crypto::key_wrap::unwrap_document_key(
            &self.keys.document_key,
            &entry.wrapped_document_key,
        )?;

        encrypted_document.decrypt(&document_key)
    }
    pub async fn find_orphaned_documents(&self) -> Result<Vec<String>, CryptoError> {
        self.ensure_unlocked()?;

        let stored_cids = self.storage.list_document_cids().await?;

        let referenced_cids: std::collections::HashSet<String> = self
            .manifest
            .documents
            .iter()
            .map(|document| document.ipfs_cid.clone())
            .collect();

        Ok(stored_cids
            .into_iter()
            .filter(|cid| !referenced_cids.contains(cid))
            .collect())
    }
    pub async fn find_orphaned_manifests(&self) -> Result<Vec<String>, CryptoError> {
        self.ensure_unlocked()?;

        // The signed VaultRoot is the authoritative source for the
        // currently committed manifest.
        let current_root = self
            .vault_root
            .as_ref()
            .ok_or(CryptoError::StorageUnavailable)?;

        let current_manifest_cid = &current_root.manifest_cid;

        // Ask storage for every manifest object currently retained.
        let stored_cids = self.storage.list_manifest_cids().await?;

        // Any stored manifest that is not the manifest referenced by the
        // committed VaultRoot is considered an orphan.
        Ok(stored_cids
            .into_iter()
            .filter(|cid| cid != current_manifest_cid)
            .collect())
    }

    pub async fn remove_orphaned_manifest(&mut self, cid: &str) -> Result<(), CryptoError> {
        self.ensure_unlocked()?;

        // The signed VaultRoot is authoritative for the currently
        // committed manifest. It must never be deleted.
        let current_root = self
            .vault_root
            .as_ref()
            .ok_or(CryptoError::StorageUnavailable)?;

        if current_root.manifest_cid == cid {
            return Err(CryptoError::StorageUnavailable);
        }

        // Verify that the CID is actually an orphan before allowing
        // deletion. This prevents arbitrary manifest deletion.
        let orphaned_manifests = self.find_orphaned_manifests().await?;

        if !orphaned_manifests.iter().any(|orphan| orphan == cid) {
            return Err(CryptoError::StorageUnavailable);
        }

        self.storage.delete_manifest(cid).await
    }

    pub async fn remove_orphaned_document(&mut self, cid: &str) -> Result<(), CryptoError> {
        self.ensure_unlocked()?;

        let orphans = self.find_orphaned_documents().await?;

        if !orphans.iter().any(|orphan| orphan == cid) {
            return Err(CryptoError::DocumentNotFound);
        }

        self.storage.delete_document(cid).await
    }

    /// Delete a document from the vault.
    pub async fn delete_document(&mut self, document_id: &str) -> Result<(), CryptoError> {
        self.ensure_unlocked()?;

        // Capture the manifest entry before modifying the manifest.
        let entry = self
            .manifest
            .find_document(document_id)
            .cloned()
            .ok_or(CryptoError::DocumentNotFound)?;

        // Remove the entry from the in-memory manifest.
        self.manifest.remove_document(document_id);

        // Persist the manifest change first.
        //
        // If this fails, restore the in-memory entry and leave the
        // encrypted document untouched in storage.
        if let Err(error) = self.save_manifest().await {
            self.manifest.add_document(entry);
            return Err(error);
        }

        // Only delete the encrypted document after the manifest has
        // successfully committed the deletion.
        self.storage.delete_document(&entry.ipfs_cid).await?;

        Ok(())
    }

    /// Encrypt the current manifest.
    fn encrypt_manifest(
        manifest_key: &[u8; KEY_LEN],
        manifest: &VaultManifest,
    ) -> Result<EncryptedData, CryptoError> {
        let data = manifest
            .serialize()
            .map_err(|_| CryptoError::EncryptionFailed)?;

        encrypt(manifest_key, &data)
    }

    /// Decrypt an encrypted manifest.
    fn decrypt_manifest(
        manifest_key: &[u8; KEY_LEN],
        encrypted_manifest: &EncryptedData,
    ) -> Result<VaultManifest, CryptoError> {
        let data = decrypt(manifest_key, encrypted_manifest)?;

        VaultManifest::deserialize(&data).map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Save the current manifest to storage and update its CID.
    async fn save_manifest(&mut self) -> Result<(), CryptoError> {
        self.ensure_unlocked()?;

        let current_root = self
            .vault_root
            .as_ref()
            .ok_or(CryptoError::StorageUnavailable)?;

        let identity_record = self.storage.load_identity().await?;
        let protected_identity = identity_record.to_protected_identity();

        let signing_key = protected_identity.unlock_signing_key(&self.keys.identity_key)?;

        let encrypted_manifest = Self::encrypt_manifest(&self.keys.manifest_key, &self.manifest)?;

        // Store the new manifest first.
        let cid = self.storage.save_manifest(&encrypted_manifest).await?;

        let mut updated_root = current_root.clone();

        updated_root.update_manifest_cid(cid.clone(), &signing_key)?;

        // The manifest is now stored, but the root has not been
        // committed yet. If root persistence fails, remove the newly
        // stored manifest so it does not become an orphan.
        if let Err(error) = self.storage.save_root(&updated_root).await {
            let _ = self.storage.delete_manifest(&cid).await;
            return Err(error);
        }

        // Only update in-memory state after both manifest and root
        // persistence have succeeded.
        self.vault_root = Some(updated_root);
        self.encrypted_manifest = encrypted_manifest;
        self.manifest_cid = cid;

        Ok(())
    }
    /// Lock the vault.
    pub fn lock(&mut self) {
        self.unlocked = false;
    }

    /// Check whether the vault is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.unlocked
    }

    /// Return the vault salt.
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// Return the current manifest.
    pub fn manifest(&self) -> Result<&VaultManifest, CryptoError> {
        self.ensure_unlocked()?;

        Ok(&self.manifest)
    }

    /// Return mutable access to the manifest.
    pub fn manifest_mut(&mut self) -> Result<&mut VaultManifest, CryptoError> {
        self.ensure_unlocked()?;

        Ok(&mut self.manifest)
    }

    /// Return the encrypted manifest.
    pub fn encrypted_manifest(&self) -> Result<&EncryptedData, CryptoError> {
        self.ensure_unlocked()?;

        Ok(&self.encrypted_manifest)
    }

    /// Return the current manifest CID.
    pub fn manifest_cid(&self) -> Result<&str, CryptoError> {
        self.ensure_unlocked()?;

        if self.manifest_cid.is_empty() {
            return Err(CryptoError::StorageUnavailable);
        }

        Ok(&self.manifest_cid)
    }

    /// Return the protected identity CID.
    pub fn identity_cid(&self) -> Result<&str, CryptoError> {
        self.ensure_unlocked()?;

        if self.identity_cid.is_empty() {
            return Err(CryptoError::StorageUnavailable);
        }

        Ok(&self.identity_cid)
    }

    /// Return the signed VaultRoot created for this vault.
    ///
    /// A newly-created vault has a root. A vault unlocked through
    /// the legacy manifest-only unlock path does not have one loaded yet.
    pub fn vault_root(&self) -> Result<&VaultRoot, CryptoError> {
        self.ensure_unlocked()?;

        self.vault_root
            .as_ref()
            .ok_or(CryptoError::StorageUnavailable)
    }

    /// Return a reference to the underlying storage.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Return mutable access to the underlying storage.
    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    /// Consume the manager and return its storage backend.
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Return the vault document wrapping key.
    ///
    /// This is intended for internal cryptographic operations and
    /// should not be exposed through an external API.
    pub(crate) fn document_key(&self) -> Result<&[u8; KEY_LEN], CryptoError> {
        self.ensure_unlocked()?;

        Ok(&self.keys.document_key)
    }

    /// Generate a fresh random document key.
    fn generate_document_key() -> Result<[u8; KEY_LEN], CryptoError> {
        let bytes = random_bytes(KEY_LEN)?;

        let mut key = [0u8; KEY_LEN];

        key.copy_from_slice(&bytes);

        Ok(key)
    }

    /// Generate a unique vault identifier.
    fn generate_vault_id() -> Result<String, CryptoError> {
        let bytes = random_bytes(16)?;

        Ok(hex::encode(bytes))
    }

    fn ensure_unlocked(&self) -> Result<(), CryptoError> {
        if !self.unlocked {
            return Err(CryptoError::VaultNotUnlocked);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::encryption::encrypt;
    use crate::vault::storage::MemoryStorage;

    fn test_storage() -> MemoryStorage {
        MemoryStorage::new()
    }
    struct FailingRootStorage {
        inner: MemoryStorage,
        fail_root_save: bool,
    }

    impl FailingRootStorage {
        fn new() -> Self {
            Self {
                inner: MemoryStorage::new(),
                fail_root_save: false,
            }
        }

        fn fail_root_save(&mut self) {
            self.fail_root_save = true;
        }
    }

    #[tokio::test]
    async fn remove_orphaned_manifest_deletes_storage_orphan() {
        let password = b"manifest-orphan-removal-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("vault creation should succeed");

        let current_manifest_cid = vault
            .manifest_cid()
            .expect("current manifest CID should exist")
            .to_string();

        let replacement_manifest = VaultManifest::new();

        let orphaned_encrypted_manifest = VaultManager::<MemoryStorage>::encrypt_manifest(
            &vault.keys.manifest_key,
            &replacement_manifest,
        )
        .expect("replacement manifest encryption should succeed");

        let orphaned_cid = vault
            .storage_mut()
            .save_manifest(&orphaned_encrypted_manifest)
            .await
            .expect("orphaned manifest should be stored");

        assert_ne!(current_manifest_cid, orphaned_cid);

        let orphans = vault
            .find_orphaned_manifests()
            .await
            .expect("orphan detection should succeed");

        assert_eq!(orphans, vec![orphaned_cid.clone()]);

        vault
            .remove_orphaned_manifest(&orphaned_cid)
            .await
            .expect("orphaned manifest should be removed");

        let orphans_after_removal = vault
            .find_orphaned_manifests()
            .await
            .expect("orphan detection should succeed after removal");

        assert!(
            orphans_after_removal.is_empty(),
            "removed manifest must no longer be reported as an orphan"
        );
    }
    #[tokio::test]
    async fn remove_orphaned_manifest_rejects_current_manifest() {
        let password = b"current-manifest-protection-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("vault creation should succeed");

        let current_manifest_cid = vault
            .manifest_cid()
            .expect("current manifest CID should exist")
            .to_string();

        let result = vault.remove_orphaned_manifest(&current_manifest_cid).await;

        assert!(
            result.is_err(),
            "the committed manifest must never be removable"
        );

        let current_manifest_after = vault
            .manifest_cid()
            .expect("current manifest CID should still exist");

        assert_eq!(
            current_manifest_after, current_manifest_cid,
            "current manifest must remain unchanged"
        );
    }
    #[tokio::test]
    async fn remove_orphaned_manifest_rejects_unknown_cid() {
        let password = b"unknown-manifest-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("vault creation should succeed");

        let result = vault
            .remove_orphaned_manifest("memory-manifest-does-not-exist")
            .await;

        assert!(
            result.is_err(),
            "unknown manifest CIDs must not be removable"
        );
    }

    #[async_trait::async_trait]
    impl crate::vault::storage::VaultStorage for FailingRootStorage {
        async fn save_manifest(
            &mut self,
            manifest: &crate::crypto::encryption::EncryptedData,
        ) -> Result<String, CryptoError> {
            self.inner.save_manifest(manifest).await
        }

        async fn load_manifest(
            &self,
        ) -> Result<crate::vault::storage::ManifestStorageRecord, CryptoError> {
            self.inner.load_manifest().await
        }

        async fn list_manifest_cids(&self) -> Result<Vec<String>, CryptoError> {
            self.inner.list_manifest_cids().await
        }

        async fn delete_manifest(&mut self, cid: &str) -> Result<(), CryptoError> {
            self.inner.delete_manifest(cid).await
        }

        async fn save_identity(
            &mut self,
            identity: &crate::vault::identity_storage::IdentityStorageRecord,
        ) -> Result<String, CryptoError> {
            self.inner.save_identity(identity).await
        }

        async fn load_identity(
            &self,
        ) -> Result<crate::vault::identity_storage::IdentityStorageRecord, CryptoError> {
            self.inner.load_identity().await
        }

        async fn store_document(
            &mut self,
            document: crate::crypto::encrypted_document::EncryptedDocument,
        ) -> Result<String, CryptoError> {
            self.inner.store_document(document).await
        }

        async fn load_document(
            &self,
            cid: &str,
        ) -> Result<crate::crypto::encrypted_document::EncryptedDocument, CryptoError> {
            self.inner.load_document(cid).await
        }

        async fn delete_document(&mut self, cid: &str) -> Result<(), CryptoError> {
            self.inner.delete_document(cid).await
        }

        async fn list_document_cids(&self) -> Result<Vec<String>, CryptoError> {
            self.inner.list_document_cids().await
        }

        async fn save_root(
            &mut self,
            root: &crate::vault::root::VaultRoot,
        ) -> Result<String, CryptoError> {
            if self.fail_root_save {
                return Err(CryptoError::StorageUnavailable);
            }

            self.inner.save_root(root).await
        }

        async fn load_root(&self) -> Result<crate::vault::root::VaultRoot, CryptoError> {
            self.inner.load_root().await
        }
    }

    struct FaultInjectingStorage {
        inner: MemoryStorage,
        manifest_saves_before_failure: usize,
        fail_document_delete: bool,
        fail_manifest_delete_enabled: bool,
        fail_root_save_enabled: bool,
    }

    impl FaultInjectingStorage {
        fn fail_after_manifest_saves(count: usize) -> Self {
            Self {
                inner: MemoryStorage::new(),
                manifest_saves_before_failure: count,
                fail_document_delete: false,
                fail_manifest_delete_enabled: false,
                fail_root_save_enabled: false,
            }
        }

        fn fail_document_delete(&mut self) {
            self.fail_document_delete = true;
        }

        fn clear_document_delete_failure(&mut self) {
            self.fail_document_delete = false;
        }

        fn fail_manifest_delete(&mut self) {
            self.fail_manifest_delete_enabled = true;
        }

        fn clear_manifest_delete_failure(&mut self) {
            self.fail_manifest_delete_enabled = false;
        }

        fn fail_root_save(&mut self) {
            self.fail_root_save_enabled = true;
        }

        fn clear_root_save_failure(&mut self) {
            self.fail_root_save_enabled = false;
        }

        fn document_count(&self) -> usize {
            self.inner.document_count()
        }
    }

    #[async_trait::async_trait]
    impl crate::vault::storage::VaultStorage for FaultInjectingStorage {
        async fn save_manifest(
            &mut self,
            manifest: &crate::crypto::encryption::EncryptedData,
        ) -> Result<String, CryptoError> {
            if self.manifest_saves_before_failure == 0 {
                return Err(CryptoError::StorageUnavailable);
            }

            self.manifest_saves_before_failure -= 1;

            self.inner.save_manifest(manifest).await
        }

        async fn load_manifest(
            &self,
        ) -> Result<crate::vault::storage::ManifestStorageRecord, CryptoError> {
            self.inner.load_manifest().await
        }
        async fn list_manifest_cids(&self) -> Result<Vec<String>, CryptoError> {
            self.inner.list_manifest_cids().await
        }

        async fn delete_manifest(&mut self, cid: &str) -> Result<(), CryptoError> {
            if self.fail_manifest_delete_enabled {
                return Err(CryptoError::StorageUnavailable);
            }

            self.inner.delete_manifest(cid).await
        }

        async fn save_identity(
            &mut self,
            identity: &crate::vault::identity_storage::IdentityStorageRecord,
        ) -> Result<String, CryptoError> {
            self.inner.save_identity(identity).await
        }

        async fn load_identity(
            &self,
        ) -> Result<crate::vault::identity_storage::IdentityStorageRecord, CryptoError> {
            self.inner.load_identity().await
        }

        async fn store_document(
            &mut self,
            document: crate::crypto::encrypted_document::EncryptedDocument,
        ) -> Result<String, CryptoError> {
            self.inner.store_document(document).await
        }

        async fn load_document(
            &self,
            cid: &str,
        ) -> Result<crate::crypto::encrypted_document::EncryptedDocument, CryptoError> {
            self.inner.load_document(cid).await
        }

        async fn delete_document(&mut self, cid: &str) -> Result<(), CryptoError> {
            if self.fail_document_delete {
                return Err(CryptoError::StorageUnavailable);
            }

            self.inner.delete_document(cid).await
        }

        async fn list_document_cids(&self) -> Result<Vec<String>, CryptoError> {
            self.inner.list_document_cids().await
        }

        async fn save_root(&mut self, root: &VaultRoot) -> Result<String, CryptoError> {
            if self.fail_root_save_enabled {
                return Err(CryptoError::StorageUnavailable);
            }

            self.inner.save_root(root).await
        }

        async fn load_root(&self) -> Result<crate::vault::root::VaultRoot, CryptoError> {
            self.inner.load_root().await
        }
    }

    #[tokio::test]
    async fn failed_manifest_commit_preserves_vault_state_and_allows_retry() {
        let password = b"manifest-retry-state-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(5);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        // ------------------------------------------------------------
        // 1. Create an initial committed document.
        // ------------------------------------------------------------
        let original_cid = vault
            .add_document("original", b"original document")
            .await
            .expect("original document should be added");

        let original_root = vault.vault_root.clone().expect("vault root should exist");

        // ------------------------------------------------------------
        // 2. Force both root persistence and manifest cleanup to fail.
        // ------------------------------------------------------------
        vault.storage_mut().fail_root_save();
        vault.storage_mut().fail_manifest_delete();

        let result = vault.add_document("failed", b"failed document").await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));

        // ------------------------------------------------------------
        // 3. The committed root must still point to the original
        //    manifest.
        // ------------------------------------------------------------
        let current_root = vault
            .vault_root
            .clone()
            .expect("vault root should still exist");

        assert_eq!(current_root.manifest_cid, original_root.manifest_cid);

        // ------------------------------------------------------------
        // 4. The original document must remain accessible.
        // ------------------------------------------------------------
        let document = vault
            .get_document("original")
            .await
            .expect("original document should remain accessible");

        assert_eq!(document, b"original document");

        // ------------------------------------------------------------
        // 5. The failed document must not remain in the committed
        //    in-memory manifest.
        // ------------------------------------------------------------
        let failed_document = vault.get_document("failed").await;

        assert!(matches!(
            failed_document,
            Err(CryptoError::DocumentNotFound)
        ));

        // ------------------------------------------------------------
        // 6. Because manifest cleanup was intentionally forced to
        //    fail, there should be at least one orphaned manifest.
        //
        //    NOTE:
        //    MemoryStorage preserves previous manifest revisions.
        //    Therefore there may be more than one orphan here.
        // ------------------------------------------------------------
        let orphaned_manifests = vault
            .find_orphaned_manifests()
            .await
            .expect("orphaned manifest detection should succeed");

        assert!(
            !orphaned_manifests.is_empty(),
            "failed manifest commit should leave at least one recoverable orphan"
        );

        // ------------------------------------------------------------
        // 7. Clear both simulated storage failures.
        // ------------------------------------------------------------
        vault.storage_mut().clear_root_save_failure();

        vault.storage_mut().clear_manifest_delete_failure();

        // ------------------------------------------------------------
        // 8. Remove every currently detected orphaned manifest.
        //
        //    This is necessary because MemoryStorage retains historical
        //    manifest revisions, not just the manifest created by the
        //    failed transaction.
        // ------------------------------------------------------------
        for orphan_cid in orphaned_manifests {
            vault
                .remove_orphaned_manifest(&orphan_cid)
                .await
                .expect("orphaned manifest should be removable");
        }

        // Confirm that all currently stored non-current manifests
        // have been removed.
        let orphaned_manifests = vault
            .find_orphaned_manifests()
            .await
            .expect("orphaned manifest detection should succeed");

        assert!(
            orphaned_manifests.is_empty(),
            "all detected orphaned manifests should be removable"
        );

        // ------------------------------------------------------------
        // 9. Retry the operation after storage recovery.
        // ------------------------------------------------------------
        let retry_cid = vault
            .add_document("retry", b"retry document")
            .await
            .expect("retry document should be added");

        assert_ne!(retry_cid, original_cid);

        // ------------------------------------------------------------
        // 10. The original document must still be accessible.
        // ------------------------------------------------------------
        let original_document = vault
            .get_document("original")
            .await
            .expect("original document should remain accessible");

        assert_eq!(original_document, b"original document");

        // ------------------------------------------------------------
        // 11. The retried document must be accessible.
        // ------------------------------------------------------------
        let retry_document = vault
            .get_document("retry")
            .await
            .expect("retry document should be accessible");

        assert_eq!(retry_document, b"retry document");

        // ------------------------------------------------------------
        // 12. The retry must have produced a new committed root.
        // ------------------------------------------------------------
        let final_root = vault
            .vault_root
            .clone()
            .expect("final vault root should exist");

        assert_ne!(final_root.manifest_cid, original_root.manifest_cid);

        // ------------------------------------------------------------
        // 13. Verify the current root points to the latest committed
        //     manifest.
        // ------------------------------------------------------------
        let stored_manifest = vault
            .storage
            .load_manifest()
            .await
            .expect("latest manifest should be loadable");

        assert_eq!(stored_manifest.cid, final_root.manifest_cid);

        // ------------------------------------------------------------
        // IMPORTANT:
        //
        // After the successful retry, MemoryStorage creates another
        // manifest revision. The previous manifest is therefore again
        // considered an orphan by find_orphaned_manifests().
        //
        // We should NOT assert that the orphan list is empty here.
        // Instead, verify that the current root's manifest is NOT
        // considered an orphan.
        // ------------------------------------------------------------
        let orphaned_manifests = vault
            .find_orphaned_manifests()
            .await
            .expect("orphaned manifest detection should succeed");

        assert!(
            !orphaned_manifests
                .iter()
                .any(|cid| cid == &final_root.manifest_cid),
            "the committed manifest must never be reported as orphaned"
        );
    }
    #[tokio::test]
    async fn delete_document_manifest_save_failure_does_not_leave_missing_document_reference() {
        let password = b"delete-manifest-save-failure-test";

        // Save #1: vault creation.
        // Save #2: adding the document.
        // Save #3: deletion, which will fail.
        let storage = FaultInjectingStorage::fail_after_manifest_saves(2);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        vault
            .add_document("doc-1", b"secret document")
            .await
            .expect("document creation should succeed");

        let result = vault.delete_document("doc-1").await;

        assert!(
            matches!(result, Err(CryptoError::StorageUnavailable)),
            "delete_document should report the manifest storage failure"
        );

        // The document should still be available because the deletion
        // operation was not successfully committed.
        let result = vault.get_document("doc-1").await;

        assert!(
            result.is_ok(),
            "failed document deletion should not make the document inaccessible"
        );

        let manifest = vault.manifest().expect("vault should remain unlocked");

        assert!(
            manifest.find_document("doc-1").is_some(),
            "failed document deletion should leave the manifest entry intact"
        );
    }

    #[tokio::test]
    async fn remove_orphaned_manifest_failure_leaves_orphan_detectable() {
        let password = b"manifest-delete-failure-test";

        let mut vault = VaultManager::create(
            password,
            FaultInjectingStorage::fail_after_manifest_saves(10),
        )
        .await
        .expect("vault creation should succeed");

        let current_manifest_cid = vault
            .manifest_cid()
            .expect("current manifest CID should exist")
            .to_string();

        let replacement_manifest = VaultManifest::new();

        let orphaned_encrypted_manifest = VaultManager::<FaultInjectingStorage>::encrypt_manifest(
            &vault.keys.manifest_key,
            &replacement_manifest,
        )
        .expect("replacement manifest encryption should succeed");

        let orphaned_cid = vault
            .storage_mut()
            .save_manifest(&orphaned_encrypted_manifest)
            .await
            .expect("orphaned manifest should be stored");

        assert_ne!(current_manifest_cid, orphaned_cid);

        let orphans = vault
            .find_orphaned_manifests()
            .await
            .expect("orphan detection should succeed");

        assert_eq!(orphans, vec![orphaned_cid.clone()]);

        vault.storage_mut().fail_manifest_delete();

        let result = vault.remove_orphaned_manifest(&orphaned_cid).await;

        assert!(
            result.is_err(),
            "manifest deletion should fail when storage failure is injected"
        );

        let orphans_after_failure = vault
            .find_orphaned_manifests()
            .await
            .expect("orphan detection should still succeed");

        assert_eq!(
            orphans_after_failure,
            vec![orphaned_cid.clone()],
            "failed deletion must leave the orphan detectable"
        );
    }

    #[tokio::test]
    async fn manifest_save_root_failure_with_cleanup_failure_leaves_recoverable_orphan() {
        let password = b"manifest-cleanup-failure-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(3);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let original_root = vault.vault_root.clone().expect("vault root should exist");

        // Force the root update to fail.
        vault.storage_mut().fail_root_save();

        // Also force cleanup of the newly stored manifest to fail.
        vault.storage_mut().fail_manifest_delete();

        let result = vault.add_document("doc-1", b"document").await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));

        // The original root must remain authoritative.
        let current_root = vault
            .vault_root
            .clone()
            .expect("vault root should still exist");

        assert_eq!(current_root.manifest_cid, original_root.manifest_cid);

        // Because cleanup failed, the newly stored manifest should
        // remain detectable as an orphan.
        let orphaned_manifests = vault
            .find_orphaned_manifests()
            .await
            .expect("orphaned manifest detection should succeed");

        assert_eq!(orphaned_manifests.len(), 1);

        assert_ne!(orphaned_manifests[0], original_root.manifest_cid);

        // Clear the simulated cleanup failure.
        vault.storage_mut().clear_manifest_delete_failure();

        // The orphan should now be recoverable.
        let orphan_cid = orphaned_manifests[0].clone();

        vault
            .remove_orphaned_manifest(&orphan_cid)
            .await
            .expect("orphaned manifest should be removable after recovery");

        let orphaned_manifests = vault
            .find_orphaned_manifests()
            .await
            .expect("orphaned manifest detection should succeed");

        assert!(
            orphaned_manifests.is_empty(),
            "recovered manifest orphan should be removed"
        );
    }

    #[tokio::test]
    async fn manifest_save_root_failure_preserves_previous_root() {
        let password = b"manifest-root-failure-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(3);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let original_root = vault.vault_root.clone().expect("vault root should exist");

        vault.storage_mut().fail_root_save();

        let result = vault.add_document("doc-1", b"document");

        let result = result.await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));

        let current_root = vault
            .vault_root
            .clone()
            .expect("vault root should still exist");

        assert_eq!(current_root.manifest_cid, original_root.manifest_cid);
    }
    #[tokio::test]
    async fn remove_orphaned_manifest_can_be_retried_after_failure() {
        let password = b"manifest-delete-retry-test";

        let mut vault = VaultManager::create(
            password,
            FaultInjectingStorage::fail_after_manifest_saves(10),
        )
        .await
        .expect("vault creation should succeed");

        let current_manifest_cid = vault
            .manifest_cid()
            .expect("current manifest CID should exist")
            .to_string();

        let replacement_manifest = VaultManifest::new();

        let orphaned_encrypted_manifest = VaultManager::<FaultInjectingStorage>::encrypt_manifest(
            &vault.keys.manifest_key,
            &replacement_manifest,
        )
        .expect("replacement manifest encryption should succeed");

        let orphaned_cid = vault
            .storage_mut()
            .save_manifest(&orphaned_encrypted_manifest)
            .await
            .expect("orphaned manifest should be stored");

        assert_ne!(current_manifest_cid, orphaned_cid);

        vault.storage_mut().fail_manifest_delete();

        let failed_result = vault.remove_orphaned_manifest(&orphaned_cid).await;

        assert!(failed_result.is_err(), "first deletion attempt should fail");

        vault.storage_mut().clear_manifest_delete_failure();

        vault
            .remove_orphaned_manifest(&orphaned_cid)
            .await
            .expect("retry should successfully remove the orphan");

        let orphans = vault
            .find_orphaned_manifests()
            .await
            .expect("orphan detection should succeed after retry");

        assert!(
            orphans.is_empty(),
            "successfully removed orphan must no longer be detectable"
        );

        assert_eq!(
            vault
                .manifest_cid()
                .expect("current manifest CID should still exist"),
            current_manifest_cid,
            "removing an orphan must not change the committed manifest"
        );
    }

    #[tokio::test]
    async fn remove_orphaned_document_rejects_referenced_document() {
        let password = b"referenced-document-protection-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(3);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let cid = vault
            .add_document("doc-1", b"valid document")
            .await
            .expect("document creation should succeed");

        let result = vault.remove_orphaned_document(&cid).await;

        assert!(
            matches!(result, Err(CryptoError::DocumentNotFound)),
            "a manifest-referenced document must not be removable as an orphan"
        );

        // The document must still be accessible.
        let document = vault
            .get_document("doc-1")
            .await
            .expect("referenced document should remain accessible");

        assert_eq!(document, b"valid document");

        // There must still be no orphans.
        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert!(
            orphans.is_empty(),
            "a valid document must not become an orphan"
        );
    }

    #[tokio::test]
    async fn creates_encrypted_manifest() {
        let password = b"correct horse battery staple";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        assert!(vault.is_unlocked());

        let encrypted_manifest = vault
            .encrypted_manifest()
            .expect("manifest should be available");

        assert!(!encrypted_manifest.ciphertext.is_empty());

        let cid = vault.manifest_cid().expect("manifest CID should exist");

        assert!(!cid.is_empty());
    }

    #[tokio::test]
    async fn creates_protected_identity() {
        let password = b"identity-create-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let identity_cid = vault.identity_cid().expect("identity CID should exist");

        assert!(!identity_cid.is_empty());

        let identity = vault
            .storage()
            .load_identity()
            .await
            .expect("protected identity should exist");

        assert!(!identity.encrypted_seed.ciphertext.is_empty());
        assert!(!identity.verifying_key.is_empty());
    }

    #[tokio::test]
    async fn creates_signed_vault_root() {
        let password = b"root-create-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let root = vault.vault_root().expect("vault root should exist");

        assert_eq!(root.manifest_cid, vault.manifest_cid().unwrap());

        assert_eq!(root.identity_cid(), vault.identity_cid().unwrap());

        assert!(!root.vault_id().is_empty());

        assert!(!root.verifying_key().unwrap().encode().is_empty());

        assert!(!root.signature.is_empty());

        root.validate()
            .expect("vault root signature should be valid");
    }

    #[tokio::test]
    async fn vault_root_identity_cid_matches_stored_identity() {
        let password = b"root-identity-link-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let root = vault.vault_root().expect("vault root should exist");

        let stored_identity_cid = vault.identity_cid().expect("identity CID should exist");

        assert_eq!(root.identity_cid(), stored_identity_cid);
    }
    #[tokio::test]
    async fn add_document_manifest_save_failure_does_not_leave_orphaned_document() {
        let password = b"manifest-save-failure-test";

        // The first manifest save happens during vault creation.
        // The second manifest save will fail.
        let storage = FaultInjectingStorage::fail_after_manifest_saves(1);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let result = vault.add_document("doc-1", b"secret document").await;

        assert!(
            matches!(result, Err(CryptoError::StorageUnavailable)),
            "add_document should report the manifest storage failure"
        );

        // The failed operation should not leave the document accessible
        // through the manager's in-memory manifest.
        let result = vault.get_document("doc-1").await;

        assert!(
            matches!(result, Err(CryptoError::DocumentNotFound)),
            "failed document addition should not remain in the manifest"
        );

        // The encrypted document should also have been rolled back
        // from storage.
        let storage = vault.into_storage();

        assert_eq!(
            storage.document_count(),
            0,
            "failed document addition should not leave an orphaned document"
        );
    }
    #[tokio::test]
    async fn find_orphaned_documents_detects_storage_orphan() {
        let password = b"orphan-detection-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(3);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let cid = vault
            .add_document("doc-1", b"secret document")
            .await
            .expect("document creation should succeed");

        vault.storage_mut().fail_document_delete();

        let result = vault.delete_document("doc-1").await;

        assert!(
            matches!(result, Err(CryptoError::StorageUnavailable)),
            "physical deletion should fail"
        );

        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert_eq!(
            orphans,
            vec![cid],
            "the physically retained document should be detected as an orphan"
        );
    }
    #[tokio::test]
    async fn find_orphaned_manifests_detects_storage_orphan() {
        let password = b"manifest-orphan-detection-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("vault creation should succeed");

        let current_manifest_cid = vault
            .manifest_cid()
            .expect("current manifest CID should exist")
            .to_string();

        // Create another valid encrypted manifest object in storage.
        //
        // This object is intentionally not committed through VaultRoot.
        let replacement_manifest = VaultManifest::new();

        let orphaned_encrypted_manifest = VaultManager::<MemoryStorage>::encrypt_manifest(
            &vault.keys.manifest_key,
            &replacement_manifest,
        )
        .expect("replacement manifest encryption should succeed");

        let orphaned_cid = vault
            .storage_mut()
            .save_manifest(&orphaned_encrypted_manifest)
            .await
            .expect("orphaned manifest should be stored");

        assert_ne!(
            current_manifest_cid, orphaned_cid,
            "the orphaned manifest must have a different CID"
        );

        let orphans = vault
            .find_orphaned_manifests()
            .await
            .expect("manifest orphan detection should succeed");

        assert_eq!(
            orphans,
            vec![orphaned_cid],
            "the uncommitted manifest should be detected as an orphan"
        );
    }
    #[tokio::test]
    async fn find_orphaned_manifests_ignores_current_manifest() {
        let password = b"manifest-current-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("vault creation should succeed");

        let current_manifest_cid = vault
            .manifest_cid()
            .expect("current manifest CID should exist")
            .to_string();

        let orphans = vault
            .find_orphaned_manifests()
            .await
            .expect("manifest orphan detection should succeed");

        assert!(
            !orphans.contains(&current_manifest_cid),
            "the committed manifest must never be reported as an orphan"
        );

        assert!(
            orphans.is_empty(),
            "a newly created vault should have no orphaned manifests"
        );
    }
    #[tokio::test]
    async fn remove_orphaned_document_removes_storage_object() {
        let password = b"orphan-removal-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(3);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let cid = vault
            .add_document("doc-1", b"orphaned document")
            .await
            .expect("document creation should succeed");

        // Force the physical deletion to fail so the document becomes an orphan.
        vault.storage_mut().fail_document_delete();

        let result = vault.delete_document("doc-1").await;

        assert!(
            matches!(result, Err(CryptoError::StorageUnavailable)),
            "physical deletion should fail"
        );

        // Confirm the orphan exists.
        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert_eq!(orphans, vec![cid.clone()]);

        // Allow physical deletion again.
        vault.storage_mut().clear_document_delete_failure();

        vault
            .remove_orphaned_document(&cid)
            .await
            .expect("orphan removal should succeed");

        // The orphan should now be gone.
        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert!(orphans.is_empty(), "removed orphan should no longer exist");
    }

    #[tokio::test]
    async fn remove_orphaned_document_failure_leaves_orphan_detectable() {
        let password = b"orphan-removal-failure-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(3);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let cid = vault
            .add_document("doc-1", b"orphaned document")
            .await
            .expect("document should be added");

        // Force the normal document deletion to fail, creating an orphan.
        vault.storage_mut().fail_document_delete();

        let result = vault.delete_document("doc-1").await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));

        // The document must now be an orphan.
        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert_eq!(orphans, vec![cid.clone()]);

        // Force the orphan cleanup deletion to fail as well.
        vault.storage_mut().fail_document_delete();

        // Attempt orphan removal while storage deletion is failing.
        let result = vault.remove_orphaned_document(&cid).await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));

        // The orphan must still exist and remain detectable.
        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should still succeed");

        assert_eq!(orphans, vec![cid]);
    }
    #[tokio::test]
    async fn remove_orphaned_document_can_be_retried_after_failure() {
        let password = b"orphan-retry-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(3);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let cid = vault
            .add_document("doc-1", b"orphaned document")
            .await
            .expect("document should be added");

        // Create an orphan by forcing physical document deletion to fail.
        vault.storage_mut().fail_document_delete();

        let result = vault.delete_document("doc-1").await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));

        // The document should now exist in storage but no longer be
        // referenced by the manifest.
        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert_eq!(orphans, vec![cid.clone()]);

        // Keep document deletion failure enabled so the first orphan
        // cleanup attempt fails.
        let result = vault.remove_orphaned_document(&cid).await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));

        // The orphan must still be present after the failed cleanup.
        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert_eq!(orphans, vec![cid.clone()]);

        // Clear the simulated storage failure before retrying.
        vault.storage_mut().clear_document_delete_failure();

        // Retry the cleanup after the storage failure has cleared.
        vault
            .remove_orphaned_document(&cid)
            .await
            .expect("orphan cleanup retry should succeed");

        // The orphan should now be gone.
        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert!(orphans.is_empty());
    }
    #[tokio::test]
    async fn find_orphaned_documents_handles_multiple_orphans_independently() {
        let password = b"multiple-orphans-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(6);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let cid_a = vault
            .add_document("doc-a", b"document A")
            .await
            .expect("document A should be added");

        let cid_b = vault
            .add_document("doc-b", b"document B")
            .await
            .expect("document B should be added");

        let cid_c = vault
            .add_document("doc-c", b"document C")
            .await
            .expect("document C should be added");

        // Make document A an orphan.
        vault.storage_mut().fail_document_delete();

        let result = vault.delete_document("doc-a").await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));

        // Make document B an orphan.
        let result = vault.delete_document("doc-b").await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));

        // Document C remains valid and referenced by the manifest.
        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert_eq!(orphans.len(), 2);
        assert!(orphans.contains(&cid_a));
        assert!(orphans.contains(&cid_b));
        assert!(!orphans.contains(&cid_c));

        // Clear the simulated storage failure before orphan cleanup.
        vault.storage_mut().clear_document_delete_failure();

        // Remove only orphan A.
        vault
            .remove_orphaned_document(&cid_a)
            .await
            .expect("orphan A should be removable");

        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert_eq!(orphans, vec![cid_b.clone()]);

        // Document C must still be accessible.
        let document = vault
            .get_document("doc-c")
            .await
            .expect("document C should remain accessible");

        assert_eq!(document, b"document C");

        // Remove orphan B.
        vault
            .remove_orphaned_document(&cid_b)
            .await
            .expect("orphan B should be removable");

        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert!(orphans.is_empty());

        // Document C must still be accessible after all orphan cleanup.
        let document = vault
            .get_document("doc-c")
            .await
            .expect("document C should remain accessible");

        assert_eq!(document, b"document C");
    }
    #[tokio::test]
    async fn find_orphaned_documents_ignores_valid_documents() {
        let password = b"orphan-valid-document-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(3);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let cid = vault
            .add_document("doc-1", b"valid document")
            .await
            .expect("document creation should succeed");

        let orphans = vault
            .find_orphaned_documents()
            .await
            .expect("orphan detection should succeed");

        assert!(
            !orphans.contains(&cid),
            "a document referenced by the manifest must not be reported as an orphan"
        );

        assert!(orphans.is_empty(), "there should be no orphaned documents");
    }

    #[tokio::test]
    async fn manifest_save_root_failure_does_not_leave_new_manifest_as_orphan() {
        let password = b"manifest-root-no-orphan-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(3);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let original_root = vault.vault_root.clone().expect("vault root should exist");

        vault.storage_mut().fail_root_save();

        let result = vault.add_document("doc-1", b"document").await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));

        // The root must still point to the original manifest.
        let current_root = vault
            .vault_root
            .clone()
            .expect("vault root should still exist");

        assert_eq!(current_root.manifest_cid, original_root.manifest_cid);

        // The failed manifest commit must be cleaned up.
        let orphaned_manifests = vault
            .find_orphaned_manifests()
            .await
            .expect("orphaned manifest detection should succeed");

        assert!(
            orphaned_manifests.is_empty(),
            "failed manifest commit should not leave an orphaned manifest"
        );
    }
    #[tokio::test]
    async fn manifest_save_root_failure_cleans_up_new_manifest() {
        let password = b"manifest-root-cleanup-test";

        let storage = FaultInjectingStorage::fail_after_manifest_saves(3);

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let original_root = vault.vault_root.clone().expect("vault root should exist");

        vault.storage_mut().fail_root_save();

        let result = vault.add_document("doc-1", b"document").await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));

        // The root must still point to the original manifest.
        let current_root = vault
            .vault_root
            .clone()
            .expect("vault root should still exist");

        assert_eq!(current_root.manifest_cid, original_root.manifest_cid);

        // The failed manifest commit must not leave an orphaned
        // manifest in storage.
        let orphaned_manifests = vault
            .find_orphaned_manifests()
            .await
            .expect("orphaned manifest detection should succeed");

        assert!(
            orphaned_manifests.is_empty(),
            "failed manifest commit should not leave an orphaned manifest"
        );
    }

    #[tokio::test]
    async fn creates_and_persists_signed_vault_root() {
        let storage = MemoryStorage::new();

        let manager = VaultManager::create(b"test-password", storage)
            .await
            .expect("vault should be created");

        let stored_root = manager
            .storage()
            .load_root()
            .await
            .expect("root should be stored");

        let manager_root = manager.vault_root().expect("vault root should exist");

        assert_eq!(stored_root, manager_root.clone());

        assert!(stored_root.validate().is_ok());

        assert_eq!(stored_root.identity_cid(), manager.identity_cid().unwrap());

        assert_eq!(stored_root.manifest_cid, manager.manifest_cid().unwrap());
    }

    #[tokio::test]
    async fn unlock_does_not_generate_new_identity() {
        let password = b"unlock-no-identity-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let salt = *vault.salt();

        let encrypted_manifest = vault.encrypted_manifest().unwrap().clone();

        let storage = vault.into_storage();

        let unlocked = VaultManager::unlock(password, salt, encrypted_manifest, storage)
            .expect("failed to unlock vault");

        assert!(matches!(
            unlocked.identity_cid(),
            Err(CryptoError::StorageUnavailable)
        ));

        assert!(matches!(
            unlocked.vault_root(),
            Err(CryptoError::StorageUnavailable)
        ));
    }

    #[tokio::test]
    async fn unlock_from_storage_does_not_generate_new_identity() {
        let password = b"unlock-storage-no-identity";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let salt = *vault.salt();

        let expected_identity_cid = vault
            .identity_cid()
            .expect("vault identity CID should be available")
            .to_string();

        let storage = vault.into_storage();

        let unlocked = VaultManager::unlock_from_storage(password, salt, storage)
            .await
            .expect("failed to unlock vault");

        assert_eq!(
            unlocked
                .identity_cid()
                .expect("unlocked vault should have an identity CID"),
            expected_identity_cid
        );
    }
    #[tokio::test]
    async fn unlock_from_storage_rejects_tampered_vault_root() {
        let password = b"tampered-root-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let salt = *vault.salt();

        let mut tampered_root = vault.vault_root().expect("vault root should exist").clone();

        // Modify a field that is covered by the VaultRoot signature.
        tampered_root.vault_id = "tampered-vault-id".to_string();

        let mut storage = vault.into_storage();

        // Replace the valid root with the tampered, incorrectly signed root.
        storage
            .save_root(&tampered_root)
            .await
            .expect("failed to save tampered root");

        let result = VaultManager::unlock_from_storage(password, salt, storage).await;

        assert!(matches!(
            result,
            Err(CryptoError::SignatureVerificationFailed)
        ));
    }
    #[tokio::test]
    async fn unlock_from_storage_rejects_mismatched_identity_key() {
        let password = b"mismatched-identity-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let salt = *vault.salt();

        // Derive the same identity protection key that the vault uses.
        let root_key = derive_key(password, &salt).expect("failed to derive root key");

        let keys = derive_vault_keys(&root_key).expect("failed to derive vault keys");

        // Generate a completely different ML-DSA identity.
        let attacker_identity = generate_keypair();

        // Protect the attacker's identity using the legitimate vault's
        // identity protection key.
        let protected_identity =
            ProtectedVaultIdentity::protect(&keys.identity_key, &attacker_identity)
                .expect("failed to protect replacement identity");

        // Convert it into the storage representation expected by VaultStorage.
        let replacement_identity =
            IdentityStorageRecord::from_protected_identity(&protected_identity);

        let mut storage = vault.into_storage();

        // Replace the legitimate identity with the attacker's identity.
        storage
            .save_identity(&replacement_identity)
            .await
            .expect("failed to replace stored identity");

        let result = VaultManager::unlock_from_storage(password, salt, storage).await;

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }

    #[tokio::test]
    async fn unlock_from_storage_rejects_mismatched_manifest_cid() {
        let password = b"mismatched-manifest-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let salt = *vault.salt();

        let original_manifest_cid = vault
            .manifest_cid()
            .expect("manifest CID should exist")
            .to_string();

        let mut storage = vault.into_storage();

        // Store a document first so MemoryStorage generates a different
        // manifest CID on the next save.
        let document_key = crate::crypto::document::generate_document_key()
            .expect("failed to generate document key");

        let document = EncryptedDocument::encrypt(&document_key, b"test document")
            .expect("failed to encrypt test document");

        storage
            .store_document(document)
            .await
            .expect("failed to store test document");

        // The replacement manifest itself can be empty. The important
        // property is that it receives a different CID.
        let root_key = derive_key(password, &salt).expect("failed to derive root key");

        let keys = derive_vault_keys(&root_key).expect("failed to derive vault keys");

        let replacement_manifest = VaultManifest::new();

        let encrypted_replacement_manifest = VaultManager::<MemoryStorage>::encrypt_manifest(
            &keys.manifest_key,
            &replacement_manifest,
        )
        .expect("failed to encrypt replacement manifest");

        let replacement_cid = storage
            .save_manifest(&encrypted_replacement_manifest)
            .await
            .expect("failed to save replacement manifest");

        assert_ne!(original_manifest_cid, replacement_cid);

        let result = VaultManager::unlock_from_storage(password, salt, storage).await;

        assert!(matches!(result, Err(CryptoError::InvalidVaultRoot)));
    }
    #[tokio::test]
    async fn unlocks_from_storage() {
        let password = b"vault-password";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let salt = *vault.salt();

        let storage = vault.into_storage();

        let unlocked = VaultManager::unlock_from_storage(password, salt, storage)
            .await
            .expect("failed to unlock vault");

        assert!(unlocked.is_unlocked());

        assert_eq!(unlocked.manifest().unwrap().document_count(), 0);

        assert!(!unlocked.manifest_cid().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unlock_from_storage_recovers_manifest_cid() {
        let password = b"manifest-cid-password";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let original_cid = vault.manifest_cid().unwrap().to_string();

        let salt = *vault.salt();

        let storage = vault.into_storage();

        let unlocked = VaultManager::unlock_from_storage(password, salt, storage)
            .await
            .expect("failed to unlock vault");

        assert_eq!(unlocked.manifest_cid().unwrap(), original_cid);
    }

    #[tokio::test]
    async fn wrong_password_cannot_unlock() {
        let password = b"correct-password";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let salt = *vault.salt();

        let encrypted_manifest = vault.encrypted_manifest().unwrap().clone();

        let storage = vault.into_storage();

        let result = VaultManager::unlock(b"wrong-password", salt, encrypted_manifest, storage);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn lock_prevents_manifest_access() {
        let password = b"lock-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        vault.lock();

        assert!(!vault.is_unlocked());

        assert!(vault.manifest().is_err());
        assert!(vault.encrypted_manifest().is_err());
        assert!(vault.manifest_cid().is_err());
    }

    #[tokio::test]
    async fn adding_document_updates_manifest_cid() {
        let password = b"manifest-update-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let initial_cid = vault.manifest_cid().unwrap().to_string();

        vault
            .add_document("document-1", b"secret document")
            .await
            .expect("failed to add document");

        let updated_cid = vault.manifest_cid().unwrap().to_string();

        assert_ne!(initial_cid, updated_cid);
    }
    #[tokio::test]
    async fn save_manifest_root_failure_does_not_update_manager_manifest_cid() {
        let password = b"root-save-failure-test";

        let storage = FailingRootStorage::new();

        let mut vault = VaultManager::create(password, storage)
            .await
            .expect("vault creation should succeed");

        let original_manifest_cid = vault
            .manifest_cid()
            .expect("manifest CID should exist")
            .to_string();

        let original_root = vault.vault_root().expect("vault root should exist").clone();

        // The next save_root() must fail.
        vault.storage_mut().fail_root_save();

        let result = vault.add_document("doc-1", b"secret document").await;

        assert!(
            matches!(result, Err(CryptoError::StorageUnavailable)),
            "document addition should fail when root persistence fails"
        );

        // The in-memory manifest entry is rolled back by add_document().
        let manifest = vault.manifest().expect("vault should remain unlocked");

        assert!(
            manifest.find_document("doc-1").is_none(),
            "failed document addition must not remain in the manifest"
        );

        // The persisted root must still contain the original manifest CID.
        let stored_root = vault
            .storage()
            .load_root()
            .await
            .expect("stored root should still exist");

        assert_eq!(
            stored_root.manifest_cid, original_manifest_cid,
            "persisted root must still reference the previously committed manifest"
        );

        // The manager's root currently needs to be checked explicitly.
        let manager_root = vault
            .vault_root()
            .expect("manager should still have a vault root");

        assert_eq!(
        manager_root.manifest_cid,
        original_root.manifest_cid,
        "failed root persistence must not leave the manager root pointing at an uncommitted manifest"
    );
    }

    #[tokio::test]
    async fn document_roundtrip() {
        let password = b"document-roundtrip";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let plaintext = b"This is a secret document.";

        vault
            .add_document("doc-1", plaintext)
            .await
            .expect("failed to add document");

        let recovered = vault
            .get_document("doc-1")
            .await
            .expect("failed to get document");

        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn deleting_document_updates_manifest() {
        let password = b"delete-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        vault
            .add_document("doc-1", b"secret")
            .await
            .expect("failed to add document");

        assert_eq!(vault.manifest().unwrap().document_count(), 1);

        vault
            .delete_document("doc-1")
            .await
            .expect("failed to delete document");

        assert_eq!(vault.manifest().unwrap().document_count(), 0);
    }

    #[tokio::test]
    async fn manifest_storage_record_contains_expected_data() {
        let password = b"storage-record-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let expected = vault.encrypted_manifest().unwrap().clone();

        let storage = vault.into_storage();

        let record = storage
            .load_manifest()
            .await
            .expect("failed to load manifest");

        assert!(!record.cid.is_empty());

        assert_eq!(record.encrypted_manifest.nonce, expected.nonce);

        assert_eq!(record.encrypted_manifest.ciphertext, expected.ciphertext);
    }

    #[tokio::test]
    async fn missing_manifest_returns_storage_error() {
        let storage = MemoryStorage::new();

        let result = storage.load_manifest().await;

        assert!(matches!(result, Err(CryptoError::StorageUnavailable)));
    }

    #[tokio::test]
    async fn manifest_cid_changes_after_manifest_update() {
        let password = b"cid-change-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let first_cid = vault.manifest_cid().unwrap().to_string();

        vault
            .add_document("doc-1", b"document")
            .await
            .expect("failed to add document");

        let second_cid = vault.manifest_cid().unwrap().to_string();

        assert_ne!(first_cid, second_cid);
    }

    #[tokio::test]
    async fn encrypted_manifest_is_not_plaintext() {
        let password = b"encryption-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let encrypted = vault.encrypted_manifest().unwrap();

        let plaintext_manifest = VaultManifest::new()
            .serialize()
            .expect("failed to serialize manifest");

        assert_ne!(encrypted.ciphertext, plaintext_manifest);
    }

    #[tokio::test]
    async fn different_vaults_have_different_salts() {
        let password = b"same-password";

        let vault_a = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault A");

        let vault_b = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault B");

        assert_ne!(vault_a.salt(), vault_b.salt());
    }

    #[tokio::test]
    async fn manifest_can_be_decrypted_with_correct_key() {
        let password = b"manifest-key-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let encrypted = vault.encrypted_manifest().unwrap();

        let root_key = crate::crypto::kdf::derive_key(password, vault.salt())
            .expect("failed to derive root key");

        let keys = crate::crypto::key_derivation::derive_vault_keys(&root_key)
            .expect("failed to derive vault keys");

        let manifest =
            VaultManager::<MemoryStorage>::decrypt_manifest(&keys.manifest_key, encrypted)
                .expect("failed to decrypt manifest");

        assert_eq!(manifest.document_count(), 0);
    }

    #[tokio::test]
    async fn wrong_manifest_key_cannot_decrypt() {
        let password = b"manifest-key-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let encrypted = vault.encrypted_manifest().unwrap();

        let wrong_key = [99u8; KEY_LEN];

        let result = VaultManager::<MemoryStorage>::decrypt_manifest(&wrong_key, encrypted);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn manifest_cid_requires_unlocked_vault() {
        let password = b"cid-lock-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        assert!(vault.manifest_cid().is_ok());

        vault.lock();

        assert!(vault.manifest_cid().is_err());
    }

    #[tokio::test]
    async fn storage_record_matches_manager_state() {
        let password = b"record-state-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let expected_cid = vault.manifest_cid().unwrap().to_string();

        let expected_manifest = vault.encrypted_manifest().unwrap().clone();

        let storage = vault.into_storage();

        let record = storage
            .load_manifest()
            .await
            .expect("failed to load manifest");

        assert_eq!(record.cid, expected_cid);

        assert_eq!(record.encrypted_manifest.nonce, expected_manifest.nonce);

        assert_eq!(
            record.encrypted_manifest.ciphertext,
            expected_manifest.ciphertext
        );
    }

    #[tokio::test]
    async fn unlock_from_storage_preserves_manifest() {
        let password = b"preserve-manifest-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        vault
            .add_document("doc-1", b"persistent secret")
            .await
            .expect("failed to add document");

        let salt = *vault.salt();

        let expected_cid = vault.manifest_cid().unwrap().to_string();

        let storage = vault.into_storage();

        let unlocked = VaultManager::unlock_from_storage(password, salt, storage)
            .await
            .expect("failed to unlock vault");

        assert_eq!(unlocked.manifest().unwrap().document_count(), 1);

        assert_eq!(unlocked.manifest_cid().unwrap(), expected_cid);

        let plaintext = unlocked
            .get_document("doc-1")
            .await
            .expect("failed to recover document");

        assert_eq!(plaintext, b"persistent secret");
    }

    #[tokio::test]
    async fn duplicate_document_id_is_rejected() {
        let password = b"duplicate-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        vault
            .add_document("doc-1", b"first")
            .await
            .expect("failed to add first document");

        let result = vault.add_document("doc-1", b"second").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn missing_document_returns_error() {
        let password = b"missing-document";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let result = vault.get_document("does-not-exist").await;

        assert!(matches!(result, Err(CryptoError::DocumentNotFound)));
    }
    #[tokio::test]
    async fn get_document_rejects_tampered_ciphertext() {
        let password = b"document-tampering-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        vault
            .add_document("doc-1", b"secret document")
            .await
            .expect("failed to add document");

        let entry = vault
            .manifest()
            .expect("manifest should be available")
            .find_document("doc-1")
            .expect("document entry should exist")
            .clone();

        let mut encrypted_document = vault
            .storage()
            .load_document(&entry.ipfs_cid)
            .await
            .expect("encrypted document should exist");

        // Tamper with the authenticated ciphertext.
        encrypted_document.content.ciphertext[0] ^= 0x01;

        // Directly verify that the tampered document cannot be decrypted
        // with the legitimate document key.
        let wrapping_key = vault
            .document_key()
            .expect("document key should be available");

        let document_key =
            crate::crypto::key_wrap::unwrap_document_key(wrapping_key, &entry.wrapped_document_key)
                .expect("document key should unwrap");

        let result = encrypted_document.decrypt(&document_key);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }
    #[tokio::test]
    async fn get_document_rejects_tampered_wrapped_document_key() {
        let password = b"tampered-wrapped-key-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        vault
            .add_document("secret.txt", b"top secret document")
            .await
            .expect("failed to add document");

        {
            let manifest = vault.manifest_mut().expect("vault should be unlocked");

            let entry = manifest
                .documents
                .iter_mut()
                .find(|entry| entry.document_id == "secret.txt")
                .expect("document should exist");

            // Tamper with the wrapped document key ciphertext.
            entry.wrapped_document_key.ciphertext[0] ^= 0x01;
        }

        let result = vault.get_document("secret.txt").await;

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }
    #[tokio::test]
    async fn deleted_document_cannot_be_retrieved() {
        let password = b"delete-document-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        vault
            .add_document("doc-1", b"secret document")
            .await
            .expect("failed to add document");

        vault
            .delete_document("doc-1")
            .await
            .expect("failed to delete document");

        let result = vault.get_document("doc-1").await;

        assert!(matches!(result, Err(CryptoError::DocumentNotFound)));

        let manifest = vault.manifest().expect("manifest should be available");

        assert!(
            manifest.find_document("doc-1").is_none(),
            "deleted document should not remain in the manifest"
        );
    }

    #[tokio::test]
    async fn tampered_stored_document_cannot_be_decrypted() {
        let password = b"stored-document-tampering-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        vault
            .add_document("doc-1", b"secret document")
            .await
            .expect("failed to add document");

        let entry = vault
            .manifest()
            .expect("manifest should be available")
            .find_document("doc-1")
            .expect("document entry should exist")
            .clone();

        let mut encrypted_document = vault
            .storage()
            .load_document(&entry.ipfs_cid)
            .await
            .expect("encrypted document should exist");

        // Tamper with the encrypted document ciphertext.
        encrypted_document.content.ciphertext[0] ^= 0x01;

        // Recover the legitimate document key from the manifest.
        let wrapping_key = vault
            .document_key()
            .expect("document key should be available");

        let document_key =
            crate::crypto::key_wrap::unwrap_document_key(wrapping_key, &entry.wrapped_document_key)
                .expect("document key should unwrap");

        // The tampered ciphertext must fail AES-GCM authentication.
        let result = encrypted_document.decrypt(&document_key);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[tokio::test]
    async fn deleting_missing_document_returns_error() {
        let password = b"delete-missing";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let result = vault.delete_document("does-not-exist").await;

        assert!(matches!(result, Err(CryptoError::DocumentNotFound)));
    }

    #[tokio::test]
    async fn locked_vault_rejects_document_access() {
        let password = b"locked-document";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        vault.lock();

        assert!(vault.get_document("doc-1").await.is_err());
    }

    #[tokio::test]
    async fn locked_vault_rejects_manifest_access() {
        let password = b"locked-manifest";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        vault.lock();

        assert!(vault.manifest().is_err());
        assert!(vault.encrypted_manifest().is_err());
        assert!(vault.manifest_cid().is_err());
    }

    #[tokio::test]
    async fn manifest_serialization_roundtrip() {
        let manifest = VaultManifest::new();

        let data = manifest.serialize().expect("failed to serialize");

        let recovered = VaultManifest::deserialize(&data).expect("failed to deserialize");

        assert_eq!(recovered.document_count(), manifest.document_count());

        assert_eq!(recovered.version, manifest.version);
    }

    #[tokio::test]
    async fn document_keys_are_random() {
        let key_a = VaultManager::<MemoryStorage>::generate_document_key()
            .expect("failed to generate key A");

        let key_b = VaultManager::<MemoryStorage>::generate_document_key()
            .expect("failed to generate key B");

        assert_ne!(key_a, key_b);
    }

    #[tokio::test]
    async fn encrypted_document_uses_unique_content_encryption() {
        let password = b"unique-encryption-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let cid_a = vault
            .add_document("doc-a", b"same plaintext")
            .await
            .expect("failed to add document A");

        let cid_b = vault
            .add_document("doc-b", b"same plaintext")
            .await
            .expect("failed to add document B");

        assert_ne!(cid_a, cid_b);
    }

    #[tokio::test]
    async fn manifest_cid_is_updated_after_add() {
        let password = b"cid-add-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let before = vault.manifest_cid().unwrap().to_string();

        vault
            .add_document("doc-1", b"secret")
            .await
            .expect("failed to add document");

        let after = vault.manifest_cid().unwrap().to_string();

        assert_ne!(before, after);
    }

    #[tokio::test]
    async fn manifest_cid_is_updated_after_delete() {
        let password = b"cid-delete-test";

        let mut vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        vault
            .add_document("doc-1", b"secret")
            .await
            .expect("failed to add document");

        let before = vault.manifest_cid().unwrap().to_string();

        vault
            .delete_document("doc-1")
            .await
            .expect("failed to delete document");

        let after = vault.manifest_cid().unwrap().to_string();

        assert_ne!(before, after);
    }

    #[tokio::test]
    async fn unlock_preserves_encrypted_manifest() {
        let password = b"unlock-manifest-test";

        let vault = VaultManager::create(password, test_storage())
            .await
            .expect("failed to create vault");

        let salt = *vault.salt();

        let encrypted = vault.encrypted_manifest().unwrap().clone();

        let storage = vault.into_storage();

        let unlocked = VaultManager::unlock_from_storage(password, salt, storage)
            .await
            .expect("failed to unlock vault");

        let recovered = unlocked.encrypted_manifest().unwrap();

        assert_eq!(recovered.nonce, encrypted.nonce);
        assert_eq!(recovered.ciphertext, encrypted.ciphertext);
    }

    #[tokio::test]
    async fn manifest_storage_record_roundtrip() {
        let key = [42u8; 32];

        let encrypted = encrypt(&key, b"manifest record").expect("failed to encrypt");

        let record = ManifestStorageRecord {
            cid: "memory-manifest-test".to_string(),
            encrypted_manifest: encrypted.clone(),
        };

        assert_eq!(record.cid, "memory-manifest-test");

        assert_eq!(record.encrypted_manifest.nonce, encrypted.nonce);

        assert_eq!(record.encrypted_manifest.ciphertext, encrypted.ciphertext);
    }
}
