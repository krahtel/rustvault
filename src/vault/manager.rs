use crate::crypto::encrypted_document::EncryptedDocument;
use crate::crypto::encryption::{decrypt, encrypt, EncryptedData};
use crate::crypto::error::CryptoError;
use crate::crypto::kdf::{derive_key, generate_salt, KEY_LEN, SALT_LEN};
use crate::crypto::key_derivation::{derive_vault_keys, VaultKeySet};
use crate::crypto::random::random_bytes;
use crate::vault::manifest::{ManifestEntry, VaultManifest};
use crate::vault::storage::{ManifestStorageRecord, VaultStorage};

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
    /// Create a new RustVault instance.
    pub async fn create(
        password: &[u8],
        mut storage: S,
    ) -> Result<Self, CryptoError> {
        let salt = generate_salt()?;

        let root_key = derive_key(password, &salt)?;

        let keys = derive_vault_keys(&root_key)?;

        let manifest = VaultManifest::new();

        let encrypted_manifest =
            Self::encrypt_manifest(&keys.manifest_key, &manifest)?;

        let manifest_cid =
            storage.save_manifest(&encrypted_manifest).await?;

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

    /// Unlock a vault using an already-loaded encrypted manifest.
    ///
    /// This method is useful when the caller already has the
    /// encrypted manifest and its CID.
    pub fn unlock(
        password: &[u8],
        salt: [u8; SALT_LEN],
        encrypted_manifest: EncryptedData,
        storage: S,
    ) -> Result<Self, CryptoError> {
        let root_key = derive_key(password, &salt)?;

        let keys = derive_vault_keys(&root_key)?;

        let manifest =
            Self::decrypt_manifest(&keys.manifest_key, &encrypted_manifest)?;

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

    /// Unlock a vault by loading the encrypted manifest and CID
    /// from the configured storage backend.
    pub async fn unlock_from_storage(
        password: &[u8],
        salt: [u8; SALT_LEN],
        storage: S,
    ) -> Result<Self, CryptoError> {
        let manifest_record: ManifestStorageRecord =
            storage.load_manifest().await?;

        let root_key = derive_key(password, &salt)?;

        let keys = derive_vault_keys(&root_key)?;

        let manifest = Self::decrypt_manifest(
            &keys.manifest_key,
            &manifest_record.encrypted_manifest,
        )?;

        Ok(Self {
            salt,
            keys,
            manifest,
            encrypted_manifest: manifest_record.encrypted_manifest,
            manifest_cid: manifest_record.cid,
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

        if self
            .manifest
            .find_document(&document_id)
            .is_some()
        {
            return Err(CryptoError::DocumentNotFound);
        }

        // Generate a fresh random key for this document.
        let document_key = Self::generate_document_key()?;

        // Encrypt document content using the document-specific key.
        let encrypted_content =
            EncryptedDocument::encrypt(&document_key, plaintext)?;

        // Wrap the document key using the vault document key.
        let wrapped_document_key =
            crate::crypto::key_wrap::wrap_document_key(
                &self.keys.document_key,
                &document_key,
            )?;

        // Store encrypted document in IPFS/storage.
        let cid = self
            .storage
            .store_document(encrypted_content.clone())
            .await?;

        // Encrypt metadata separately.
        let encrypted_metadata =
            encrypt(
                &self.keys.document_key,
                document_id.as_bytes(),
            )?;

        let entry = ManifestEntry {
            document_id,
            ipfs_cid: cid.clone(),
            wrapped_document_key,
            encrypted_metadata,
        };

        self.manifest.add_document(entry);

        self.save_manifest().await?;

        Ok(cid)
    }

    /// Retrieve and decrypt a document by document ID.
    pub async fn get_document(
        &self,
        document_id: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        self.ensure_unlocked()?;

        let entry = self
            .manifest
            .find_document(document_id)
            .ok_or(CryptoError::DocumentNotFound)?;

        let encrypted_document =
            self.storage.load_document(&entry.ipfs_cid).await?;

        let document_key =
            crate::crypto::key_wrap::unwrap_document_key(
                &self.keys.document_key,
                &entry.wrapped_document_key,
            )?;

        encrypted_document.decrypt(&document_key)
    }

    /// Delete a document from the vault.
    pub async fn delete_document(
        &mut self,
        document_id: &str,
    ) -> Result<(), CryptoError> {
        self.ensure_unlocked()?;

        let entry = self
            .manifest
            .find_document(document_id)
            .ok_or(CryptoError::DocumentNotFound)?
            .clone();

        self.storage
            .delete_document(&entry.ipfs_cid)
            .await?;

        self.manifest.remove_document(document_id);

        self.save_manifest().await?;

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
        let data =
            decrypt(manifest_key, encrypted_manifest)?;

        VaultManifest::deserialize(&data)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Save the current manifest to storage and update its CID.
    async fn save_manifest(&mut self) -> Result<(), CryptoError> {
        self.ensure_unlocked()?;

        self.encrypted_manifest =
            Self::encrypt_manifest(
                &self.keys.manifest_key,
                &self.manifest,
            )?;

        let cid = self
            .storage
            .save_manifest(&self.encrypted_manifest)
            .await?;

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
    pub fn manifest_mut(
        &mut self,
    ) -> Result<&mut VaultManifest, CryptoError> {
        self.ensure_unlocked()?;

        Ok(&mut self.manifest)
    }

    /// Return the encrypted manifest.
    pub fn encrypted_manifest(
        &self,
    ) -> Result<&EncryptedData, CryptoError> {
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
    pub(crate) fn document_key(
        &self,
    ) -> Result<&[u8; KEY_LEN], CryptoError> {
        self.ensure_unlocked()?;

        Ok(&self.keys.document_key)
    }

    /// Generate a fresh random document key.
    fn generate_document_key(
    ) -> Result<[u8; KEY_LEN], CryptoError> {
        let bytes = random_bytes(KEY_LEN)?;

        let mut key = [0u8; KEY_LEN];

        key.copy_from_slice(&bytes);

        Ok(key)
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

    #[tokio::test]
    async fn creates_encrypted_manifest() {
        let password = b"correct horse battery staple";

        let vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        assert!(vault.is_unlocked());

        let encrypted_manifest =
            vault
                .encrypted_manifest()
                .expect("manifest should be available");

        assert!(
            !encrypted_manifest.ciphertext.is_empty()
        );

        let cid = vault
            .manifest_cid()
            .expect("manifest CID should exist");

        assert!(!cid.is_empty());
    }

    #[tokio::test]
    async fn unlocks_from_storage() {
        let password = b"vault-password";

        let vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let salt = *vault.salt();

        let storage =
            vault.into_storage();

        let unlocked =
            VaultManager::unlock_from_storage(
                password,
                salt,
                storage,
            )
            .await
            .expect("failed to unlock vault");

        assert!(unlocked.is_unlocked());

        assert_eq!(
            unlocked.manifest().unwrap().document_count(),
            0
        );

        assert!(
            !unlocked
                .manifest_cid()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn unlock_from_storage_recovers_manifest_cid() {
        let password = b"manifest-cid-password";

        let vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let original_cid =
            vault
                .manifest_cid()
                .unwrap()
                .to_string();

        let salt = *vault.salt();

        let storage =
            vault.into_storage();

        let unlocked =
            VaultManager::unlock_from_storage(
                password,
                salt,
                storage,
            )
            .await
            .expect("failed to unlock vault");

        assert_eq!(
            unlocked.manifest_cid().unwrap(),
            original_cid
        );
    }

    #[tokio::test]
    async fn wrong_password_cannot_unlock() {
        let password = b"correct-password";

        let vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let salt = *vault.salt();

        let encrypted_manifest =
            vault
                .encrypted_manifest()
                .unwrap()
                .clone();

        let storage =
            vault.into_storage();

        let result =
            VaultManager::unlock(
                b"wrong-password",
                salt,
                encrypted_manifest,
                storage,
            );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn lock_prevents_manifest_access() {
        let password = b"lock-test";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        vault.lock();

        assert!(!vault.is_unlocked());

        assert!(
            vault.manifest().is_err()
        );

        assert!(
            vault.encrypted_manifest().is_err()
        );

        assert!(
            vault.manifest_cid().is_err()
        );
    }

    #[tokio::test]
    async fn adding_document_updates_manifest_cid() {
        let password = b"manifest-update-test";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let initial_cid =
            vault
                .manifest_cid()
                .unwrap()
                .to_string();

        vault
            .add_document(
                "document-1",
                b"secret document",
            )
            .await
            .expect("failed to add document");

        let updated_cid =
            vault
                .manifest_cid()
                .unwrap()
                .to_string();

        assert_ne!(
            initial_cid,
            updated_cid
        );
    }

    #[tokio::test]
    async fn document_roundtrip() {
        let password = b"document-roundtrip";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let plaintext =
            b"This is a secret document.";

        vault
            .add_document(
                "doc-1",
                plaintext,
            )
            .await
            .expect("failed to add document");

        let recovered =
            vault
                .get_document("doc-1")
                .await
                .expect("failed to get document");

        assert_eq!(
            recovered,
            plaintext
        );
    }

    #[tokio::test]
    async fn deleting_document_updates_manifest() {
        let password = b"delete-test";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        vault
            .add_document(
                "doc-1",
                b"secret",
            )
            .await
            .expect("failed to add document");

        assert_eq!(
            vault
                .manifest()
                .unwrap()
                .document_count(),
            1
        );

        vault
            .delete_document("doc-1")
            .await
            .expect("failed to delete document");

        assert_eq!(
            vault
                .manifest()
                .unwrap()
                .document_count(),
            0
        );
    }

    #[tokio::test]
    async fn manifest_storage_record_contains_expected_data() {
        let password = b"storage-record-test";

        let vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let expected =
            vault
                .encrypted_manifest()
                .unwrap()
                .clone();

        let storage =
            vault.into_storage();

        let record =
            storage
                .load_manifest()
                .await
                .expect("failed to load manifest");

        assert!(!record.cid.is_empty());

        assert_eq!(
            record.encrypted_manifest.nonce,
            expected.nonce
        );

        assert_eq!(
            record.encrypted_manifest.ciphertext,
            expected.ciphertext
        );
    }

    #[tokio::test]
    async fn missing_manifest_returns_storage_error() {
        let storage =
            MemoryStorage::new();

        let result =
            storage.load_manifest().await;

        assert!(
            matches!(
                result,
                Err(CryptoError::StorageUnavailable)
            )
        );
    }

    #[tokio::test]
    async fn manifest_cid_changes_after_manifest_update() {
        let password = b"cid-change-test";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let first_cid =
            vault
                .manifest_cid()
                .unwrap()
                .to_string();

        vault
            .add_document(
                "doc-1",
                b"document",
            )
            .await
            .expect("failed to add document");

        let second_cid =
            vault
                .manifest_cid()
                .unwrap()
                .to_string();

        assert_ne!(
            first_cid,
            second_cid
        );
    }

    #[tokio::test]
    async fn encrypted_manifest_is_not_plaintext() {
        let password = b"encryption-test";

        let vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let encrypted =
            vault
                .encrypted_manifest()
                .unwrap();

        let plaintext_manifest =
            VaultManifest::new()
                .serialize()
                .expect("failed to serialize manifest");

        assert_ne!(
            encrypted.ciphertext,
            plaintext_manifest
        );
    }

    #[tokio::test]
    async fn different_vaults_have_different_salts() {
        let password = b"same-password";

        let vault_a =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault A");

        let vault_b =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault B");

        assert_ne!(
            vault_a.salt(),
            vault_b.salt()
        );
    }

    #[tokio::test]
    async fn manifest_can_be_decrypted_with_correct_key() {
        let password = b"manifest-key-test";

        let vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let encrypted =
            vault
                .encrypted_manifest()
                .unwrap();

        let root_key =
            crate::crypto::kdf::derive_key(
                password,
                vault.salt(),
            )
            .expect("failed to derive root key");

        let keys =
            crate::crypto::key_derivation::derive_vault_keys(
                &root_key,
            )
            .expect("failed to derive vault keys");

        let manifest =
            VaultManager::<MemoryStorage>::decrypt_manifest(
                &keys.manifest_key,
                encrypted,
            )
            .expect("failed to decrypt manifest");

        assert_eq!(
            manifest.document_count(),
            0
        );
    }

    #[tokio::test]
    async fn wrong_manifest_key_cannot_decrypt() {
        let password = b"manifest-key-test";

        let vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let encrypted =
            vault
                .encrypted_manifest()
                .unwrap();

        let wrong_key =
            [99u8; KEY_LEN];

        let result =
            VaultManager::<MemoryStorage>::decrypt_manifest(
                &wrong_key,
                encrypted,
            );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn manifest_cid_requires_unlocked_vault() {
        let password = b"cid-lock-test";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        assert!(
            vault.manifest_cid().is_ok()
        );

        vault.lock();

        assert!(
            vault.manifest_cid().is_err()
        );
    }

    #[tokio::test]
    async fn storage_record_matches_manager_state() {
        let password = b"record-state-test";

        let vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let expected_cid =
            vault
                .manifest_cid()
                .unwrap()
                .to_string();

        let expected_manifest =
            vault
                .encrypted_manifest()
                .unwrap()
                .clone();

        let storage =
            vault.into_storage();

        let record =
            storage
                .load_manifest()
                .await
                .expect("failed to load manifest");

        assert_eq!(
            record.cid,
            expected_cid
        );

        assert_eq!(
            record.encrypted_manifest.nonce,
            expected_manifest.nonce
        );

        assert_eq!(
            record.encrypted_manifest.ciphertext,
            expected_manifest.ciphertext
        );
    }

    #[tokio::test]
    async fn unlock_from_storage_preserves_manifest() {
        let password = b"preserve-manifest-test";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        vault
            .add_document(
                "doc-1",
                b"persistent secret",
            )
            .await
            .expect("failed to add document");

        let salt =
            *vault.salt();

        let expected_cid =
            vault
                .manifest_cid()
                .unwrap()
                .to_string();

        let storage =
            vault.into_storage();

        let unlocked =
            VaultManager::unlock_from_storage(
                password,
                salt,
                storage,
            )
            .await
            .expect("failed to unlock vault");

        assert_eq!(
            unlocked
                .manifest()
                .unwrap()
                .document_count(),
            1
        );

        assert_eq!(
            unlocked.manifest_cid().unwrap(),
            expected_cid
        );

        let plaintext =
            unlocked
                .get_document("doc-1")
                .await
                .expect("failed to recover document");

        assert_eq!(
            plaintext,
            b"persistent secret"
        );
    }

    #[tokio::test]
    async fn duplicate_document_id_is_rejected() {
        let password = b"duplicate-test";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        vault
            .add_document(
                "doc-1",
                b"first",
            )
            .await
            .expect("failed to add first document");

        let result =
            vault
                .add_document(
                    "doc-1",
                    b"second",
                )
                .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn missing_document_returns_error() {
        let password = b"missing-document";

        let vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let result =
            vault.get_document("does-not-exist")
                .await;

        assert!(
            matches!(
                result,
                Err(CryptoError::DocumentNotFound)
            )
        );
    }

    #[tokio::test]
    async fn deleting_missing_document_returns_error() {
        let password = b"delete-missing";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let result =
            vault
                .delete_document("does-not-exist")
                .await;

        assert!(
            matches!(
                result,
                Err(CryptoError::DocumentNotFound)
            )
        );
    }

    #[tokio::test]
    async fn locked_vault_rejects_document_access() {
        let password = b"locked-document";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        vault.lock();

        assert!(
            vault
                .get_document("doc-1")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn locked_vault_rejects_manifest_access() {
        let password = b"locked-manifest";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        vault.lock();

        assert!(
            vault.manifest().is_err()
        );

        assert!(
            vault.encrypted_manifest().is_err()
        );

        assert!(
            vault.manifest_cid().is_err()
        );
    }

    #[tokio::test]
    async fn manifest_serialization_roundtrip() {
        let manifest =
            VaultManifest::new();

        let data =
            manifest
                .serialize()
                .expect("failed to serialize");

        let recovered =
            VaultManifest::deserialize(&data)
                .expect("failed to deserialize");

        assert_eq!(
            recovered.document_count(),
            manifest.document_count()
        );

        assert_eq!(
            recovered.version,
            manifest.version
        );
    }

    #[tokio::test]
    async fn document_keys_are_random() {
        let key_a =
            VaultManager::<MemoryStorage>::generate_document_key()
                .expect("failed to generate key A");

        let key_b =
            VaultManager::<MemoryStorage>::generate_document_key()
                .expect("failed to generate key B");

        assert_ne!(
            key_a,
            key_b
        );
    }

    #[tokio::test]
    async fn encrypted_document_uses_unique_content_encryption() {
        let password = b"unique-encryption-test";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let cid_a =
            vault
                .add_document(
                    "doc-a",
                    b"same plaintext",
                )
                .await
                .expect("failed to add document A");

        let cid_b =
            vault
                .add_document(
                    "doc-b",
                    b"same plaintext",
                )
                .await
                .expect("failed to add document B");

        assert_ne!(
            cid_a,
            cid_b
        );
    }

    #[tokio::test]
    async fn manifest_cid_is_updated_after_add() {
        let password = b"cid-add-test";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let before =
            vault
                .manifest_cid()
                .unwrap()
                .to_string();

        vault
            .add_document(
                "doc-1",
                b"secret",
            )
            .await
            .expect("failed to add document");

        let after =
            vault
                .manifest_cid()
                .unwrap()
                .to_string();

        assert_ne!(
            before,
            after
        );
    }

    #[tokio::test]
    async fn manifest_cid_is_updated_after_delete() {
        let password = b"cid-delete-test";

        let mut vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        vault
            .add_document(
                "doc-1",
                b"secret",
            )
            .await
            .expect("failed to add document");

        let before =
            vault
                .manifest_cid()
                .unwrap()
                .to_string();

        vault
            .delete_document("doc-1")
            .await
            .expect("failed to delete document");

        let after =
            vault
                .manifest_cid()
                .unwrap()
                .to_string();

        assert_ne!(
            before,
            after
        );
    }

    #[tokio::test]
    async fn unlock_preserves_encrypted_manifest() {
        let password = b"unlock-manifest-test";

        let vault =
            VaultManager::create(
                password,
                test_storage(),
            )
            .await
            .expect("failed to create vault");

        let salt =
            *vault.salt();

        let encrypted =
            vault
                .encrypted_manifest()
                .unwrap()
                .clone();

        let storage =
            vault.into_storage();

        let unlocked =
            VaultManager::unlock_from_storage(
                password,
                salt,
                storage,
            )
            .await
            .expect("failed to unlock vault");

        let recovered =
            unlocked
                .encrypted_manifest()
                .unwrap();

        assert_eq!(
            recovered.nonce,
            encrypted.nonce
        );

        assert_eq!(
            recovered.ciphertext,
            encrypted.ciphertext
        );
    }

    #[tokio::test]
    async fn manifest_storage_record_roundtrip() {
        let key = [42u8; 32];

        let encrypted =
            encrypt(
                &key,
                b"manifest record",
            )
            .expect("failed to encrypt");

        let record =
            ManifestStorageRecord {
                cid: "memory-manifest-test".to_string(),
                encrypted_manifest: encrypted.clone(),
            };

        assert_eq!(
            record.cid,
            "memory-manifest-test"
        );

        assert_eq!(
            record.encrypted_manifest.nonce,
            encrypted.nonce
        );

        assert_eq!(
            record.encrypted_manifest.ciphertext,
            encrypted.ciphertext
        );
    }
}