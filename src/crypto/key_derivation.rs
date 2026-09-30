use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::error::CryptoError;

pub const KEY_LEN: usize = 32;

pub const MANIFEST_KEY_INFO: &[u8] = b"rustvault/manifest/v1";
pub const DOCUMENT_KEY_INFO: &[u8] = b"rustvault/document/v1";
pub const IDENTITY_KEY_INFO: &[u8] = b"rustvault/identity/v1";
pub const RECOVERY_KEY_INFO: &[u8] = b"rustvault/recovery/v1";
pub const KEM_SHARED_SECRET_INFO: &[u8] = b"rustvault/kem/shared-secret/v1";

#[derive(Clone)]
pub struct VaultKeySet {
    pub manifest_key: [u8; KEY_LEN],
    pub document_key: [u8; KEY_LEN],
    pub identity_key: [u8; KEY_LEN],
    pub recovery_key: [u8; KEY_LEN],
}

pub fn derive_subkey(root_key: &[u8; KEY_LEN], info: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, root_key);

    let mut output = [0u8; KEY_LEN];

    hkdf.expand(info, &mut output)
        .map_err(|_| CryptoError::HkdfFailed)?;

    Ok(output)
}

pub fn derive_vault_keys(root_key: &[u8; KEY_LEN]) -> Result<VaultKeySet, CryptoError> {
    Ok(VaultKeySet {
        manifest_key: derive_subkey(root_key, MANIFEST_KEY_INFO)?,
        document_key: derive_subkey(root_key, DOCUMENT_KEY_INFO)?,
        identity_key: derive_subkey(root_key, IDENTITY_KEY_INFO)?,
        recovery_key: derive_subkey(root_key, RECOVERY_KEY_INFO)?,
    })
}

pub fn derive_kem_key(shared_secret: &[u8]) -> Result<[u8; KEY_LEN], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);

    let mut output = [0u8; KEY_LEN];

    hkdf.expand(KEM_SHARED_SECRET_INFO, &mut output)
        .map_err(|_| CryptoError::HkdfFailed)?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_32_byte_subkey() {
        let root_key = [42u8; KEY_LEN];

        let key = derive_subkey(&root_key, MANIFEST_KEY_INFO).unwrap();

        assert_eq!(key.len(), KEY_LEN);
    }

    #[test]
    fn different_contexts_produce_different_keys() {
        let root_key = [42u8; KEY_LEN];

        let manifest_key = derive_subkey(&root_key, MANIFEST_KEY_INFO).unwrap();

        let document_key = derive_subkey(&root_key, DOCUMENT_KEY_INFO).unwrap();

        assert_ne!(manifest_key, document_key);
    }

    #[test]
    fn same_root_and_context_produce_same_key() {
        let root_key = [42u8; KEY_LEN];

        let key1 = derive_subkey(&root_key, MANIFEST_KEY_INFO).unwrap();

        let key2 = derive_subkey(&root_key, MANIFEST_KEY_INFO).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn different_root_keys_produce_different_keys() {
        let root_key1 = [42u8; KEY_LEN];
        let root_key2 = [43u8; KEY_LEN];

        let key1 = derive_subkey(&root_key1, MANIFEST_KEY_INFO).unwrap();

        let key2 = derive_subkey(&root_key2, MANIFEST_KEY_INFO).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn vault_key_set_contains_separate_keys() {
        let root_key = [42u8; KEY_LEN];

        let keys = derive_vault_keys(&root_key).unwrap();

        assert_ne!(keys.manifest_key, keys.document_key);
        assert_ne!(keys.document_key, keys.identity_key);
        assert_ne!(keys.identity_key, keys.recovery_key);
    }

    #[test]
    fn kem_shared_secret_derives_32_byte_key() {
        let shared_secret = [42u8; 32];

        let key = derive_kem_key(&shared_secret).unwrap();

        assert_eq!(key.len(), KEY_LEN);
    }

    #[test]
    fn same_kem_secret_produces_same_key() {
        let shared_secret = [42u8; 32];

        let key1 = derive_kem_key(&shared_secret).unwrap();
        let key2 = derive_kem_key(&shared_secret).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn different_kem_secrets_produce_different_keys() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];

        let key1 = derive_kem_key(&secret1).unwrap();
        let key2 = derive_kem_key(&secret2).unwrap();

        assert_ne!(key1, key2);
    }
}
