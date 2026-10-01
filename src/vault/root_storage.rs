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
