use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::SysRng;
use rand::TryRng;

use crate::crypto::error::CryptoError;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], CryptoError> {
    let params = Params::new(
        19_456, // memory cost in KiB (~19 MiB)
        2,      // iterations
        1,      // parallelism
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::KdfFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];

    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| CryptoError::KdfFailed)?;

    Ok(key)
}

pub fn generate_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    let mut salt = [0u8; SALT_LEN];

    SysRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;

    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_password_and_salt_produce_same_key() {
        let password = b"correct horse battery staple";
        let salt = [42u8; SALT_LEN];

        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let password = b"correct horse battery staple";
        let salt1 = [1u8; SALT_LEN];
        let salt2 = [2u8; SALT_LEN];

        let key1 = derive_key(password, &salt1).unwrap();
        let key2 = derive_key(password, &salt2).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn different_passwords_produce_different_keys() {
        let salt = [42u8; SALT_LEN];

        let key1 = derive_key(b"password-one", &salt).unwrap();
        let key2 = derive_key(b"password-two", &salt).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn generated_salt_has_correct_length() {
        let salt = generate_salt().unwrap();

        assert_eq!(salt.len(), SALT_LEN);
    }

    #[test]
    fn generated_salts_are_not_identical() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();

        assert_ne!(salt1, salt2);
    }

    #[test]
    fn derived_key_has_correct_length() {
        let password = b"test password";
        let salt = [42u8; SALT_LEN];

        let key = derive_key(password, &salt).unwrap();

        assert_eq!(key.len(), KEY_LEN);
    }
}
