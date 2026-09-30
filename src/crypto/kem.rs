use ml_kem::{kem::Kem, MlKem768};
pub struct KemKeyPair {
    pub decapsulation_key: <MlKem768 as Kem>::DecapsulationKey,
    pub encapsulation_key: <MlKem768 as Kem>::EncapsulationKey,
}

/// Generate a new ML-KEM-768 key pair.
pub fn generate_keypair() -> KemKeyPair {
    let (decapsulation_key, encapsulation_key) = MlKem768::generate_keypair();

    KemKeyPair {
        decapsulation_key,
        encapsulation_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::{Decapsulate, Encapsulate};

    #[test]
    fn ml_kem_768_roundtrip() {
        let keypair = generate_keypair();

        let (ciphertext, sender_shared_secret) = keypair.encapsulation_key.encapsulate();

        let recipient_shared_secret = keypair.decapsulation_key.decapsulate(&ciphertext);

        assert_eq!(sender_shared_secret, recipient_shared_secret);
    }

    #[test]
    fn different_encapsulations_produce_different_secrets() {
        let keypair = generate_keypair();

        let (ciphertext1, secret1) = keypair.encapsulation_key.encapsulate();

        let (ciphertext2, secret2) = keypair.encapsulation_key.encapsulate();

        assert_ne!(secret1, secret2);
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn different_keypairs_are_independent() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();

        let (_, secret1) = keypair1.encapsulation_key.encapsulate();

        let (_, secret2) = keypair2.encapsulation_key.encapsulate();

        assert_ne!(secret1, secret2);
    }

    #[test]
    fn ciphertext_decapsulates_to_original_secret() {
        let keypair = generate_keypair();

        let (ciphertext, sender_secret) = keypair.encapsulation_key.encapsulate();

        let recipient_secret = keypair.decapsulation_key.decapsulate(&ciphertext);

        assert_eq!(sender_secret, recipient_secret);
    }

    #[test]
    fn wrong_private_key_does_not_reproduce_sender_secret() {
        let recipient = generate_keypair();
        let wrong_keypair = generate_keypair();

        let (ciphertext, sender_secret) = recipient.encapsulation_key.encapsulate();

        let wrong_secret = wrong_keypair.decapsulation_key.decapsulate(&ciphertext);

        assert_ne!(sender_secret, wrong_secret);
    }
}
