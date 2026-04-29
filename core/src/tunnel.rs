extern crate alloc;
use alloc::vec::Vec;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub fn derive_shared_secret(secret: EphemeralSecret, public_key: &PublicKey) -> [u8; 32] {
    secret.diffie_hellman(public_key).to_bytes()
}

pub fn encrypt_payload(key_bytes: &[u8; 32], nonce_bytes: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let key = Key::from(*key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .encrypt(nonce, plaintext)
        .expect("encryption failure")
}

pub fn decrypt_payload(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let key = Key::from(*key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    #[test]
    fn test_tunnel_cycle() {
        let alice_secret = EphemeralSecret::random_from_rng(OsRng);
        let bob_secret = EphemeralSecret::random_from_rng(OsRng);

        // Dalek 2.0 requires explicitly converting the reference to a PublicKey
        let alice_public = PublicKey::from(&alice_secret);
        let bob_public = PublicKey::from(&bob_secret);

        let alice_shared = derive_shared_secret(alice_secret, &bob_public);
        let bob_shared = derive_shared_secret(bob_secret, &alice_public);

        assert_eq!(alice_shared, bob_shared);

        let key_bytes = alice_shared;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let plaintext = b"Hello, secure tunnel!";
        let ciphertext = encrypt_payload(&key_bytes, &nonce_bytes, plaintext);
        let decrypted =
            decrypt_payload(&key_bytes, &nonce_bytes, &ciphertext).expect("decryption failure");

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn encrypt_payload_adds_poly1305_authentication_tag() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"authenticated bytes";

        let ciphertext = encrypt_payload(&key, &nonce, plaintext);

        assert_eq!(ciphertext.len(), plaintext.len() + 16);
        assert_ne!(ciphertext, plaintext);
    }

    #[test]
    fn decrypt_payload_rejects_wrong_key() {
        let key = [1u8; 32];
        let wrong_key = [9u8; 32];
        let nonce = [2u8; 12];
        let ciphertext = encrypt_payload(&key, &nonce, b"secret");

        assert!(decrypt_payload(&wrong_key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn decrypt_payload_rejects_wrong_nonce() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let wrong_nonce = [3u8; 12];
        let ciphertext = encrypt_payload(&key, &nonce, b"secret");

        assert!(decrypt_payload(&key, &wrong_nonce, &ciphertext).is_err());
    }

    #[test]
    fn decrypt_payload_rejects_tampered_ciphertext() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let mut ciphertext = encrypt_payload(&key, &nonce, b"secret");
        ciphertext[0] ^= 0x01;

        assert!(decrypt_payload(&key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn decrypt_payload_rejects_tampered_authentication_tag() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let mut ciphertext = encrypt_payload(&key, &nonce, b"secret");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x80;

        assert!(decrypt_payload(&key, &nonce, &ciphertext).is_err());
    }

    #[test]
    fn encrypt_decrypt_round_trips_empty_payload() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let ciphertext = encrypt_payload(&key, &nonce, b"");
        let plaintext = decrypt_payload(&key, &nonce, &ciphertext).unwrap();

        assert!(plaintext.is_empty());
        assert_eq!(ciphertext.len(), 16);
    }

    #[test]
    fn decrypt_payload_rejects_empty_ciphertext() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];

        assert!(decrypt_payload(&key, &nonce, b"").is_err());
    }

    #[test]
    fn same_plaintext_with_different_nonce_produces_different_ciphertext() {
        let key = [1u8; 32];
        let plaintext = b"nonce domain separation";
        let ciphertext_a = encrypt_payload(&key, &[2u8; 12], plaintext);
        let ciphertext_b = encrypt_payload(&key, &[3u8; 12], plaintext);

        assert_ne!(ciphertext_a, ciphertext_b);
    }

    #[test]
    fn same_plaintext_with_different_key_produces_different_ciphertext() {
        let nonce = [2u8; 12];
        let plaintext = b"key domain separation";
        let ciphertext_a = encrypt_payload(&[1u8; 32], &nonce, plaintext);
        let ciphertext_b = encrypt_payload(&[9u8; 32], &nonce, plaintext);

        assert_ne!(ciphertext_a, ciphertext_b);
    }
}
