extern crate alloc;
use alloc::vec::Vec;
use x25519_dalek::{EphemeralSecret, PublicKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, aead::Aead};

pub fn derive_shared_secret(secret: EphemeralSecret, public_key: &PublicKey) -> [u8; 32] {
    secret.diffie_hellman(public_key).to_bytes()
}

pub fn encrypt_payload(key_bytes: &[u8; 32], nonce_bytes: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let key = Key::from(*key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.encrypt(nonce, plaintext).expect("encryption failure")
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
    use x25519_dalek::{EphemeralSecret, PublicKey};
    use rand::rngs::OsRng;
    use rand::RngCore;

    #[test]
    fn test_tunnel_cycle() {
        let alice_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let bob_secret = EphemeralSecret::random_from_rng(&mut OsRng);

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
        let decrypted = decrypt_payload(&key_bytes, &nonce_bytes, &ciphertext).expect("decryption failure");

        assert_eq!(plaintext, decrypted.as_slice());
    }
}
