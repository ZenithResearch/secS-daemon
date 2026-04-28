#![no_std]
extern crate alloc;
use alloc::vec::Vec;
use x25519_dalek::{EphemeralSecret, PublicKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Aead, KeyInit};

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
