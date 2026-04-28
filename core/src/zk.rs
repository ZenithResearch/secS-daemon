#![no_std]
extern crate alloc;
use alloc::vec::Vec;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rs_merkle::{MerkleProof, algorithms::Sha256};

pub fn generate_proof(keypair: &SigningKey, message: &[u8]) -> Vec<u8> {
    let mut signer = keypair;
    let signature = signer.sign(message);
    signature.to_bytes().to_vec()
}

pub fn verify_proof(public_key: &VerifyingKey, signature_bytes: &[u8], message: &[u8]) -> bool {
    match Signature::from_slice(signature_bytes) {
        Ok(signature) => {
            let public_key = *public_key;
            public_key.verify(message, &signature).is_ok()
        }
        Err(_) => false,
    }
}

pub fn verify_merkle_root(
    proof: &MerkleProof<Sha256>,
    leaf_hash: [u8; 32],
    root: [u8; 32],
    leaf_indices: &[usize],
    total_leaves: usize,
) -> bool {
    proof.verify(root, leaf_indices, &[leaf_hash], total_leaves)
}
