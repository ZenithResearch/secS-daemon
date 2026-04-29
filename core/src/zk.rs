extern crate alloc;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rs_merkle::{algorithms::Sha256, MerkleProof};

pub fn generate_proof(keypair: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature = keypair.sign(message);
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    #[test]
    fn test_proof_cycle() {
        let mut secret_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_key_bytes);
        let keypair = SigningKey::from_bytes(&secret_key_bytes);
        let public_key = keypair.verifying_key();

        let message: &[u8] = b"test proof cycle message";
        let signature_bytes = generate_proof(&keypair, message);

        assert!(verify_proof(&public_key, &signature_bytes, message));
    }
}
