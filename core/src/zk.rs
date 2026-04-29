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
    use alloc::vec;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof, MerkleTree};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

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

    #[test]
    fn generated_proof_is_ed25519_signature_length() {
        let signature = generate_proof(&signing_key(1), b"length check");

        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn proof_verification_rejects_tampered_message() {
        let keypair = signing_key(2);
        let public_key = keypair.verifying_key();
        let signature = generate_proof(&keypair, b"original message");

        assert!(!verify_proof(&public_key, &signature, b"original messagf"));
    }

    #[test]
    fn proof_verification_rejects_wrong_public_key() {
        let signer = signing_key(3);
        let attacker = signing_key(4);
        let signature = generate_proof(&signer, b"bound to signer");

        assert!(!verify_proof(
            &attacker.verifying_key(),
            &signature,
            b"bound to signer"
        ));
    }

    #[test]
    fn proof_verification_rejects_truncated_signature() {
        let keypair = signing_key(5);
        let public_key = keypair.verifying_key();
        let mut signature = generate_proof(&keypair, b"truncate me");
        signature.truncate(63);

        assert!(!verify_proof(&public_key, &signature, b"truncate me"));
    }

    #[test]
    fn proof_verification_rejects_extended_signature() {
        let keypair = signing_key(6);
        let public_key = keypair.verifying_key();
        let mut signature = generate_proof(&keypair, b"extend me");
        signature.push(0);

        assert!(!verify_proof(&public_key, &signature, b"extend me"));
    }

    #[test]
    fn proof_verification_rejects_bit_flipped_signature() {
        let keypair = signing_key(7);
        let public_key = keypair.verifying_key();
        let mut signature = generate_proof(&keypair, b"signed bytes");
        signature[0] ^= 0x01;

        assert!(!verify_proof(&public_key, &signature, b"signed bytes"));
    }

    #[test]
    fn merkle_root_verifies_valid_single_leaf_proof() {
        let leaves = [Sha256::hash(b"leaf-0")];
        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let root = tree.root().unwrap();
        let proof = tree.proof(&[0]);

        assert!(verify_merkle_root(
            &proof,
            leaves[0],
            root,
            &[0],
            leaves.len()
        ));
    }

    #[test]
    fn merkle_root_rejects_wrong_leaf_hash() {
        let leaves = [Sha256::hash(b"leaf-0"), Sha256::hash(b"leaf-1")];
        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let root = tree.root().unwrap();
        let proof = tree.proof(&[0]);
        let wrong_leaf = Sha256::hash(b"evil-leaf");

        assert!(!verify_merkle_root(
            &proof,
            wrong_leaf,
            root,
            &[0],
            leaves.len()
        ));
    }

    #[test]
    fn merkle_root_rejects_wrong_total_leaf_count() {
        let leaves = [
            Sha256::hash(b"leaf-0"),
            Sha256::hash(b"leaf-1"),
            Sha256::hash(b"leaf-2"),
        ];
        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let root = tree.root().unwrap();
        let proof = tree.proof(&[1]);

        assert!(!verify_merkle_root(&proof, leaves[1], root, &[1], 99));
    }

    #[test]
    fn malformed_merkle_proof_does_not_verify() {
        let leaves = [Sha256::hash(b"leaf-0"), Sha256::hash(b"leaf-1")];
        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let root = tree.root().unwrap();
        let empty_proof = MerkleProof::<Sha256>::new(vec![]);

        assert!(!verify_merkle_root(
            &empty_proof,
            leaves[1],
            root,
            &[1],
            leaves.len()
        ));
    }
}
