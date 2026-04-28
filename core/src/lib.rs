#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub mod zk;
pub mod tunnel;
#[cfg(feature = "uniffi")]
pub mod ffi;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[repr(C)]
pub struct ZenithPacket {
    pub session_id: [u8; 16],
    pub nonce: [u8; 12],
    pub opcode: u8,
    pub proof: Vec<u8>,
    pub claim_ttl: u64,
    pub encrypted_payload: Vec<u8>,
    pub mac: [u8; 16],
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[repr(C)]
pub struct SessionHandshake {
    pub ephemeral_public_key: [u8; 32],
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode;

    #[test]
    fn test_zenith_packet_serialization() {
        let packet = ZenithPacket {
            session_id: [0xAA; 16],
            nonce: [0xBB; 12],
            opcode: 1,
            proof: alloc::vec![0xCC; 64],
            claim_ttl: 3600,
            encrypted_payload: alloc::vec![0xDD; 128],
            mac: [0xEE; 16],
        };

        let bytes = bincode::serialize(&packet).unwrap();
        let deserialized: ZenithPacket = bincode::deserialize(&bytes).unwrap();

        assert_eq!(packet, deserialized);
    }

    #[test]
    fn test_session_handshake_serialization() {
        let handshake = SessionHandshake {
            ephemeral_public_key: [0xFF; 32],
            timestamp: 1234567890,
        };

        let bytes = bincode::serialize(&handshake).unwrap();
        let deserialized: SessionHandshake = bincode::deserialize(&bytes).unwrap();

        assert_eq!(handshake, deserialized);
    }

    #[test]
    fn test_handshake_in_encrypted_payload() {
        let handshake = SessionHandshake {
            ephemeral_public_key: [0xFF; 32],
            timestamp: 1234567890,
        };

        let encrypted_payload = alloc::vec![
            0x01; 32, // ephemeral_public_key placeholder
            0x02,     // timestamp placeholder
        ];

        let packet = ZenithPacket {
            session_id: [0xAA; 16],
            nonce: [0xBB; 12],
            opcode: 0x01,
            proof: vec![],
            claim_ttl: 3600,
            encrypted_payload,
            mac: [0x00; 16],
        };

        let bytes = bincode::serialize(&packet).unwrap();
        let deserialized: ZenithPacket = bincode::deserialize(&bytes).unwrap();

        assert_eq!(packet.encrypted_payload.len(), deserialized.encrypted_payload.len());
    }
}
