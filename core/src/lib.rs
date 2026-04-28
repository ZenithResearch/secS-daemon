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
}
