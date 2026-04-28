use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use libsec_core::ZenithPacket;
use libsec_core::zk::generate_proof;
use alloc::vec::Vec;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Send { message: String },
    System { cmd: String },
}

fn load_or_create_identity() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

async fn dispatch_packet(identity: &SigningKey, opcode: u8, payload: Vec<u8>) {
    let mut packet = ZenithPacket {
        session_id: [0u8; 16],
        nonce: [0u8; 12],
        proof: vec![],
        claim_ttl: 3600,
        encrypted_payload: vec![],
        mac: [0u8; 16],
    };

    packet.session_id = [0xFF; 16];
    packet.opcode = opcode;
    packet.encrypted_payload = payload;
    packet.proof = generate_proof(identity, &payload);

    let bytes = bincode::serialize(&packet).unwrap();
    let mut stream = TcpStream::connect("127.0.0.1:9000").await.expect("Failed to connect to secS");
    stream.write_all(&bytes).await.expect("Failed to write");
    stream.flush().await.expect("Failed to flush");
}

#[tokio::main]
async fn main() {
    let identity = load_or_create_identity();
    let cli = Cli::parse();

    match cli.command {
        Commands::Send { message } => {
            println!("Client: Preparing to send message: {} [Identity: {}]", message, identity.verifying_key());
            dispatch_packet(&identity, 0x01, message.into_bytes()).await;
        }
        Commands::System { cmd } => {
            println!("Client: Preparing system command: {} [Identity: {}]", cmd, identity.verifying_key());
            dispatch_packet(&identity, 0x02, cmd.into_bytes()).await;
        }
    }
}
