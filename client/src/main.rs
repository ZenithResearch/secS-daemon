use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use libsec_core::zk::generate_proof;
use libsec_core::ZenithPacket;
use rand::rngs::OsRng;
use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short = 's', long, env = "SECS_URL", default_value = "127.0.0.1:9000")]
    server: String,
}

#[derive(Subcommand)]
enum Commands {
    Generate { prompt: String },
    Chat { message: String },
    Hub { opcode: u8, payload: String },
}

fn load_or_create_identity() -> SigningKey {
    let secret = OsRng.gen::<[u8; 32]>();
    SigningKey::from_bytes(&secret)
}

async fn dispatch_packet(identity: &SigningKey, server_addr: &str, opcode: u8, payload: Vec<u8>) {
    let mut packet = ZenithPacket {
        session_id: [0u8; 16],
        nonce: [0u8; 12],
        opcode,
        proof: vec![],
        claim_ttl: 3600,
        encrypted_payload: payload.clone(),
        mac: [0u8; 16],
    };

    packet.session_id = [0xFF; 16];
    packet.proof = generate_proof(identity, &payload);

    let bytes = bincode::serialize(&packet).unwrap();
    let mut stream = TcpStream::connect(server_addr)
        .await
        .expect("Failed to connect to Node");
    stream.write_all(&bytes).await.expect("Failed to write");
    stream.flush().await.expect("Failed to flush");
}

#[tokio::main]
async fn main() {
    let identity = load_or_create_identity();
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { prompt } => {
            println!(
                "Client: Preparing Generate command [Identity: {:?}]",
                identity.verifying_key()
            );
            dispatch_packet(&identity, &cli.server, 0x01, prompt.into_bytes()).await;
        }
        Commands::Chat { message } => {
            println!(
                "Client: Preparing Chat command [Identity: {:?}]",
                identity.verifying_key()
            );
            dispatch_packet(&identity, &cli.server, 0x02, message.into_bytes()).await;
        }
        Commands::Hub { opcode, payload } => {
            println!(
                "Client: Preparing Hub M2M command ({:#04x}) [Identity: {:?}]",
                opcode,
                identity.verifying_key()
            );
            dispatch_packet(&identity, &cli.server, opcode, payload.into_bytes()).await;
        }
    }
}
