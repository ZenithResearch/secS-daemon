use async_trait::async_trait;
use libsec_core::{tunnel::decrypt_payload, ZenithPacket};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

#[async_trait]
pub trait MachineProgram: Send + Sync {
    async fn execute(&self, payload: &[u8]);
}

struct ConfigurableRouter {
    programs: HashMap<u8, Box<dyn MachineProgram>>,
    pool: SqlitePool,
}

impl ConfigurableRouter {
    fn new(pool: SqlitePool) -> Self {
        Self {
            programs: HashMap::new(),
            pool,
        }
    }

    fn register(&mut self, opcode: u8, program: Box<dyn MachineProgram>) {
        self.programs.insert(opcode, program);
    }

    async fn route(&self, opcode: u8, payload: Vec<u8>) {
        let payload_size = payload.len() as i64;

        if let Err(e) =
            sqlx::query("INSERT INTO node_telemetry (opcode, payload_size) VALUES (?, ?)")
                .bind(i64::from(opcode))
                .bind(payload_size)
                .execute(&self.pool)
                .await
        {
            eprintln!("secZ [Telemetry]: Failed to write log - {}", e);
        }

        match self.programs.get(&opcode) {
            Some(program) => program.execute(&payload).await,
            None => eprintln!("secZ [Router]: Rejected unmapped opcode {:#04x}", opcode),
        }
    }
}

// 1. THE UNIVERSAL SUBPROCESS FORWARDER
struct SubprocessForwarder {
    program: String,
    args: Vec<String>,
}

impl SubprocessForwarder {
    fn new(program: &str, args: Vec<&str>) -> Self {
        Self {
            program: program.to_string(),
            args: args.into_iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[async_trait]
impl MachineProgram for SubprocessForwarder {
    async fn execute(&self, payload: &[u8]) {
        println!(
            "secZ [Subprocess]: Invoking `{} {:?}`",
            self.program, self.args
        );
        let mut child = match tokio::process::Command::new(&self.program)
            .args(&self.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("secZ [Subprocess]: Failed to spawn - {}", e);
                return;
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut stdin, payload).await {
                eprintln!(
                    "secZ [Subprocess]: Failed to write payload to stdin - {}",
                    e
                );
            }
        }
        let _ = child.wait().await;
    }
}

// 2. NATIVE RUST BINDING STUB
struct LocalRustQueue;
#[async_trait]
impl MachineProgram for LocalRustQueue {
    async fn execute(&self, payload: &[u8]) {
        println!("secZ [Native Rust]: Enqueueing {} bytes...", payload.len());
        // Future native logic here
    }
}

async fn handle_connection(router: Arc<ConfigurableRouter>, mut socket: TcpStream) {
    let mut wire_bytes = Vec::new();
    if let Err(e) = socket.read_to_end(&mut wire_bytes).await {
        eprintln!("secZ [Transport]: Failed to read connection - {}", e);
        return;
    }

    if wire_bytes.is_empty() {
        return;
    }

    let packet = match bincode::deserialize::<ZenithPacket>(&wire_bytes) {
        Ok(packet) => packet,
        Err(e) => {
            eprintln!("secZ [Transport]: Rejected malformed packet - {}", e);
            return;
        }
    };

    if !validate_zk_proof(&packet) {
        eprintln!("secZ [Auth]: Rejected packet with invalid ZK proof envelope");
        return;
    }

    let payload = match decrypt_machine_payload(&packet) {
        Ok(payload) => payload,
        Err(e) => {
            eprintln!("secZ [Crypto]: Rejected undecryptable payload - {}", e);
            return;
        }
    };

    router.route(packet.opcode, payload).await;
}

fn validate_zk_proof(packet: &ZenithPacket) -> bool {
    !packet.proof.is_empty() && packet.claim_ttl > 0
}

fn decrypt_machine_payload(packet: &ZenithPacket) -> Result<Vec<u8>, String> {
    match load_tunnel_key() {
        Some(key) => decrypt_payload(&key, &packet.nonce, &packet.encrypted_payload)
            .map_err(|_| "ChaCha20Poly1305 authentication failed".to_string()),
        None => Ok(packet.encrypted_payload.clone()),
    }
}

fn load_tunnel_key() -> Option<[u8; 32]> {
    std::env::var("SECZ_TUNNEL_KEY_HEX")
        .or_else(|_| std::env::var("SECS_TUNNEL_KEY_HEX"))
        .ok()
        .and_then(|hex| parse_hex_32(&hex))
}

fn parse_hex_32(input: &str) -> Option<[u8; 32]> {
    let clean = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input)
        .trim();

    if clean.len() != 64 {
        return None;
    }

    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        let end = start + 2;
        *byte = u8::from_str_radix(&clean[start..end], 16).ok()?;
    }
    Some(out)
}

#[tokio::main]
async fn main() {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite:node_telemetry.db?mode=rwc")
        .await
        .expect("secZ: Failed to connect to node_telemetry SQLite DB");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS node_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            opcode INTEGER NOT NULL,
            payload_size INTEGER NOT NULL
        );",
    )
    .execute(&pool)
    .await
    .expect("secZ: Failed to initialize node_telemetry table");

    // 3. MANIFEST CONFIGURATION (Inside main)
    // Initialize pool, create table, then bind opcodes:
    let mut router = ConfigurableRouter::new(pool);

    // Bind 0x10 to a system bash script
    router.register(
        0x10,
        Box::new(SubprocessForwarder::new(
            "bash",
            vec!["-c", "echo 'Bash received payload:'; cat"],
        )),
    );

    // Bind 0x20 to custom Native Rust Logic
    router.register(0x20, Box::new(LocalRustQueue));

    // Bind 0x30 to jq for JSON parsing
    router.register(0x30, Box::new(SubprocessForwarder::new("jq", vec!["."])));

    let router = Arc::new(router);
    let listener = TcpListener::bind("0.0.0.0:9001")
        .await
        .expect("secZ: Failed to bind TCP listener");

    println!("secZ [Gateway]: Universal configurable gateway listening on 0.0.0.0:9001");

    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                println!("secZ [Transport]: Accepted connection from {}", peer);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    handle_connection(router, socket).await;
                });
            }
            Err(e) => eprintln!("secZ [Transport]: Failed to accept connection - {}", e),
        }
    }
}
