use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use libsec_core::ZenithPacket;
use bincode;

async fn process_payload(opcode: u8, payload: Vec<u8>) {
    match opcode {
        0x01 => println!("Handoff: Processing Chat Message..."),
        0x02 => println!("Handoff: Processing System Command..."),
        _ => println!("Handoff: Unknown Opcode received"),
    }
}

async fn handle_client(mut socket: TcpStream) {
    let mut buf = [0; 1024];
    loop {
        let n = socket.read(&mut buf).await.expect("failed to read data from socket");
        if n == 0 {
            return;
        }
        
        if n > 0 {
            match bincode::deserialize::<ZenithPacket>(&buf[..n]) {
                Ok(packet) => {
                    println!("Packet Received: Opcode {}", packet.opcode);
                    if !packet.proof.is_empty() {
                        println!("Validating Proof...");
                    }
                    process_payload(packet.opcode, packet.encrypted_payload).await;
                }
                Err(e) => eprintln!("Failed to deserialize packet: {}", e),
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:9000").await.expect("failed to bind");
    println!("secS Daemon: Listening on 0.0.0.0:9000");
    loop {
        match listener.accept().await {
            Ok((socket, _)) => tokio::spawn(async move { handle_client(socket).await; }),
            Err(e) => eprintln!("Failed to accept connection: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_daemon_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handle_client(socket).await;
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"ZENITH_PING").await.unwrap();
    }
}
