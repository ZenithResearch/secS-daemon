use async_trait::async_trait;
use libsec_core::{OPCODE_CHAT, OPCODE_GENERATE};
use server::{run_node, session::SessionStore, PayloadRouter};
use std::sync::Arc;

struct SecSRouter;

#[async_trait]
impl PayloadRouter for SecSRouter {
    async fn route(&self, store: &SessionStore, opcode: u8, _payload: Vec<u8>) {
        match opcode {
            OPCODE_GENERATE => println!("Handoff: Local Generate Handler..."),
            OPCODE_CHAT => {
                let session_id = "chat_01";
                if store.is_active(session_id).await {
                    println!("Handoff: Resuming active Chat Session [{}]...", session_id);
                } else {
                    println!("Handoff: Initiating new Chat Session [{}]...", session_id);
                }
                store.register_session(session_id.to_string()).await;
            }
            0x10 | 0x20 => println!("Handoff: Dispatching to secZ Hub..."),
            _ => println!("Handoff: Unknown Opcode received"),
        }
    }
}

#[tokio::main]
async fn main() {
    let session_store = Arc::new(SessionStore::new());
    let router = Arc::new(SecSRouter);
    run_node("0.0.0.0:9000", session_store, router).await;
}
