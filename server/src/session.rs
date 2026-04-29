use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Instant;

pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, Instant>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register_session(&self, id: String) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(id, Instant::now());
    }

    pub async fn is_active(&self, id: &str) -> bool {
        let sessions = self.sessions.read().await;
        let now = Instant::now();
        if let Some(last_active) = sessions.get(id) {
            now.duration_since(*last_active).as_secs() < 300
        } else {
            false
        }
    }
}

impl Clone for SessionStore {
    fn clone(&self) -> Self {
        Self {
            sessions: Arc::clone(&self.sessions),
        }
    }
}
