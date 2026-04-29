use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Instant;

pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, Instant>>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
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

    #[cfg(test)]
    async fn insert_session_at(&self, id: String, instant: Instant) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(id, instant);
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.sessions.read().await.len()
    }
}

impl Clone for SessionStore {
    fn clone(&self) -> Self {
        Self {
            sessions: Arc::clone(&self.sessions),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[tokio::test]
    async fn new_store_has_no_active_sessions() {
        let store = SessionStore::new();

        assert!(!store.is_active("missing").await);
        assert_eq!(store.len().await, 0);
    }

    #[tokio::test]
    async fn registered_session_is_active() {
        let store = SessionStore::new();

        store.register_session("chat_01".to_string()).await;

        assert!(store.is_active("chat_01").await);
    }

    #[tokio::test]
    async fn clone_shares_underlying_session_state() {
        let store = SessionStore::new();
        let clone = store.clone();

        clone.register_session("shared".to_string()).await;

        assert!(store.is_active("shared").await);
        assert_eq!(store.len().await, 1);
    }

    #[tokio::test]
    async fn session_exactly_under_ttl_is_active() {
        let store = SessionStore::new();
        store
            .insert_session_at(
                "fresh".to_string(),
                Instant::now() - Duration::from_secs(299),
            )
            .await;

        assert!(store.is_active("fresh").await);
    }

    #[tokio::test]
    async fn session_at_or_over_ttl_is_inactive() {
        let store = SessionStore::new();
        store
            .insert_session_at(
                "expired".to_string(),
                Instant::now() - Duration::from_secs(301),
            )
            .await;

        assert!(!store.is_active("expired").await);
    }

    #[tokio::test]
    async fn registering_existing_session_refreshes_expired_timestamp() {
        let store = SessionStore::new();
        store
            .insert_session_at(
                "refresh".to_string(),
                Instant::now() - Duration::from_secs(301),
            )
            .await;
        assert!(!store.is_active("refresh").await);

        store.register_session("refresh".to_string()).await;

        assert!(store.is_active("refresh").await);
        assert_eq!(store.len().await, 1);
    }
}
