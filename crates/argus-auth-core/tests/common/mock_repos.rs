//! Mock repositories for testing

use argus_db::{
    CreateSession, CreateUser, DbResult, SessionRepository, SessionRow, UserRepository, UserRow,
};
use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

/// In-memory user repository for testing
#[derive(Default, Clone)]
pub struct MockUserRepository {
    users: Arc<DashMap<Uuid, UserRow>>,
    by_email: Arc<DashMap<String, Uuid>>,
    by_cognito_sub: Arc<DashMap<String, Uuid>>,
}

impl MockUserRepository {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a test user directly
    pub fn insert_user(&self, user: UserRow) {
        self.by_email.insert(user.email.clone(), user.id);
        if let Some(ref sub) = user.cognito_sub {
            self.by_cognito_sub.insert(sub.clone(), user.id);
        }
        self.users.insert(user.id, user);
    }

    /// Create a test user with given tier
    #[allow(dead_code)]
    pub fn create_test_user(tier: &str) -> UserRow {
        UserRow {
            id: Uuid::new_v4(),
            email: format!("test-{}@example.com", Uuid::new_v4()),
            cognito_sub: Some(Uuid::new_v4().to_string()),
            tier: tier.to_string(),
            role: "user".to_string(),
            stripe_customer_id: None,
            email_verified: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[async_trait]
impl UserRepository for MockUserRepository {
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<UserRow>> {
        Ok(self.users.get(&id).map(|r| r.value().clone()))
    }

    async fn find_by_email(&self, email: &str) -> DbResult<Option<UserRow>> {
        Ok(self
            .by_email
            .get(email)
            .and_then(|id| self.users.get(id.value()).map(|r| r.value().clone())))
    }

    async fn find_by_cognito_sub(&self, sub: &str) -> DbResult<Option<UserRow>> {
        Ok(self
            .by_cognito_sub
            .get(sub)
            .and_then(|id| self.users.get(id.value()).map(|r| r.value().clone())))
    }

    async fn find_by_stripe_customer_id(&self, _: &str) -> DbResult<Option<UserRow>> {
        Ok(None)
    }

    async fn create(&self, user: CreateUser) -> DbResult<UserRow> {
        let row = UserRow {
            id: user.id,
            email: user.email.clone(),
            cognito_sub: user.cognito_sub.clone(),
            tier: user.tier,
            role: user.role,
            stripe_customer_id: None,
            email_verified: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.insert_user(row.clone());
        Ok(row)
    }

    async fn update_tier(&self, id: Uuid, tier: &str) -> DbResult<()> {
        if let Some(mut user) = self.users.get_mut(&id) {
            user.tier = tier.to_string();
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn update_stripe_customer_id(&self, _: Uuid, _: &str) -> DbResult<()> {
        Ok(())
    }

    async fn update_email_verified(&self, id: Uuid, verified: bool) -> DbResult<()> {
        if let Some(mut user) = self.users.get_mut(&id) {
            user.email_verified = verified;
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> DbResult<()> {
        // Remove from main store and clean up indices
        if let Some((_, user)) = self.users.remove(&id) {
            self.by_email.remove(&user.email);
            if let Some(ref sub) = user.cognito_sub {
                self.by_cognito_sub.remove(sub);
            }
        }
        Ok(())
    }
}

/// In-memory session repository for testing
#[derive(Default, Clone)]
pub struct MockSessionRepository {
    sessions: Arc<DashMap<Uuid, SessionRow>>,
    by_token_hash: Arc<DashMap<String, Uuid>>,
}

impl MockSessionRepository {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a session directly for testing
    #[allow(dead_code)]
    pub fn insert_session(&self, session: SessionRow) {
        self.by_token_hash
            .insert(session.token_hash.clone(), session.id);
        self.sessions.insert(session.id, session);
    }
}

#[async_trait]
impl SessionRepository for MockSessionRepository {
    async fn find_by_id(&self, id: Uuid) -> DbResult<Option<SessionRow>> {
        Ok(self.sessions.get(&id).map(|r| r.value().clone()))
    }

    async fn find_by_token_hash(&self, hash: &str) -> DbResult<Option<SessionRow>> {
        Ok(self
            .by_token_hash
            .get(hash)
            .and_then(|id| self.sessions.get(id.value()).map(|r| r.value().clone())))
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> DbResult<Vec<SessionRow>> {
        Ok(self
            .sessions
            .iter()
            .filter(|r| r.value().user_id == user_id)
            .map(|r| r.value().clone())
            .collect())
    }

    async fn create(&self, session: CreateSession) -> DbResult<SessionRow> {
        let row = SessionRow {
            id: session.id,
            user_id: session.user_id,
            token_hash: session.token_hash.clone(),
            ip_address: session.ip_address,
            user_agent: session.user_agent,
            expires_at: session.expires_at,
            revoked: false,
            last_active_at: Utc::now(),
            created_at: Utc::now(),
        };
        self.by_token_hash.insert(session.token_hash, session.id);
        self.sessions.insert(session.id, row.clone());
        Ok(row)
    }

    async fn update_last_active(&self, id: Uuid) -> DbResult<()> {
        if let Some(mut s) = self.sessions.get_mut(&id) {
            s.last_active_at = Utc::now();
        }
        Ok(())
    }

    async fn revoke(&self, id: Uuid) -> DbResult<()> {
        if let Some(mut s) = self.sessions.get_mut(&id) {
            s.revoked = true;
        }
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> DbResult<u64> {
        let mut count = 0;
        for mut s in self.sessions.iter_mut() {
            if s.user_id == user_id && !s.revoked {
                s.revoked = true;
                count += 1;
            }
        }
        Ok(count)
    }

    async fn delete_expired(&self) -> DbResult<u64> {
        let now = Utc::now();
        let expired: Vec<Uuid> = self
            .sessions
            .iter()
            .filter(|r| r.expires_at < now)
            .map(|r| r.id)
            .collect();
        let count = expired.len() as u64;
        for id in expired {
            if let Some((_, session)) = self.sessions.remove(&id) {
                self.by_token_hash.remove(&session.token_hash);
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_user_repo_crud() {
        let repo = MockUserRepository::new();

        // Create
        let user = repo
            .create(CreateUser {
                id: Uuid::new_v4(),
                email: "test@example.com".to_string(),
                cognito_sub: Some("sub-123".to_string()),
                tier: "professional".to_string(),
                role: "user".to_string(),
            })
            .await
            .unwrap();

        // Find by ID
        let found = repo.find_by_id(user.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().email, "test@example.com");

        // Find by email
        let found = repo.find_by_email("test@example.com").await.unwrap();
        assert!(found.is_some());

        // Find by cognito sub
        let found = repo.find_by_cognito_sub("sub-123").await.unwrap();
        assert!(found.is_some());

        // Update tier
        repo.update_tier(user.id, "enterprise").await.unwrap();
        let found = repo.find_by_id(user.id).await.unwrap().unwrap();
        assert_eq!(found.tier, "enterprise");

        // Delete
        repo.delete(user.id).await.unwrap();
        let found = repo.find_by_id(user.id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_mock_session_repo_crud() {
        let repo = MockSessionRepository::new();
        let user_id = Uuid::new_v4();

        // Create
        let session = repo
            .create(CreateSession {
                id: Uuid::new_v4(),
                user_id,
                token_hash: "hash123".to_string(),
                ip_address: Some("127.0.0.1".to_string()),
                user_agent: Some("Test Agent".to_string()),
                expires_at: Utc::now() + chrono::Duration::hours(24),
            })
            .await
            .unwrap();

        // Find by ID
        let found = repo.find_by_id(session.id).await.unwrap();
        assert!(found.is_some());

        // Find by token hash
        let found = repo.find_by_token_hash("hash123").await.unwrap();
        assert!(found.is_some());

        // Find by user ID
        let sessions = repo.find_by_user_id(user_id).await.unwrap();
        assert_eq!(sessions.len(), 1);

        // Revoke
        repo.revoke(session.id).await.unwrap();
        let found = repo.find_by_id(session.id).await.unwrap().unwrap();
        assert!(found.revoked);
    }

    #[tokio::test]
    async fn test_revoke_all_for_user() {
        let repo = MockSessionRepository::new();
        let user_id = Uuid::new_v4();

        // Create multiple sessions
        for i in 0..3 {
            repo.create(CreateSession {
                id: Uuid::new_v4(),
                user_id,
                token_hash: format!("hash{i}"),
                ip_address: None,
                user_agent: None,
                expires_at: Utc::now() + chrono::Duration::hours(24),
            })
            .await
            .unwrap();
        }

        // Revoke all
        let count = repo.revoke_all_for_user(user_id).await.unwrap();
        assert_eq!(count, 3);

        // Verify all revoked
        let sessions = repo.find_by_user_id(user_id).await.unwrap();
        assert!(sessions.iter().all(|s| s.revoked));
    }
}
