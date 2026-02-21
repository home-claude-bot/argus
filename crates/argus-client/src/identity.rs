//! Identity client
//!
//! Client for user profiles, organizations, and API key management.

use argus_proto::identity_service::identity_service_client::IdentityServiceClient;
use argus_types::UserId;
use tonic::transport::Channel;
use tracing::instrument;

use crate::{ClientConfig, ClientError, Result};

/// Client for identity service operations.
///
/// Provides methods for:
/// - User profile management
/// - Organization management
/// - API key operations
/// - Invitation handling
#[derive(Debug, Clone)]
pub struct IdentityClient {
    inner: IdentityServiceClient<Channel>,
    #[allow(dead_code)]
    config: ClientConfig,
}

impl IdentityClient {
    /// Connect to the identity service.
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        let channel = tonic::transport::Channel::from_shared(config.identity_endpoint.clone())
            .map_err(|e| ClientError::connection(format!("invalid endpoint: {e}"), false))?
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .connect_lazy();

        let inner = IdentityServiceClient::new(channel);

        Ok(Self { inner, config })
    }

    /// Create from an existing channel.
    pub fn from_channel(channel: Channel, config: ClientConfig) -> Self {
        Self {
            inner: IdentityServiceClient::new(channel),
            config,
        }
    }

    // =========================================================================
    // User Management
    // =========================================================================

    /// Get a user by ID.
    #[instrument(skip(self), level = "debug")]
    pub async fn get_user(&mut self, user_id: &UserId) -> Result<User> {
        use argus_proto::{GetUserRequest, UserId as ProtoUserId};

        let request = GetUserRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
        };

        let response = self.inner.get_user(request).await?;
        let user = response
            .into_inner()
            .user
            .ok_or_else(|| ClientError::Internal("missing user in response".to_string()))?;

        Ok(User::from_proto(user))
    }

    /// Update a user's profile.
    pub async fn update_user(
        &mut self,
        user_id: &UserId,
        display_name: Option<String>,
        avatar_url: Option<String>,
    ) -> Result<User> {
        use argus_proto::{UpdateUserRequest, UserId as ProtoUserId};

        let request = UpdateUserRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            display_name,
            avatar_url,
            metadata: std::collections::HashMap::new(),
        };

        let response = self.inner.update_user(request).await?;
        let user = response
            .into_inner()
            .user
            .ok_or_else(|| ClientError::Internal("missing user in response".to_string()))?;

        Ok(User::from_proto(user))
    }

    /// Delete a user account.
    pub async fn delete_user(
        &mut self,
        user_id: &UserId,
        confirmation: &str,
        requester_id: Option<&UserId>,
        reason: Option<&str>,
    ) -> Result<bool> {
        use argus_proto::{DeleteUserRequest, UserId as ProtoUserId};

        let request = DeleteUserRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            confirmation: confirmation.to_string(),
            requester_id: requester_id.map(|id| ProtoUserId {
                value: id.to_string(),
            }),
            reason: reason.unwrap_or_default().to_string(),
        };

        let response = self.inner.delete_user(request).await?;
        Ok(response.into_inner().success)
    }

    /// Get a user by email address.
    pub async fn get_user_by_email(&mut self, email: &str) -> Result<User> {
        use argus_proto::GetUserByEmailRequest;

        let request = GetUserByEmailRequest {
            email: email.to_string(),
        };

        let response = self.inner.get_user_by_email(request).await?;
        let user = response
            .into_inner()
            .user
            .ok_or_else(|| ClientError::Internal("missing user in response".to_string()))?;

        Ok(User::from_proto(user))
    }

    // =========================================================================
    // Organization Management
    // =========================================================================

    /// Create a new organization.
    pub async fn create_organization(
        &mut self,
        name: &str,
        owner_id: &UserId,
        slug: Option<&str>,
        description: Option<&str>,
    ) -> Result<Organization> {
        use argus_proto::{CreateOrganizationRequest, UserId as ProtoUserId};

        let request = CreateOrganizationRequest {
            name: name.to_string(),
            slug: slug.unwrap_or_default().to_string(),
            description: description.unwrap_or_default().to_string(),
            logo_url: String::new(),
            owner_id: Some(ProtoUserId {
                value: owner_id.to_string(),
            }),
        };

        let response = self.inner.create_organization(request).await?;
        let org = response
            .into_inner()
            .organization
            .ok_or_else(|| ClientError::Internal("missing organization in response".to_string()))?;

        Ok(Organization::from_proto(org))
    }

    /// Get an organization by ID.
    pub async fn get_organization(&mut self, org_id: &str) -> Result<Organization> {
        use argus_proto::{
            get_organization_request::Identifier, GetOrganizationRequest, OrganizationId,
        };

        let request = GetOrganizationRequest {
            identifier: Some(Identifier::Id(OrganizationId {
                value: org_id.to_string(),
            })),
        };

        let response = self.inner.get_organization(request).await?;
        let org = response
            .into_inner()
            .organization
            .ok_or_else(|| ClientError::Internal("missing organization in response".to_string()))?;

        Ok(Organization::from_proto(org))
    }

    /// Get an organization by slug.
    pub async fn get_organization_by_slug(&mut self, slug: &str) -> Result<Organization> {
        use argus_proto::{get_organization_request::Identifier, GetOrganizationRequest};

        let request = GetOrganizationRequest {
            identifier: Some(Identifier::Slug(slug.to_string())),
        };

        let response = self.inner.get_organization(request).await?;
        let org = response
            .into_inner()
            .organization
            .ok_or_else(|| ClientError::Internal("missing organization in response".to_string()))?;

        Ok(Organization::from_proto(org))
    }

    /// List organizations for a user.
    pub async fn list_organizations(&mut self, user_id: &UserId) -> Result<Vec<Organization>> {
        use argus_proto::{ListOrganizationsRequest, UserId as ProtoUserId};

        let request = ListOrganizationsRequest {
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            pagination: None,
        };

        let response = self.inner.list_organizations(request).await?;
        let orgs = response
            .into_inner()
            .organizations
            .into_iter()
            .map(Organization::from_proto)
            .collect();

        Ok(orgs)
    }

    // =========================================================================
    // API Key Management
    // =========================================================================

    /// Create a new API key for a user.
    pub async fn create_api_key(
        &mut self,
        user_id: &UserId,
        name: &str,
        scopes: Vec<String>,
    ) -> Result<(ApiKey, String)> {
        use argus_proto::{
            create_api_key_request::Owner, CreateApiKeyRequest, UserId as ProtoUserId,
        };

        let request = CreateApiKeyRequest {
            name: name.to_string(),
            owner: Some(Owner::UserId(ProtoUserId {
                value: user_id.to_string(),
            })),
            scopes,
            expires_at: None,
        };

        let response = self.inner.create_api_key(request).await?.into_inner();
        let api_key = response
            .api_key
            .ok_or_else(|| ClientError::Internal("missing api_key in response".to_string()))?;

        Ok((ApiKey::from_proto(api_key), response.key))
    }

    /// List API keys for a user.
    pub async fn list_api_keys(&mut self, user_id: &UserId) -> Result<Vec<ApiKey>> {
        use argus_proto::{
            list_api_keys_request::Owner, ListApiKeysRequest, UserId as ProtoUserId,
        };

        let request = ListApiKeysRequest {
            owner: Some(Owner::UserId(ProtoUserId {
                value: user_id.to_string(),
            })),
            pagination: None,
        };

        let response = self.inner.list_api_keys(request).await?;
        let keys = response
            .into_inner()
            .api_keys
            .into_iter()
            .map(ApiKey::from_proto)
            .collect();

        Ok(keys)
    }

    /// Revoke an API key.
    pub async fn revoke_api_key(&mut self, api_key_id: &str) -> Result<bool> {
        use argus_proto::{ApiKeyId, RevokeApiKeyRequest};

        let request = RevokeApiKeyRequest {
            api_key_id: Some(ApiKeyId {
                value: api_key_id.to_string(),
            }),
        };

        let response = self.inner.revoke_api_key(request).await?;
        Ok(response.into_inner().success)
    }

    /// Validate an API key.
    #[instrument(skip(self, key), level = "debug")]
    pub async fn validate_api_key(
        &mut self,
        key: &str,
        required_scopes: Vec<String>,
    ) -> Result<Option<ApiKey>> {
        use argus_proto::ValidateApiKeyRequest;

        let request = ValidateApiKeyRequest {
            key: key.to_string(),
            required_scopes,
        };

        let response = self.inner.validate_api_key(request).await?.into_inner();

        if response.valid {
            let api_key = response
                .api_key
                .ok_or_else(|| ClientError::Internal("missing api_key in response".to_string()))?;
            Ok(Some(ApiKey::from_proto(api_key)))
        } else {
            Ok(None)
        }
    }

    // =========================================================================
    // User Search (Admin)
    // =========================================================================

    /// Search for users (admin only).
    pub async fn search_users(
        &mut self,
        query: &str,
        tier: Option<argus_types::Tier>,
        admin_only: bool,
        page_size: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<(Vec<User>, Option<String>)> {
        use argus_proto::{PageRequest, SearchUsersRequest};

        let request = SearchUsersRequest {
            query: query.to_string(),
            tier: tier.map_or(0, |t| tier_to_proto(t) as i32),
            role: if admin_only {
                argus_proto::Role::Admin as i32
            } else {
                0
            },
            pagination: Some(PageRequest {
                page: 1,
                page_size: page_size.unwrap_or(50),
                cursor: cursor.unwrap_or_default().to_string(),
            }),
        };

        let response = self.inner.search_users(request).await?.into_inner();
        let users: Vec<User> = response.users.into_iter().map(User::from_proto).collect();
        let next_cursor = response.pagination.and_then(|p| {
            if p.next_cursor.is_empty() {
                None
            } else {
                Some(p.next_cursor)
            }
        });

        Ok((users, next_cursor))
    }

    // =========================================================================
    // Organization Management (continued)
    // =========================================================================

    /// Update an organization.
    pub async fn update_organization(
        &mut self,
        org_id: &str,
        name: Option<&str>,
        description: Option<&str>,
        logo_url: Option<&str>,
    ) -> Result<Organization> {
        use argus_proto::{OrganizationId, UpdateOrganizationRequest};

        let request = UpdateOrganizationRequest {
            organization_id: Some(OrganizationId {
                value: org_id.to_string(),
            }),
            name: name.map(ToString::to_string),
            description: description.map(ToString::to_string),
            logo_url: logo_url.map(ToString::to_string),
            settings: std::collections::HashMap::new(),
        };

        let response = self.inner.update_organization(request).await?;
        let org = response
            .into_inner()
            .organization
            .ok_or_else(|| ClientError::Internal("missing organization in response".to_string()))?;

        Ok(Organization::from_proto(org))
    }

    /// Delete an organization.
    pub async fn delete_organization(
        &mut self,
        org_id: &str,
        confirmation: &str,
        requester_id: &UserId,
        reason: Option<&str>,
    ) -> Result<bool> {
        use argus_proto::{DeleteOrganizationRequest, OrganizationId, UserId as ProtoUserId};

        let request = DeleteOrganizationRequest {
            organization_id: Some(OrganizationId {
                value: org_id.to_string(),
            }),
            confirmation: confirmation.to_string(),
            requester_id: Some(ProtoUserId {
                value: requester_id.to_string(),
            }),
            reason: reason.unwrap_or_default().to_string(),
        };

        let response = self.inner.delete_organization(request).await?;
        Ok(response.into_inner().success)
    }

    // =========================================================================
    // Organization Members
    // =========================================================================

    /// Add a member to an organization.
    pub async fn add_organization_member(
        &mut self,
        org_id: &str,
        email: &str,
        role: OrganizationRole,
    ) -> Result<OrganizationMember> {
        use argus_proto::{AddOrganizationMemberRequest, OrganizationId};

        let request = AddOrganizationMemberRequest {
            organization_id: Some(OrganizationId {
                value: org_id.to_string(),
            }),
            email: email.to_string(),
            role: role_to_org_role_proto(role) as i32,
        };

        let response = self.inner.add_organization_member(request).await?;
        let member = response
            .into_inner()
            .member
            .ok_or_else(|| ClientError::Internal("missing member in response".to_string()))?;

        Ok(OrganizationMember::from_proto(member))
    }

    /// Remove a member from an organization.
    pub async fn remove_organization_member(
        &mut self,
        org_id: &str,
        user_id: &UserId,
    ) -> Result<bool> {
        use argus_proto::{OrganizationId, RemoveOrganizationMemberRequest, UserId as ProtoUserId};

        let request = RemoveOrganizationMemberRequest {
            organization_id: Some(OrganizationId {
                value: org_id.to_string(),
            }),
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
        };

        let response = self.inner.remove_organization_member(request).await?;
        Ok(response.into_inner().success)
    }

    /// Update a member's role in an organization.
    pub async fn update_organization_member(
        &mut self,
        org_id: &str,
        user_id: &UserId,
        role: OrganizationRole,
    ) -> Result<OrganizationMember> {
        use argus_proto::{OrganizationId, UpdateOrganizationMemberRequest, UserId as ProtoUserId};

        let request = UpdateOrganizationMemberRequest {
            organization_id: Some(OrganizationId {
                value: org_id.to_string(),
            }),
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
            role: role_to_org_role_proto(role) as i32,
        };

        let response = self.inner.update_organization_member(request).await?;
        let member = response
            .into_inner()
            .member
            .ok_or_else(|| ClientError::Internal("missing member in response".to_string()))?;

        Ok(OrganizationMember::from_proto(member))
    }

    /// List members of an organization.
    pub async fn list_organization_members(
        &mut self,
        org_id: &str,
        page_size: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<(Vec<OrganizationMember>, Option<String>)> {
        use argus_proto::{ListOrganizationMembersRequest, OrganizationId, PageRequest};

        let request = ListOrganizationMembersRequest {
            organization_id: Some(OrganizationId {
                value: org_id.to_string(),
            }),
            pagination: Some(PageRequest {
                page: 1,
                page_size: page_size.unwrap_or(50),
                cursor: cursor.unwrap_or_default().to_string(),
            }),
        };

        let response = self
            .inner
            .list_organization_members(request)
            .await?
            .into_inner();
        let members: Vec<OrganizationMember> = response
            .members
            .into_iter()
            .map(OrganizationMember::from_proto)
            .collect();
        let next_cursor = response.pagination.and_then(|p| {
            if p.next_cursor.is_empty() {
                None
            } else {
                Some(p.next_cursor)
            }
        });

        Ok((members, next_cursor))
    }

    // =========================================================================
    // Invitations
    // =========================================================================

    /// Create an invitation to join an organization.
    pub async fn create_invitation(
        &mut self,
        email: &str,
        org_id: &str,
        role: OrganizationRole,
        invited_by: &UserId,
    ) -> Result<(Invitation, String)> {
        use argus_proto::{CreateInvitationRequest, OrganizationId, UserId as ProtoUserId};

        let request = CreateInvitationRequest {
            email: email.to_string(),
            organization_id: Some(OrganizationId {
                value: org_id.to_string(),
            }),
            role: role_to_org_role_proto(role) as i32,
            invited_by: Some(ProtoUserId {
                value: invited_by.to_string(),
            }),
        };

        let response = self.inner.create_invitation(request).await?.into_inner();
        let invitation = response
            .invitation
            .ok_or_else(|| ClientError::Internal("missing invitation in response".to_string()))?;

        Ok((Invitation::from_proto(invitation), response.invitation_url))
    }

    /// Accept an invitation to join an organization.
    pub async fn accept_invitation(
        &mut self,
        token: &str,
        user_id: &UserId,
    ) -> Result<OrganizationMembership> {
        use argus_proto::{AcceptInvitationRequest, UserId as ProtoUserId};

        let request = AcceptInvitationRequest {
            token: token.to_string(),
            user_id: Some(ProtoUserId {
                value: user_id.to_string(),
            }),
        };

        let response = self.inner.accept_invitation(request).await?;
        let membership = response
            .into_inner()
            .membership
            .ok_or_else(|| ClientError::Internal("missing membership in response".to_string()))?;

        Ok(OrganizationMembership::from_proto(membership))
    }

    /// List invitations for an email.
    pub async fn list_invitations_by_email(
        &mut self,
        email: &str,
        include_expired: bool,
        page_size: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<(Vec<Invitation>, Option<String>)> {
        use argus_proto::{list_invitations_request::Scope, ListInvitationsRequest, PageRequest};

        let request = ListInvitationsRequest {
            scope: Some(Scope::Email(email.to_string())),
            include_expired,
            pagination: Some(PageRequest {
                page: 1,
                page_size: page_size.unwrap_or(50),
                cursor: cursor.unwrap_or_default().to_string(),
            }),
        };

        let response = self.inner.list_invitations(request).await?.into_inner();
        let invitations: Vec<Invitation> = response
            .invitations
            .into_iter()
            .map(Invitation::from_proto)
            .collect();
        let next_cursor = response.pagination.and_then(|p| {
            if p.next_cursor.is_empty() {
                None
            } else {
                Some(p.next_cursor)
            }
        });

        Ok((invitations, next_cursor))
    }

    /// List invitations for an organization.
    pub async fn list_invitations_by_org(
        &mut self,
        org_id: &str,
        include_expired: bool,
        page_size: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<(Vec<Invitation>, Option<String>)> {
        use argus_proto::{
            list_invitations_request::Scope, ListInvitationsRequest, OrganizationId, PageRequest,
        };

        let request = ListInvitationsRequest {
            scope: Some(Scope::OrganizationId(OrganizationId {
                value: org_id.to_string(),
            })),
            include_expired,
            pagination: Some(PageRequest {
                page: 1,
                page_size: page_size.unwrap_or(50),
                cursor: cursor.unwrap_or_default().to_string(),
            }),
        };

        let response = self.inner.list_invitations(request).await?.into_inner();
        let invitations: Vec<Invitation> = response
            .invitations
            .into_iter()
            .map(Invitation::from_proto)
            .collect();
        let next_cursor = response.pagination.and_then(|p| {
            if p.next_cursor.is_empty() {
                None
            } else {
                Some(p.next_cursor)
            }
        });

        Ok((invitations, next_cursor))
    }

    /// Revoke an invitation.
    pub async fn revoke_invitation(&mut self, invitation_id: &str) -> Result<bool> {
        use argus_proto::{InvitationId, RevokeInvitationRequest};

        let request = RevokeInvitationRequest {
            invitation_id: Some(InvitationId {
                value: invitation_id.to_string(),
            }),
        };

        let response = self.inner.revoke_invitation(request).await?;
        Ok(response.into_inner().success)
    }

    // =========================================================================
    // Health Check
    // =========================================================================

    /// Check service health.
    pub async fn health_check(&mut self) -> Result<bool> {
        use argus_proto::{health_check_response::ServingStatus, HealthCheckRequest};

        let request = HealthCheckRequest {
            service: String::new(),
        };
        let response = self.inner.health_check(request).await?;
        Ok(response.into_inner().status() == ServingStatus::Serving)
    }
}

// =============================================================================
// Domain Types
// =============================================================================

/// User profile information.
#[derive(Debug, Clone)]
pub struct User {
    /// User ID
    pub id: UserId,
    /// Email address
    pub email: String,
    /// Display name
    pub display_name: String,
    /// Avatar URL
    pub avatar_url: Option<String>,
    /// User tier
    pub tier: argus_types::Tier,
    /// Whether email is verified
    pub email_verified: bool,
}

impl User {
    fn from_proto(proto: argus_proto::User) -> Self {
        // Extract tier before moving other fields
        let tier = tier_from_proto(proto.tier());
        let email_verified = proto.email_verified;

        Self {
            id: UserId::parse(&proto.id.map_or_else(String::new, |id| id.value))
                .unwrap_or_default(),
            email: proto.email,
            display_name: proto.display_name,
            avatar_url: if proto.avatar_url.is_empty() {
                None
            } else {
                Some(proto.avatar_url)
            },
            tier,
            email_verified,
        }
    }
}

/// Organization information.
#[derive(Debug, Clone)]
pub struct Organization {
    /// Organization ID
    pub id: String,
    /// Organization name
    pub name: String,
    /// URL-friendly slug
    pub slug: String,
    /// Description
    pub description: Option<String>,
    /// Owner user ID
    pub owner_id: UserId,
    /// Member count
    pub member_count: u32,
}

impl Organization {
    fn from_proto(proto: argus_proto::Organization) -> Self {
        Self {
            id: proto.id.map_or_else(String::new, |id| id.value),
            name: proto.name,
            slug: proto.slug,
            description: if proto.description.is_empty() {
                None
            } else {
                Some(proto.description)
            },
            owner_id: UserId::parse(&proto.owner_id.map_or_else(String::new, |id| id.value))
                .unwrap_or_default(),
            member_count: proto.member_count,
        }
    }
}

/// API key information.
#[derive(Debug, Clone)]
pub struct ApiKey {
    /// API key ID
    pub id: String,
    /// Key name
    pub name: String,
    /// Key prefix (first 8 chars)
    pub prefix: String,
    /// Scopes/permissions
    pub scopes: Vec<String>,
    /// Whether key is active
    pub active: bool,
}

impl ApiKey {
    fn from_proto(proto: argus_proto::ApiKey) -> Self {
        Self {
            id: proto.id.map_or_else(String::new, |id| id.value),
            name: proto.name,
            prefix: proto.prefix,
            scopes: proto.scopes,
            active: proto.active,
        }
    }
}

/// Organization member role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationRole {
    /// Regular member
    Member,
    /// Organization admin
    Admin,
    /// Organization owner
    Owner,
}

/// Organization member information.
#[derive(Debug, Clone)]
pub struct OrganizationMember {
    /// User ID
    pub user_id: UserId,
    /// Email address
    pub email: String,
    /// Display name
    pub display_name: String,
    /// Avatar URL
    pub avatar_url: Option<String>,
    /// Role in organization
    pub role: OrganizationRole,
    /// When user joined
    pub joined_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl OrganizationMember {
    fn from_proto(proto: argus_proto::OrganizationMember) -> Self {
        let role = org_role_from_proto(proto.role());

        Self {
            user_id: UserId::parse(&proto.user_id.map_or_else(String::new, |id| id.value))
                .unwrap_or_default(),
            email: proto.email,
            display_name: proto.display_name,
            avatar_url: if proto.avatar_url.is_empty() {
                None
            } else {
                Some(proto.avatar_url)
            },
            role,
            joined_at: proto.joined_at.map(|ts| {
                chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32).unwrap_or_default()
            }),
        }
    }
}

/// Organization membership info (from user perspective).
#[derive(Debug, Clone)]
pub struct OrganizationMembership {
    /// Organization ID
    pub organization_id: String,
    /// Organization name
    pub organization_name: String,
    /// User's role
    pub role: OrganizationRole,
    /// When user joined
    pub joined_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl OrganizationMembership {
    fn from_proto(proto: argus_proto::OrganizationMembership) -> Self {
        let role = org_role_from_proto(proto.role());

        Self {
            organization_id: proto
                .organization_id
                .map_or_else(String::new, |id| id.value),
            organization_name: proto.organization_name,
            role,
            joined_at: proto.joined_at.map(|ts| {
                chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32).unwrap_or_default()
            }),
        }
    }
}

/// Invitation to join an organization.
#[derive(Debug, Clone)]
pub struct Invitation {
    /// Invitation ID
    pub id: String,
    /// Invited email
    pub email: String,
    /// Organization ID
    pub organization_id: String,
    /// Organization name
    pub organization_name: String,
    /// Role to assign
    pub role: OrganizationRole,
    /// Who sent the invitation
    pub invited_by: UserId,
    /// When invitation was created
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When invitation expires
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether invitation was accepted
    pub accepted: bool,
}

impl Invitation {
    fn from_proto(proto: argus_proto::Invitation) -> Self {
        let role = org_role_from_proto(proto.role());

        Self {
            id: proto.id.map_or_else(String::new, |id| id.value),
            email: proto.email,
            organization_id: proto
                .organization_id
                .map_or_else(String::new, |id| id.value),
            organization_name: proto.organization_name,
            role,
            invited_by: UserId::parse(&proto.invited_by.map_or_else(String::new, |id| id.value))
                .unwrap_or_default(),
            created_at: proto.created_at.map(|ts| {
                chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32).unwrap_or_default()
            }),
            expires_at: proto.expires_at.map(|ts| {
                chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32).unwrap_or_default()
            }),
            accepted: proto.accepted,
        }
    }
}

// =============================================================================
// Proto Conversion Helpers
// =============================================================================

fn tier_from_proto(tier: argus_proto::Tier) -> argus_types::Tier {
    match tier {
        argus_proto::Tier::Unspecified | argus_proto::Tier::Explorer => argus_types::Tier::Explorer,
        argus_proto::Tier::Professional => argus_types::Tier::Professional,
        argus_proto::Tier::Business => argus_types::Tier::Business,
        argus_proto::Tier::Enterprise => argus_types::Tier::Enterprise,
    }
}

fn tier_to_proto(tier: argus_types::Tier) -> argus_proto::Tier {
    match tier {
        argus_types::Tier::Explorer => argus_proto::Tier::Explorer,
        argus_types::Tier::Professional => argus_proto::Tier::Professional,
        argus_types::Tier::Business => argus_proto::Tier::Business,
        argus_types::Tier::Enterprise => argus_proto::Tier::Enterprise,
    }
}

fn org_role_from_proto(role: argus_proto::OrganizationRole) -> OrganizationRole {
    match role {
        argus_proto::OrganizationRole::Unspecified | argus_proto::OrganizationRole::Member => {
            OrganizationRole::Member
        }
        argus_proto::OrganizationRole::Admin => OrganizationRole::Admin,
        argus_proto::OrganizationRole::Owner => OrganizationRole::Owner,
    }
}

fn role_to_org_role_proto(role: OrganizationRole) -> argus_proto::OrganizationRole {
    match role {
        OrganizationRole::Member => argus_proto::OrganizationRole::Member,
        OrganizationRole::Admin => argus_proto::OrganizationRole::Admin,
        OrganizationRole::Owner => argus_proto::OrganizationRole::Owner,
    }
}
