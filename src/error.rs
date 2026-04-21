use philharmonic_store::StoreError;
use philharmonic_types::{Sha256, Uuid};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    #[error("permission document parse failed: {0}")]
    PermissionDocumentParse(#[from] serde_json::Error),

    #[error("principal not found: {principal_id}")]
    PrincipalNotFound { principal_id: Uuid },

    #[error("role not found: {role_id}")]
    RoleNotFound { role_id: Uuid },

    #[error("permissions content slot missing on role {role_id}")]
    MissingPermissionsSlot { role_id: Uuid },

    #[error("permissions blob missing from content store for role {role_id}, hash {hash}")]
    MissingPermissionsBlob { role_id: Uuid, hash: Sha256 },

    #[error("missing entity attribute '{attribute}' on {entity_name}")]
    MissingEntityAttribute {
        entity_name: &'static str,
        attribute: &'static str,
    },

    #[error("missing scalar attribute '{attribute}' on {entity_name}")]
    MissingScalarAttribute {
        entity_name: &'static str,
        attribute: &'static str,
    },

    #[error(
        "invalid scalar type for attribute '{attribute}' on {entity_name}: expected {expected}, found {actual}"
    )]
    InvalidScalarType {
        entity_name: &'static str,
        attribute: &'static str,
        expected: &'static str,
        actual: &'static str,
    },

    #[error("entity kind mismatch for {entity_name}: expected {expected}, found {actual}")]
    EntityKindMismatch {
        entity_name: &'static str,
        expected: Uuid,
        actual: Uuid,
    },

    #[error("invalid subdomain name: {reason}")]
    InvalidSubdomainName { reason: String },

    #[error("invalid tenant status discriminant: {value}")]
    InvalidTenantStatusDiscriminant { value: i64 },

    #[error("invalid principal kind discriminant: {value}")]
    InvalidPrincipalKindDiscriminant { value: i64 },
}
