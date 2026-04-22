use philharmonic_store::StoreError;
use philharmonic_types::{Sha256, Uuid};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    #[error("permission document parse failed: {0}")]
    PermissionDocumentParse(#[from] serde_json::Error),

    #[error("unknown permission atom: {atom}")]
    UnknownPermissionAtom { atom: String },

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

    #[error("sck key I/O failed: {0}")]
    SckIo(#[from] std::io::Error),

    #[error("sck key file length invalid: expected {expected} bytes, got {actual}")]
    SckKeyFileLength { expected: usize, actual: usize },

    #[error("sck ciphertext too short: got {len} bytes, need at least {required}")]
    SckCiphertextTooShort { len: usize, required: usize },

    #[error("unsupported sck wire version byte: 0x{byte:02x}")]
    SckUnsupportedVersion { byte: u8 },

    #[error("sck decryption failed")]
    SckDecryptFailed,

    #[error("token has wrong length: expected {expected}, got {actual}")]
    TokenWrongLength { expected: usize, actual: usize },

    #[error("token has wrong prefix")]
    TokenWrongPrefix,

    #[error("token contains invalid base64")]
    TokenInvalidBase64,

    #[error("decoded token has wrong byte length: expected {expected}, got {actual}")]
    TokenDecodedWrongLength { expected: usize, actual: usize },
}
