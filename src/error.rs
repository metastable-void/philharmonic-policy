use philharmonic_store::StoreError;
use philharmonic_types::{Sha256, Uuid};

/// Errors produced by policy operations.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// Storage substrate failure.
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    /// Permission document JSON parsing failed.
    #[error("permission document parse failed: {0}")]
    PermissionDocumentParse(#[from] serde_json::Error),

    /// A permission atom is not in the known set.
    #[error("unknown permission atom: {atom}")]
    UnknownPermissionAtom {
        /// The unrecognised atom string.
        atom: String,
    },

    /// Principal entity was not found.
    #[error("principal not found: {principal_id}")]
    PrincipalNotFound {
        /// Looked-up principal UUID.
        principal_id: Uuid,
    },

    /// Role entity was not found.
    #[error("role not found: {role_id}")]
    RoleNotFound {
        /// Looked-up role UUID.
        role_id: Uuid,
    },

    /// Role entity is missing its permissions content slot.
    #[error("permissions content slot missing on role {role_id}")]
    MissingPermissionsSlot {
        /// Role UUID.
        role_id: Uuid,
    },

    /// Permissions blob is absent from the content store.
    #[error("permissions blob missing from content store for role {role_id}, hash {hash}")]
    MissingPermissionsBlob {
        /// Role UUID.
        role_id: Uuid,
        /// Expected content hash.
        hash: Sha256,
    },

    /// A required entity attribute is missing on a revision.
    #[error("missing entity attribute '{attribute}' on {entity_name}")]
    MissingEntityAttribute {
        /// Entity type name.
        entity_name: &'static str,
        /// Missing attribute name.
        attribute: &'static str,
    },

    /// A required scalar attribute is missing on a revision.
    #[error("missing scalar attribute '{attribute}' on {entity_name}")]
    MissingScalarAttribute {
        /// Entity type name.
        entity_name: &'static str,
        /// Missing attribute name.
        attribute: &'static str,
    },

    /// A scalar attribute has unexpected type.
    #[error(
        "invalid scalar type for attribute '{attribute}' on {entity_name}: expected {expected}, found {actual}"
    )]
    InvalidScalarType {
        /// Entity type name.
        entity_name: &'static str,
        /// Attribute name.
        attribute: &'static str,
        /// Expected scalar type.
        expected: &'static str,
        /// Actual scalar type.
        actual: &'static str,
    },

    /// Entity kind UUID does not match the expected kind.
    #[error("entity kind mismatch for {entity_name}: expected {expected}, found {actual}")]
    EntityKindMismatch {
        /// Entity type name.
        entity_name: &'static str,
        /// Expected kind UUID.
        expected: Uuid,
        /// Actual kind UUID.
        actual: Uuid,
    },

    /// Subdomain name failed validation.
    #[error("invalid subdomain name: {reason}")]
    InvalidSubdomainName {
        /// Validation failure reason.
        reason: String,
    },

    /// Tenant status i64 discriminant is unknown.
    #[error("invalid tenant status discriminant: {value}")]
    InvalidTenantStatusDiscriminant {
        /// Unrecognised discriminant value.
        value: i64,
    },

    /// Principal kind i64 discriminant is unknown.
    #[error("invalid principal kind discriminant: {value}")]
    InvalidPrincipalKindDiscriminant {
        /// Unrecognised discriminant value.
        value: i64,
    },

    /// SCK key file I/O failure.
    #[error("sck key I/O failed: {0}")]
    SckIo(#[from] std::io::Error),

    /// SCK key file has wrong byte length.
    #[error("sck key file length invalid: expected {expected} bytes, got {actual}")]
    SckKeyFileLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// SCK ciphertext is shorter than the minimum wire size.
    #[error("sck ciphertext too short: got {len} bytes, need at least {required}")]
    SckCiphertextTooShort {
        /// Actual length.
        len: usize,
        /// Minimum required length.
        required: usize,
    },

    /// SCK wire format version byte is unsupported.
    #[error("unsupported sck wire version byte: 0x{byte:02x}")]
    SckUnsupportedVersion {
        /// Unsupported version byte.
        byte: u8,
    },

    /// SCK AES-GCM decryption failed (wrong key, corrupted, or tampered).
    #[error("sck decryption failed")]
    SckDecryptFailed,

    /// API token string has wrong total length.
    #[error("token has wrong length: expected {expected}, got {actual}")]
    TokenWrongLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// API token string does not start with the expected prefix.
    #[error("token has wrong prefix")]
    TokenWrongPrefix,

    /// API token base64 payload is invalid.
    #[error("token contains invalid base64")]
    TokenInvalidBase64,

    /// Decoded API token bytes have wrong length.
    #[error("decoded token has wrong byte length: expected {expected}, got {actual}")]
    TokenDecodedWrongLength {
        /// Expected decoded length.
        expected: usize,
        /// Actual decoded length.
        actual: usize,
    },
}
