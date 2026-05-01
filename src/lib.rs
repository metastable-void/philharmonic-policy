//! Policy primitives for Philharmonic: entities, permissions, SCK encryption, and API tokens.

mod api_token;
mod entity;
mod error;
mod evaluation;
mod permission;
mod sck;
mod token;

pub use api_token::{
    ALLOWED_CLOCK_SKEW_MILLIS, ApiSignedToken, ApiSigningKey, ApiTokenMintError,
    ApiTokenVerifyError, ApiVerifyingKeyEntry, ApiVerifyingKeyRegistry, CoseSign1,
    EphemeralApiTokenClaims, KID_MAX_LEN, KID_MIN_LEN, MAX_INJECTED_CLAIMS_BYTES, MAX_TOKEN_BYTES,
    MAX_TOKEN_LIFETIME_MILLIS, RegistryInsertError, VerifyLimits, VerifyingKey,
    mint_ephemeral_api_token, verify_ephemeral_api_token, verify_ephemeral_api_token_with_limits,
};
pub use entity::{
    AuditEvent, MintingAuthority, Principal, PrincipalKind, RESERVED_SUBDOMAIN_NAMES,
    RoleDefinition, RoleMembership, Tenant, TenantEndpointConfig, TenantStatus,
    validate_subdomain_name,
};
pub use error::PolicyError;
pub use evaluation::evaluate_permission;
pub use permission::{ALL_ATOMS, PermissionDocument, atom};
pub use sck::{Sck, sck_decrypt, sck_encrypt};
pub use token::{
    TOKEN_BYTES, TOKEN_ENCODED_LEN, TOKEN_FULL_LEN, TOKEN_PREFIX, TokenHash, generate_api_token,
    parse_api_token,
};
