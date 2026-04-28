use std::collections::{HashMap, hash_map::Entry};
use std::fmt;

pub use coset::CoseSign1;
use coset::{Algorithm, CborSerializable, CoseSign1Builder, HeaderBuilder, iana};
pub use ed25519_dalek::VerifyingKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use philharmonic_types::{CanonicalJson, UnixMillis, Uuid};
use serde::de::Error as _;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

/// Default maximum accepted serialized COSE_Sign1 token length.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Default maximum accepted injected-claims canonical JSON length.
pub const MAX_INJECTED_CLAIMS_BYTES: usize = 4 * 1024;
/// Default maximum token lifetime in milliseconds.
pub const MAX_TOKEN_LIFETIME_MILLIS: i64 = 24 * 60 * 60 * 1000;
/// Default allowed clock skew in milliseconds for `iat` future checks.
pub const ALLOWED_CLOCK_SKEW_MILLIS: i64 = 60_000;
/// Minimum accepted key identifier length in bytes.
pub const KID_MIN_LEN: usize = 1;
/// Maximum accepted key identifier length in bytes.
pub const KID_MAX_LEN: usize = 128;

/// Verified claims carried in an ephemeral API token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EphemeralApiTokenClaims {
    /// API-layer issuer identity.
    pub iss: String,
    /// Issued-at timestamp in Unix milliseconds.
    pub iat: UnixMillis,
    /// Expiry timestamp in Unix milliseconds.
    pub exp: UnixMillis,
    /// Opaque subject identifier supplied by the minting authority.
    pub sub: String,
    /// Tenant scope UUID.
    pub tenant: Uuid,
    /// Minting authority UUID.
    pub authority: Uuid,
    /// Minting authority epoch at token mint time.
    pub authority_epoch: u64,
    /// Optional workflow-instance UUID scope.
    pub instance: Option<Uuid>,
    /// Effective permission atoms granted to the ephemeral subject.
    pub permissions: Vec<String>,
    /// Canonical injected subject metadata.
    pub claims: CanonicalJson,
    /// Signing key identifier.
    pub kid: String,
}

impl Serialize for EphemeralApiTokenClaims {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = if self.instance.is_some() { 11 } else { 10 };
        let mut state = serializer.serialize_struct("EphemeralApiTokenClaims", field_count)?;
        state.serialize_field("iss", &self.iss)?;
        state.serialize_field("iat", &self.iat)?;
        state.serialize_field("exp", &self.exp)?;
        state.serialize_field("sub", &self.sub)?;
        state.serialize_field("tenant", &self.tenant)?;
        state.serialize_field("authority", &self.authority)?;
        state.serialize_field("authority_epoch", &self.authority_epoch)?;
        if let Some(instance) = self.instance {
            state.serialize_field("instance", &instance)?;
        }
        state.serialize_field("permissions", &self.permissions)?;
        let claims =
            std::str::from_utf8(self.claims.as_bytes()).map_err(serde::ser::Error::custom)?;
        state.serialize_field("claims", claims)?;
        state.serialize_field("kid", &self.kid)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for EphemeralApiTokenClaims {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ClaimsHelper {
            iss: String,
            iat: UnixMillis,
            exp: UnixMillis,
            sub: String,
            tenant: Uuid,
            authority: Uuid,
            authority_epoch: u64,
            instance: Option<Uuid>,
            permissions: Vec<String>,
            claims: String,
            kid: String,
        }

        let helper = ClaimsHelper::deserialize(deserializer)?;
        let claims =
            CanonicalJson::from_bytes(helper.claims.as_bytes()).map_err(D::Error::custom)?;
        Ok(Self {
            iss: helper.iss,
            iat: helper.iat,
            exp: helper.exp,
            sub: helper.sub,
            tenant: helper.tenant,
            authority: helper.authority,
            authority_epoch: helper.authority_epoch,
            instance: helper.instance,
            permissions: helper.permissions,
            claims,
            kid: helper.kid,
        })
    }
}

/// Ed25519 signing material used to mint ephemeral API tokens.
#[derive(Clone)]
pub struct ApiSigningKey {
    seed: Zeroizing<[u8; 32]>,
    kid: String,
}

impl fmt::Debug for ApiSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiSigningKey")
            .field("kid", &self.kid)
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl ApiSigningKey {
    /// Construct an API signing key from a 32-byte Ed25519 seed and key identifier.
    pub fn from_seed(seed: Zeroizing<[u8; 32]>, kid: String) -> Self {
        Self { seed, kid }
    }

    /// Return the configured key identifier.
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

/// Type-safe wrapper for ephemeral API tokens (`COSE_Sign1`).
#[derive(Clone, Debug)]
pub struct ApiSignedToken(CoseSign1);

impl ApiSignedToken {
    /// Wrap a COSE_Sign1 value as an ephemeral API token.
    pub fn new(inner: CoseSign1) -> Self {
        Self(inner)
    }

    /// Borrow the wrapped COSE_Sign1 value.
    pub fn as_cose_sign1(&self) -> &CoseSign1 {
        &self.0
    }

    /// Consume the wrapper and return the raw COSE_Sign1 value.
    pub fn into_cose_sign1(self) -> CoseSign1 {
        self.0
    }

    /// Serialize the wrapped COSE_Sign1 value to CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, coset::CoseError> {
        self.0.clone().to_vec()
    }

    /// Parse CBOR bytes into an ephemeral API token wrapper.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, coset::CoseError> {
        CoseSign1::from_slice(bytes).map(Self)
    }
}

impl AsRef<CoseSign1> for ApiSignedToken {
    fn as_ref(&self) -> &CoseSign1 {
        self.as_cose_sign1()
    }
}

impl From<CoseSign1> for ApiSignedToken {
    fn from(value: CoseSign1) -> Self {
        Self::new(value)
    }
}

impl From<ApiSignedToken> for CoseSign1 {
    fn from(value: ApiSignedToken) -> Self {
        value.into_cose_sign1()
    }
}

/// One API signing key verifier plus issuer and validity metadata.
#[derive(Clone, Debug)]
pub struct ApiVerifyingKeyEntry {
    /// Ed25519 verifying key.
    pub vk: VerifyingKey,
    /// Issuer string this key is permitted to sign for.
    pub issuer: String,
    /// Lower bound (inclusive) of this key's acceptance window.
    pub not_before: UnixMillis,
    /// Upper bound (exclusive) of this key's acceptance window.
    pub not_after: UnixMillis,
}

/// In-memory lookup table of API verifying keys by key identifier.
#[derive(Clone, Debug, Default)]
pub struct ApiVerifyingKeyRegistry {
    by_kid: HashMap<String, ApiVerifyingKeyEntry>,
}

impl ApiVerifyingKeyRegistry {
    /// Construct an empty API verifying-key registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one verifying-key entry, rejecting malformed or duplicate key identifiers.
    pub fn insert(
        &mut self,
        kid: String,
        entry: ApiVerifyingKeyEntry,
    ) -> Result<(), RegistryInsertError> {
        validate_kid_profile(&kid)
            .map_err(|_| RegistryInsertError::KidProfileViolation { kid: kid.clone() })?;

        match self.by_kid.entry(kid) {
            Entry::Occupied(occupied) => Err(RegistryInsertError::DuplicateKid {
                kid: occupied.key().clone(),
            }),
            Entry::Vacant(slot) => {
                slot.insert(entry);
                Ok(())
            }
        }
    }

    /// Look up one verifying-key entry by key identifier.
    pub fn lookup(&self, kid: &str) -> Option<&ApiVerifyingKeyEntry> {
        self.by_kid.get(kid)
    }
}

/// Registry insertion failures for API verifying keys.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegistryInsertError {
    /// The key identifier is outside the accepted profile.
    #[error("key identifier is outside the accepted profile: {kid}")]
    KidProfileViolation {
        /// Rejected key identifier.
        kid: String,
    },

    /// The registry already contains this key identifier.
    #[error("duplicate key identifier: {kid}")]
    DuplicateKid {
        /// Duplicate key identifier.
        kid: String,
    },
}

/// Verification limits for deployments that need stricter-than-default checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyLimits {
    /// Maximum serialized COSE_Sign1 token length.
    pub max_token_bytes: usize,
    /// Maximum injected-claims canonical JSON length.
    pub max_injected_claims_bytes: usize,
    /// Maximum token lifetime in milliseconds.
    pub max_token_lifetime_millis: i64,
    /// Allowed clock skew in milliseconds for `iat` future checks.
    pub allowed_clock_skew_millis: i64,
}

impl VerifyLimits {
    /// Return limits clamped so caller-supplied values cannot loosen defaults.
    pub fn clamped(self) -> Self {
        Self {
            max_token_bytes: self.max_token_bytes.min(MAX_TOKEN_BYTES),
            max_injected_claims_bytes: self
                .max_injected_claims_bytes
                .min(MAX_INJECTED_CLAIMS_BYTES),
            max_token_lifetime_millis: self
                .max_token_lifetime_millis
                .min(MAX_TOKEN_LIFETIME_MILLIS),
            allowed_clock_skew_millis: self
                .allowed_clock_skew_millis
                .min(ALLOWED_CLOCK_SKEW_MILLIS),
        }
    }
}

impl Default for VerifyLimits {
    fn default() -> Self {
        Self {
            max_token_bytes: MAX_TOKEN_BYTES,
            max_injected_claims_bytes: MAX_INJECTED_CLAIMS_BYTES,
            max_token_lifetime_millis: MAX_TOKEN_LIFETIME_MILLIS,
            allowed_clock_skew_millis: ALLOWED_CLOCK_SKEW_MILLIS,
        }
    }
}

/// Failures while minting an ephemeral API token.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ApiTokenMintError {
    /// The claims `kid` does not match the signing key `kid`.
    #[error("claims kid '{claims_kid}' does not match signing key kid '{signing_key_kid}'")]
    KidMismatch {
        /// Signing key identifier configured on the signing key.
        signing_key_kid: String,
        /// Signing key identifier carried in the claims.
        claims_kid: String,
    },

    /// A key identifier is outside the accepted profile.
    #[error("key identifier is outside the accepted profile: {kid}")]
    KidProfileViolation {
        /// Rejected key identifier.
        kid: String,
    },

    /// The injected claims exceed the configured size cap.
    #[error("injected claims too large: limit {limit} bytes, got {actual} bytes")]
    ClaimsTooLarge {
        /// Applied byte limit.
        limit: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// Token lifetime fields violate the primitive's invariants.
    #[error("token lifetime invariant violation")]
    LifetimeInvariantViolation,

    /// Claims serialization failed.
    #[error("claims serialization failed: {detail}")]
    SerializationFailure {
        /// Serialization failure detail.
        detail: String,
    },

    /// Ed25519 signing failed.
    #[error("token signing failed: {detail}")]
    SigningFailure {
        /// Signing failure detail.
        detail: String,
    },
}

/// Failures while verifying an ephemeral API token.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ApiTokenVerifyError {
    /// The serialized token exceeds the configured size cap.
    #[error("token too large: limit {limit} bytes, got {actual} bytes")]
    TokenTooLarge {
        /// Applied byte limit.
        limit: usize,
        /// Actual byte length.
        actual: usize,
    },

    /// The COSE_Sign1 or claim payload is malformed.
    #[error("malformed token")]
    Malformed,

    /// The COSE header profile is outside the accepted shape.
    #[error("COSE header profile violation")]
    HeaderProfileViolation,

    /// The protected algorithm is not EdDSA.
    #[error("algorithm is not allowed")]
    AlgorithmNotAllowed,

    /// The protected key identifier is outside the accepted profile.
    #[error("key identifier is outside the accepted profile")]
    KidProfileViolation,

    /// The protected key identifier is not present in the registry.
    #[error("unknown key identifier: {kid}")]
    UnknownKid {
        /// Unknown key identifier.
        kid: String,
    },

    /// The verifying key is outside its acceptance window.
    #[error(
        "key is outside its validity window: now {now:?}, not_before {not_before:?}, not_after {not_after:?}"
    )]
    KeyOutOfWindow {
        /// Verification time.
        now: UnixMillis,
        /// Lower bound (inclusive) of this key's acceptance window.
        not_before: UnixMillis,
        /// Upper bound (exclusive) of this key's acceptance window.
        not_after: UnixMillis,
    },

    /// The Ed25519 signature is invalid.
    #[error("bad signature")]
    BadSignature,

    /// The injected claims field is not canonical JSON text.
    #[error("injected claims are not canonical JSON")]
    ClaimsNotCanonical,

    /// The signed issuer does not match the registry entry.
    #[error("issuer mismatch: expected '{expected}', found '{found}'")]
    IssuerMismatch {
        /// Issuer configured for the verifying key.
        expected: String,
        /// Issuer carried in the signed claims.
        found: String,
    },

    /// The protected `kid` and signed claim `kid` differ.
    #[error("kid mismatch between protected header '{protected}' and claims '{claims}'")]
    KidInconsistent {
        /// Protected-header key identifier.
        protected: String,
        /// Signed-claims key identifier.
        claims: String,
    },

    /// Token lifetime fields violate the primitive's invariants.
    #[error("token lifetime invariant violation")]
    LifetimeInvariantViolation,

    /// The token is expired.
    #[error("token expired at {exp:?}; verification time {now:?}")]
    Expired {
        /// Expiry timestamp in Unix milliseconds.
        exp: UnixMillis,
        /// Verification timestamp in Unix milliseconds.
        now: UnixMillis,
    },

    /// The injected claims exceed the configured size cap.
    #[error("injected claims too large: limit {limit} bytes, got {actual} bytes")]
    ClaimsTooLarge {
        /// Applied byte limit.
        limit: usize,
        /// Actual byte length.
        actual: usize,
    },
}

/// Mint a signed ephemeral API token.
pub fn mint_ephemeral_api_token(
    signing_key: &ApiSigningKey,
    claims: &EphemeralApiTokenClaims,
    now: UnixMillis,
) -> Result<ApiSignedToken, ApiTokenMintError> {
    if claims.kid != signing_key.kid {
        return Err(ApiTokenMintError::KidMismatch {
            signing_key_kid: signing_key.kid.clone(),
            claims_kid: claims.kid.clone(),
        });
    }

    validate_kid_profile(&signing_key.kid).map_err(|_| ApiTokenMintError::KidProfileViolation {
        kid: signing_key.kid.clone(),
    })?;
    validate_kid_profile(&claims.kid).map_err(|_| ApiTokenMintError::KidProfileViolation {
        kid: claims.kid.clone(),
    })?;

    let claims_len = claims.claims.as_bytes().len();
    if claims_len > MAX_INJECTED_CLAIMS_BYTES {
        return Err(ApiTokenMintError::ClaimsTooLarge {
            limit: MAX_INJECTED_CLAIMS_BYTES,
            actual: claims_len,
        });
    }

    validate_lifetime(
        claims,
        now,
        MAX_TOKEN_LIFETIME_MILLIS,
        ALLOWED_CLOCK_SKEW_MILLIS,
        false,
    )
    .map_err(|err| match err {
        LifetimeError::Expired { .. } | LifetimeError::Invariant => {
            ApiTokenMintError::LifetimeInvariantViolation
        }
    })?;

    let payload = serialize_claims(claims)?;
    let signing_key = SigningKey::from_bytes(&signing_key.seed);

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .key_id(claims.kid.as_bytes().to_vec())
        .build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .try_create_signature(b"", |sig_structure| {
            signing_key
                .try_sign(sig_structure)
                .map(|signature| signature.to_bytes().to_vec())
                .map_err(|err| ApiTokenMintError::SigningFailure {
                    detail: err.to_string(),
                })
        })?
        .build();

    Ok(ApiSignedToken::new(sign1))
}

/// Verify an ephemeral API token using the default verification limits.
pub fn verify_ephemeral_api_token(
    cose_bytes: &[u8],
    registry: &ApiVerifyingKeyRegistry,
    now: UnixMillis,
) -> Result<EphemeralApiTokenClaims, ApiTokenVerifyError> {
    verify_internal(cose_bytes, registry, now, VerifyLimits::default())
}

/// Verify an ephemeral API token using caller-supplied limits clamped to defaults.
pub fn verify_ephemeral_api_token_with_limits(
    cose_bytes: &[u8],
    registry: &ApiVerifyingKeyRegistry,
    now: UnixMillis,
    limits: &VerifyLimits,
) -> Result<EphemeralApiTokenClaims, ApiTokenVerifyError> {
    verify_internal(cose_bytes, registry, now, (*limits).clamped())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KidProfileError {
    Invalid,
}

fn validate_kid_profile(kid: &str) -> Result<(), KidProfileError> {
    let len = kid.len();
    if !(KID_MIN_LEN..=KID_MAX_LEN).contains(&len) {
        return Err(KidProfileError::Invalid);
    }

    if kid.bytes().all(is_kid_byte) {
        Ok(())
    } else {
        Err(KidProfileError::Invalid)
    }
}

fn is_kid_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
}

fn verify_internal(
    cose_bytes: &[u8],
    registry: &ApiVerifyingKeyRegistry,
    now: UnixMillis,
    limits: VerifyLimits,
) -> Result<EphemeralApiTokenClaims, ApiTokenVerifyError> {
    if cose_bytes.len() > limits.max_token_bytes {
        return Err(ApiTokenVerifyError::TokenTooLarge {
            limit: limits.max_token_bytes,
            actual: cose_bytes.len(),
        });
    }

    let sign1 = CoseSign1::from_slice(cose_bytes).map_err(|_| ApiTokenVerifyError::Malformed)?;

    validate_header_profile(&sign1)?;

    if !matches!(
        sign1.protected.header.alg,
        Some(Algorithm::Assigned(iana::Algorithm::EdDSA))
    ) {
        return Err(ApiTokenVerifyError::AlgorithmNotAllowed);
    }

    let protected_kid = std::str::from_utf8(sign1.protected.header.key_id.as_slice())
        .map_err(|_| ApiTokenVerifyError::KidProfileViolation)?;
    validate_kid_profile(protected_kid).map_err(|_| ApiTokenVerifyError::KidProfileViolation)?;

    let key_entry =
        registry
            .lookup(protected_kid)
            .ok_or_else(|| ApiTokenVerifyError::UnknownKid {
                kid: protected_kid.to_owned(),
            })?;

    if now < key_entry.not_before || now >= key_entry.not_after {
        return Err(ApiTokenVerifyError::KeyOutOfWindow {
            now,
            not_before: key_entry.not_before,
            not_after: key_entry.not_after,
        });
    }

    sign1.verify_signature(b"", |signature_bytes, signed_bytes| {
        let signature =
            Signature::try_from(signature_bytes).map_err(|_| ApiTokenVerifyError::BadSignature)?;
        key_entry
            .vk
            .verify(signed_bytes, &signature)
            .map_err(|_| ApiTokenVerifyError::BadSignature)
    })?;

    let claims_payload = sign1
        .payload
        .as_deref()
        .ok_or(ApiTokenVerifyError::Malformed)?;
    let mut claims_reader: &[u8] = claims_payload;
    let claims: EphemeralApiTokenClaims = ciborium::de::from_reader(&mut claims_reader)
        .map_err(|_| ApiTokenVerifyError::Malformed)?;
    if !claims_reader.is_empty() {
        return Err(ApiTokenVerifyError::Malformed);
    }

    let raw_claims = raw_injected_claims_text(claims_payload)?;
    if raw_claims.as_bytes() != claims.claims.as_bytes() {
        return Err(ApiTokenVerifyError::ClaimsNotCanonical);
    }

    if claims.iss != key_entry.issuer {
        return Err(ApiTokenVerifyError::IssuerMismatch {
            expected: key_entry.issuer.clone(),
            found: claims.iss,
        });
    }

    if claims.kid != protected_kid {
        return Err(ApiTokenVerifyError::KidInconsistent {
            protected: protected_kid.to_owned(),
            claims: claims.kid,
        });
    }

    validate_lifetime(
        &claims,
        now,
        limits.max_token_lifetime_millis,
        limits.allowed_clock_skew_millis,
        true,
    )
    .map_err(|err| match err {
        LifetimeError::Expired { exp, now } => ApiTokenVerifyError::Expired { exp, now },
        LifetimeError::Invariant => ApiTokenVerifyError::LifetimeInvariantViolation,
    })?;

    let claims_len = claims.claims.as_bytes().len();
    if claims_len > limits.max_injected_claims_bytes {
        return Err(ApiTokenVerifyError::ClaimsTooLarge {
            limit: limits.max_injected_claims_bytes,
            actual: claims_len,
        });
    }

    Ok(claims)
}

fn validate_header_profile(sign1: &CoseSign1) -> Result<(), ApiTokenVerifyError> {
    let protected = &sign1.protected.header;
    let unprotected = &sign1.unprotected;
    let protected_has_only_alg_and_kid = protected.crit.is_empty()
        && protected.content_type.is_none()
        && !protected.key_id.is_empty()
        && protected.iv.is_empty()
        && protected.partial_iv.is_empty()
        && protected.counter_signatures.is_empty()
        && protected.rest.is_empty();

    if !protected_has_only_alg_and_kid || !unprotected.is_empty() {
        return Err(ApiTokenVerifyError::HeaderProfileViolation);
    }

    Ok(())
}

fn serialize_claims(claims: &EphemeralApiTokenClaims) -> Result<Vec<u8>, ApiTokenMintError> {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(claims, &mut payload).map_err(|err| {
        ApiTokenMintError::SerializationFailure {
            detail: err.to_string(),
        }
    })?;
    Ok(payload)
}

fn raw_injected_claims_text(payload: &[u8]) -> Result<String, ApiTokenVerifyError> {
    let mut reader: &[u8] = payload;
    let value: ciborium::value::Value =
        ciborium::de::from_reader(&mut reader).map_err(|_| ApiTokenVerifyError::Malformed)?;
    if !reader.is_empty() {
        return Err(ApiTokenVerifyError::Malformed);
    }
    let map = value
        .into_map()
        .map_err(|_| ApiTokenVerifyError::Malformed)?;

    for (key, value) in map {
        if matches!(key.as_text(), Some("claims")) {
            return value
                .into_text()
                .map_err(|_| ApiTokenVerifyError::Malformed);
        }
    }

    Err(ApiTokenVerifyError::Malformed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LifetimeError {
    Expired { exp: UnixMillis, now: UnixMillis },
    Invariant,
}

fn validate_lifetime(
    claims: &EphemeralApiTokenClaims,
    now: UnixMillis,
    max_lifetime_millis: i64,
    allowed_clock_skew_millis: i64,
    check_expiry_against_now: bool,
) -> Result<(), LifetimeError> {
    let latest_iat = now
        .0
        .checked_add(allowed_clock_skew_millis)
        .ok_or(LifetimeError::Invariant)?;
    if claims.iat.0 > latest_iat {
        return Err(LifetimeError::Invariant);
    }

    if check_expiry_against_now && claims.exp <= now {
        return Err(LifetimeError::Expired {
            exp: claims.exp,
            now,
        });
    }

    if claims.exp <= claims.iat {
        return Err(LifetimeError::Invariant);
    }

    let lifetime = claims
        .exp
        .0
        .checked_sub(claims.iat.0)
        .ok_or(LifetimeError::Invariant)?;
    if lifetime > max_lifetime_millis {
        return Err(LifetimeError::Invariant);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims() -> EphemeralApiTokenClaims {
        EphemeralApiTokenClaims {
            iss: "philharmonic-api.example".to_owned(),
            iat: UnixMillis(1_924_991_880_000),
            exp: UnixMillis(1_924_992_000_000),
            sub: "user-42".to_owned(),
            tenant: Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap(),
            authority: Uuid::parse_str("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").unwrap(),
            authority_epoch: 7,
            instance: Some(Uuid::parse_str("66666666-7777-4888-8999-aaaaaaaaaaaa").unwrap()),
            permissions: vec!["workflow:instance_execute".to_owned()],
            claims: CanonicalJson::from_bytes(br#"{"role":"viewer","session_id":"demo"}"#).unwrap(),
            kid: "api.test-2026-04-28-deadbeef".to_owned(),
        }
    }

    #[test]
    fn kid_profile_accepts_expected_shapes() {
        for kid in [
            "a",
            "A",
            "0",
            "api.test-2026-04-28-deadbeef",
            "issuer_slug:2026_04_28.rand",
        ] {
            assert_eq!(validate_kid_profile(kid), Ok(()));
        }
    }

    #[test]
    fn kid_profile_rejects_invalid_shapes() {
        let overlong = "a".repeat(KID_MAX_LEN + 1);
        for kid in ["", "has space", "has/slash", "unicode-é", "\n"] {
            assert_eq!(validate_kid_profile(kid), Err(KidProfileError::Invalid));
        }
        assert_eq!(
            validate_kid_profile(&overlong),
            Err(KidProfileError::Invalid)
        );
    }

    #[test]
    fn signing_key_debug_redacts_seed() {
        let seed = Zeroizing::new([0x9d; 32]);
        let key = ApiSigningKey::from_seed(seed, "api.test".to_owned());
        let debug = format!("{key:?}");

        assert!(debug.contains("api.test"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("9d9d9d9d"));
    }

    #[test]
    fn verify_limits_clamp_to_defaults() {
        let loose = VerifyLimits {
            max_token_bytes: MAX_TOKEN_BYTES + 1,
            max_injected_claims_bytes: MAX_INJECTED_CLAIMS_BYTES + 1,
            max_token_lifetime_millis: MAX_TOKEN_LIFETIME_MILLIS + 1,
            allowed_clock_skew_millis: ALLOWED_CLOCK_SKEW_MILLIS + 1,
        }
        .clamped();

        assert_eq!(loose, VerifyLimits::default());

        let strict = VerifyLimits {
            max_token_bytes: 1,
            max_injected_claims_bytes: 2,
            max_token_lifetime_millis: 3,
            allowed_clock_skew_millis: 4,
        }
        .clamped();

        assert_eq!(
            strict,
            VerifyLimits {
                max_token_bytes: 1,
                max_injected_claims_bytes: 2,
                max_token_lifetime_millis: 3,
                allowed_clock_skew_millis: 4,
            }
        );
    }

    #[test]
    fn registry_insert_rejects_duplicate_and_profile_violation() {
        let vk = VerifyingKey::from_bytes(&[0u8; 32]).unwrap();
        let entry = ApiVerifyingKeyEntry {
            vk,
            issuer: "philharmonic-api.example".to_owned(),
            not_before: UnixMillis(1),
            not_after: UnixMillis(2),
        };
        let mut registry = ApiVerifyingKeyRegistry::new();

        registry
            .insert("api.test".to_owned(), entry.clone())
            .expect("first insert should succeed");
        assert_eq!(
            registry.insert("api.test".to_owned(), entry.clone()),
            Err(RegistryInsertError::DuplicateKid {
                kid: "api.test".to_owned()
            })
        );
        assert_eq!(
            registry.insert("bad slash".to_owned(), entry),
            Err(RegistryInsertError::KidProfileViolation {
                kid: "bad slash".to_owned()
            })
        );
    }

    #[test]
    fn claims_cbor_round_trip_is_byte_stable() {
        let claims = sample_claims();
        let encoded = serialize_claims(&claims).expect("sample claims should encode");
        let decoded: EphemeralApiTokenClaims =
            ciborium::de::from_reader(encoded.as_slice()).expect("sample claims should decode");
        let reencoded = serialize_claims(&decoded).expect("decoded claims should encode");

        assert_eq!(decoded, claims);
        assert_eq!(reencoded, encoded);
    }
}
