use coset::{
    CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, Label,
    RegisteredLabelWithPrivate, iana,
};
use ed25519_dalek::{Signer, SigningKey};
use philharmonic_policy::{
    ALLOWED_CLOCK_SKEW_MILLIS, ApiSigningKey, ApiTokenVerifyError, ApiVerifyingKeyEntry,
    ApiVerifyingKeyRegistry, EphemeralApiTokenClaims, KID_MAX_LEN, MAX_INJECTED_CLAIMS_BYTES,
    MAX_TOKEN_BYTES, MAX_TOKEN_LIFETIME_MILLIS, mint_ephemeral_api_token,
    verify_ephemeral_api_token,
};
use philharmonic_types::{CanonicalJson, UnixMillis, Uuid};
use proptest::prelude::*;
use zeroize::Zeroizing;

const CLAIMS_WITH_INSTANCE_HEX: &str =
    include_str!("vectors/api_token/claims_with_instance.cbor.hex");
const CLAIMS_NO_INSTANCE_HEX: &str = include_str!("vectors/api_token/claims_no_instance.cbor.hex");
const SIGNED_WITH_INSTANCE_HEX: &str = include_str!("vectors/api_token/signed_with_instance.hex");
const SIGNED_NO_INSTANCE_HEX: &str = include_str!("vectors/api_token/signed_no_instance.hex");

const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const PUBLIC: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const ISSUER: &str = "philharmonic-api.example";
const KID: &str = "api.test-2026-04-28-deadbeef";
const NOW: UnixMillis = UnixMillis(1_924_991_880_000);
const EXP: UnixMillis = UnixMillis(1_924_992_000_000);

fn signing_key() -> ApiSigningKey {
    ApiSigningKey::from_seed(Zeroizing::new(SEED), KID.to_owned())
}

fn dalek_signing_key() -> SigningKey {
    SigningKey::from_bytes(&SEED)
}

fn registry_for(
    kid: &str,
    issuer: &str,
    not_before: UnixMillis,
    not_after: UnixMillis,
) -> ApiVerifyingKeyRegistry {
    let mut registry = ApiVerifyingKeyRegistry::new();
    registry
        .insert(
            kid.to_owned(),
            ApiVerifyingKeyEntry {
                vk: ed25519_dalek::VerifyingKey::from_bytes(&PUBLIC)
                    .expect("public key vector must decode"),
                issuer: issuer.to_owned(),
                not_before,
                not_after,
            },
        )
        .expect("registry fixture should insert");
    registry
}

fn valid_registry() -> ApiVerifyingKeyRegistry {
    registry_for(
        KID,
        ISSUER,
        UnixMillis(1_900_000_000_000),
        UnixMillis(1_950_000_000_000),
    )
}

fn out_of_window_registry() -> ApiVerifyingKeyRegistry {
    registry_for(
        KID,
        ISSUER,
        UnixMillis(1_700_000_000_000),
        UnixMillis(1_800_000_000_000),
    )
}

fn tenant_uuid() -> Uuid {
    Uuid::parse_str("11111111-2222-4333-8444-555555555555").expect("test UUID must be valid")
}

fn authority_uuid() -> Uuid {
    Uuid::parse_str("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").expect("test UUID must be valid")
}

fn instance_uuid() -> Uuid {
    Uuid::parse_str("66666666-7777-4888-8999-aaaaaaaaaaaa").expect("test UUID must be valid")
}

fn claims_with_instance() -> EphemeralApiTokenClaims {
    EphemeralApiTokenClaims {
        iss: ISSUER.to_owned(),
        iat: NOW,
        exp: EXP,
        sub: "user-42".to_owned(),
        tenant: tenant_uuid(),
        authority: authority_uuid(),
        authority_epoch: 7,
        instance: Some(instance_uuid()),
        permissions: vec!["workflow:instance_execute".to_owned()],
        claims: CanonicalJson::from_bytes(br#"{"session_id":"demo-session-001","role":"viewer"}"#)
            .expect("fixture claims should canonicalize"),
        kid: KID.to_owned(),
    }
}

fn claims_no_instance() -> EphemeralApiTokenClaims {
    EphemeralApiTokenClaims {
        instance: None,
        permissions: vec!["workflow:list".to_owned(), "workflow:read".to_owned()],
        claims: CanonicalJson::from_bytes(br#"{}"#).expect("fixture claims should canonicalize"),
        ..claims_with_instance()
    }
}

fn serialize_claims(claims: &EphemeralApiTokenClaims) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(claims, &mut out).expect("claims fixture must serialize");
    out
}

fn sign_payload(payload: Vec<u8>, protected_kid: &str, alg: iana::Algorithm) -> Vec<u8> {
    let protected = HeaderBuilder::new()
        .algorithm(alg)
        .key_id(protected_kid.as_bytes().to_vec())
        .build();
    sign_payload_with_protected(payload, protected)
}

fn sign_payload_with_protected(payload: Vec<u8>, protected: coset::Header) -> Vec<u8> {
    CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(b"", |sig_structure| {
            dalek_signing_key().sign(sig_structure).to_bytes().to_vec()
        })
        .build()
        .to_vec()
        .expect("COSE_Sign1 fixture must serialize")
}

fn mint_bytes(claims: &EphemeralApiTokenClaims) -> Vec<u8> {
    mint_ephemeral_api_token(&signing_key(), claims, NOW)
        .expect("fixture token should mint")
        .to_bytes()
        .expect("fixture token should serialize")
}

fn positive_with_instance() -> Vec<u8> {
    mint_bytes(&claims_with_instance())
}

fn positive_no_instance() -> Vec<u8> {
    mint_bytes(&claims_no_instance())
}

fn mutate_positive(mutator: impl FnOnce(&mut CoseSign1)) -> Vec<u8> {
    let mut sign1 =
        CoseSign1::from_slice(&positive_with_instance()).expect("positive token should parse");
    sign1.protected.original_data = None;
    mutator(&mut sign1);
    sign1
        .to_vec()
        .expect("mutated COSE_Sign1 fixture should serialize")
}

fn mutate_claim_payload(mutator: impl FnOnce(&mut ciborium::value::Value)) -> Vec<u8> {
    let payload = serialize_claims(&claims_with_instance());
    let mut value: ciborium::value::Value =
        ciborium::de::from_reader(payload.as_slice()).expect("claims fixture should decode");
    mutator(&mut value);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out).expect("mutated claims should serialize");
    out
}

fn set_claims_text(value: &mut ciborium::value::Value, claims_text: &str) {
    let map = value
        .as_map_mut()
        .expect("claims fixture should encode as a map");
    for (key, value) in map {
        if matches!(key.as_text(), Some("claims")) {
            *value = ciborium::value::Value::Text(claims_text.to_owned());
            return;
        }
    }
    panic!("claims field should be present in fixture");
}

fn set_claim_string(value: &mut ciborium::value::Value, field: &str, replacement: &str) {
    let map = value
        .as_map_mut()
        .expect("claims fixture should encode as a map");
    for (key, value) in map {
        if matches!(key.as_text(), Some(name) if name == field) {
            *value = ciborium::value::Value::Text(replacement.to_owned());
            return;
        }
    }
    panic!("{field} field should be present in fixture");
}

fn set_claim_i64(value: &mut ciborium::value::Value, field: &str, replacement: i64) {
    let map = value
        .as_map_mut()
        .expect("claims fixture should encode as a map");
    for (key, value) in map {
        if matches!(key.as_text(), Some(name) if name == field) {
            *value = ciborium::value::Value::Integer(replacement.into());
            return;
        }
    }
    panic!("{field} field should be present in fixture");
}

fn set_claim_u64(value: &mut ciborium::value::Value, field: &str, replacement: u64) {
    let map = value
        .as_map_mut()
        .expect("claims fixture should encode as a map");
    for (key, value) in map {
        if matches!(key.as_text(), Some(name) if name == field) {
            *value = ciborium::value::Value::Integer(replacement.into());
            return;
        }
    }
    panic!("{field} field should be present in fixture");
}

fn negative_vectors() -> Vec<(&'static str, Vec<u8>, ApiTokenVerifyError)> {
    let mut tampered_sig = positive_with_instance();
    let sig_last = tampered_sig
        .len()
        .checked_sub(1)
        .expect("positive token should be nonempty");
    tampered_sig[sig_last] ^= 0x01;

    let tampered_payload = mutate_positive(|sign1| {
        let payload = sign1
            .payload
            .as_mut()
            .expect("positive token should have payload");
        let first = payload
            .first_mut()
            .expect("positive token payload should be nonempty");
        *first ^= 0x01;
    });

    let kid_too_long = "a".repeat(KID_MAX_LEN + 1);
    let oversize_claims = format!(r#"{{"blob":"{}"}}"#, "a".repeat(MAX_INJECTED_CLAIMS_BYTES));

    vec![
        (
            "api_token_too_large.hex",
            vec![0_u8; MAX_TOKEN_BYTES + 1],
            ApiTokenVerifyError::TokenTooLarge {
                limit: MAX_TOKEN_BYTES,
                actual: MAX_TOKEN_BYTES + 1,
            },
        ),
        (
            "api_unprotected_nonempty.hex",
            mutate_positive(|sign1| {
                sign1.unprotected.key_id = b"decoy".to_vec();
            }),
            ApiTokenVerifyError::HeaderProfileViolation,
        ),
        (
            "api_protected_unknown_label.hex",
            mutate_positive(|sign1| {
                sign1.protected.header.rest.push((
                    Label::Text("unknown".to_owned()),
                    ciborium::value::Value::Bytes(vec![1]),
                ));
            }),
            ApiTokenVerifyError::HeaderProfileViolation,
        ),
        (
            "api_protected_crit.hex",
            sign_payload_with_protected(
                serialize_claims(&claims_with_instance()),
                HeaderBuilder::new()
                    .algorithm(iana::Algorithm::EdDSA)
                    .key_id(KID.as_bytes().to_vec())
                    .add_critical_label(RegisteredLabelWithPrivate::Text("critical".to_owned()))
                    .build(),
            ),
            ApiTokenVerifyError::HeaderProfileViolation,
        ),
        (
            "api_bad_alg.hex",
            sign_payload(
                serialize_claims(&claims_with_instance()),
                KID,
                iana::Algorithm::ES256,
            ),
            ApiTokenVerifyError::AlgorithmNotAllowed,
        ),
        (
            "api_kid_too_long.hex",
            sign_payload(
                serialize_claims(&claims_with_instance()),
                &kid_too_long,
                iana::Algorithm::EdDSA,
            ),
            ApiTokenVerifyError::KidProfileViolation,
        ),
        (
            "api_kid_invalid_chars.hex",
            sign_payload(
                serialize_claims(&claims_with_instance()),
                "api/test",
                iana::Algorithm::EdDSA,
            ),
            ApiTokenVerifyError::KidProfileViolation,
        ),
        (
            "api_unknown_kid.hex",
            sign_payload(
                mutate_claim_payload(|value| set_claim_string(value, "kid", "api.unknown")),
                "api.unknown",
                iana::Algorithm::EdDSA,
            ),
            ApiTokenVerifyError::UnknownKid {
                kid: "api.unknown".to_owned(),
            },
        ),
        (
            "api_key_out_of_window.hex",
            positive_with_instance(),
            ApiTokenVerifyError::KeyOutOfWindow {
                now: NOW,
                not_before: UnixMillis(1_700_000_000_000),
                not_after: UnixMillis(1_800_000_000_000),
            },
        ),
        (
            "api_tampered_sig.hex",
            tampered_sig,
            ApiTokenVerifyError::BadSignature,
        ),
        (
            "api_tampered_payload.hex",
            tampered_payload,
            ApiTokenVerifyError::BadSignature,
        ),
        (
            "api_claims_not_canonical.hex",
            sign_payload(
                mutate_claim_payload(|value| set_claims_text(value, r#"{"z":1,"a":2}"#)),
                KID,
                iana::Algorithm::EdDSA,
            ),
            ApiTokenVerifyError::ClaimsNotCanonical,
        ),
        (
            "api_issuer_mismatch.hex",
            sign_payload(
                mutate_claim_payload(|value| {
                    set_claim_string(value, "iss", "philharmonic-api.attacker")
                }),
                KID,
                iana::Algorithm::EdDSA,
            ),
            ApiTokenVerifyError::IssuerMismatch {
                expected: ISSUER.to_owned(),
                found: "philharmonic-api.attacker".to_owned(),
            },
        ),
        (
            "api_kid_inconsistent.hex",
            sign_payload(
                mutate_claim_payload(|value| set_claim_string(value, "kid", "api.other")),
                KID,
                iana::Algorithm::EdDSA,
            ),
            ApiTokenVerifyError::KidInconsistent {
                protected: KID.to_owned(),
                claims: "api.other".to_owned(),
            },
        ),
        (
            "api_iat_in_future.hex",
            sign_payload(
                mutate_claim_payload(|value| {
                    set_claim_i64(value, "iat", NOW.0 + ALLOWED_CLOCK_SKEW_MILLIS + 1)
                }),
                KID,
                iana::Algorithm::EdDSA,
            ),
            ApiTokenVerifyError::LifetimeInvariantViolation,
        ),
        (
            "api_exp_before_iat.hex",
            sign_payload(
                mutate_claim_payload(|value| {
                    set_claim_i64(value, "iat", NOW.0 + 1_000);
                    set_claim_i64(value, "exp", NOW.0 + 500);
                }),
                KID,
                iana::Algorithm::EdDSA,
            ),
            ApiTokenVerifyError::LifetimeInvariantViolation,
        ),
        (
            "api_lifetime_too_long.hex",
            sign_payload(
                mutate_claim_payload(|value| {
                    set_claim_i64(value, "iat", NOW.0);
                    set_claim_i64(value, "exp", NOW.0 + MAX_TOKEN_LIFETIME_MILLIS + 1);
                }),
                KID,
                iana::Algorithm::EdDSA,
            ),
            ApiTokenVerifyError::LifetimeInvariantViolation,
        ),
        (
            "api_expired.hex",
            sign_payload(
                mutate_claim_payload(|value| {
                    set_claim_i64(value, "iat", 0);
                    set_claim_i64(value, "exp", 1);
                }),
                KID,
                iana::Algorithm::EdDSA,
            ),
            ApiTokenVerifyError::Expired {
                exp: UnixMillis(1),
                now: NOW,
            },
        ),
        (
            "api_claims_too_large.hex",
            sign_payload(
                mutate_claim_payload(|value| {
                    set_claim_i64(value, "iat", NOW.0);
                    set_claim_i64(value, "exp", NOW.0 + 1);
                    set_claim_u64(value, "authority_epoch", 7);
                    set_claims_text(value, &oversize_claims);
                }),
                KID,
                iana::Algorithm::EdDSA,
            ),
            ApiTokenVerifyError::ClaimsTooLarge {
                limit: MAX_INJECTED_CLAIMS_BYTES,
                actual: oversize_claims.len(),
            },
        ),
    ]
}

fn registry_for_negative(name: &str) -> ApiVerifyingKeyRegistry {
    if name == "api_key_out_of_window.hex" {
        out_of_window_registry()
    } else {
        valid_registry()
    }
}

fn decode_hex(input: &str) -> Vec<u8> {
    let trimmed = input.trim();
    assert_eq!(trimmed.len() % 2, 0, "hex length must be even");
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let high = decode_hex_nibble(bytes[index]);
        let low = decode_hex_nibble(bytes[index + 1]);
        out.push((high << 4) | low);
        index += 2;
    }
    out
}

fn decode_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        other => panic!("invalid hex byte: {other}"),
    }
}

fn vector_bytes(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/vectors/api_token/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path)
        .map(|contents| decode_hex(&contents))
        .unwrap_or_else(|err| panic!("vector file {name} must be readable: {err}"))
}

#[test]
fn positive_with_instance_known_answer_mints_and_verifies() {
    let claims = claims_with_instance();
    let expected_claims = decode_hex(CLAIMS_WITH_INSTANCE_HEX);
    let expected_token = decode_hex(SIGNED_WITH_INSTANCE_HEX);

    assert_eq!(serialize_claims(&claims), expected_claims);
    assert_eq!(mint_bytes(&claims), expected_token);

    let verified = verify_ephemeral_api_token(&expected_token, &valid_registry(), NOW)
        .expect("positive vector should verify");
    assert_eq!(verified, claims);
}

#[test]
fn positive_no_instance_known_answer_mints_and_verifies() {
    let claims = claims_no_instance();
    let expected_claims = decode_hex(CLAIMS_NO_INSTANCE_HEX);
    let expected_token = decode_hex(SIGNED_NO_INSTANCE_HEX);

    assert_eq!(serialize_claims(&claims), expected_claims);
    assert_eq!(positive_no_instance(), expected_token);

    let verified = verify_ephemeral_api_token(&expected_token, &valid_registry(), NOW)
        .expect("positive vector should verify");
    assert_eq!(verified, claims);
}

#[test]
fn negative_vectors_match_generated_bytes_and_expected_errors() {
    let vectors = negative_vectors();
    assert_eq!(vectors.len(), 19);

    for (name, generated_bytes, expected_error) in vectors {
        let fixture_bytes = vector_bytes(name);
        assert_eq!(fixture_bytes, generated_bytes, "{name} fixture drifted");

        let err = verify_ephemeral_api_token(&fixture_bytes, &registry_for_negative(name), NOW)
            .expect_err("negative vector should reject");
        assert_eq!(err, expected_error, "{name} produced wrong error");
    }
}

#[test]
fn mint_serialize_verify_round_trips_claims() {
    let claims = EphemeralApiTokenClaims {
        sub: "round-trip-subject".to_owned(),
        permissions: vec![
            "workflow:instance_execute".to_owned(),
            "workflow:read".to_owned(),
        ],
        claims: CanonicalJson::from_bytes(br#"{"nested":{"a":1,"z":2},"roles":["viewer"]}"#)
            .expect("fixture claims should canonicalize"),
        ..claims_with_instance()
    };

    let token = mint_ephemeral_api_token(&signing_key(), &claims, NOW)
        .expect("round-trip token should mint");
    let bytes = token.to_bytes().expect("round-trip token should serialize");
    let verified =
        verify_ephemeral_api_token(&bytes, &valid_registry(), NOW).expect("token should verify");

    assert_eq!(verified, claims);
}

fn arb_claims() -> impl Strategy<Value = EphemeralApiTokenClaims> {
    (
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        prop::option::of(any::<[u8; 16]>()),
        "[a-zA-Z0-9._:-]{1,24}",
        prop::collection::vec("[a-z]{1,12}:[a-z_]{1,16}", 0..5),
        prop::collection::btree_map("[a-z]{1,8}", "[a-zA-Z0-9 _.-]{0,24}", 0..5),
        0_u64..32,
        1_i64..1_000_000,
    )
        .prop_map(
            |(
                tenant,
                authority,
                instance,
                subject,
                permissions,
                injected_claims,
                authority_epoch,
                duration,
            )| EphemeralApiTokenClaims {
                iss: ISSUER.to_owned(),
                iat: NOW,
                exp: UnixMillis(NOW.0 + duration),
                sub: subject,
                tenant: Uuid::from_bytes(tenant),
                authority: Uuid::from_bytes(authority),
                authority_epoch,
                instance: instance.map(Uuid::from_bytes),
                permissions,
                claims: CanonicalJson::from_serializable(&injected_claims)
                    .expect("generated JSON map should canonicalize"),
                kid: KID.to_owned(),
            },
        )
}

proptest! {
    #[test]
    fn proptest_mint_verify_round_trip(claims in arb_claims()) {
        let token = mint_ephemeral_api_token(&signing_key(), &claims, NOW)
            .expect("generated token should mint");
        let bytes = token.to_bytes().expect("generated token should serialize");
        let verified = verify_ephemeral_api_token(&bytes, &valid_registry(), NOW)
            .expect("generated token should verify");

        prop_assert_eq!(verified, claims);
    }

    #[test]
    fn proptest_noncanonical_injected_claims_reject(z in 0_i64..10_000, a in 0_i64..10_000) {
        let text = format!(r#"{{"z":{z},"a":{a}}}"#);
        let bytes = sign_payload(
            mutate_claim_payload(|value| set_claims_text(value, &text)),
            KID,
            iana::Algorithm::EdDSA,
        );

        let err = verify_ephemeral_api_token(&bytes, &valid_registry(), NOW)
            .expect_err("non-canonical injected claims should reject");
        prop_assert_eq!(err, ApiTokenVerifyError::ClaimsNotCanonical);
    }
}
