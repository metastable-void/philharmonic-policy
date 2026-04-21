pub use philharmonic_policy::PolicyError;

#[path = "../src/sck.rs"]
#[allow(dead_code)]
mod sck_internal;
#[path = "../src/token.rs"]
#[allow(dead_code)]
mod token_internal;

use hex_literal::hex;

use philharmonic_policy::{Sck, TokenHash, generate_api_token, parse_api_token, sck_decrypt};
use philharmonic_types::Uuid;

const SCK_1: [u8; 32] = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const NONCE_1: [u8; 12] = hex!("101112131415161718191a1b");
const PLAINTEXT_1: [u8; 38] =
    hex!("7b227265616c6d223a226c6c6d222c22696d706c223a2278222c22636f6e666967223a7b7d7d");
const WIRE_1: [u8; 67] = hex!(
    "01101112131415161718191a1b06dcea7328a55791f0576471625b4571be3d3e
     6239f875c9c5d5c004313a32b237cb6d7888db25e1be0219d64b83d1645de6ba
     45571a"
);

const SCK_2: [u8; 32] = hex!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
const NONCE_2: [u8; 12] = hex!("303132333435363738393a3b");
const PLAINTEXT_2: [u8; 28] = hex!("7b22646973706c61795f6e616d65223a22e38386e382b9e38388227d");
const WIRE_2: [u8; 57] = hex!(
    "01303132333435363738393a3b2139141263b0bd4717f60c3c9ab83b272911b5
     ca50617dd5a1df20cbebab062b3c79213ac04003daab844519"
);

const SCK_3: [u8; 32] = hex!("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
const NONCE_3: [u8; 12] = hex!("505152535455565758595a5b");
const PLAINTEXT_3: [u8; 2] = hex!("7b7d");
const WIRE_3: [u8; 31] = hex!("01505152535455565758595a5bed36f3f497b1eae71aaa363947390d6f3a91");

const RAW_1: [u8; 32] = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const RAW_2: [u8; 32] = hex!("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0");
const RAW_3: [u8; 32] = hex!("a55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55a");

const TOKEN_1: &str = "pht_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const TOKEN_2: &str = "pht___79_Pv6-fj39vX08_Lx8O_u7ezr6uno5-bl5OPi4eA";
const TOKEN_3: &str = "pht_pVqlWqVapVqlWqVapVqlWqVapVqlWqVapVqlWqVapVo";

const HASH_1: [u8; 32] = hex!("642b986e2d7c4afd6922e6228a93c46fc9e831d0569a750c5f97aaedd6799a85");
const HASH_2: [u8; 32] = hex!("7004403c0e97e82ff4aef986720abe8146217905df403b23b9c22d32b291d10e");
const HASH_3: [u8; 32] = hex!("c72d9531bdcd158fb10093899d4694b1bb885916dc8c0c16fbd4008d5e174521");

struct SckVector {
    sck: [u8; 32],
    nonce: [u8; 12],
    tenant_id: Uuid,
    config_uuid: Uuid,
    key_version: i64,
    plaintext: &'static [u8],
    wire: &'static [u8],
}

fn sck_vectors() -> [SckVector; 3] {
    [
        SckVector {
            sck: SCK_1,
            nonce: NONCE_1,
            tenant_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            config_uuid: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            key_version: 1,
            plaintext: &PLAINTEXT_1,
            wire: &WIRE_1,
        },
        SckVector {
            sck: SCK_2,
            nonce: NONCE_2,
            tenant_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            config_uuid: Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap(),
            key_version: 7,
            plaintext: &PLAINTEXT_2,
            wire: &WIRE_2,
        },
        SckVector {
            sck: SCK_3,
            nonce: NONCE_3,
            tenant_id: Uuid::parse_str("55555555-5555-5555-5555-555555555555").unwrap(),
            config_uuid: Uuid::parse_str("66666666-6666-6666-6666-666666666666").unwrap(),
            key_version: 42,
            plaintext: &PLAINTEXT_3,
            wire: &WIRE_3,
        },
    ]
}

fn flip_one_bit_in_uuid(uuid: Uuid) -> Uuid {
    let mut bytes = *uuid.as_bytes();
    bytes[0] ^= 0x01;
    Uuid::from_bytes(bytes)
}

#[test]
fn sck_encrypt_with_nonce_matches_all_vectors() {
    for vector in sck_vectors() {
        let sck = sck_internal::Sck::from_bytes(vector.sck);
        let wire = sck_internal::sck_encrypt_with_nonce(
            &sck,
            vector.plaintext,
            &vector.nonce,
            vector.tenant_id,
            vector.config_uuid,
            vector.key_version,
        )
        .unwrap();
        assert_eq!(wire, vector.wire);
    }
}

#[test]
fn sck_decrypt_round_trips_all_vectors() {
    for vector in sck_vectors() {
        let sck = Sck::from_bytes(vector.sck);
        let plaintext = sck_decrypt(
            &sck,
            vector.wire,
            vector.tenant_id,
            vector.config_uuid,
            vector.key_version,
        )
        .unwrap();
        assert_eq!(plaintext.as_slice(), vector.plaintext);
    }
}

#[test]
fn sck_decrypt_rejects_wrong_tenant_id_for_all_vectors() {
    for vector in sck_vectors() {
        let sck = Sck::from_bytes(vector.sck);
        let err = sck_decrypt(
            &sck,
            vector.wire,
            flip_one_bit_in_uuid(vector.tenant_id),
            vector.config_uuid,
            vector.key_version,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::SckDecryptFailed));
    }
}

#[test]
fn sck_decrypt_rejects_wrong_config_uuid_for_all_vectors() {
    for vector in sck_vectors() {
        let sck = Sck::from_bytes(vector.sck);
        let err = sck_decrypt(
            &sck,
            vector.wire,
            vector.tenant_id,
            flip_one_bit_in_uuid(vector.config_uuid),
            vector.key_version,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::SckDecryptFailed));
    }
}

#[test]
fn sck_decrypt_rejects_wrong_key_version_for_all_vectors() {
    for vector in sck_vectors() {
        let sck = Sck::from_bytes(vector.sck);
        let err = sck_decrypt(
            &sck,
            vector.wire,
            vector.tenant_id,
            vector.config_uuid,
            vector.key_version + 1,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::SckDecryptFailed));
    }
}

#[test]
fn sck_decrypt_rejects_flipped_tag_byte_for_all_vectors() {
    for vector in sck_vectors() {
        let sck = Sck::from_bytes(vector.sck);
        let mut tampered = vector.wire.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        let err = sck_decrypt(
            &sck,
            &tampered,
            vector.tenant_id,
            vector.config_uuid,
            vector.key_version,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::SckDecryptFailed));
    }
}

#[test]
fn sck_decrypt_rejects_short_ciphertext() {
    let sck = Sck::from_bytes(SCK_1);
    let short_wire = &WIRE_1[..28];
    let err = sck_decrypt(
        &sck,
        short_wire,
        Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
        1,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        PolicyError::SckCiphertextTooShort {
            len: 28,
            required: 29
        }
    ));
}

#[test]
fn sck_decrypt_rejects_unsupported_wire_version() {
    let sck = Sck::from_bytes(SCK_1);
    let mut unsupported = WIRE_1.to_vec();
    unsupported[0] = 0x02;

    let err = sck_decrypt(
        &sck,
        &unsupported,
        Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
        1,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        PolicyError::SckUnsupportedVersion { byte: 0x02 }
    ));
}

#[test]
fn pht_generate_from_bytes_matches_vectors() {
    for (raw, expected_token, expected_hash) in [
        (RAW_1, TOKEN_1, HASH_1),
        (RAW_2, TOKEN_2, HASH_2),
        (RAW_3, TOKEN_3, HASH_3),
    ] {
        let (token, hash) = token_internal::generate_api_token_from_bytes(raw);
        assert_eq!(token.as_str(), expected_token);
        assert_eq!(hash.0, expected_hash);
    }
}

#[test]
fn pht_parse_matches_vectors() {
    for (token, expected_hash) in [(TOKEN_1, HASH_1), (TOKEN_2, HASH_2), (TOKEN_3, HASH_3)] {
        let parsed = parse_api_token(token).unwrap();
        assert_eq!(parsed, TokenHash(expected_hash));
    }
}

#[test]
fn pht_parse_rejects_wrong_length() {
    let err = parse_api_token("pht_").unwrap_err();
    assert!(matches!(
        err,
        PolicyError::TokenWrongLength {
            expected: 47,
            actual: 4
        }
    ));
}

#[test]
fn pht_parse_rejects_wrong_prefix() {
    let err = parse_api_token("php_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap_err();
    assert!(matches!(err, PolicyError::TokenWrongPrefix));
}

#[test]
fn pht_parse_rejects_invalid_base64() {
    let err = parse_api_token("pht_!!ECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap_err();
    assert!(matches!(err, PolicyError::TokenInvalidBase64));
}

#[test]
fn pht_token_decoded_wrong_length_variant_is_constructible() {
    let err = PolicyError::TokenDecodedWrongLength {
        expected: 32,
        actual: 31,
    };
    assert!(matches!(
        err,
        PolicyError::TokenDecodedWrongLength {
            expected: 32,
            actual: 31
        }
    ));
}

#[test]
fn pht_generate_and_parse_round_trip() {
    let (token, expected_hash) = generate_api_token();
    let parsed = parse_api_token(&token).unwrap();
    assert_eq!(parsed, expected_hash);
}
