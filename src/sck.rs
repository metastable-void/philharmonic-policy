use crate::PolicyError;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use philharmonic_types::Uuid;
use rand::TryRng;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

use std::path::Path;

const SCK_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const VERSION_LEN: usize = 1;
const WIRE_VERSION: u8 = 0x01;
const AAD_LEN: usize = 40;
const MIN_WIRE_LEN: usize = VERSION_LEN + NONCE_LEN + TAG_LEN;

pub struct Sck {
    key: Zeroizing<[u8; SCK_KEY_LEN]>,
}

impl Sck {
    pub fn from_bytes(bytes: [u8; SCK_KEY_LEN]) -> Self {
        Self {
            key: Zeroizing::new(bytes),
        }
    }

    pub fn from_file(path: &Path) -> Result<Self, PolicyError> {
        let bytes = Zeroizing::new(std::fs::read(path)?);
        if bytes.len() != SCK_KEY_LEN {
            return Err(PolicyError::SckKeyFileLength {
                expected: SCK_KEY_LEN,
                actual: bytes.len(),
            });
        }

        let mut key = [0_u8; SCK_KEY_LEN];
        key.copy_from_slice(bytes.as_slice());
        Ok(Self::from_bytes(key))
    }
}

pub fn sck_encrypt(
    sck: &Sck,
    plaintext: &[u8],
    tenant_id: Uuid,
    config_uuid: Uuid,
    key_version: i64,
) -> Result<Vec<u8>, PolicyError> {
    let mut nonce = [0_u8; NONCE_LEN];
    fill_random(&mut nonce);
    sck_encrypt_with_nonce(sck, plaintext, &nonce, tenant_id, config_uuid, key_version)
}

pub fn sck_decrypt(
    sck: &Sck,
    wire: &[u8],
    tenant_id: Uuid,
    config_uuid: Uuid,
    key_version: i64,
) -> Result<Zeroizing<Vec<u8>>, PolicyError> {
    if wire.len() < MIN_WIRE_LEN {
        return Err(PolicyError::SckCiphertextTooShort {
            len: wire.len(),
            required: MIN_WIRE_LEN,
        });
    }

    let version = wire[0];
    if version != WIRE_VERSION {
        return Err(PolicyError::SckUnsupportedVersion { byte: version });
    }

    let nonce = &wire[VERSION_LEN..VERSION_LEN + NONCE_LEN];
    let ciphertext_and_tag = &wire[VERSION_LEN + NONCE_LEN..];

    let aad = build_aad(tenant_id, config_uuid, key_version);
    let key = Key::<Aes256Gcm>::from_slice(sck.key.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext_and_tag,
                aad: &aad,
            },
        )
        .map_err(|_| PolicyError::SckDecryptFailed)?;

    Ok(Zeroizing::new(plaintext))
}

pub(crate) fn sck_encrypt_with_nonce(
    sck: &Sck,
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
    tenant_id: Uuid,
    config_uuid: Uuid,
    key_version: i64,
) -> Result<Vec<u8>, PolicyError> {
    let aad = build_aad(tenant_id, config_uuid, key_version);
    let key = Key::<Aes256Gcm>::from_slice(sck.key.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    let ciphertext_and_tag = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| PolicyError::SckDecryptFailed)?;

    let mut wire = Vec::with_capacity(VERSION_LEN + NONCE_LEN + ciphertext_and_tag.len());
    wire.push(WIRE_VERSION);
    wire.extend_from_slice(nonce);
    wire.extend_from_slice(&ciphertext_and_tag);
    Ok(wire)
}

fn build_aad(tenant_id: Uuid, config_uuid: Uuid, key_version: i64) -> [u8; AAD_LEN] {
    let mut aad = [0_u8; AAD_LEN];
    aad[0..16].copy_from_slice(tenant_id.as_bytes());
    aad[16..32].copy_from_slice(config_uuid.as_bytes());
    aad[32..40].copy_from_slice(&key_version.to_be_bytes());
    aad
}

fn fill_random(bytes: &mut [u8]) {
    SysRng
        .try_fill_bytes(bytes)
        .expect("OS RNG failure — system entropy unavailable");
}
