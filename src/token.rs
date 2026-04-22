use crate::PolicyError;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const TOKEN_PREFIX: &str = "pht_";
pub const TOKEN_BYTES: usize = 32;
pub const TOKEN_ENCODED_LEN: usize = 43;
pub const TOKEN_FULL_LEN: usize = 47;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenHash(pub [u8; 32]);

pub fn generate_api_token() -> (Zeroizing<String>, TokenHash) {
    let mut raw = Zeroizing::new([0_u8; TOKEN_BYTES]);
    fill_random(raw.as_mut_slice());
    generate_api_token_from_bytes(&raw)
}

pub fn parse_api_token(s: &str) -> Result<TokenHash, PolicyError> {
    if s.len() != TOKEN_FULL_LEN {
        return Err(PolicyError::TokenWrongLength {
            expected: TOKEN_FULL_LEN,
            actual: s.len(),
        });
    }

    if !s.starts_with(TOKEN_PREFIX) {
        return Err(PolicyError::TokenWrongPrefix);
    }

    let encoded = &s[TOKEN_PREFIX.len()..];
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| PolicyError::TokenInvalidBase64)?;
    if decoded.len() != TOKEN_BYTES {
        return Err(PolicyError::TokenDecodedWrongLength {
            expected: TOKEN_BYTES,
            actual: decoded.len(),
        });
    }

    Ok(TokenHash(hash_token(s)))
}

pub(crate) fn generate_api_token_from_bytes(raw: &[u8; 32]) -> (Zeroizing<String>, TokenHash) {
    let encoded = URL_SAFE_NO_PAD.encode(raw);
    debug_assert_eq!(encoded.len(), TOKEN_ENCODED_LEN);

    let token = Zeroizing::new(format!("{TOKEN_PREFIX}{encoded}"));
    debug_assert_eq!(token.len(), TOKEN_FULL_LEN);

    let hash = hash_token(&token);
    (token, TokenHash(hash))
}

fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn fill_random(bytes: &mut [u8]) {
    SysRng
        .try_fill_bytes(bytes)
        .expect("OS RNG failure — system entropy unavailable");
}
