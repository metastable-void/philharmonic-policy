# Changelog

All notable changes to this crate are documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1]

- Added doc comments across entity types, error variants, permission
  atoms, SCK functions, and token types.

## [0.2.0]

- Added ephemeral API token primitives in `api_token`: COSE_Sign1
  minting and fourteen-step verification, an API signing-key wrapper
  with redacted `Debug`, a verifying-key registry, strict `kid` and
  COSE-header profiles, lifetime and injected-claims size enforcement,
  and `CanonicalJson` injected claims encoded as signed CBOR text.
  Gate-1 + Gate-2 crypto review passed.

## [0.1.0]

Initial functional release. Implements Phase 2 of the Philharmonic
roadmap (§"philharmonic-policy"): seven entity kinds, permission
evaluation with full tenant-boundary enforcement, SCK at-rest
encryption primitives, and the `pht_` long-lived API token format.

Entity kinds (content / entity / scalar slots per
`docs/design/09-policy-and-tenancy.md`):

- Added `Tenant` with a `TenantStatus` discriminant enum
  (`Active` / `Suspended` / `Retired`, `TryFrom<i64>`).
- Added `TenantEndpointConfig` with `display_name` +
  `encrypted_config` content slots, `key_version` +
  `is_retired` scalar slots, and a pinned `tenant` entity slot.
- Added `Principal` with a `PrincipalKind` discriminant enum
  (`User` / `ServiceAccount`, `TryFrom<i64>`).
- Added `RoleDefinition` (content: `permissions`,
  `display_name`; pinned `tenant`).
- Added `RoleMembership` with three pinned entity slots
  (`principal`, `role`, `tenant`).
- Added `MintingAuthority`.
- Added `AuditEvent`.
- Added `validate_subdomain_name` and
  `RESERVED_SUBDOMAIN_NAMES` (reserves `admin`, `api`, `www`,
  `app`, `connector`).

Authorization evaluation:

- Added `evaluate_permission(store, principal, tenant, atom)`
  walking `RoleMembership` → `RoleDefinition` → permission
  atom membership.
- Enforces three-way tenant binding: principal's tenant,
  membership's tenant, and role's tenant must all match the
  requested tenant. Mismatches silently skip the role rather
  than erroring, matching the defensive-deny pattern for
  retired entities.
- Added `PermissionDocument` with parse-time validation
  against the canonical `ALL_ATOMS` list; unknown atoms fail
  deserialization with `PolicyError::UnknownPermissionAtom`.
- Added the `atom::*` module and `ALL_ATOMS` const with the
  v1 vocabulary of 22 permission atoms.

Cryptographic primitives (Yuka's Gate-2 approved):

- Added `Sck` (Substrate Confidentiality Key) wrapping
  `Zeroizing<[u8; 32]>`, with `Sck::from_bytes` and
  `Sck::from_file` constructors.
- Added `sck_encrypt` / `sck_decrypt` using AES-256-GCM.
  Wire format: `[version:u8=0x01] [nonce:12]
  [ciphertext||tag(16)]`. AAD binds
  `tenant_id || config_uuid || key_version` (40 bytes, big-
  endian). Decrypt failures return the opaque
  `SckDecryptFailed` variant regardless of AEAD sub-cause
  (side-channel clean).
- Added `pht_` long-lived API token format:
  `pht_<43-char base64url-no-pad encoding of 32 random bytes>`,
  47 chars total. `generate_api_token` returns the token as
  `Zeroizing<String>` plus a `TokenHash([u8; 32])` storage
  hash (SHA-256 of the full token string including prefix).
  `parse_api_token` validates length, prefix, and base64
  encoding before hashing.
- Zeroize discipline: SCK key material in `Zeroizing<[u8;
  32]>`, decrypt output in `Zeroizing<Vec<u8>>`, raw token
  bytes wrapped at declaration, token string returned as
  `Zeroizing<String>`.

Dependencies (from the Gate-1 approval as amended): `aes-gcm
0.10`, `sha2 0.11`, `base64 0.22`, `rand 0.10`, `zeroize 1`.
No `unsafe`, no `anyhow`, no `println!`/`eprintln!`/`tracing`
in library code.

Test discipline:

- Three-tier test pattern: fast unit tests (no
  `#[ignore]`), in-memory mock-store integration tests, and
  MySQL-testcontainer integration tests gated with
  `#[ignore]`.
- Added 3 SCK and 3 `pht_` crypto test vectors with
  byte-for-byte expected values committed as hex literals in
  `tests/crypto_vectors.rs`. Python reference generators
  (`gen_sck.py`, `gen_pht.py`) committed under
  `tests/crypto_vectors/` for audit-reproducibility against
  pyca `cryptography`.
- Miri (`cargo +nightly miri test`) clean across the crypto
  vector suite and the mock-store integration tests.

## [0.0.0]

In-git placeholder version used during Phase 0–2 scaffolding.
Never published to crates.io; `0.1.0` is the first release on
the index.
