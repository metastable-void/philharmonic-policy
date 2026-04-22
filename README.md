# philharmonic-policy

Policy and tenancy types for the Philharmonic workflow orchestration
system. Part of the Philharmonic crate family:
https://github.com/metastable-void/philharmonic-workspace

`philharmonic-policy` defines the entity kinds and authorization
logic that every Philharmonic deployment needs: tenants, principals,
per-tenant roles, per-tenant encrypted endpoint configs, long-lived
API tokens, and minting authorities for ephemeral tokens. It depends
only on [`philharmonic-types`][types] (the cornerstone vocabulary
crate) and [`philharmonic-store`][store] (the storage substrate
trait), so it can be consumed by workflow, connector, and API
crates without pulling in a specific database backend.

[types]: https://crates.io/crates/philharmonic-types
[store]: https://crates.io/crates/philharmonic-store

## What this crate provides

**Entity kinds** (seven, each with a stable wire-format `KIND` UUID):

- `Tenant` with a `TenantStatus` discriminant
  (`Active` / `Suspended` / `Retired`).
- `Principal` with a `PrincipalKind` discriminant
  (`User` / `ServiceAccount`).
- `TenantEndpointConfig` — per-tenant connector configuration with
  an SCK-encrypted `encrypted_config` content slot.
- `RoleDefinition` with a JSON `permissions` content slot.
- `RoleMembership` — three-way binding of
  `principal` × `role` × `tenant`.
- `MintingAuthority` — issues ephemeral tokens with scoped claims.
- `AuditEvent` — append-only audit log entries.

Each entity type implements the `philharmonic_types::Entity` trait
with its content / entity / scalar slot schema declared as
`const` arrays — the substrate layer (via `philharmonic-store`)
uses those declarations for validation and storage.

**Permission evaluation** (`evaluate_permission`) walks
`RoleMembership` → `RoleDefinition` → permission-atom membership with
**three-way tenant binding enforced**: the principal's tenant, the
membership's tenant, and the role's tenant must all match the
requested tenant. Mismatches silently skip the role rather than
erroring out, matching the existing defensive-deny pattern for
retired entities. This closes a cross-tenant role-confusion class
surfaced during review — see the workspace's
`docs/codex-reports/` for the original finding and
`docs/notes-to-humans/` for the resolution.

**Permission atoms** are a closed vocabulary of 22 strings (see
`ALL_ATOMS` and the `atom::*` module). `PermissionDocument::deserialize`
rejects unknown atoms at parse time, so stored role documents are
guaranteed to reference only the canonical set.

**SCK (Substrate Confidentiality Key) at-rest encryption**:

- `Sck` wraps a `Zeroizing<[u8; 32]>` key, with `Sck::from_bytes`
  and `Sck::from_file` constructors.
- `sck_encrypt` / `sck_decrypt` use AES-256-GCM with a versioned
  wire format: `[version:u8=0x01] [nonce:12] [ciphertext || tag(16)]`.
  AAD binds `tenant_id || config_uuid || key_version` (40 bytes, big-
  endian) so wire bytes encrypted under one context don't decrypt
  under another.
- Decrypt failures return the opaque `PolicyError::SckDecryptFailed`
  variant regardless of AEAD sub-cause — no timing or error-variant
  side channel between tag-mismatch / AAD-mismatch / wrong-key cases.
- Decrypt results are `Zeroizing<Vec<u8>>`, so callers can't forget
  to scrub plaintext.

**`pht_` long-lived API tokens**:

- `generate_api_token()` returns a
  `(Zeroizing<String>, TokenHash)` pair. The token string is
  `pht_<43-char base64url-no-pad encoding of 32 random OS-RNG bytes>`,
  47 chars total. The `TokenHash` is SHA-256 over the whole token
  string (including the `pht_` prefix).
- `parse_api_token` validates length, prefix, and base64 encoding
  before hashing, and returns the same `TokenHash` shape for
  storage-side comparison.
- Raw token bytes live in `Zeroizing<[u8; 32]>` during generation;
  the token string itself returns as `Zeroizing<String>` so caller
  scrubbing is automatic on drop.

## Cryptographic primitives

`philharmonic-policy` ships only RustCrypto primitives; no hand-
rolled crypto, no `unsafe`. Direct dependencies:

- [`aes-gcm`] 0.10 — AES-256-GCM AEAD.
- [`sha2`] 0.11 — SHA-256 for token storage hashing and content-
  addressing.
- [`base64`] 0.22 — URL-safe no-padding encoding for `pht_` token
  bodies.
- [`rand`] 0.10 — OS random via `rand::rngs::SysRng`.
- [`zeroize`] 1 — memory scrubbing for key material and plaintext.

[`aes-gcm`]: https://crates.io/crates/aes-gcm
[`sha2`]: https://crates.io/crates/sha2
[`base64`]: https://crates.io/crates/base64
[`rand`]: https://crates.io/crates/rand
[`zeroize`]: https://crates.io/crates/zeroize

The construction details (AAD shape, wire-format versioning,
side-channel considerations) are governed by design doc
`11-security-and-cryptography.md` in the workspace repository.
Deviations from that doc require an explicit review round.

## Testing

- Unit tests for entity validation, discriminant round-trips, and
  permission-document parsing.
- A fast in-memory `MockStore` integration tier for end-to-end
  authorization-evaluation scenarios.
- An `#[ignore]`-gated MySQL-testcontainer tier that exercises the
  real storage path (entity round-trips per kind, permission
  evaluation against a real substrate).
- Committed crypto test vectors (three SCK wire-format vectors +
  three `pht_` token vectors) with byte-exact expected outputs,
  cross-checked against Python reference scripts in
  `tests/crypto_vectors/`. If RustCrypto's output ever drifts from
  the committed hex, that's a regression in the Rust crate, not
  in the vectors.
- Routine `cargo +nightly miri test` sweeps against the crypto
  paths catch UB classes `cargo test` doesn't observe.

## Versioning

Pre-1.0. Minor-version bumps (`0.1 → 0.2`) are breaking; patch
bumps (`0.1.1`) are additive. See [`CHANGELOG.md`](CHANGELOG.md).

## License

Dual-licensed under `Apache-2.0 OR MPL-2.0`. Either license is
sufficient; choose whichever fits your project. See
[LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MPL](LICENSE-MPL).

SPDX-License-Identifier: `Apache-2.0 OR MPL-2.0`
