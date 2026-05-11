//! Canonical event-type discriminants for the [`AuditEvent`]
//! entity's `event_type` scalar slot.
//!
//! The `AuditEvent` entity stores `event_type` as an `i64`
//! deployment-defined discriminant. To keep historical rows
//! interpretable across consumers, this module pins one stable
//! numeric value per documented audit-event category in
//! [`docs/design/09-policy-and-tenancy.md` §Audit trail].
//!
//! ## Stability rules
//!
//! - **Numbering is append-only.** Never renumber an existing
//!   constant, even if its event becomes obsolete. Historical
//!   rows reference these numbers.
//! - **Gaps are intentional.** Each category reserves a block
//!   (1-9, 10-19, 20-29, ...) so additions to a category don't
//!   force renumbering anywhere else.
//! - **Unknown values are valid on read.** Consumers may
//!   encounter `event_type` values from later code versions
//!   they don't recognise. Use [`name`] to map known
//!   discriminants to short labels; treat `None` as
//!   "unknown / forward-compatible" rather than an error.
//!
//! [`AuditEvent`]: crate::AuditEvent
//! [`docs/design/09-policy-and-tenancy.md` §Audit trail]: https://github.com/metastable-void/philharmonic-workspace/blob/main/docs/design/09-policy-and-tenancy.md#audit-trail

// Principals (1-9).

/// Principal created.
pub const PRINCIPAL_CREATED: i64 = 1;
/// Principal credential rotated.
pub const PRINCIPAL_CREDENTIAL_ROTATED: i64 = 2;
/// Principal retired.
pub const PRINCIPAL_RETIRED: i64 = 3;

// Roles + memberships (10-19).

/// Role definition created.
pub const ROLE_CREATED: i64 = 10;
/// Role definition modified.
pub const ROLE_MODIFIED: i64 = 11;
/// Role definition retired.
pub const ROLE_RETIRED: i64 = 12;
/// Role membership created.
pub const ROLE_MEMBERSHIP_CREATED: i64 = 13;
/// Role membership removed.
pub const ROLE_MEMBERSHIP_REMOVED: i64 = 14;

// Endpoint configs (20-29).

/// Endpoint config created.
pub const ENDPOINT_CREATED: i64 = 20;
/// Endpoint config rotated (key version bumped, ciphertext
/// rewritten).
pub const ENDPOINT_ROTATED: i64 = 21;
/// Endpoint config retired.
pub const ENDPOINT_RETIRED: i64 = 22;

// Minting authorities (30-39).

/// Minting authority created.
pub const AUTHORITY_CREATED: i64 = 30;
/// Minting authority modified (permission envelope or
/// lifetime updated).
pub const AUTHORITY_MODIFIED: i64 = 31;
/// Minting authority retired.
pub const AUTHORITY_RETIRED: i64 = 32;
/// Minting authority epoch bumped (revokes outstanding
/// tokens signed under the previous epoch).
pub const AUTHORITY_EPOCH_BUMPED: i64 = 33;

// Token minting (40-49).

/// Ephemeral token minted. Payload records subject
/// identifier and minting-authority ID only — **never** the
/// injected claims, per the privacy decision in
/// `docs/design/09-policy-and-tenancy.md` §Audit trail.
pub const TOKEN_MINTED: i64 = 40;

// Tenant lifecycle (50-59).

/// Tenant status changed (e.g. active → suspended).
pub const TENANT_STATUS_CHANGED: i64 = 50;

/// Map a known discriminant to its canonical snake_case
/// label. Returns `None` for unknown values — call sites
/// should treat that as "unknown / forward-compatible event
/// type" rather than an error.
pub fn name(event_type: i64) -> Option<&'static str> {
    Some(match event_type {
        PRINCIPAL_CREATED => "principal_created",
        PRINCIPAL_CREDENTIAL_ROTATED => "principal_credential_rotated",
        PRINCIPAL_RETIRED => "principal_retired",
        ROLE_CREATED => "role_created",
        ROLE_MODIFIED => "role_modified",
        ROLE_RETIRED => "role_retired",
        ROLE_MEMBERSHIP_CREATED => "role_membership_created",
        ROLE_MEMBERSHIP_REMOVED => "role_membership_removed",
        ENDPOINT_CREATED => "endpoint_created",
        ENDPOINT_ROTATED => "endpoint_rotated",
        ENDPOINT_RETIRED => "endpoint_retired",
        AUTHORITY_CREATED => "authority_created",
        AUTHORITY_MODIFIED => "authority_modified",
        AUTHORITY_RETIRED => "authority_retired",
        AUTHORITY_EPOCH_BUMPED => "authority_epoch_bumped",
        TOKEN_MINTED => "token_minted",
        TENANT_STATUS_CHANGED => "tenant_status_changed",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_discriminants_have_canonical_names() {
        let cases = [
            (PRINCIPAL_CREATED, "principal_created"),
            (PRINCIPAL_CREDENTIAL_ROTATED, "principal_credential_rotated"),
            (PRINCIPAL_RETIRED, "principal_retired"),
            (ROLE_CREATED, "role_created"),
            (ROLE_MODIFIED, "role_modified"),
            (ROLE_RETIRED, "role_retired"),
            (ROLE_MEMBERSHIP_CREATED, "role_membership_created"),
            (ROLE_MEMBERSHIP_REMOVED, "role_membership_removed"),
            (ENDPOINT_CREATED, "endpoint_created"),
            (ENDPOINT_ROTATED, "endpoint_rotated"),
            (ENDPOINT_RETIRED, "endpoint_retired"),
            (AUTHORITY_CREATED, "authority_created"),
            (AUTHORITY_MODIFIED, "authority_modified"),
            (AUTHORITY_RETIRED, "authority_retired"),
            (AUTHORITY_EPOCH_BUMPED, "authority_epoch_bumped"),
            (TOKEN_MINTED, "token_minted"),
            (TENANT_STATUS_CHANGED, "tenant_status_changed"),
        ];

        for (value, expected) in cases {
            assert_eq!(name(value), Some(expected));
        }
    }

    #[test]
    fn unknown_discriminants_return_none() {
        assert_eq!(name(0), None);
        assert_eq!(name(9999), None);
        assert_eq!(name(-1), None);
    }

    #[test]
    fn category_blocks_have_no_overlap() {
        let all_values = [
            PRINCIPAL_CREATED,
            PRINCIPAL_CREDENTIAL_ROTATED,
            PRINCIPAL_RETIRED,
            ROLE_CREATED,
            ROLE_MODIFIED,
            ROLE_RETIRED,
            ROLE_MEMBERSHIP_CREATED,
            ROLE_MEMBERSHIP_REMOVED,
            ENDPOINT_CREATED,
            ENDPOINT_ROTATED,
            ENDPOINT_RETIRED,
            AUTHORITY_CREATED,
            AUTHORITY_MODIFIED,
            AUTHORITY_RETIRED,
            AUTHORITY_EPOCH_BUMPED,
            TOKEN_MINTED,
            TENANT_STATUS_CHANGED,
        ];

        for (i, &left) in all_values.iter().enumerate() {
            for &right in &all_values[i + 1..] {
                assert_ne!(left, right, "duplicate discriminant {left}");
            }
        }
    }
}
