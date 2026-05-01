use crate::PolicyError;

use philharmonic_types::{
    ContentSlot, Entity, EntitySlot, ScalarSlot, ScalarType, SlotPinning, Uuid,
};

use uuid::uuid;

/// Multi-tenant organisation entity.
pub struct Tenant;

impl Entity for Tenant {
    const KIND: Uuid = uuid!("6a79e7a2-ea05-46d8-a578-b24c3b62c860");
    const NAME: &'static str = "tenant";
    const CONTENT_SLOTS: &'static [ContentSlot] = &[
        ContentSlot::new("display_name"),
        ContentSlot::new("settings"),
    ];
    const ENTITY_SLOTS: &'static [EntitySlot] = &[];
    const SCALAR_SLOTS: &'static [ScalarSlot] = &[ScalarSlot::new("status", ScalarType::I64, true)];
}

/// Encrypted endpoint configuration scoped to a tenant.
pub struct TenantEndpointConfig;

impl Entity for TenantEndpointConfig {
    const KIND: Uuid = uuid!("19d1a8f5-6ef0-49b0-adf5-48e1cd3daea9");
    const NAME: &'static str = "tenant_endpoint_config";
    const CONTENT_SLOTS: &'static [ContentSlot] = &[
        ContentSlot::new("display_name"),
        ContentSlot::new("encrypted_config"),
    ];
    const ENTITY_SLOTS: &'static [EntitySlot] =
        &[EntitySlot::of::<Tenant>("tenant", SlotPinning::Pinned)];
    const SCALAR_SLOTS: &'static [ScalarSlot] = &[
        ScalarSlot::new("key_version", ScalarType::I64, false),
        ScalarSlot::new("is_retired", ScalarType::Bool, true),
    ];
}

/// Lifecycle status of a tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum TenantStatus {
    /// Tenant is active and operational.
    Active = 0,
    /// Tenant is temporarily suspended.
    Suspended = 1,
    /// Tenant is permanently retired.
    Retired = 2,
}

impl TenantStatus {
    /// Return the stable i64 discriminant.
    pub const fn as_i64(self) -> i64 {
        self as i64
    }
}

impl TryFrom<i64> for TenantStatus {
    type Error = PolicyError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Active),
            1 => Ok(Self::Suspended),
            2 => Ok(Self::Retired),
            _ => Err(PolicyError::InvalidTenantStatusDiscriminant { value }),
        }
    }
}

/// The `epoch` scalar is reserved for future token-format migration and is
/// intentionally unused in v1.
pub struct Principal;

impl Entity for Principal {
    const KIND: Uuid = uuid!("3676b722-928b-4b3b-9417-659c5c1ea216");
    const NAME: &'static str = "principal";
    const CONTENT_SLOTS: &'static [ContentSlot] = &[
        ContentSlot::new("credential_hash"),
        ContentSlot::new("display_name"),
    ];
    const ENTITY_SLOTS: &'static [EntitySlot] =
        &[EntitySlot::of::<Tenant>("tenant", SlotPinning::Pinned)];
    const SCALAR_SLOTS: &'static [ScalarSlot] = &[
        ScalarSlot::new("kind", ScalarType::I64, true),
        ScalarSlot::new("epoch", ScalarType::I64, true),
        ScalarSlot::new("is_retired", ScalarType::Bool, true),
    ];
}

/// Discriminant for principal types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum PrincipalKind {
    /// Human user principal.
    User = 0,
    /// Non-human service account principal.
    ServiceAccount = 1,
}

impl PrincipalKind {
    /// Return the stable i64 discriminant.
    pub const fn as_i64(self) -> i64 {
        self as i64
    }
}

impl TryFrom<i64> for PrincipalKind {
    type Error = PolicyError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::User),
            1 => Ok(Self::ServiceAccount),
            _ => Err(PolicyError::InvalidPrincipalKindDiscriminant { value }),
        }
    }
}

/// Tenant-scoped role with a set of permission atoms.
pub struct RoleDefinition;

impl Entity for RoleDefinition {
    const KIND: Uuid = uuid!("da0d6fee-d989-44d1-b67e-f18b36a95043");
    const NAME: &'static str = "role_definition";
    const CONTENT_SLOTS: &'static [ContentSlot] = &[
        ContentSlot::new("permissions"),
        ContentSlot::new("display_name"),
    ];
    const ENTITY_SLOTS: &'static [EntitySlot] =
        &[EntitySlot::of::<Tenant>("tenant", SlotPinning::Pinned)];
    const SCALAR_SLOTS: &'static [ScalarSlot] =
        &[ScalarSlot::new("is_retired", ScalarType::Bool, true)];
}

/// Association binding a principal to a role within a tenant.
pub struct RoleMembership;

impl Entity for RoleMembership {
    const KIND: Uuid = uuid!("cae4d1de-8f2f-4598-9ff0-2629819ca3ba");
    const NAME: &'static str = "role_membership";
    const CONTENT_SLOTS: &'static [ContentSlot] = &[];
    const ENTITY_SLOTS: &'static [EntitySlot] = &[
        EntitySlot::of::<Principal>("principal", SlotPinning::Pinned),
        EntitySlot::of::<RoleDefinition>("role", SlotPinning::Pinned),
        EntitySlot::of::<Tenant>("tenant", SlotPinning::Pinned),
    ];
    const SCALAR_SLOTS: &'static [ScalarSlot] =
        &[ScalarSlot::new("is_retired", ScalarType::Bool, true)];
}

/// Authority permitted to mint ephemeral API tokens for a tenant.
pub struct MintingAuthority;

impl Entity for MintingAuthority {
    const KIND: Uuid = uuid!("932c30fc-9b31-488d-badb-62b1c49b7d6d");
    const NAME: &'static str = "minting_authority";
    const CONTENT_SLOTS: &'static [ContentSlot] = &[
        ContentSlot::new("credential_hash"),
        ContentSlot::new("display_name"),
        ContentSlot::new("permission_envelope"),
        ContentSlot::new("minting_constraints"),
    ];
    const ENTITY_SLOTS: &'static [EntitySlot] =
        &[EntitySlot::of::<Tenant>("tenant", SlotPinning::Pinned)];
    const SCALAR_SLOTS: &'static [ScalarSlot] = &[
        ScalarSlot::new("epoch", ScalarType::I64, true),
        ScalarSlot::new("is_retired", ScalarType::Bool, true),
    ];
}

/// Immutable audit-trail event scoped to a tenant.
pub struct AuditEvent;

impl Entity for AuditEvent {
    const KIND: Uuid = uuid!("92474986-4b6b-48c9-b902-8629061ef619");
    const NAME: &'static str = "audit_event";
    const CONTENT_SLOTS: &'static [ContentSlot] = &[ContentSlot::new("event_data")];
    const ENTITY_SLOTS: &'static [EntitySlot] =
        &[EntitySlot::of::<Tenant>("tenant", SlotPinning::Pinned)];
    const SCALAR_SLOTS: &'static [ScalarSlot] = &[
        ScalarSlot::new("event_type", ScalarType::I64, true),
        ScalarSlot::new("timestamp", ScalarType::I64, true),
    ];
}

/// Subdomain names reserved by the platform and unavailable for tenant use.
pub const RESERVED_SUBDOMAIN_NAMES: [&str; 5] = ["admin", "api", "www", "app", "connector"];

/// Validate a candidate subdomain name against length, charset, and reservation rules.
pub fn validate_subdomain_name(name: &str) -> Result<(), PolicyError> {
    if !(2..=63).contains(&name.len()) {
        return Err(PolicyError::InvalidSubdomainName {
            reason: "name length must be between 2 and 63".to_string(),
        });
    }

    if RESERVED_SUBDOMAIN_NAMES.contains(&name) {
        return Err(PolicyError::InvalidSubdomainName {
            reason: "name is reserved".to_string(),
        });
    }

    let bytes = name.as_bytes();

    if !bytes.first().is_some_and(u8::is_ascii_lowercase) {
        return Err(PolicyError::InvalidSubdomainName {
            reason: "first character must be a lowercase letter".to_string(),
        });
    }

    if bytes.last() == Some(&b'-') {
        return Err(PolicyError::InvalidSubdomainName {
            reason: "name cannot end with a hyphen".to_string(),
        });
    }

    let mut previous_hyphen = false;
    for &byte in bytes {
        let is_allowed = byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-';
        if !is_allowed {
            return Err(PolicyError::InvalidSubdomainName {
                reason: "name can only include lowercase letters, digits, and hyphens".to_string(),
            });
        }

        let is_hyphen = byte == b'-';
        if is_hyphen && previous_hyphen {
            return Err(PolicyError::InvalidSubdomainName {
                reason: "name cannot include consecutive hyphens".to_string(),
            });
        }
        previous_hyphen = is_hyphen;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PrincipalKind, TenantStatus, validate_subdomain_name};

    #[test]
    fn validate_subdomain_name_accepts_valid_names() {
        let max = format!("a{}", "b".repeat(62));

        assert!(validate_subdomain_name("acme-corp").is_ok());
        assert!(validate_subdomain_name("a1").is_ok());
        assert!(validate_subdomain_name(&max).is_ok());
    }

    #[test]
    fn validate_subdomain_name_rejects_invalid_names() {
        let cases = [
            "a",
            "1acme",
            "-acme",
            "acme-",
            "acme--corp",
            "admin",
            "UPPER",
            "acme_corp",
        ];

        for case in cases {
            assert!(validate_subdomain_name(case).is_err(), "{case} should fail");
        }
    }

    #[test]
    fn tenant_status_discriminant_round_trip() {
        for (raw, expected) in [
            (0_i64, TenantStatus::Active),
            (1_i64, TenantStatus::Suspended),
            (2_i64, TenantStatus::Retired),
        ] {
            let parsed = TenantStatus::try_from(raw).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_i64(), raw);
        }

        assert!(TenantStatus::try_from(99).is_err());
    }

    #[test]
    fn principal_kind_discriminant_round_trip() {
        for (raw, expected) in [
            (0_i64, PrincipalKind::User),
            (1_i64, PrincipalKind::ServiceAccount),
        ] {
            let parsed = PrincipalKind::try_from(raw).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_i64(), raw);
        }

        assert!(PrincipalKind::try_from(99).is_err());
    }
}
