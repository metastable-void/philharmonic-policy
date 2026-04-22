use crate::PolicyError;
use crate::entity::{Principal, RoleDefinition, RoleMembership, Tenant};
use crate::permission::parse_permission_document;

use philharmonic_store::{ContentStore, EntityStoreExt, RevisionRow};
use philharmonic_types::{Entity, EntityId, ScalarValue, Uuid};

pub async fn evaluate_permission<S>(
    store: &S,
    principal: EntityId<Principal>,
    tenant: EntityId<Tenant>,
    required_atom: &str,
) -> Result<bool, PolicyError>
where
    S: EntityStoreExt + ContentStore,
{
    let Some(principal_revision) = store
        .get_latest_revision_typed::<Principal>(principal)
        .await?
    else {
        return Err(PolicyError::PrincipalNotFound {
            principal_id: principal.internal().as_uuid(),
        });
    };

    let principal_tenant = entity_attr(&principal_revision, Principal::NAME, "tenant")?;
    if principal_tenant != tenant.internal().as_uuid() {
        return Ok(false);
    }

    if scalar_bool(&principal_revision, Principal::NAME, "is_retired")? {
        return Ok(false);
    }

    let membership_refs = store
        .list_revisions_referencing(principal.internal().as_uuid(), "principal")
        .await?;

    let mut role_ids = Vec::new();
    for reference in membership_refs {
        let Some(entity) = store.get_entity(reference.entity_id).await? else {
            continue;
        };

        if entity.kind != RoleMembership::KIND {
            continue;
        }

        let Some(membership_revision) = store.get_latest_revision(reference.entity_id).await?
        else {
            continue;
        };

        if membership_revision.revision_seq != reference.revision_seq {
            continue;
        }

        if scalar_bool(&membership_revision, RoleMembership::NAME, "is_retired")? {
            continue;
        }

        let membership_tenant = entity_attr(&membership_revision, RoleMembership::NAME, "tenant")?;
        if membership_tenant != tenant.internal().as_uuid() {
            continue;
        }

        let role_id = entity_attr(&membership_revision, RoleMembership::NAME, "role")?;
        role_ids.push(role_id);
    }

    for role_id in role_ids {
        let Some(role_entity) = store.get_entity(role_id).await? else {
            return Err(PolicyError::RoleNotFound { role_id });
        };

        if role_entity.kind != RoleDefinition::KIND {
            return Err(PolicyError::EntityKindMismatch {
                entity_name: RoleDefinition::NAME,
                expected: RoleDefinition::KIND,
                actual: role_entity.kind,
            });
        }

        let Some(role_revision) = store.get_latest_revision(role_id).await? else {
            return Err(PolicyError::RoleNotFound { role_id });
        };

        let role_tenant = entity_attr(&role_revision, RoleDefinition::NAME, "tenant")?;
        if role_tenant != tenant.internal().as_uuid() {
            continue;
        }

        if scalar_bool(&role_revision, RoleDefinition::NAME, "is_retired")? {
            continue;
        }

        let permissions_hash = role_revision
            .content_attrs
            .get("permissions")
            .copied()
            .ok_or(PolicyError::MissingPermissionsSlot { role_id })?;

        let Some(permissions_content) = store.get(permissions_hash).await? else {
            return Err(PolicyError::MissingPermissionsBlob {
                role_id,
                hash: permissions_hash,
            });
        };

        let doc = parse_permission_document(permissions_content.bytes())?;
        if doc.contains(required_atom) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn entity_attr(
    revision: &RevisionRow,
    entity_name: &'static str,
    attribute: &'static str,
) -> Result<Uuid, PolicyError> {
    let value =
        revision
            .entity_attrs
            .get(attribute)
            .ok_or(PolicyError::MissingEntityAttribute {
                entity_name,
                attribute,
            })?;
    Ok(value.target_entity_id)
}

fn scalar_bool(
    revision: &RevisionRow,
    entity_name: &'static str,
    attribute: &'static str,
) -> Result<bool, PolicyError> {
    let value =
        revision
            .scalar_attrs
            .get(attribute)
            .ok_or(PolicyError::MissingScalarAttribute {
                entity_name,
                attribute,
            })?;

    match value {
        ScalarValue::Bool(boolean) => Ok(*boolean),
        ScalarValue::I64(_) => Err(PolicyError::InvalidScalarType {
            entity_name,
            attribute,
            expected: "bool",
            actual: "i64",
        }),
    }
}
