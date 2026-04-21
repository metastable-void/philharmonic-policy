mod common;

use common::mock::MockStore;

use philharmonic_policy::{
    PermissionDocument, PolicyError, Principal, PrincipalKind, RoleDefinition, RoleMembership,
    Tenant, TenantStatus, atom, evaluate_permission,
};

use philharmonic_store::{ContentStore, EntityRefValue, EntityStoreExt, RevisionInput};
use philharmonic_types::{ContentValue, Entity, EntityId, Identity, ScalarValue, Sha256, Uuid};

fn fixed_identity(seed: u64) -> Identity {
    let internal =
        Uuid::parse_str(&format!("00000000-0000-7000-8000-{seed:012x}")).expect("valid UUIDv7");
    let public =
        Uuid::parse_str(&format!("00000000-0000-4000-8000-{seed:012x}")).expect("valid UUIDv4");
    Identity { internal, public }
}

fn fixed_id<T: Entity>(seed: u64) -> EntityId<T> {
    fixed_identity(seed).typed::<T>().expect("typed identity")
}

async fn put_content(store: &MockStore, bytes: &[u8]) -> Sha256 {
    let value = ContentValue::new(bytes.to_vec());
    let hash = value.digest();
    store.put(&value).await.unwrap();
    hash
}

async fn seed_tenant(store: &MockStore, tenant_id: EntityId<Tenant>, status: TenantStatus) {
    let display_name_hash = put_content(store, br#"{"display_name":"tenant"}"#).await;
    let settings_hash = put_content(store, br#"{"settings":{}}"#).await;

    store
        .create_entity_typed::<Tenant>(tenant_id)
        .await
        .unwrap();
    let revision = RevisionInput::new()
        .with_content("display_name", display_name_hash)
        .with_content("settings", settings_hash)
        .with_scalar("status", ScalarValue::I64(status.as_i64()));
    store
        .append_revision_typed::<Tenant>(tenant_id, 0, &revision)
        .await
        .unwrap();
}

async fn seed_principal(
    store: &MockStore,
    principal_id: EntityId<Principal>,
    tenant_id: EntityId<Tenant>,
    is_retired: bool,
) {
    let credential_hash =
        put_content(store, br#"{"credential_hash":"not-implemented-in-wave-1"}"#).await;
    let display_name_hash = put_content(store, br#"{"display_name":"principal"}"#).await;

    store
        .create_entity_typed::<Principal>(principal_id)
        .await
        .unwrap();
    let revision = RevisionInput::new()
        .with_content("credential_hash", credential_hash)
        .with_content("display_name", display_name_hash)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant_id.internal().as_uuid(), 0),
        )
        .with_scalar("kind", ScalarValue::I64(PrincipalKind::User.as_i64()))
        .with_scalar("epoch", ScalarValue::I64(0))
        .with_scalar("is_retired", ScalarValue::Bool(is_retired));
    store
        .append_revision_typed::<Principal>(principal_id, 0, &revision)
        .await
        .unwrap();
}

async fn seed_role_definition(
    store: &MockStore,
    role_id: EntityId<RoleDefinition>,
    tenant_id: EntityId<Tenant>,
    permissions_json: &[u8],
    is_retired: bool,
) {
    let permissions_hash = put_content(store, permissions_json).await;
    seed_role_definition_with_hash(
        store,
        role_id,
        tenant_id,
        permissions_hash,
        is_retired,
        br#"{"display_name":"role"}"#,
    )
    .await;
}

async fn seed_role_definition_with_hash(
    store: &MockStore,
    role_id: EntityId<RoleDefinition>,
    tenant_id: EntityId<Tenant>,
    permissions_hash: Sha256,
    is_retired: bool,
    display_name_json: &[u8],
) {
    let display_name_hash = put_content(store, display_name_json).await;

    store
        .create_entity_typed::<RoleDefinition>(role_id)
        .await
        .unwrap();
    let revision = RevisionInput::new()
        .with_content("permissions", permissions_hash)
        .with_content("display_name", display_name_hash)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant_id.internal().as_uuid(), 0),
        )
        .with_scalar("is_retired", ScalarValue::Bool(is_retired));
    store
        .append_revision_typed::<RoleDefinition>(role_id, 0, &revision)
        .await
        .unwrap();
}

async fn seed_role_membership(
    store: &MockStore,
    membership_id: EntityId<RoleMembership>,
    principal_id: EntityId<Principal>,
    role_id: Uuid,
    tenant_id: EntityId<Tenant>,
    is_retired: bool,
) {
    store
        .create_entity_typed::<RoleMembership>(membership_id)
        .await
        .unwrap();
    let revision = RevisionInput::new()
        .with_entity(
            "principal",
            EntityRefValue::pinned(principal_id.internal().as_uuid(), 0),
        )
        .with_entity("role", EntityRefValue::pinned(role_id, 0))
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant_id.internal().as_uuid(), 0),
        )
        .with_scalar("is_retired", ScalarValue::Bool(is_retired));
    store
        .append_revision_typed::<RoleMembership>(membership_id, 0, &revision)
        .await
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn permission_evaluation_happy_path() {
    let store = MockStore::new();

    let tenant_id = fixed_id::<Tenant>(1);
    let principal_id = fixed_id::<Principal>(2);
    let role_id = fixed_id::<RoleDefinition>(3);
    let membership_id = fixed_id::<RoleMembership>(4);

    seed_tenant(&store, tenant_id, TenantStatus::Active).await;
    seed_principal(&store, principal_id, tenant_id, false).await;
    seed_role_definition(
        &store,
        role_id,
        tenant_id,
        br#"["workflow:template_read","audit:read"]"#,
        false,
    )
    .await;
    seed_role_membership(
        &store,
        membership_id,
        principal_id,
        role_id.internal().as_uuid(),
        tenant_id,
        false,
    )
    .await;

    let allowed = evaluate_permission(&store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(allowed);
}

#[tokio::test(flavor = "current_thread")]
async fn permission_evaluation_permission_denied() {
    let store = MockStore::new();

    let tenant_id = fixed_id::<Tenant>(11);
    let principal_id = fixed_id::<Principal>(12);
    let role_id = fixed_id::<RoleDefinition>(13);
    let membership_id = fixed_id::<RoleMembership>(14);

    seed_tenant(&store, tenant_id, TenantStatus::Active).await;
    seed_principal(&store, principal_id, tenant_id, false).await;
    seed_role_definition(
        &store,
        role_id,
        tenant_id,
        br#"["workflow:template_read"]"#,
        false,
    )
    .await;
    seed_role_membership(
        &store,
        membership_id,
        principal_id,
        role_id.internal().as_uuid(),
        tenant_id,
        false,
    )
    .await;

    let allowed = evaluate_permission(&store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(!allowed);
}

#[tokio::test(flavor = "current_thread")]
async fn permission_evaluation_retired_role_denied() {
    let store = MockStore::new();

    let tenant_id = fixed_id::<Tenant>(21);
    let principal_id = fixed_id::<Principal>(22);
    let role_id = fixed_id::<RoleDefinition>(23);
    let membership_id = fixed_id::<RoleMembership>(24);

    seed_tenant(&store, tenant_id, TenantStatus::Active).await;
    seed_principal(&store, principal_id, tenant_id, false).await;
    seed_role_definition(&store, role_id, tenant_id, br#"["audit:read"]"#, true).await;
    seed_role_membership(
        &store,
        membership_id,
        principal_id,
        role_id.internal().as_uuid(),
        tenant_id,
        false,
    )
    .await;

    let allowed = evaluate_permission(&store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(!allowed);
}

#[tokio::test(flavor = "current_thread")]
async fn permission_evaluation_retired_membership_denied() {
    let store = MockStore::new();

    let tenant_id = fixed_id::<Tenant>(31);
    let principal_id = fixed_id::<Principal>(32);
    let role_id = fixed_id::<RoleDefinition>(33);
    let membership_id = fixed_id::<RoleMembership>(34);

    seed_tenant(&store, tenant_id, TenantStatus::Active).await;
    seed_principal(&store, principal_id, tenant_id, false).await;
    seed_role_definition(&store, role_id, tenant_id, br#"["audit:read"]"#, false).await;
    seed_role_membership(
        &store,
        membership_id,
        principal_id,
        role_id.internal().as_uuid(),
        tenant_id,
        true,
    )
    .await;

    let allowed = evaluate_permission(&store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(!allowed);
}

#[tokio::test(flavor = "current_thread")]
async fn permission_evaluation_retired_principal_denied() {
    let store = MockStore::new();

    let tenant_id = fixed_id::<Tenant>(41);
    let principal_id = fixed_id::<Principal>(42);
    let role_id = fixed_id::<RoleDefinition>(43);
    let membership_id = fixed_id::<RoleMembership>(44);

    seed_tenant(&store, tenant_id, TenantStatus::Active).await;
    seed_principal(&store, principal_id, tenant_id, true).await;
    seed_role_definition(&store, role_id, tenant_id, br#"["audit:read"]"#, false).await;
    seed_role_membership(
        &store,
        membership_id,
        principal_id,
        role_id.internal().as_uuid(),
        tenant_id,
        false,
    )
    .await;

    let allowed = evaluate_permission(&store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(!allowed);
}

#[tokio::test(flavor = "current_thread")]
async fn permission_evaluation_cross_tenant_denied() {
    let store = MockStore::new();

    let tenant_a = fixed_id::<Tenant>(51);
    let tenant_b = fixed_id::<Tenant>(52);
    let principal_id = fixed_id::<Principal>(53);
    let role_id = fixed_id::<RoleDefinition>(54);
    let membership_id = fixed_id::<RoleMembership>(55);

    seed_tenant(&store, tenant_a, TenantStatus::Active).await;
    seed_tenant(&store, tenant_b, TenantStatus::Active).await;
    seed_principal(&store, principal_id, tenant_a, false).await;
    seed_role_definition(&store, role_id, tenant_a, br#"["audit:read"]"#, false).await;
    seed_role_membership(
        &store,
        membership_id,
        principal_id,
        role_id.internal().as_uuid(),
        tenant_a,
        false,
    )
    .await;

    let allowed = evaluate_permission(&store, principal_id, tenant_b, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(!allowed);
}

#[tokio::test(flavor = "current_thread")]
async fn permission_evaluation_multi_role_positive() {
    let store = MockStore::new();

    let tenant_id = fixed_id::<Tenant>(61);
    let principal_id = fixed_id::<Principal>(62);
    let role_a = fixed_id::<RoleDefinition>(63);
    let role_b = fixed_id::<RoleDefinition>(64);
    let membership_a = fixed_id::<RoleMembership>(65);
    let membership_b = fixed_id::<RoleMembership>(66);

    seed_tenant(&store, tenant_id, TenantStatus::Active).await;
    seed_principal(&store, principal_id, tenant_id, false).await;
    seed_role_definition(
        &store,
        role_a,
        tenant_id,
        br#"["workflow:template_read"]"#,
        false,
    )
    .await;
    seed_role_definition(&store, role_b, tenant_id, br#"["audit:read"]"#, false).await;
    seed_role_membership(
        &store,
        membership_a,
        principal_id,
        role_a.internal().as_uuid(),
        tenant_id,
        false,
    )
    .await;
    seed_role_membership(
        &store,
        membership_b,
        principal_id,
        role_b.internal().as_uuid(),
        tenant_id,
        false,
    )
    .await;

    let allowed = evaluate_permission(&store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(allowed);
}

#[tokio::test(flavor = "current_thread")]
async fn permission_evaluation_principal_not_found_errors() {
    let store = MockStore::new();
    let tenant_id = fixed_id::<Tenant>(71);
    let missing_principal = fixed_id::<Principal>(72);

    seed_tenant(&store, tenant_id, TenantStatus::Active).await;

    let err = evaluate_permission(&store, missing_principal, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap_err();

    assert!(matches!(err, PolicyError::PrincipalNotFound { .. }));
}

#[tokio::test(flavor = "current_thread")]
async fn permission_evaluation_role_not_found_errors() {
    let store = MockStore::new();

    let tenant_id = fixed_id::<Tenant>(81);
    let principal_id = fixed_id::<Principal>(82);
    let membership_id = fixed_id::<RoleMembership>(83);
    let missing_role_uuid = Uuid::parse_str("00000000-0000-7000-8000-000000000999").unwrap();

    seed_tenant(&store, tenant_id, TenantStatus::Active).await;
    seed_principal(&store, principal_id, tenant_id, false).await;
    seed_role_membership(
        &store,
        membership_id,
        principal_id,
        missing_role_uuid,
        tenant_id,
        false,
    )
    .await;

    let err = evaluate_permission(&store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap_err();

    assert!(matches!(err, PolicyError::RoleNotFound { .. }));
}

#[tokio::test(flavor = "current_thread")]
async fn permission_evaluation_missing_permissions_blob_errors() {
    let store = MockStore::new();

    let tenant_id = fixed_id::<Tenant>(91);
    let principal_id = fixed_id::<Principal>(92);
    let role_id = fixed_id::<RoleDefinition>(93);
    let membership_id = fixed_id::<RoleMembership>(94);

    seed_tenant(&store, tenant_id, TenantStatus::Active).await;
    seed_principal(&store, principal_id, tenant_id, false).await;

    let missing_hash = Sha256::of(b"missing-permissions-blob");
    seed_role_definition_with_hash(
        &store,
        role_id,
        tenant_id,
        missing_hash,
        false,
        br#"{"display_name":"missing-perms"}"#,
    )
    .await;

    seed_role_membership(
        &store,
        membership_id,
        principal_id,
        role_id.internal().as_uuid(),
        tenant_id,
        false,
    )
    .await;

    let err = evaluate_permission(&store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap_err();

    assert!(matches!(err, PolicyError::MissingPermissionsBlob { .. }));
}

#[tokio::test(flavor = "current_thread")]
async fn permission_document_tolerant_parser_via_mock_pipeline() {
    let store = MockStore::new();

    let tenant_id = fixed_id::<Tenant>(101);
    let principal_id = fixed_id::<Principal>(102);
    let role_array = fixed_id::<RoleDefinition>(103);
    let role_wrapped = fixed_id::<RoleDefinition>(104);
    let membership_array = fixed_id::<RoleMembership>(105);
    let membership_wrapped = fixed_id::<RoleMembership>(106);

    seed_tenant(&store, tenant_id, TenantStatus::Active).await;
    seed_principal(&store, principal_id, tenant_id, false).await;
    seed_role_definition(
        &store,
        role_array,
        tenant_id,
        br#"["workflow:template_read"]"#,
        false,
    )
    .await;
    seed_role_definition(
        &store,
        role_wrapped,
        tenant_id,
        br#"{"permissions":["audit:read"]}"#,
        false,
    )
    .await;
    seed_role_membership(
        &store,
        membership_array,
        principal_id,
        role_array.internal().as_uuid(),
        tenant_id,
        false,
    )
    .await;
    seed_role_membership(
        &store,
        membership_wrapped,
        principal_id,
        role_wrapped.internal().as_uuid(),
        tenant_id,
        false,
    )
    .await;

    let template_allowed = evaluate_permission(
        &store,
        principal_id,
        tenant_id,
        atom::WORKFLOW_TEMPLATE_READ,
    )
    .await
    .unwrap();
    let audit_allowed = evaluate_permission(&store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(template_allowed);
    assert!(audit_allowed);

    let array_doc: PermissionDocument = serde_json::from_slice(br#"["audit:read"]"#).unwrap();
    let wrapped_doc: PermissionDocument =
        serde_json::from_slice(br#"{"permissions":["audit:read"]}"#).unwrap();
    assert!(array_doc.contains(atom::AUDIT_READ));
    assert!(wrapped_doc.contains(atom::AUDIT_READ));
}
