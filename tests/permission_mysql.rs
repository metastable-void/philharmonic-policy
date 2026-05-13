use hex_literal::hex;

use philharmonic_policy::{
    AuditEvent, MintingAuthority, Principal, PrincipalKind, RoleDefinition, RoleMembership, Sck,
    Tenant, TenantEndpointConfig, TenantStatus, atom, evaluate_permission, sck_decrypt,
    sck_encrypt,
};

use philharmonic_store::{ContentStore, EntityRefValue, EntityStoreExt, RevisionInput, StoreExt};
use philharmonic_store_sqlx_mysql::{SinglePool, SqlStore, migrate};
use philharmonic_types::{ContentValue, EntityId, ScalarValue, Sha256};

use sqlx::{MySqlPool, mysql::MySqlPoolOptions};

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dockerlet::{Container, GenericImage, IntoContainerPort, WaitFor};
use tokio::sync::OnceCell;

/// Warm shared MySQL container; see philharmonic-store-sqlx-mysql
/// /tests/integration.rs for the pattern. Per-test isolation by
/// unique database name, not per-test container.
static SHARED_MYSQL: OnceCell<SharedMysql> = OnceCell::const_new();

struct SharedMysql {
    _container: Container,
    base_url: String,
}

async fn shared_mysql() -> &'static SharedMysql {
    SHARED_MYSQL
        .get_or_init(|| async {
            let container = GenericImage::new("mysql", "8")
                .with_exposed_port(3306.tcp())
                .with_env_var("MYSQL_ALLOW_EMPTY_PASSWORD", "yes")
                .with_wait_for(WaitFor::message_on_stderr("ready for connections"))
                .with_startup_timeout(Duration::from_secs(180))
                .start()
                .await
                .expect("start shared MySQL container");
            let host = container.get_host().await.expect("container host");
            let port = container
                .get_host_port_ipv4(3306.tcp())
                .await
                .expect("container port");
            SharedMysql {
                _container: container,
                base_url: format!("mysql://root@{host}:{port}"),
            }
        })
        .await
}

fn unique_db_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("dl_t_{}_{n}", std::process::id())
}

async fn connect_with_retry(url: &str) -> MySqlPool {
    use std::time::Instant;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut backoff = Duration::from_millis(100);
    let mut last_err = None;
    while Instant::now() < deadline {
        match MySqlPool::connect(url).await {
            Ok(pool) => return pool,
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, Duration::from_secs(2));
            }
        }
    }
    panic!(
        "could not connect to shared MySQL within 30s: {:?}",
        last_err
    );
}

struct TestContext {
    db_name: String,
    _pool: MySqlPool,
    store: SqlStore<SinglePool>,
}

impl Drop for TestContext {
    fn drop(&mut self) {
        let db_name = self.db_name.clone();
        let base_url = SHARED_MYSQL
            .get()
            .map(|s| s.base_url.clone())
            .unwrap_or_default();
        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            runtime.block_on(async move {
                if let Ok(pool) = MySqlPool::connect(&base_url).await {
                    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS `{db_name}`"))
                        .execute(&pool)
                        .await;
                }
            });
        });
    }
}

async fn setup() -> TestContext {
    let shared = shared_mysql().await;
    let db_name = unique_db_name();

    let admin_pool = connect_with_retry(&format!("{}/mysql", shared.base_url)).await;
    sqlx::query(&format!("CREATE DATABASE `{db_name}`"))
        .execute(&admin_pool)
        .await
        .unwrap();
    drop(admin_pool);

    let database_url = format!("{}/{db_name}", shared.base_url);
    let pool = MySqlPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await
        .unwrap();

    migrate(&pool).await.unwrap();

    let store = SqlStore::from_pool(pool.clone());

    TestContext {
        db_name,
        _pool: pool,
        store,
    }
}

async fn put_content(store: &SqlStore<SinglePool>, bytes: &[u8]) -> Sha256 {
    let value = ContentValue::new(bytes.to_vec());
    let hash = value.digest();
    store.put(&value).await.unwrap();
    hash
}

async fn seed_tenant(
    store: &SqlStore<SinglePool>,
    status: TenantStatus,
    display_name: &[u8],
) -> EntityId<Tenant> {
    let tenant_id = store.create_entity_minting::<Tenant>().await.unwrap();
    let display_name_hash = put_content(store, display_name).await;
    let settings_hash = put_content(store, br#"{"settings":{}}"#).await;

    let revision = RevisionInput::new()
        .with_content("display_name", display_name_hash)
        .with_content("settings", settings_hash)
        .with_scalar("status", ScalarValue::I64(status.as_i64()));
    store
        .append_revision_typed::<Tenant>(tenant_id, 0, &revision)
        .await
        .unwrap();

    tenant_id
}

async fn seed_principal(
    store: &SqlStore<SinglePool>,
    tenant_id: EntityId<Tenant>,
    kind: PrincipalKind,
    epoch: i64,
    is_retired: bool,
) -> EntityId<Principal> {
    let principal_id = store.create_entity_minting::<Principal>().await.unwrap();
    let credential_hash = put_content(store, br#"{"credential_hash":"wave-1"}"#).await;
    let display_name = put_content(store, br#"{"display_name":"principal"}"#).await;

    let revision = RevisionInput::new()
        .with_content("credential_hash", credential_hash)
        .with_content("display_name", display_name)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant_id.internal().as_uuid(), 0),
        )
        .with_scalar("kind", ScalarValue::I64(kind.as_i64()))
        .with_scalar("epoch", ScalarValue::I64(epoch))
        .with_scalar("is_retired", ScalarValue::Bool(is_retired));
    store
        .append_revision_typed::<Principal>(principal_id, 0, &revision)
        .await
        .unwrap();

    principal_id
}

async fn seed_role_definition(
    store: &SqlStore<SinglePool>,
    tenant_id: EntityId<Tenant>,
    permissions_json: &[u8],
    is_retired: bool,
) -> EntityId<RoleDefinition> {
    let role_id = store
        .create_entity_minting::<RoleDefinition>()
        .await
        .unwrap();
    let permissions = put_content(store, permissions_json).await;
    let display_name = put_content(store, br#"{"display_name":"role"}"#).await;

    let revision = RevisionInput::new()
        .with_content("permissions", permissions)
        .with_content("display_name", display_name)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant_id.internal().as_uuid(), 0),
        )
        .with_scalar("is_retired", ScalarValue::Bool(is_retired));
    store
        .append_revision_typed::<RoleDefinition>(role_id, 0, &revision)
        .await
        .unwrap();

    role_id
}

async fn seed_role_membership(
    store: &SqlStore<SinglePool>,
    principal_id: EntityId<Principal>,
    role_id: EntityId<RoleDefinition>,
    tenant_id: EntityId<Tenant>,
    is_retired: bool,
) -> EntityId<RoleMembership> {
    let membership_id = store
        .create_entity_minting::<RoleMembership>()
        .await
        .unwrap();

    let revision = RevisionInput::new()
        .with_entity(
            "principal",
            EntityRefValue::pinned(principal_id.internal().as_uuid(), 0),
        )
        .with_entity(
            "role",
            EntityRefValue::pinned(role_id.internal().as_uuid(), 0),
        )
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant_id.internal().as_uuid(), 0),
        )
        .with_scalar("is_retired", ScalarValue::Bool(is_retired));
    store
        .append_revision_typed::<RoleMembership>(membership_id, 0, &revision)
        .await
        .unwrap();

    membership_id
}

async fn seed_minting_authority(
    store: &SqlStore<SinglePool>,
    tenant_id: EntityId<Tenant>,
) -> EntityId<MintingAuthority> {
    let authority_id = store
        .create_entity_minting::<MintingAuthority>()
        .await
        .unwrap();
    let credential_hash = put_content(store, br#"{"credential_hash":"authority"}"#).await;
    let display_name = put_content(store, br#"{"display_name":"authority"}"#).await;
    let envelope = put_content(store, br#"["mint:ephemeral_token"]"#).await;
    let constraints = put_content(store, br#"{"max_lifetime_seconds":3600}"#).await;

    let revision = RevisionInput::new()
        .with_content("credential_hash", credential_hash)
        .with_content("display_name", display_name)
        .with_content("permission_envelope", envelope)
        .with_content("minting_constraints", constraints)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant_id.internal().as_uuid(), 0),
        )
        .with_scalar("epoch", ScalarValue::I64(7))
        .with_scalar("is_retired", ScalarValue::Bool(false));
    store
        .append_revision_typed::<MintingAuthority>(authority_id, 0, &revision)
        .await
        .unwrap();

    authority_id
}

async fn seed_audit_event(
    store: &SqlStore<SinglePool>,
    tenant_id: EntityId<Tenant>,
) -> EntityId<AuditEvent> {
    let event_id = store.create_entity_minting::<AuditEvent>().await.unwrap();
    let event_data = put_content(store, br#"{"event":"created"}"#).await;

    let revision = RevisionInput::new()
        .with_content("event_data", event_data)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant_id.internal().as_uuid(), 0),
        )
        .with_scalar("event_type", ScalarValue::I64(3))
        .with_scalar("timestamp", ScalarValue::I64(1_700_000_123_000));
    store
        .append_revision_typed::<AuditEvent>(event_id, 0, &revision)
        .await
        .unwrap();

    event_id
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn tenant_entity_round_trip() {
    let ctx = setup().await;
    let tenant_id = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-a"}"#,
    )
    .await;

    let revision = ctx
        .store
        .get_latest_revision_typed::<Tenant>(tenant_id)
        .await
        .unwrap()
        .unwrap();

    assert!(revision.content_attrs.contains_key("display_name"));
    assert!(revision.content_attrs.contains_key("settings"));
    assert_eq!(
        revision.scalar_attrs.get("status"),
        Some(&ScalarValue::I64(TenantStatus::Active.as_i64()))
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn principal_entity_round_trip() {
    let ctx = setup().await;
    let tenant_id = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-b"}"#,
    )
    .await;
    let principal_id = seed_principal(
        &ctx.store,
        tenant_id,
        PrincipalKind::ServiceAccount,
        9,
        false,
    )
    .await;

    let revision = ctx
        .store
        .get_latest_revision_typed::<Principal>(principal_id)
        .await
        .unwrap()
        .unwrap();

    assert!(revision.content_attrs.contains_key("credential_hash"));
    assert!(revision.content_attrs.contains_key("display_name"));
    assert_eq!(
        revision
            .entity_attrs
            .get("tenant")
            .unwrap()
            .target_entity_id,
        tenant_id.internal().as_uuid()
    );
    assert_eq!(
        revision.scalar_attrs.get("kind"),
        Some(&ScalarValue::I64(PrincipalKind::ServiceAccount.as_i64()))
    );
    assert_eq!(
        revision.scalar_attrs.get("epoch"),
        Some(&ScalarValue::I64(9))
    );
    assert_eq!(
        revision.scalar_attrs.get("is_retired"),
        Some(&ScalarValue::Bool(false))
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn role_definition_entity_round_trip() {
    let ctx = setup().await;
    let tenant_id = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-c"}"#,
    )
    .await;
    let role_id = seed_role_definition(&ctx.store, tenant_id, br#"["audit:read"]"#, false).await;

    let revision = ctx
        .store
        .get_latest_revision_typed::<RoleDefinition>(role_id)
        .await
        .unwrap()
        .unwrap();

    assert!(revision.content_attrs.contains_key("permissions"));
    assert!(revision.content_attrs.contains_key("display_name"));
    assert_eq!(
        revision
            .entity_attrs
            .get("tenant")
            .unwrap()
            .target_entity_id,
        tenant_id.internal().as_uuid()
    );
    assert_eq!(
        revision.scalar_attrs.get("is_retired"),
        Some(&ScalarValue::Bool(false))
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn role_membership_entity_round_trip() {
    let ctx = setup().await;
    let tenant_id = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-d"}"#,
    )
    .await;
    let principal_id = seed_principal(&ctx.store, tenant_id, PrincipalKind::User, 0, false).await;
    let role_id = seed_role_definition(&ctx.store, tenant_id, br#"["audit:read"]"#, false).await;
    let membership_id =
        seed_role_membership(&ctx.store, principal_id, role_id, tenant_id, false).await;

    let revision = ctx
        .store
        .get_latest_revision_typed::<RoleMembership>(membership_id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        revision
            .entity_attrs
            .get("principal")
            .unwrap()
            .target_entity_id,
        principal_id.internal().as_uuid()
    );
    assert_eq!(
        revision.entity_attrs.get("role").unwrap().target_entity_id,
        role_id.internal().as_uuid()
    );
    assert_eq!(
        revision
            .entity_attrs
            .get("tenant")
            .unwrap()
            .target_entity_id,
        tenant_id.internal().as_uuid()
    );
    assert_eq!(
        revision.scalar_attrs.get("is_retired"),
        Some(&ScalarValue::Bool(false))
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn minting_authority_entity_round_trip() {
    let ctx = setup().await;
    let tenant_id = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-e"}"#,
    )
    .await;
    let authority_id = seed_minting_authority(&ctx.store, tenant_id).await;

    let revision = ctx
        .store
        .get_latest_revision_typed::<MintingAuthority>(authority_id)
        .await
        .unwrap()
        .unwrap();

    assert!(revision.content_attrs.contains_key("credential_hash"));
    assert!(revision.content_attrs.contains_key("display_name"));
    assert!(revision.content_attrs.contains_key("permission_envelope"));
    assert!(revision.content_attrs.contains_key("minting_constraints"));
    assert_eq!(
        revision
            .entity_attrs
            .get("tenant")
            .unwrap()
            .target_entity_id,
        tenant_id.internal().as_uuid()
    );
    assert_eq!(
        revision.scalar_attrs.get("epoch"),
        Some(&ScalarValue::I64(7))
    );
    assert_eq!(
        revision.scalar_attrs.get("is_retired"),
        Some(&ScalarValue::Bool(false))
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn audit_event_entity_round_trip() {
    let ctx = setup().await;
    let tenant_id = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-f"}"#,
    )
    .await;
    let event_id = seed_audit_event(&ctx.store, tenant_id).await;

    let revision = ctx
        .store
        .get_latest_revision_typed::<AuditEvent>(event_id)
        .await
        .unwrap()
        .unwrap();

    assert!(revision.content_attrs.contains_key("event_data"));
    assert_eq!(
        revision
            .entity_attrs
            .get("tenant")
            .unwrap()
            .target_entity_id,
        tenant_id.internal().as_uuid()
    );
    assert_eq!(
        revision.scalar_attrs.get("event_type"),
        Some(&ScalarValue::I64(3))
    );
    assert_eq!(
        revision.scalar_attrs.get("timestamp"),
        Some(&ScalarValue::I64(1_700_000_123_000))
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn permission_evaluation_happy_path_end_to_end() {
    let ctx = setup().await;

    let tenant_id = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-g"}"#,
    )
    .await;
    let principal_id = seed_principal(&ctx.store, tenant_id, PrincipalKind::User, 0, false).await;
    let role_id = seed_role_definition(&ctx.store, tenant_id, br#"["audit:read"]"#, false).await;
    seed_role_membership(&ctx.store, principal_id, role_id, tenant_id, false).await;

    let allowed = evaluate_permission(&ctx.store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(allowed);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn permission_evaluation_retired_role_end_to_end() {
    let ctx = setup().await;

    let tenant_id = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-h"}"#,
    )
    .await;
    let principal_id = seed_principal(&ctx.store, tenant_id, PrincipalKind::User, 0, false).await;
    let role_id = seed_role_definition(&ctx.store, tenant_id, br#"["audit:read"]"#, true).await;
    seed_role_membership(&ctx.store, principal_id, role_id, tenant_id, false).await;

    let allowed = evaluate_permission(&ctx.store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(!allowed);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn permission_evaluation_cross_tenant_denial_end_to_end() {
    let ctx = setup().await;

    let tenant_a = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-i"}"#,
    )
    .await;
    let tenant_b = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-j"}"#,
    )
    .await;
    let principal_id = seed_principal(&ctx.store, tenant_a, PrincipalKind::User, 0, false).await;
    let role_id = seed_role_definition(&ctx.store, tenant_a, br#"["audit:read"]"#, false).await;
    seed_role_membership(&ctx.store, principal_id, role_id, tenant_a, false).await;

    let allowed = evaluate_permission(&ctx.store, principal_id, tenant_b, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(!allowed);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn permission_evaluation_role_tenant_mismatch_denied_end_to_end() {
    let ctx = setup().await;

    let tenant_a = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-role-mismatch-a"}"#,
    )
    .await;
    let tenant_b = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-role-mismatch-b"}"#,
    )
    .await;

    let principal_id = seed_principal(&ctx.store, tenant_a, PrincipalKind::User, 0, false).await;
    let foreign_role =
        seed_role_definition(&ctx.store, tenant_b, br#"["audit:read"]"#, false).await;
    seed_role_membership(&ctx.store, principal_id, foreign_role, tenant_a, false).await;

    let allowed = evaluate_permission(&ctx.store, principal_id, tenant_a, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(!allowed);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn permission_evaluation_multi_role_positive_end_to_end() {
    let ctx = setup().await;

    let tenant_id = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-k"}"#,
    )
    .await;
    let principal_id = seed_principal(&ctx.store, tenant_id, PrincipalKind::User, 0, false).await;
    let role_a = seed_role_definition(
        &ctx.store,
        tenant_id,
        br#"["workflow:template_read"]"#,
        false,
    )
    .await;
    let role_b = seed_role_definition(&ctx.store, tenant_id, br#"["audit:read"]"#, false).await;
    seed_role_membership(&ctx.store, principal_id, role_a, tenant_id, false).await;
    seed_role_membership(&ctx.store, principal_id, role_b, tenant_id, false).await;

    let allowed = evaluate_permission(&ctx.store, principal_id, tenant_id, atom::AUDIT_READ)
        .await
        .unwrap();

    assert!(allowed);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MySQL testcontainer"]
async fn tenant_endpoint_config_entity_round_trip() {
    let ctx = setup().await;

    let tenant_id = seed_tenant(
        &ctx.store,
        TenantStatus::Active,
        br#"{"display_name":"tenant-l"}"#,
    )
    .await;

    let config_id = ctx
        .store
        .create_entity_minting::<TenantEndpointConfig>()
        .await
        .unwrap();

    let key_version = 3_i64;
    let sck = Sck::from_bytes(hex!(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    ));
    let plaintext = br#"{"driver":"mysql","dsn":"tenant-l"}"#;
    let wire = sck_encrypt(
        &sck,
        plaintext,
        tenant_id.internal().as_uuid(),
        config_id.internal().as_uuid(),
        key_version,
    )
    .unwrap();

    let display_name = put_content(&ctx.store, br#"{"display_name":"endpoint-l"}"#).await;
    let encrypted_config = put_content(&ctx.store, &wire).await;

    let revision = RevisionInput::new()
        .with_content("display_name", display_name)
        .with_content("encrypted_config", encrypted_config)
        .with_entity(
            "tenant",
            EntityRefValue::pinned(tenant_id.internal().as_uuid(), 0),
        )
        .with_scalar("key_version", ScalarValue::I64(key_version))
        .with_scalar("is_retired", ScalarValue::Bool(false));

    ctx.store
        .append_revision_typed::<TenantEndpointConfig>(config_id, 0, &revision)
        .await
        .unwrap();

    let loaded = ctx
        .store
        .get_latest_revision_typed::<TenantEndpointConfig>(config_id)
        .await
        .unwrap()
        .unwrap();

    assert!(loaded.content_attrs.contains_key("display_name"));
    assert!(loaded.content_attrs.contains_key("encrypted_config"));
    assert_eq!(
        loaded.entity_attrs.get("tenant").unwrap().target_entity_id,
        tenant_id.internal().as_uuid()
    );
    assert_eq!(
        loaded.scalar_attrs.get("key_version"),
        Some(&ScalarValue::I64(3))
    );
    assert_eq!(
        loaded.scalar_attrs.get("is_retired"),
        Some(&ScalarValue::Bool(false))
    );

    let stored_hash = *loaded.content_attrs.get("encrypted_config").unwrap();
    let stored_wire = ctx.store.get(stored_hash).await.unwrap().unwrap();
    let decrypted = sck_decrypt(
        &sck,
        stored_wire.bytes(),
        tenant_id.internal().as_uuid(),
        config_id.internal().as_uuid(),
        key_version,
    )
    .unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);
}
