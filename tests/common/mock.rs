use philharmonic_store::{
    ContentStore, EntityRefValue, EntityRow, EntityStore, RevisionInput, RevisionRef, RevisionRow,
    StoreError,
};
use philharmonic_types::{ContentValue, Identity, ScalarValue, Sha256, UnixMillis, Uuid};

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

#[derive(Default)]
struct State {
    content: HashMap<Sha256, ContentValue>,
    entities: HashMap<Uuid, EntityRow>,
    revisions: HashMap<(Uuid, u64), RevisionRow>,
    next_timestamp: i64,
}

impl State {
    fn next_unix_millis(&mut self) -> UnixMillis {
        self.next_timestamp += 1;
        UnixMillis(self.next_timestamp)
    }
}

#[derive(Default)]
pub(crate) struct MockStore {
    state: Mutex<State>,
}

impl MockStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ContentStore for MockStore {
    async fn put(&self, value: &ContentValue) -> Result<(), StoreError> {
        let mut state = self.state.lock().expect("lock state");
        state.content.insert(value.digest(), value.clone());
        Ok(())
    }

    async fn get(&self, hash: Sha256) -> Result<Option<ContentValue>, StoreError> {
        let state = self.state.lock().expect("lock state");
        Ok(state.content.get(&hash).cloned())
    }

    async fn exists(&self, hash: Sha256) -> Result<bool, StoreError> {
        let state = self.state.lock().expect("lock state");
        Ok(state.content.contains_key(&hash))
    }
}

#[async_trait]
impl EntityStore for MockStore {
    async fn create_entity(&self, identity: Identity, kind: Uuid) -> Result<(), StoreError> {
        let mut state = self.state.lock().expect("lock state");
        if state.entities.contains_key(&identity.internal) {
            return Err(StoreError::IdentityCollision {
                uuid: identity.internal,
            });
        }

        let created_at = state.next_unix_millis();
        state.entities.insert(
            identity.internal,
            EntityRow {
                identity,
                kind,
                created_at,
            },
        );
        Ok(())
    }

    async fn get_entity(&self, entity_id: Uuid) -> Result<Option<EntityRow>, StoreError> {
        let state = self.state.lock().expect("lock state");
        Ok(state.entities.get(&entity_id).cloned())
    }

    async fn append_revision(
        &self,
        entity_id: Uuid,
        revision_seq: u64,
        input: &RevisionInput,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().expect("lock state");

        if !state.entities.contains_key(&entity_id) {
            return Err(StoreError::EntityNotFound { entity_id });
        }

        let key = (entity_id, revision_seq);
        if state.revisions.contains_key(&key) {
            return Err(StoreError::RevisionConflict {
                entity_id,
                revision_seq,
            });
        }

        let created_at = state.next_unix_millis();
        state.revisions.insert(
            key,
            RevisionRow {
                entity_id,
                revision_seq,
                created_at,
                content_attrs: input.content_attrs.clone(),
                entity_attrs: input.entity_attrs.clone(),
                scalar_attrs: input.scalar_attrs.clone(),
            },
        );
        Ok(())
    }

    async fn get_revision(
        &self,
        entity_id: Uuid,
        revision_seq: u64,
    ) -> Result<Option<RevisionRow>, StoreError> {
        let state = self.state.lock().expect("lock state");
        Ok(state.revisions.get(&(entity_id, revision_seq)).cloned())
    }

    async fn get_latest_revision(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<RevisionRow>, StoreError> {
        let state = self.state.lock().expect("lock state");
        let latest = state
            .revisions
            .values()
            .filter(|row| row.entity_id == entity_id)
            .max_by_key(|row| row.revision_seq)
            .cloned();
        Ok(latest)
    }

    async fn list_revisions_referencing(
        &self,
        target_entity_id: Uuid,
        attribute_name: &str,
    ) -> Result<Vec<RevisionRef>, StoreError> {
        let state = self.state.lock().expect("lock state");
        let mut refs = state
            .revisions
            .values()
            .filter_map(|row| {
                let attr = row.entity_attrs.get(attribute_name)?;
                if attr.target_entity_id != target_entity_id {
                    return None;
                }
                Some(RevisionRef::new(row.entity_id, row.revision_seq))
            })
            .collect::<Vec<_>>();
        refs.sort_by_key(|item| (item.entity_id.as_u128(), item.revision_seq));
        Ok(refs)
    }

    async fn find_by_scalar(
        &self,
        kind: Uuid,
        attribute_name: &str,
        value: &ScalarValue,
    ) -> Result<Vec<EntityRow>, StoreError> {
        let state = self.state.lock().expect("lock state");
        let mut rows = Vec::new();

        for entity in state.entities.values() {
            if entity.kind != kind {
                continue;
            }

            let latest = state
                .revisions
                .values()
                .filter(|row| row.entity_id == entity.identity.internal)
                .max_by_key(|row| row.revision_seq);
            let Some(latest) = latest else {
                continue;
            };

            if latest.scalar_attrs.get(attribute_name) == Some(value) {
                rows.push(entity.clone());
            }
        }

        rows.sort_by_key(|row| row.identity.internal.as_u128());
        Ok(rows)
    }
}

#[allow(dead_code)]
fn _assert_entity_ref_value_send_sync(_: EntityRefValue) {}
