//! Raw SQLite/point adapters for whole native authorization operations.
//! Typed results are reconstructed from primitive-validated keys; no row,
//! liveness, delegation, clock or scope policy is interpreted here.
use std::collections::HashMap;

use rusqlite::Connection;
use synch_core::{origin::OriginParseError, NodeId, OriginId};
use synch_mpt::Scope;
use synch_verified::{authorization as native, cas::OperationError};

use crate::{
    lean_storage::SqliteStorage, Binding, BindingSource, PublishScope, Result, Store, StoreError,
};

#[derive(Default)]
struct Crypto {
    keys: HashMap<Vec<u8>, NodeId>,
}

impl Crypto {
    fn seed(&mut self, origin: &OriginId) {
        if let OriginId::Key(key) = origin {
            self.keys.insert(key.as_bytes().to_vec(), *key);
        }
    }

    fn key(&self, bytes: Vec<u8>) -> Result<NodeId> {
        self.keys
            .get(&bytes)
            .copied()
            .ok_or_else(|| StoreError::invalid("Lean returned an unvalidated authorization key"))
    }

    fn origin(&self, origin: native::Origin) -> Result<OriginId> {
        match origin {
            native::Origin::Named(value) => Ok(OriginId::Named {
                domain: value.domain,
                id: value.id,
            }),
            native::Origin::Key(bytes) => self.key(bytes).map(OriginId::Key),
        }
    }

    fn binding(&self, binding: native::Binding) -> Result<Binding> {
        Ok(Binding {
            origin: self.origin(binding.origin)?,
            node_id: self.key(binding.node_id)?,
            source: match binding.source {
                native::Source::Static => BindingSource::Static,
                native::Source::Dns => BindingSource::Dns,
                native::Source::Delegated => BindingSource::Delegated,
            },
            domain: binding.domain,
            issuer: binding
                .issuer
                .map(|origin| self.origin(origin))
                .transpose()?,
            spaces: binding.spaces,
            note: binding.note,
            added_at: binding.added_at,
            expires_at: binding.expires_at,
        })
    }
}

impl synch_verified::host::Crypto for Crypto {
    type Error = StoreError;
    fn validate_ed25519(&mut self, bytes: &[u8]) -> Result<bool> {
        let key = <&[u8; 32]>::try_from(bytes)
            .ok()
            .and_then(|bytes| NodeId::from_bytes(bytes).ok());
        if let Some(key) = key {
            self.keys.insert(bytes.to_vec(), key);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn origin(value: &OriginId) -> native::Origin {
    match value {
        OriginId::Key(key) => native::Origin::Key(key.as_bytes().to_vec()),
        OriginId::Named { domain, id } => native::Origin::Named(synch_verified::origin::Named {
            domain: domain.clone(),
            id: id.clone(),
        }),
    }
}

fn publication(scope: native::PublishScope) -> PublishScope {
    match scope {
        native::PublishScope::Untrusted => PublishScope::Untrusted,
        native::PublishScope::Unrestricted => PublishScope::Unrestricted,
        native::PublishScope::Confined(spaces) => PublishScope::Confined(spaces),
    }
}

fn error(error: native::Error<StoreError>) -> StoreError {
    match error {
        native::Error::Operation(OperationError::Host(error)) => error,
        native::Error::Operation(_) | native::Error::Domain(native::DomainError::Malformed) => {
            StoreError::invalid("invalid Lean authorization operation result")
        }
        native::Error::Domain(native::DomainError::ColumnType {
            index,
            column,
            actual,
        }) => rusqlite::Error::InvalidColumnType(
            index as usize,
            column,
            match actual {
                native::CellType::Null => rusqlite::types::Type::Null,
                native::CellType::Integer => rusqlite::types::Type::Integer,
                native::CellType::Real => rusqlite::types::Type::Real,
                native::CellType::Text => rusqlite::types::Type::Text,
                native::CellType::Blob => rusqlite::types::Type::Blob,
            },
        )
        .into(),
        native::Error::Domain(native::DomainError::InvalidText(bytes)) => {
            match std::str::from_utf8(&bytes) {
                Err(error) => rusqlite::Error::Utf8Error(error).into(),
                Ok(_) => StoreError::invalid("invalid Lean UTF-8 diagnostic"),
            }
        }
        native::Error::Domain(native::DomainError::Column { column, reason }) => {
            column_error(&column, reason)
        }
        native::Error::Domain(native::DomainError::Origin { column, error }) => {
            column_error(&column, OriginParseError::from(error).to_string())
        }
    }
}

fn column_error(column: &str, reason: String) -> StoreError {
    let column = match column {
        "bindings.origin_id" => "bindings.origin_id",
        "bindings.node_id" => "bindings.node_id",
        "bindings.source" => "bindings.source",
        "bindings.issuer" => "bindings.issuer",
        "device_keys.node_id" => "device_keys.node_id",
        "device_keys.state" => "device_keys.state",
        "config.self_origin_id" => "config.self_origin_id",
        _ => return StoreError::invalid("unknown Lean authorization column diagnostic"),
    };
    StoreError::column(column, reason)
}

pub(crate) fn bindings(
    store: &Store,
    selection: native::BindingSelection,
    live: bool,
    now: i64,
) -> Result<Vec<Binding>> {
    store.with_connection_scope(|conn| {
        let mut storage = SqliteStorage::new(conn);
        let mut crypto = Crypto::default();
        let rows =
            native::bindings(&mut storage, &mut crypto, selection, live, now).map_err(error)?;
        rows.into_iter().map(|row| crypto.binding(row)).collect()
    })
}

pub(crate) fn for_origin(origin_id: &OriginId) -> native::BindingSelection {
    native::BindingSelection::Origin(origin(origin_id))
}

pub(crate) fn for_key(key: &NodeId) -> native::BindingSelection {
    native::BindingSelection::Key(key.as_bytes().to_vec())
}

pub(crate) fn trusted_keys(store: &Store, now: i64) -> Result<Vec<NodeId>> {
    store.with_connection_scope(|conn| {
        let mut crypto = Crypto::default();
        let values =
            native::trusted_keys(&mut SqliteStorage::new(conn), &mut crypto, now).map_err(error)?;
        values.into_iter().map(|key| crypto.key(key)).collect()
    })
}

pub(crate) fn trusted_origins(store: &Store, now: i64) -> Result<Vec<OriginId>> {
    store.with_connection_scope(|conn| {
        let mut crypto = Crypto::default();
        let values = native::trusted_origins(&mut SqliteStorage::new(conn), &mut crypto, now)
            .map_err(error)?;
        values
            .into_iter()
            .map(|value| crypto.origin(value))
            .collect()
    })
}

pub(crate) fn trusted_key(store: &Store, key: &NodeId, now: i64) -> Result<bool> {
    store.with_connection_scope(|conn| {
        native::trusted_key(
            &mut SqliteStorage::new(conn),
            &mut Crypto::default(),
            key.as_bytes(),
            now,
        )
        .map_err(error)
    })
}

pub(crate) fn bound(store: &Store, origin_id: &OriginId, key: &NodeId, now: i64) -> Result<bool> {
    store.with_connection_scope(|conn| {
        native::bound(
            &mut SqliteStorage::new(conn),
            &mut Crypto::default(),
            &origin(origin_id),
            key.as_bytes(),
            now,
        )
        .map_err(error)
    })
}

pub(crate) struct PeerAuthority {
    pub(crate) serving: Scope,
    pub(crate) publication: PublishScope,
    pub(crate) origins: Vec<OriginId>,
    pub(crate) rooted: bool,
}

pub(crate) fn peer_authority(store: &Store, key: &NodeId, now: i64) -> Result<PeerAuthority> {
    store.with_connection_scope(|conn| {
        let mut crypto = Crypto::default();
        let answer = native::peer_authority(
            &mut SqliteStorage::new(conn),
            &mut crypto,
            key.as_bytes(),
            now,
        )
        .map_err(error)?;
        Ok(PeerAuthority {
            serving: Scope::from_verified(answer.serving),
            publication: publication(answer.publication),
            origins: answer
                .origins
                .into_iter()
                .map(|value| crypto.origin(value))
                .collect::<Result<_>>()?,
            rooted: answer.rooted,
        })
    })
}

pub(crate) fn origin_publication(
    store: &Store,
    origin_id: &OriginId,
    now: i64,
) -> Result<PublishScope> {
    store.with_connection_scope(|conn| {
        native::origin_publication(
            &mut SqliteStorage::new(conn),
            &mut Crypto::default(),
            &origin(origin_id),
            now,
        )
        .map(publication)
        .map_err(error)
    })
}

pub(crate) fn origin_authority_on(
    conn: &Connection,
    origin_id: &OriginId,
    now: i64,
    borrowed: bool,
) -> Result<crate::bindings::PromotionAuthority> {
    let mut crypto = Crypto::default();
    crypto.seed(origin_id);
    let answer = if borrowed {
        let (mut storage, tx) = SqliteStorage::borrow_transaction(conn)?;
        native::origin_authority_in(&mut storage, &mut crypto, tx, &origin(origin_id), now)
    } else {
        native::origin_authority(
            &mut SqliteStorage::new(conn),
            &mut crypto,
            &origin(origin_id),
            now,
        )
    }
    .map_err(error)?;
    Ok(crate::bindings::PromotionAuthority {
        publication: publication(answer.publication),
        trie_scope: Scope::from_verified(answer.publication_keys),
        provenance: answer
            .provenance
            .map(|value| crypto.origin(value))
            .transpose()?,
    })
}

pub(crate) fn local_spaces(store: &Store) -> Result<Option<Vec<String>>> {
    store.with_connection_scope(|conn| {
        native::local_spaces(&mut SqliteStorage::new(conn), &mut Crypto::default()).map_err(error)
    })
}

pub(crate) fn local_scope_on(conn: &Connection, borrowed: bool) -> Result<Scope> {
    let mut crypto = Crypto::default();
    let answer = if borrowed {
        let (mut storage, tx) = SqliteStorage::borrow_transaction(conn)?;
        native::local_scope_in(&mut storage, &mut crypto, tx)
    } else {
        native::local_scope(&mut SqliteStorage::new(conn), &mut crypto)
    }
    .map_err(error)?;
    Ok(Scope::from_verified(answer))
}

pub(crate) fn materialization_scope_on(
    conn: &Connection,
    origin_id: &OriginId,
    borrowed: bool,
) -> Result<Scope> {
    let mut crypto = Crypto::default();
    let answer = if borrowed {
        let (mut storage, tx) = SqliteStorage::borrow_transaction(conn)?;
        native::materialization_scope_in(&mut storage, &mut crypto, tx, &origin(origin_id))
    } else {
        native::materialization_scope(
            &mut SqliteStorage::new(conn),
            &mut crypto,
            &origin(origin_id),
        )
    }
    .map_err(error)?;
    Ok(Scope::from_verified(answer))
}

pub(crate) struct LocalAuthority {
    pub(crate) issuers: Vec<OriginId>,
    pub(crate) grant: Option<Vec<String>>,
    pub(crate) rooted_elsewhere: bool,
}

pub(crate) fn local_authority(store: &Store, now: i64) -> Result<LocalAuthority> {
    store.with_connection_scope(|conn| {
        let mut crypto = Crypto::default();
        let answer = native::local_authority(&mut SqliteStorage::new(conn), &mut crypto, now)
            .map_err(error)?;
        Ok(LocalAuthority {
            issuers: answer
                .issuers
                .into_iter()
                .map(|value| crypto.origin(value))
                .collect::<Result<_>>()?,
            grant: answer.grant,
            rooted_elsewhere: answer.rooted_elsewhere,
        })
    })
}

pub(crate) fn binding_statuses(
    store: &Store,
    now: i64,
) -> Result<Vec<crate::bindings::BindingStatus>> {
    store.with_connection_scope(|conn| {
        let mut crypto = Crypto::default();
        let answers = native::binding_statuses(&mut SqliteStorage::new(conn), &mut crypto, now)
            .map_err(error)?;
        answers
            .into_iter()
            .map(|answer| {
                Ok(crate::bindings::BindingStatus {
                    binding: crypto.binding(answer.binding)?,
                    dated_live: answer.dated_live,
                    live: answer.live,
                })
            })
            .collect()
    })
}

pub(crate) fn metadata_peer(store: &Store, peer: &NodeId, now: i64) -> Result<Option<String>> {
    store.with_connection_scope(|conn| {
        let refusal = native::metadata_peer(
            &mut SqliteStorage::new(conn),
            &mut Crypto::default(),
            peer.as_bytes(),
            now,
        )
        .map_err(error)?;
        Ok(refusal.map(|refusal| match refusal {
            native::MetadataRefusal::NotFullMember => {
                "this node is a delegate and that peer is not a full member of its cluster"
                    .to_owned()
            }
            native::MetadataRefusal::DifferentCluster => {
                "this node is a delegate and that peer belongs to a different cluster".to_owned()
            }
        }))
    })
}

pub(crate) fn socket_authority(
    store: &Store,
    peer: &NodeId,
    now: i64,
) -> Result<Option<(OriginId, Option<Vec<String>>)>> {
    store.with_connection_scope(|conn| {
        let mut crypto = Crypto::default();
        let answer = native::socket_authority(
            &mut SqliteStorage::new(conn),
            &mut crypto,
            peer.as_bytes(),
            now,
        )
        .map_err(error)?;
        answer
            .map(|answer| Ok((crypto.origin(answer.origin)?, answer.spaces)))
            .transpose()
    })
}

pub(crate) fn sole_dns_hint_source(
    store: &Store,
    peer: &NodeId,
    domain: &str,
    now: i64,
) -> Result<bool> {
    store.with_connection_scope(|conn| {
        native::sole_dns_hint_source(
            &mut SqliteStorage::new(conn),
            &mut Crypto::default(),
            peer.as_bytes(),
            domain,
            now,
        )
        .map_err(error)
    })
}

pub(crate) fn has_delegations(store: &Store) -> Result<bool> {
    store.with_connection_scope(|conn| {
        native::has_delegations(&mut SqliteStorage::new(conn), &mut Crypto::default())
            .map_err(error)
    })
}

pub(crate) fn expire_dns(store: &Store, now: i64) -> Result<usize> {
    store.with_connection_scope(|conn| {
        let count = native::expire_dns(&mut SqliteStorage::new(conn), &mut Crypto::default(), now)
            .map_err(error)?;
        usize::try_from(count).map_err(|_| StoreError::invalid("binding deletion count overflow"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_base::SecretKey;
    use rusqlite::params;
    use synch_core::MIN_TRUSTED_NS;

    fn root_binding(origin: OriginId, key: NodeId) -> Binding {
        Binding {
            origin,
            node_id: key,
            source: BindingSource::Static,
            domain: None,
            issuer: None,
            spaces: vec![],
            note: None,
            added_at: 0,
            expires_at: None,
        }
    }

    fn delegate(key: NodeId, issuer: OriginId, expires: i64) -> Binding {
        Binding {
            origin: OriginId::Key(key),
            node_id: key,
            source: BindingSource::Delegated,
            domain: None,
            issuer: Some(issuer),
            spaces: vec!["photos".into()],
            note: None,
            added_at: 0,
            expires_at: Some(expires),
        }
    }

    #[test]
    fn projections_reject_corrupt_policy_without_decoding_unrelated_payload_columns() {
        let (_dir, store) = crate::testutil::store();
        let key = SecretKey::generate().public();
        store
            .put_binding(&root_binding(OriginId::Key(key), key))
            .unwrap();
        store
            .conn()
            .execute("UPDATE bindings SET note = x'ff'", [])
            .unwrap();
        assert_eq!(store.trusted_keys(MIN_TRUSTED_NS).unwrap(), [key]);
        assert!(
            store.bindings().is_err(),
            "full binding reader must validate note type"
        );
        store
            .conn()
            .execute("UPDATE bindings SET note = NULL, source = 'invented'", [])
            .unwrap();
        assert!(store.trusted_keys(MIN_TRUSTED_NS).is_err());
        assert!(store.trusted_origins(MIN_TRUSTED_NS).is_err());
        store
            .conn()
            .execute(
                "UPDATE bindings SET source = 'static', expires_at = 'forever'",
                [],
            )
            .unwrap();
        assert!(store.trusted_keys(MIN_TRUSTED_NS).is_err());
        assert!(store.trusted_origins(MIN_TRUSTED_NS).is_err());
    }

    #[test]
    fn origins_keep_typed_wire_order_and_native_keys_are_reused() {
        let (_dir, store) = crate::testutil::store();
        let key = SecretKey::generate().public();
        let by_domain = OriginId::named("z", "a.example").unwrap();
        let by_id = OriginId::named("a", "z.example").unwrap();
        for origin in [by_id.clone(), by_domain.clone(), OriginId::Key(key)] {
            store.put_binding(&root_binding(origin, key)).unwrap();
        }
        assert_eq!(
            store.trusted_origins(MIN_TRUSTED_NS).unwrap(),
            [OriginId::Key(key), by_domain, by_id]
        );
    }

    #[test]
    fn serving_and_publication_use_their_distinct_grant_precedence() {
        let (_dir, store) = crate::testutil::store();
        let issuer_key = SecretKey::generate().public();
        let subject = SecretKey::generate().public();
        let issuer = OriginId::named("issuer", "x.example").unwrap();
        store
            .put_binding(&root_binding(issuer.clone(), issuer_key))
            .unwrap();
        store
            .put_binding(&root_binding(OriginId::Key(subject), subject))
            .unwrap();
        store
            .put_binding(&delegate(subject, issuer, i64::MAX))
            .unwrap();
        assert!(store
            .scope_for_key(&subject, MIN_TRUSTED_NS)
            .unwrap()
            .is_full());
        assert_eq!(
            store
                .publish_scope_of_key(&subject, MIN_TRUSTED_NS)
                .unwrap(),
            PublishScope::Confined(vec!["photos".into()])
        );
        assert_eq!(
            store
                .publish_scope(&OriginId::Key(subject), MIN_TRUSTED_NS)
                .unwrap(),
            PublishScope::Unrestricted
        );
        store
            .remove_binding(&OriginId::Key(subject), &subject, BindingSource::Static)
            .unwrap();
        let read = store.scope_for_key(&subject, MIN_TRUSTED_NS).unwrap();
        let authority = store
            .transaction::<_, StoreError>(|tx| {
                tx.promotion_authority(&OriginId::Key(subject), MIN_TRUSTED_NS)
            })
            .unwrap();
        let path = |bytes: &[u8]| synch_mpt::Nibbles::from_bytes(bytes).as_slice().to_vec();
        assert!(read.prefixes().unwrap().contains(&path(b"d:")));
        assert!(!read.prefixes().unwrap().contains(&path(b"b:")));
        assert!(authority
            .trie_scope
            .prefixes()
            .unwrap()
            .contains(&path(b"b:")));
        assert!(!authority
            .trie_scope
            .prefixes()
            .unwrap()
            .contains(&path(b"d:")));
        for scope in [&read, &authority.trie_scope] {
            assert!(scope.prefixes().unwrap().contains(&path(b"f:photos/")));
            assert!(scope.exact().contains(&path(b"m:space/photos")));
            assert!(scope.exact().contains(&path(b"r:photos")));
            assert!(!scope.prefixes().unwrap().contains(&path(b"m:space/photos")));
        }
    }

    #[test]
    fn reporting_distinguishes_two_issuers_of_the_same_subject() {
        let (_dir, store) = crate::testutil::store();
        let subject = SecretKey::generate().public();
        let expired = OriginId::named("expired", "x.example").unwrap();
        let live = OriginId::named("live", "x.example").unwrap();
        for issuer in [&expired, &live] {
            store
                .put_binding(&root_binding(
                    issuer.clone(),
                    SecretKey::generate().public(),
                ))
                .unwrap();
        }
        store
            .put_binding(&delegate(subject, expired.clone(), MIN_TRUSTED_NS))
            .unwrap();
        store
            .put_binding(&delegate(subject, live.clone(), i64::MAX))
            .unwrap();
        let statuses = store.binding_statuses(MIN_TRUSTED_NS + 1).unwrap();
        assert!(
            !statuses
                .iter()
                .find(|row| row.binding.issuer.as_ref() == Some(&expired))
                .unwrap()
                .live
        );
        assert!(
            statuses
                .iter()
                .find(|row| row.binding.issuer.as_ref() == Some(&live))
                .unwrap()
                .live
        );
    }

    #[test]
    fn indexed_authority_does_not_scan_unrelated_bindings() {
        let (_dir, store) = crate::testutil::store();
        let issuer_key = SecretKey::generate().public();
        let subject = SecretKey::generate().public();
        let issuer = OriginId::named("issuer", "x.example").unwrap();
        store
            .put_binding(&root_binding(issuer.clone(), issuer_key))
            .unwrap();
        store
            .put_binding(&delegate(subject, issuer, i64::MAX))
            .unwrap();
        for count in [10, 1000] {
            store
                .transaction::<_, StoreError>(|tx| {
                    for index in 0..count {
                        tx.conn().execute(
                            "INSERT OR IGNORE INTO bindings
                        (origin_id,node_id,source,domain,issuer,spaces,note,added_at,expires_at)
                        VALUES (?1,?2,'static','','',NULL,NULL,0,NULL)",
                            params![
                                format!("unrelated{index}@x.example"),
                                issuer_key.as_bytes().as_slice()
                            ],
                        )?;
                    }
                    Ok(())
                })
                .unwrap();
            crate::lean_storage::take_sql_scan_work();
            assert_eq!(
                store
                    .publish_scope_of_key(&subject, MIN_TRUSTED_NS)
                    .unwrap(),
                PublishScope::Confined(vec!["photos".into()])
            );
            let (rows, full_scans) = crate::lean_storage::take_sql_scan_work();
            assert_eq!(rows, 2, "only subject and issuer binding rows at {count}");
            assert_eq!(full_scans, 0, "indexed native authority at {count}");
        }
    }
}
