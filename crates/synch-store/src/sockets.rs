//! Socket activations (`docs/SOCKETS.md` §3).
//!
//! One gate stands between a published socket entry and an invocation, and it
//! lives here: the **activation** ([`SocketActivation`]). It is a statement
//! about a *path* — "what this path holds is a socket, run it" — never about a
//! content root. It is what makes the scanner publish
//! [`EntryKind::Socket`](synch_core::EntryKind::Socket) for the path, and it
//! carries the operator's half of the policy: configuration, the stream cap,
//! and a note. Every later write to an activated path is an intentional
//! deployment: the new content serves as soon as it publishes, under whatever
//! its own manifest declares.
//!
//! An activation is **local operator state**. It is never published,
//! replicated, or derived from a peer's trie, and that is the whole point: a
//! node's own tree is not a closed system — `synch adopt path`, `synch adopt
//! tree --replace` and an S3 `PUT` all write bytes into a filesystem-source
//! directory that the scanner then publishes as this node's own view — so
//! publication cannot be the gate on execution. Activating a path is the
//! operator saying those write paths are, for this path, deployment channels.
//!
//! Content roots still exist everywhere content does — CAS integrity,
//! replication, caching, and the snapshot a running invocation keeps — but no
//! root is ever an authorization pin.

use rusqlite::{params, OptionalExtension};

use crate::{
    db::{Store, Txn},
    error::{Result, StoreError},
};

/// The most sockets one space may activate (`docs/SOCKETS.md` §10).
///
/// A sanity bound rather than a quota: an activation is operator state, and an
/// operator with sixty-five sockets in one space has a naming problem this
/// number is not going to fix. It exists so that "how much work can one space
/// make the scanner do per file?" has an answer.
pub(crate) const MAX_SOCKETS_PER_SPACE: usize = 64;

/// One activated socket path: local configuration attached to its tree path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketActivation {
    /// The space the socket lives in.
    pub space: String,
    /// Its path within that space.
    pub path: String,
    /// `k=v` pairs readable by the program through `sy_config_get`.
    pub config: Vec<(String, String)>,
    /// The concurrency cap, or `None` for the daemon's default.
    pub max_streams: Option<u32>,
    /// A free-form operator note.
    pub note: String,
    /// When the path was activated, unix nanoseconds.
    pub activated_at: i64,
}

impl SocketActivation {
    /// An activation with the defaults: no config, the daemon's default
    /// concurrency, no note.
    pub fn new(space: impl Into<String>, path: impl Into<String>, activated_at: i64) -> Self {
        SocketActivation {
            space: space.into(),
            path: path.into(),
            config: Vec::new(),
            max_streams: None,
            note: String::new(),
            activated_at,
        }
    }

    /// `<space>/<path>`, as every command and log line names a socket.
    pub fn qualified(&self) -> String {
        format!("{}/{}", self.space, self.path)
    }

    /// The value of a config key, if the operator set one.
    pub fn config_get(&self, key: &str) -> Option<&str> {
        self.config
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

impl Store {
    /// Makes a path in one of this node's spaces a socket.
    ///
    /// Replaces any existing activation for that path: re-activating with new
    /// config or a new cap is a new bargain, applied to the next admission.
    pub fn activate_socket(&self, row: &SocketActivation) -> Result<()> {
        self.transaction(|txn| txn.activate_socket(row))
    }

    /// Every activated socket, ordered by space then path.
    pub fn socket_activations(&self) -> Result<Vec<SocketActivation>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("{SELECT_ACTIVATIONS} ORDER BY space, path"))?;
        let rows = stmt.query_map([], activation_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The activated sockets of one space.
    pub fn socket_activations_in(&self, space: &str) -> Result<Vec<SocketActivation>> {
        Ok(self
            .socket_activations()?
            .into_iter()
            .filter(|s| s.space == space)
            .collect())
    }

    /// One activation, by space and path.
    pub fn socket_activation(&self, space: &str, path: &str) -> Result<Option<SocketActivation>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                &format!("{SELECT_ACTIVATIONS} WHERE space = ?1 AND path = ?2"),
                params![space, path],
                activation_row,
            )
            .optional()?)
    }

    /// True if this path is activated — what the scanner asks before deciding
    /// what kind to publish, and what admission asks before running anything.
    pub fn is_activated_socket(&self, space: &str, path: &str) -> Result<bool> {
        Ok(self
            .conn()
            .query_row(
                "SELECT 1 FROM socket_activations WHERE space = ?1 AND path = ?2",
                params![space, path],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Removes an activation. The next scan republishes the path as an
    /// ordinary file, and admission refuses it immediately.
    pub fn deactivate_socket(&self, space: &str, path: &str) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM socket_activations WHERE space = ?1 AND path = ?2",
            params![space, path],
        )?;
        Ok(n > 0)
    }

    /// What a device key may reach over `sync/sock/1`, and who it speaks for.
    ///
    /// Three answers, and the caller acts differently on each:
    ///
    /// * `None` — no live binding. Not a peer at all; refused at accept, and
    ///   refused again here because a binding can lapse mid-connection.
    /// * `Some((origin, None))` — a rooted member, unrestricted by construction.
    /// * `Some((origin, Some(spaces)))` — a delegate, and the spaces its live
    ///   delegations name.
    ///
    /// Deliberately its own query rather than a reuse of
    /// [`scope_for_key`](Store::scope_for_key), which answers in trie-key
    /// prefixes. A socket needs space *names* — to compare against the `Open`,
    /// and to hand `sy_peer_has_space` something a program can ask about — and
    /// deriving names back out of prefixes would be reconstructing what this
    /// read already has.
    pub fn socket_scope_for_key(
        &self,
        node_id: &synch_core::NodeId,
        now: i64,
    ) -> Result<Option<(synch_core::OriginId, Option<Vec<String>>)>> {
        let live: Vec<crate::bindings::Binding> = self
            .live_bindings(now)?
            .into_iter()
            .filter(|b| &b.node_id == node_id)
            .collect();
        let Some(first) = live.first() else {
            return Ok(None);
        };
        // A key bound to several origins speaks for the rooted one where there
        // is one: that is the binding that makes it unrestricted, and picking
        // a delegated origin beside it would name the caller by the narrower
        // grant while treating it as the wider one.
        let origin = live
            .iter()
            .find(|b| b.is_rooted())
            .unwrap_or(first)
            .origin
            .clone();
        if live.iter().any(|b| b.is_rooted()) {
            return Ok(Some((origin, None)));
        }
        // Two rooted origins may delegate the same key independently, so their
        // grants add rather than conflict.
        let mut spaces: Vec<String> = live.into_iter().flat_map(|b| b.spaces).collect();
        spaces.sort();
        spaces.dedup();
        Ok(Some((origin, Some(spaces))))
    }
}

impl Txn<'_> {
    /// Activates a socket path, replacing any existing activation.
    pub fn activate_socket(&self, row: &SocketActivation) -> Result<()> {
        let activated: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM socket_activations WHERE space = ?1 AND path != ?2",
            params![row.space, row.path],
            |r| r.get(0),
        )?;
        if activated >= MAX_SOCKETS_PER_SPACE as i64 {
            return Err(StoreError::Invalid(format!(
                "space `{}` already activates {activated} sockets, the most one space may \
                 (docs/SOCKETS.md §10)",
                row.space
            )));
        }
        self.conn().execute(
            "INSERT INTO socket_activations
               (space, path, config, max_streams, note, activated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(space, path) DO UPDATE SET
               config = excluded.config,
               max_streams = excluded.max_streams,
               note = excluded.note,
               activated_at = excluded.activated_at",
            params![
                row.space,
                row.path,
                join_pairs(&row.config),
                row.max_streams,
                row.note,
                row.activated_at,
            ],
        )?;
        Ok(())
    }
}

const SELECT_ACTIVATIONS: &str =
    "SELECT space, path, config, max_streams, note, activated_at FROM socket_activations";

fn activation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SocketActivation> {
    Ok(SocketActivation {
        space: row.get(0)?,
        path: row.get(1)?,
        config: split_pairs(&row.get::<_, String>(2)?),
        max_streams: row.get(3)?,
        note: row.get(4)?,
        activated_at: row.get(5)?,
    })
}

fn split_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn join_pairs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Splits stored `k=v` lines. A line with no `=` is a key with an empty value,
/// which is what `--config flag` should mean if anyone writes it.
fn split_pairs(text: &str) -> Vec<(String, String)> {
    split_lines(text)
        .into_iter()
        .map(|line| match line.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.to_string()),
            None => (line, String::new()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::store;

    fn row() -> SocketActivation {
        SocketActivation {
            config: vec![("upstream".into(), "git.internal".into())],
            max_streams: Some(32),
            ..SocketActivation::new("code", "git.sock", 1)
        }
    }

    #[test]
    fn an_activation_round_trips() {
        let (_d, store) = store();
        store.activate_socket(&row()).unwrap();
        let got = store
            .socket_activation("code", "git.sock")
            .unwrap()
            .unwrap();
        assert_eq!(got, row());
        assert!(store.is_activated_socket("code", "git.sock").unwrap());
        assert!(!store.is_activated_socket("code", "other.sock").unwrap());
    }

    #[test]
    fn reactivating_replaces_the_terms() {
        let (_d, store) = store();
        store.activate_socket(&row()).unwrap();
        let mut changed = row();
        changed.config.push(("mode".into(), "strict".into()));
        changed.max_streams = Some(8);
        store.activate_socket(&changed).unwrap();
        let got = store
            .socket_activation("code", "git.sock")
            .unwrap()
            .unwrap();
        assert_eq!(got.config, changed.config);
        assert_eq!(got.max_streams, Some(8));
    }

    #[test]
    fn deactivating_removes_the_gate() {
        let (_d, store) = store();
        store.activate_socket(&row()).unwrap();
        assert!(store.deactivate_socket("code", "git.sock").unwrap());
        assert!(!store.is_activated_socket("code", "git.sock").unwrap());
        assert!(store
            .socket_activation("code", "git.sock")
            .unwrap()
            .is_none());
        assert!(
            !store.deactivate_socket("code", "git.sock").unwrap(),
            "deactivating twice reports there was nothing to remove"
        );
    }

    #[test]
    fn listing_filters_by_space() {
        let (_d, store) = store();
        store.activate_socket(&row()).unwrap();
        store
            .activate_socket(&SocketActivation::new("docs", "d.sock", 2))
            .unwrap();
        assert_eq!(store.socket_activations().unwrap().len(), 2);
        let one = store.socket_activations_in("docs").unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].qualified(), "docs/d.sock");
    }

    #[test]
    fn a_space_may_not_activate_more_sockets_than_the_bound() {
        let (_d, store) = store();
        for i in 0..MAX_SOCKETS_PER_SPACE {
            store
                .activate_socket(&SocketActivation::new("code", format!("s{i}.sock"), 0))
                .unwrap();
        }
        // Re-activating one already counted stays legal: the bound is on how
        // many exist, not on how often they are written.
        store
            .activate_socket(&SocketActivation::new("code", "s0.sock", 0))
            .unwrap();
        let out = store.activate_socket(&SocketActivation::new("code", "one-too-many.sock", 0));
        assert!(matches!(out, Err(StoreError::Invalid(_))), "{out:?}");
        // Another space has its own budget.
        store
            .activate_socket(&SocketActivation::new("docs", "s.sock", 0))
            .unwrap();
    }
}
