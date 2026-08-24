//! Socket declarations and their arming records (`docs/SOCKETS.md` §3).
//!
//! Two gates stand between a published socket entry and an invocation, and both
//! live here. Neither is ever published, replicated, or derived from a peer's
//! trie.
//!
//! The **declaration** ([`SocketRow`]) is what makes the scanner publish
//! [`EntryKind::Socket`](synch_core::EntryKind::Socket) for a path, and carries
//! local configuration and the operator's stream cap. The **arming record**
//! ([`ArmRow`]) is the approval, keyed by the BLAKE3 content root it approved.
//!
//! Keeping them in two tables rather than two columns of one is what makes
//! disarming a deletion rather than a nulling, and what makes "declared but
//! never armed" the natural state of a socket somebody has just added a file
//! for. It also means the arming record can be dropped by a content change
//! without touching that local configuration, which is exactly the transition that
//! has to be cheap and exactly the one that must not lose anything.

use rusqlite::{params, OptionalExtension};
use synch_core::{Hash, OriginId};

use crate::{
    db::{Store, Txn},
    error::{Result, StoreError},
};

/// The most sockets one space may declare (`docs/SOCKETS.md` §10).
///
/// A sanity bound rather than a quota: a declaration is operator state, and an
/// operator with sixty-five sockets in one space has a naming problem this
/// number is not going to fix. It exists so that "how much work can one space
/// make the scanner do per file?" has an answer.
pub const MAX_SOCKETS_PER_SPACE: usize = 64;

/// One declared socket: local configuration attached to its tree path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketRow {
    /// The space the socket lives in.
    pub space: String,
    /// Its path within that space.
    pub path: String,
    /// `k=v` pairs readable by the program through `sy_config_get`.
    pub config: Vec<(String, String)>,
    /// The concurrency cap, or `None` for the daemon's default.
    pub max_streams: Option<u32>,
    /// Whether the declaration re-arms itself on every content change.
    ///
    /// Correct for a path you are the only writer of, wrong for any path an S3
    /// key, a fill or a take can reach. `synch doctor` lists these, because
    /// that list is the honest answer to "what can execute here?".
    pub auto: bool,
    /// A free-form operator note.
    pub note: String,
    /// When the declaration was made, unix nanoseconds.
    pub added_at: i64,
}

impl SocketRow {
    /// A declaration with nothing allowed: no egress, no foreign tree reads,
    /// the daemon's default concurrency, and no auto-arming.
    pub fn new(space: impl Into<String>, path: impl Into<String>, added_at: i64) -> Self {
        SocketRow {
            space: space.into(),
            path: path.into(),
            config: Vec::new(),
            max_streams: None,
            auto: false,
            note: String::new(),
            added_at,
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

/// One arming record: the approval, and what was approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmRow {
    /// The space the socket lives in.
    pub space: String,
    /// Its path within that space.
    pub path: String,
    /// The content root approved.
    pub root: Hash,
    /// The program's own declaration at the moment of approval.
    ///
    /// Stored as text so `synch socket ls` can show what was agreed to rather
    /// than re-running the init hook and showing what is claimed now. The two
    /// differing is the interesting case and it is only visible if the old one
    /// was kept.
    pub declared: String,
    /// When it was armed, unix nanoseconds.
    pub armed_at: i64,
}

/// The result of declaration work proposed for an atomic arming write.
#[derive(Debug, Clone, Copy)]
pub struct ArmCandidate<'a> {
    /// Declaration revision that requested the work.
    pub generation: &'a Hash,
    /// Content root whose program was inspected.
    pub root: &'a Hash,
    /// Rendered result of its init hook.
    pub declared: &'a str,
    /// When the inspection completed, unix nanoseconds.
    pub armed_at: i64,
}

/// What the store knows about one declared socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketState {
    /// The declaration.
    pub declaration: SocketRow,
    /// Opaque identity of this exact authorization revision.
    ///
    /// It changes on every `put_socket` and disarm, and is the compare-and-set
    /// token used by arming and final admission.
    pub generation: Hash,
    /// The arming record, if there is one.
    pub arm: Option<ArmRow>,
}

impl SocketState {
    /// Whether this socket may run `root` right now.
    ///
    /// The whole of the second gate: an armed root that is not the root the
    /// tree currently names is not an approval of the bytes a caller would
    /// reach, so it is not an approval at all.
    pub fn is_armed_for(&self, root: &Hash) -> bool {
        self.arm.as_ref().is_some_and(|arm| &arm.root == root)
    }
}

impl Store {
    /// Declares a path in one of this node's spaces to be a socket.
    ///
    /// Replaces any existing declaration for that path, and **does not** carry
    /// its arming forward: a declaration that changed the allowed egress and
    /// kept the old approval would be an approval of something nobody
    /// approved.
    pub fn put_socket(&self, row: &SocketRow) -> Result<()> {
        self.transaction(|txn| txn.put_socket(row))
    }

    /// Every declared socket, ordered by space then path.
    pub fn sockets(&self) -> Result<Vec<SocketState>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(SELECT_SOCKETS)?;
        let rows = stmt.query_map([], socket_state)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The declared sockets of one space.
    pub fn sockets_in(&self, space: &str) -> Result<Vec<SocketState>> {
        Ok(self
            .sockets()?
            .into_iter()
            .filter(|s| s.declaration.space == space)
            .collect())
    }

    /// One declared socket, by space and path.
    pub fn socket(&self, space: &str, path: &str) -> Result<Option<SocketState>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                &format!("{SELECT_SOCKETS_BASE} WHERE s.space = ?1 AND s.path = ?2"),
                params![space, path],
                socket_state,
            )
            .optional()?)
    }

    /// True if this path is declared a socket — what the scanner asks before
    /// deciding what kind to publish.
    pub fn is_declared_socket(&self, space: &str, path: &str) -> Result<bool> {
        Ok(self
            .conn()
            .query_row(
                "SELECT 1 FROM sockets WHERE space = ?1 AND path = ?2",
                params![space, path],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Removes a declaration and its arming record.
    pub fn remove_socket(&self, space: &str, path: &str) -> Result<bool> {
        self.transaction(|txn| {
            txn.conn().execute(
                "DELETE FROM socket_arms WHERE space = ?1 AND path = ?2",
                params![space, path],
            )?;
            let n = txn.conn().execute(
                "DELETE FROM sockets WHERE space = ?1 AND path = ?2",
                params![space, path],
            )?;
            Ok(n > 0)
        })
    }

    /// Records an approval of `root`, with what the program declared.
    pub fn arm_socket(
        &self,
        space: &str,
        path: &str,
        root: &Hash,
        declared: &str,
        armed_at: i64,
    ) -> Result<()> {
        self.transaction(|txn| txn.arm_socket(space, path, root, declared, armed_at))
    }

    /// Arms a manually reviewed program only if both facts reviewed by the
    /// caller are still current: the local authorization revision and this
    /// origin's published socket root.
    pub fn arm_socket_reviewed(
        &self,
        origin: &OriginId,
        space: &str,
        path: &str,
        candidate: ArmCandidate<'_>,
    ) -> Result<bool> {
        let n = self.conn().execute(
            "INSERT INTO socket_arms (space, path, root, declared, armed_at)
             SELECT ?2, ?3, ?5, ?6, ?7
              WHERE EXISTS (
                    SELECT 1 FROM sockets
                     WHERE space = ?2 AND path = ?3 AND generation = ?4
              )
                AND EXISTS (
                    SELECT 1 FROM entries
                     WHERE origin_id = ?1 AND space = ?2 AND path = ?3
                       AND kind = 4 AND content = ?5
              )
             ON CONFLICT(space, path) DO UPDATE SET
               root = excluded.root,
               declared = excluded.declared,
               armed_at = excluded.armed_at",
            params![
                origin.canonical(),
                space,
                path,
                candidate.generation.as_bytes().to_vec(),
                candidate.root.as_bytes().to_vec(),
                candidate.declared,
                candidate.armed_at,
            ],
        )?;
        Ok(n > 0)
    }

    /// Auto-arms only if the declaration that requested the work still exists
    /// unchanged and still has auto-arming enabled.
    pub fn auto_arm_socket(
        &self,
        space: &str,
        path: &str,
        candidate: ArmCandidate<'_>,
    ) -> Result<bool> {
        let n = self.conn().execute(
            "INSERT INTO socket_arms (space, path, root, declared, armed_at)
             SELECT ?1, ?2, ?4, ?5, ?6
              WHERE EXISTS (
                    SELECT 1 FROM sockets
                     WHERE space = ?1 AND path = ?2
                       AND generation = ?3 AND auto = 1
              )
             ON CONFLICT(space, path) DO UPDATE SET
               root = excluded.root,
               declared = excluded.declared,
               armed_at = excluded.armed_at",
            params![
                space,
                path,
                candidate.generation.as_bytes().to_vec(),
                candidate.root.as_bytes().to_vec(),
                candidate.declared,
                candidate.armed_at,
            ],
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

    /// Withdraws an approval, leaving the declaration standing.
    pub fn disarm_socket(&self, space: &str, path: &str) -> Result<bool> {
        self.transaction(|txn| {
            // Rotation is unconditional for an existing declaration. Besides
            // invalidating a copied manual-review token, this cancels auto-arm
            // work that may still be running even when there is no arm row yet.
            txn.conn().execute(
                "UPDATE sockets SET generation = randomblob(32)
                  WHERE space = ?1 AND path = ?2",
                params![space, path],
            )?;
            let n = txn.conn().execute(
                "DELETE FROM socket_arms WHERE space = ?1 AND path = ?2",
                params![space, path],
            )?;
            Ok(n > 0)
        })
    }

    /// Withdraws an approval only if it still names `root`.
    ///
    /// Fault quarantine uses this so an old invocation cannot disarm a newer
    /// program that was armed while the old one was still finishing.
    pub fn disarm_socket_root(&self, space: &str, path: &str, root: &Hash) -> Result<bool> {
        self.transaction(|txn| {
            let n = txn.conn().execute(
                "DELETE FROM socket_arms WHERE space = ?1 AND path = ?2 AND root = ?3",
                params![space, path, root.as_bytes().to_vec()],
            )?;
            if n > 0 {
                txn.conn().execute(
                    "UPDATE sockets SET generation = randomblob(32)
                      WHERE space = ?1 AND path = ?2",
                    params![space, path],
                )?;
            }
            Ok(n > 0)
        })
    }
}

impl Txn<'_> {
    /// Declares a socket, dropping any approval the old declaration carried.
    pub fn put_socket(&self, row: &SocketRow) -> Result<()> {
        let declared: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM sockets WHERE space = ?1 AND path != ?2",
            params![row.space, row.path],
            |r| r.get(0),
        )?;
        if declared >= MAX_SOCKETS_PER_SPACE as i64 {
            return Err(StoreError::Invalid(format!(
                "space `{}` already declares {declared} sockets, the most one space may \
                 (docs/SOCKETS.md §10)",
                row.space
            )));
        }
        self.conn().execute(
            "INSERT INTO sockets
               (space, path, config, max_streams, auto, note, added_at, generation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, randomblob(32))
             ON CONFLICT(space, path) DO UPDATE SET
               config = excluded.config,
               max_streams = excluded.max_streams,
               auto = excluded.auto,
               note = excluded.note,
               generation = randomblob(32)",
            params![
                row.space,
                row.path,
                join_pairs(&row.config),
                row.max_streams,
                i64::from(row.auto),
                row.note,
                row.added_at,
            ],
        )?;
        // A re-declaration is a new bargain, so the old approval goes with the
        // old terms. Doing this in the same transaction is what keeps a crash
        // from leaving an approval standing over a policy nobody approved.
        self.conn().execute(
            "DELETE FROM socket_arms WHERE space = ?1 AND path = ?2",
            params![row.space, row.path],
        )?;
        Ok(())
    }

    /// Records an approval of `root`.
    pub fn arm_socket(
        &self,
        space: &str,
        path: &str,
        root: &Hash,
        declared: &str,
        armed_at: i64,
    ) -> Result<()> {
        let known: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM sockets WHERE space = ?1 AND path = ?2",
            params![space, path],
            |r| r.get(0),
        )?;
        if known == 0 {
            return Err(StoreError::Invalid(format!(
                "`{space}/{path}` is not declared a socket, so there is nothing to arm"
            )));
        }
        self.conn().execute(
            "INSERT INTO socket_arms (space, path, root, declared, armed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(space, path) DO UPDATE SET
               root = excluded.root,
               declared = excluded.declared,
               armed_at = excluded.armed_at",
            params![space, path, root.as_bytes().to_vec(), declared, armed_at],
        )?;
        Ok(())
    }
}

const SELECT_SOCKETS_BASE: &str = "SELECT s.space, s.path, s.config,
            s.max_streams, s.auto, s.note, s.added_at, s.generation,
            a.root, a.declared, a.armed_at
       FROM sockets s
       LEFT JOIN socket_arms a ON a.space = s.space AND a.path = s.path";

const SELECT_SOCKETS: &str = "SELECT s.space, s.path, s.config,
            s.max_streams, s.auto, s.note, s.added_at, s.generation,
            a.root, a.declared, a.armed_at
       FROM sockets s
       LEFT JOIN socket_arms a ON a.space = s.space AND a.path = s.path
      ORDER BY s.space, s.path";

fn socket_state(row: &rusqlite::Row<'_>) -> rusqlite::Result<SocketState> {
    let space: String = row.get(0)?;
    let path: String = row.get(1)?;
    let declaration = SocketRow {
        space: space.clone(),
        path: path.clone(),
        config: split_pairs(&row.get::<_, String>(2)?),
        max_streams: row.get(3)?,
        auto: row.get::<_, i64>(4)? != 0,
        note: row.get(5)?,
        added_at: row.get(6)?,
    };
    let generation = hash_column(row, 7, "sockets.generation")?;
    let arm = match row.get::<_, Option<Vec<u8>>>(8)? {
        Some(bytes) => {
            let root = Hash::from_slice(&bytes).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Blob,
                    "socket_arms.root is not a 32-byte hash".into(),
                )
            })?;
            Some(ArmRow {
                space,
                path,
                root,
                declared: row.get(9)?,
                armed_at: row.get(10)?,
            })
        }
        None => None,
    };
    Ok(SocketState {
        declaration,
        generation,
        arm,
    })
}

fn hash_column(row: &rusqlite::Row<'_>, column: usize, name: &str) -> rusqlite::Result<Hash> {
    let bytes: Vec<u8> = row.get(column)?;
    Hash::from_slice(&bytes).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            format!("{name} is not a 32-byte hash").into(),
        )
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

    fn row() -> SocketRow {
        SocketRow {
            config: vec![("upstream".into(), "git.internal".into())],
            max_streams: Some(32),
            ..SocketRow::new("code", "git.sock", 1)
        }
    }

    #[test]
    fn a_declaration_round_trips() {
        let (_d, store) = store();
        store.put_socket(&row()).unwrap();
        let got = store.socket("code", "git.sock").unwrap().unwrap();
        assert_eq!(got.declaration, row());
        assert_eq!(got.arm, None, "a fresh declaration is not armed");
        assert!(store.is_declared_socket("code", "git.sock").unwrap());
        assert!(!store.is_declared_socket("code", "other.sock").unwrap());
    }

    #[test]
    fn arming_pins_a_root_and_only_that_root() {
        let (_d, store) = store();
        store.put_socket(&row()).unwrap();
        let armed = Hash::new(b"elf-v1");
        store
            .arm_socket("code", "git.sock", &armed, "egress git.internal:9418", 2)
            .unwrap();

        let got = store.socket("code", "git.sock").unwrap().unwrap();
        assert!(got.is_armed_for(&armed));
        assert!(
            !got.is_armed_for(&Hash::new(b"elf-v2")),
            "an approval of one root approved a different one"
        );
        assert_eq!(got.arm.unwrap().declared, "egress git.internal:9418");
    }

    #[test]
    fn arming_something_undeclared_is_refused() {
        let (_d, store) = store();
        let out = store.arm_socket("code", "nope.sock", &Hash::new(b"x"), "", 2);
        assert!(matches!(out, Err(StoreError::Invalid(_))), "{out:?}");
    }

    #[test]
    fn redeclaring_drops_the_approval_it_was_not_given_for() {
        // The transition that has to be safe: an operator changes config and
        // the old approval must not carry over onto the new terms.
        let (_d, store) = store();
        store.put_socket(&row()).unwrap();
        store
            .arm_socket("code", "git.sock", &Hash::new(b"elf"), "", 2)
            .unwrap();

        let mut changed = row();
        changed.config.push(("mode".into(), "strict".into()));
        store.put_socket(&changed).unwrap();

        let got = store.socket("code", "git.sock").unwrap().unwrap();
        assert_eq!(got.declaration.config, changed.config);
        assert!(
            got.arm.is_none(),
            "a re-declaration carried its old approval onto new terms"
        );
    }

    #[test]
    fn redeclaring_changes_the_compare_and_set_generation() {
        let (_d, store) = store();
        store.put_socket(&row()).unwrap();
        let before = store.socket("code", "git.sock").unwrap().unwrap();

        store.put_socket(&row()).unwrap();
        let after = store.socket("code", "git.sock").unwrap().unwrap();

        assert_ne!(before.generation, after.generation);
        assert!(
            !store
                .auto_arm_socket(
                    "code",
                    "git.sock",
                    ArmCandidate {
                        generation: &before.generation,
                        root: &Hash::new(b"elf"),
                        declared: "",
                        armed_at: 3,
                    },
                )
                .unwrap(),
            "stale work armed a later declaration"
        );
        assert!(store
            .socket("code", "git.sock")
            .unwrap()
            .unwrap()
            .arm
            .is_none());
    }

    #[test]
    fn disarming_keeps_the_declaration_and_removal_takes_both() {
        let (_d, store) = store();
        store.put_socket(&row()).unwrap();
        store
            .arm_socket("code", "git.sock", &Hash::new(b"elf"), "", 2)
            .unwrap();

        assert!(store.disarm_socket("code", "git.sock").unwrap());
        let got = store.socket("code", "git.sock").unwrap().unwrap();
        assert!(got.arm.is_none());
        assert!(
            store.is_declared_socket("code", "git.sock").unwrap(),
            "disarming removed the declaration too"
        );

        assert!(store.remove_socket("code", "git.sock").unwrap());
        assert!(store.socket("code", "git.sock").unwrap().is_none());
    }

    #[test]
    fn disarm_invalidates_auto_arm_work_already_in_flight() {
        let (_d, store) = store();
        let mut automatic = row();
        automatic.auto = true;
        store.put_socket(&automatic).unwrap();
        let before = store.socket("code", "git.sock").unwrap().unwrap();
        let root = Hash::new(b"elf");
        store.arm_socket("code", "git.sock", &root, "", 2).unwrap();

        assert!(store.disarm_socket("code", "git.sock").unwrap());
        let after = store.socket("code", "git.sock").unwrap().unwrap();
        assert_ne!(before.generation, after.generation);
        assert!(
            !store
                .auto_arm_socket(
                    "code",
                    "git.sock",
                    ArmCandidate {
                        generation: &before.generation,
                        root: &Hash::new(b"new elf"),
                        declared: "",
                        armed_at: 3,
                    },
                )
                .unwrap(),
            "auto-arm work that began before disarm restored the approval"
        );
        assert!(store
            .socket("code", "git.sock")
            .unwrap()
            .unwrap()
            .arm
            .is_none());
    }

    #[test]
    fn a_space_may_not_declare_more_sockets_than_the_bound() {
        let (_d, store) = store();
        for i in 0..MAX_SOCKETS_PER_SPACE {
            store
                .put_socket(&SocketRow::new("code", format!("s{i}.sock"), 0))
                .unwrap();
        }
        // Re-declaring one already counted stays legal: the bound is on how
        // many exist, not on how often they are written.
        store
            .put_socket(&SocketRow::new("code", "s0.sock", 0))
            .unwrap();
        let out = store.put_socket(&SocketRow::new("code", "one-too-many.sock", 0));
        assert!(matches!(out, Err(StoreError::Invalid(_))), "{out:?}");
        // Another space has its own budget.
        store
            .put_socket(&SocketRow::new("docs", "s.sock", 0))
            .unwrap();
    }
}
