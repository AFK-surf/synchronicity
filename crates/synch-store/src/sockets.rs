//! Socket declarations and their arming records (`docs/SOCKETS.md` §3).
//!
//! Two gates stand between a published socket entry and an invocation, and both
//! live here. Neither is ever published, replicated, or derived from a peer's
//! trie.
//!
//! The **declaration** ([`SocketRow`]) is what makes the scanner publish
//! [`EntryKind::Socket`](synch_core::EntryKind::Socket) for a path, and carries
//! the operator's half of the runtime policy. The **arming record**
//! ([`ArmRow`]) is the approval, keyed by the BLAKE3 content root it approved.
//!
//! Keeping them in two tables rather than two columns of one is what makes
//! disarming a deletion rather than a nulling, and what makes "declared but
//! never armed" the natural state of a socket somebody has just added a file
//! for. It also means the arming record can be dropped by a content change
//! without touching the operator's policy, which is exactly the transition that
//! has to be cheap and exactly the one that must not lose anything.

use rusqlite::{params, OptionalExtension};
use synch_core::Hash;

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

/// One declared socket: the operator's half of the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketRow {
    /// The space the socket lives in.
    pub space: String,
    /// Its path within that space.
    pub path: String,
    /// `k=v` pairs readable by the program through `sy_config_get`.
    pub config: Vec<(String, String)>,
    /// Destinations the program may reach, as `host` or `host:port`.
    ///
    /// A bare host allows any port on it. Empty means no egress at all, which
    /// is the default: a program that never declared a destination and an
    /// operator who never allowed one agree, and the intersection of two empty
    /// sets is the right answer either way.
    pub allow_egress: Vec<String>,
    /// Path prefixes the program may read from other origins' views.
    pub allow_tree_read: Vec<String>,
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
            allow_egress: Vec::new(),
            allow_tree_read: Vec::new(),
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

    /// Whether this declaration permits reaching `host` on `port`.
    ///
    /// Matched against the operator's list only. The runtime intersects this
    /// with what the program declared in its `synchronicity.init` hook, and
    /// both have to say yes — which is the whole of the arming bargain: the
    /// operator approves a list the program wrote, and neither can widen it
    /// alone.
    pub fn egress_allowed(&self, host: &str, port: u16) -> bool {
        self.allow_egress
            .iter()
            .any(|rule| synch_core::sock::egress_rule_matches(rule, host, port))
    }

    /// Whether this declaration permits reading `path` from another origin.
    pub fn tree_read_allowed(&self, path: &str) -> bool {
        self.allow_tree_read
            .iter()
            .any(|prefix| synch_core::sock::path_prefix_matches(prefix, path))
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

/// What the store knows about one declared socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketState {
    /// The declaration.
    pub declaration: SocketRow,
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
        let n = self.conn().execute(
            "DELETE FROM socket_arms WHERE space = ?1 AND path = ?2",
            params![space, path],
        )?;
        Ok(n > 0)
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
               (space, path, config, allow_egress, allow_tree_read, max_streams, auto, note, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(space, path) DO UPDATE SET
               config = excluded.config,
               allow_egress = excluded.allow_egress,
               allow_tree_read = excluded.allow_tree_read,
               max_streams = excluded.max_streams,
               auto = excluded.auto,
               note = excluded.note",
            params![
                row.space,
                row.path,
                join_pairs(&row.config),
                row.allow_egress.join("\n"),
                row.allow_tree_read.join("\n"),
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

const SELECT_SOCKETS_BASE: &str = "SELECT s.space, s.path, s.config, s.allow_egress,
            s.allow_tree_read, s.max_streams, s.auto, s.note, s.added_at,
            a.root, a.declared, a.armed_at
       FROM sockets s
       LEFT JOIN socket_arms a ON a.space = s.space AND a.path = s.path";

const SELECT_SOCKETS: &str = "SELECT s.space, s.path, s.config, s.allow_egress,
            s.allow_tree_read, s.max_streams, s.auto, s.note, s.added_at,
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
        allow_egress: split_lines(&row.get::<_, String>(3)?),
        allow_tree_read: split_lines(&row.get::<_, String>(4)?),
        max_streams: row.get(5)?,
        auto: row.get::<_, i64>(6)? != 0,
        note: row.get(7)?,
        added_at: row.get(8)?,
    };
    let arm = match row.get::<_, Option<Vec<u8>>>(9)? {
        Some(bytes) => {
            let root = Hash::from_slice(&bytes).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Blob,
                    "socket_arms.root is not a 32-byte hash".into(),
                )
            })?;
            Some(ArmRow {
                space,
                path,
                root,
                declared: row.get(10)?,
                armed_at: row.get(11)?,
            })
        }
        None => None,
    };
    Ok(SocketState { declaration, arm })
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
            allow_egress: vec!["git.internal:9418".into()],
            allow_tree_read: vec!["code".into()],
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
        // The transition that has to be safe: an operator widens the egress
        // list and the old approval must not carry over onto the new terms.
        let (_d, store) = store();
        store.put_socket(&row()).unwrap();
        store
            .arm_socket("code", "git.sock", &Hash::new(b"elf"), "", 2)
            .unwrap();

        let mut wider = row();
        wider.allow_egress.push("anywhere.example:80".into());
        store.put_socket(&wider).unwrap();

        let got = store.socket("code", "git.sock").unwrap().unwrap();
        assert_eq!(got.declaration.allow_egress, wider.allow_egress);
        assert!(
            got.arm.is_none(),
            "a re-declaration carried its old approval onto new terms"
        );
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
    fn egress_rules_match_host_and_port_exactly() {
        let mut r = SocketRow::new("code", "s", 0);
        r.allow_egress = vec!["git.internal:9418".into(), "cache.internal".into()];

        assert!(r.egress_allowed("git.internal", 9418));
        assert!(!r.egress_allowed("git.internal", 22), "a port was ignored");
        // A bare host allows any port on it.
        assert!(r.egress_allowed("cache.internal", 6379));
        assert!(
            r.egress_allowed("CACHE.INTERNAL", 80),
            "DNS is case-insensitive"
        );
        // No suffix matching: a rule whose reach changes when somebody else
        // registers a name is not a rule.
        assert!(!r.egress_allowed("evil-git.internal", 9418));
        assert!(!r.egress_allowed("git.internal.evil.example", 9418));
        assert!(!SocketRow::new("code", "s", 0).egress_allowed("anything", 80));
    }

    #[test]
    fn an_ipv6_literal_rule_is_not_cut_at_its_first_colon() {
        let mut r = SocketRow::new("code", "s", 0);
        r.allow_egress = vec!["[::1]:9418".into()];
        assert!(r.egress_allowed("::1", 9418));
        assert!(!r.egress_allowed("::1", 9419));
    }

    #[test]
    fn tree_read_prefixes_stop_at_a_path_boundary() {
        let mut r = SocketRow::new("code", "s", 0);
        r.allow_tree_read = vec!["code/pub".into()];

        assert!(r.tree_read_allowed("code/pub"));
        assert!(r.tree_read_allowed("code/pub/readme"));
        assert!(
            !r.tree_read_allowed("code/public-secrets"),
            "a prefix matched across a path boundary"
        );
        assert!(!r.tree_read_allowed("code"));
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
