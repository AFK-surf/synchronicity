//! Socket activations (`docs/SOCKETS.md` §3, `docs/SOCKET-PROGRAMS.md` §2).
//!
//! A **socket** is a name in a namespace of this node's own — not a path, not
//! in any space, and not in the tree. An **activation**
//! ([`SocketActivation`]) binds that name to a **program**: an ordinary file
//! at `<space>/<path>` in this node's own tree, holding an eBPF object. Many
//! sockets may name one program, and each carries its own configuration,
//! stream cap, note and scope.
//!
//! The activation is a statement about the program *path*, never about a
//! content root. While a name is activated, **every write to its program path
//! is an intentional deployment**: the new content serves as soon as it
//! publishes, under whatever its own manifest declares.
//!
//! An activation is **local operator state**. It is never published,
//! replicated, or derived from a peer's trie, and that is the whole point: a
//! node's own tree is not a closed system — `synch adopt path`, `synch adopt
//! tree --replace` and an S3 `PUT` all write bytes into a filesystem-source
//! directory that the scanner then publishes as this node's own view — so
//! publication cannot be the gate on execution. Activating a program path is
//! the operator saying those write paths are, for that path, deployment
//! channels.
//!
//! Content roots still exist everywhere content does — CAS integrity,
//! replication, caching, and the snapshot a running invocation keeps — but no
//! root is ever an authorization pin.

use rusqlite::{params, OptionalExtension};

use crate::{
    db::{Store, Txn},
    error::{Result, StoreError},
};

use synch_core::MAX_SOCKETS_PER_NODE;

/// One activated socket: a name, the program behind it, and the operator's
/// half of the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketActivation {
    /// The socket's name — what a caller opens. Unique on this node, and
    /// meaningless on any other.
    pub name: String,
    /// The space the program file lives in.
    pub program_space: String,
    /// The program's path within that space.
    pub program_path: String,
    /// The spaces whose delegates may open this socket
    /// (`docs/SOCKET-PROGRAMS.md` §2.2). Empty means rooted members only,
    /// which is the default: offering a socket to delegates is the broader
    /// grant, so it is asked for by name.
    pub scope: Vec<String>,
    /// `k=v` pairs readable by the program through `sy_config_get`.
    pub config: Vec<(String, String)>,
    /// The concurrency cap, or `None` for the daemon's default.
    pub max_streams: Option<u32>,
    /// A free-form operator note.
    pub note: String,
    /// When the name was activated, unix nanoseconds.
    pub activated_at: i64,
}

impl SocketActivation {
    /// An activation with the defaults: members only, no config, the daemon's
    /// default concurrency, no note.
    pub fn new(
        name: impl Into<String>,
        program_space: impl Into<String>,
        program_path: impl Into<String>,
        activated_at: i64,
    ) -> Self {
        SocketActivation {
            name: name.into(),
            program_space: program_space.into(),
            program_path: program_path.into(),
            scope: Vec::new(),
            config: Vec::new(),
            max_streams: None,
            note: String::new(),
            activated_at,
        }
    }

    /// `<space>/<path>`, as every command and log line names the program.
    pub fn program(&self) -> String {
        format!("{}/{}", self.program_space, self.program_path)
    }

    /// The value of a config key, if the operator set one.
    pub fn config_get(&self, key: &str) -> Option<&str> {
        self.config
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Whether a caller with these read rights may open this socket.
    ///
    /// `None` is a rooted member, which may open any socket, as it may read
    /// any space. A delegate may open one only if one of its delegated spaces
    /// is in this activation's scope — so an empty scope admits members alone.
    pub fn admits(&self, delegated: Option<&[String]>) -> bool {
        match delegated {
            None => true,
            Some(spaces) => self.scope.iter().any(|s| spaces.contains(s)),
        }
    }
}

impl Store {
    /// Binds a socket name to a program, replacing any existing activation of
    /// that name: re-activating with a new program, config, scope or cap is a
    /// new bargain, applied to the next admission.
    pub fn activate_socket(&self, row: &SocketActivation) -> Result<()> {
        self.transaction(|txn| txn.activate_socket(row))
    }

    /// Every activated socket, ordered by name.
    pub fn socket_activations(&self) -> Result<Vec<SocketActivation>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("{SELECT_ACTIVATIONS} ORDER BY name"))?;
        let rows = stmt.query_map([], activation_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// One activation, by name.
    pub fn socket_activation(&self, name: &str) -> Result<Option<SocketActivation>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                &format!("{SELECT_ACTIVATIONS} WHERE name = ?1"),
                params![name],
                activation_row,
            )
            .optional()?)
    }

    /// Every socket this program path backs — the deployment fan-out's
    /// reverse lookup (`docs/SOCKET-PROGRAMS.md` §4), and what `activate` and
    /// `ls -l` print as a program's dependents.
    pub fn activations_backed_by(&self, space: &str, path: &str) -> Result<Vec<SocketActivation>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "{SELECT_ACTIVATIONS} WHERE program_space = ?1 AND program_path = ?2 ORDER BY name"
        ))?;
        let rows = stmt.query_map(params![space, path], activation_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Whether any activation names this path as its program.
    pub fn is_program_path(&self, space: &str, path: &str) -> Result<bool> {
        Ok(self
            .conn()
            .query_row(
                "SELECT 1 FROM socket_activations WHERE program_space = ?1 AND program_path = ?2",
                params![space, path],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Removes an activation by name. Admission refuses it immediately; the
    /// program file is untouched.
    pub fn deactivate_socket(&self, name: &str) -> Result<bool> {
        let n = self.conn().execute(
            "DELETE FROM socket_activations WHERE name = ?1",
            params![name],
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
    /// prefixes. A socket needs space *names* — to compare against the
    /// activation's scope, and to hand `sy_peer_has_space` something a program
    /// can ask about — and deriving names back out of prefixes would be
    /// reconstructing what this read already has.
    pub fn socket_scope_for_key(
        &self,
        node_id: &synch_core::NodeId,
        now: i64,
    ) -> Result<Option<(synch_core::OriginId, Option<Vec<String>>)>> {
        crate::lean_authorization::socket_authority(self, node_id, now)
    }
}

impl Txn<'_> {
    /// Activates a socket name, replacing any existing activation of it.
    pub fn activate_socket(&self, row: &SocketActivation) -> Result<()> {
        let activated: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM socket_activations WHERE name != ?1",
            params![row.name],
            |r| r.get(0),
        )?;
        if activated >= MAX_SOCKETS_PER_NODE as i64 {
            return Err(StoreError::Invalid(format!(
                "this node already activates {activated} sockets, the most one node may \
                 (docs/SOCKET-PROGRAMS.md §2.1)"
            )));
        }
        self.conn().execute(
            "INSERT INTO socket_activations
               (name, program_space, program_path, scope, config, max_streams, note, activated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(name) DO UPDATE SET
               program_space = excluded.program_space,
               program_path = excluded.program_path,
               scope = excluded.scope,
               config = excluded.config,
               max_streams = excluded.max_streams,
               note = excluded.note,
               activated_at = excluded.activated_at",
            params![
                row.name,
                row.program_space,
                row.program_path,
                row.scope.join("\n"),
                join_pairs(&row.config),
                row.max_streams,
                row.note,
                row.activated_at,
            ],
        )?;
        Ok(())
    }
}

const SELECT_ACTIVATIONS: &str = "SELECT name, program_space, program_path, scope, config, \
                                  max_streams, note, activated_at FROM socket_activations";

fn activation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SocketActivation> {
    Ok(SocketActivation {
        name: row.get(0)?,
        program_space: row.get(1)?,
        program_path: row.get(2)?,
        scope: split_lines(&row.get::<_, String>(3)?),
        config: split_pairs(&row.get::<_, String>(4)?),
        max_streams: row.get(5)?,
        note: row.get(6)?,
        activated_at: row.get(7)?,
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
            scope: vec!["code".into()],
            config: vec![("upstream".into(), "git.internal".into())],
            max_streams: Some(32),
            ..SocketActivation::new("git", "code", "bin/gateway.o", 1)
        }
    }

    #[test]
    fn an_activation_round_trips() {
        let (_d, store) = store();
        store.activate_socket(&row()).unwrap();
        let got = store.socket_activation("git").unwrap().unwrap();
        assert_eq!(got, row());
        assert_eq!(got.program(), "code/bin/gateway.o");
        assert!(store.socket_activation("hg").unwrap().is_none());
    }

    #[test]
    fn reactivating_replaces_the_terms() {
        let (_d, store) = store();
        store.activate_socket(&row()).unwrap();
        let mut changed = row();
        changed.config.push(("mode".into(), "strict".into()));
        changed.max_streams = Some(8);
        changed.scope = vec!["docs".into(), "code".into()];
        changed.program_path = "bin/gateway2.o".into();
        store.activate_socket(&changed).unwrap();
        let got = store.socket_activation("git").unwrap().unwrap();
        assert_eq!(got, changed);
    }

    #[test]
    fn deactivating_removes_the_gate() {
        let (_d, store) = store();
        store.activate_socket(&row()).unwrap();
        assert!(store.deactivate_socket("git").unwrap());
        assert!(store.socket_activation("git").unwrap().is_none());
        assert!(
            !store.deactivate_socket("git").unwrap(),
            "deactivating twice reports there was nothing to remove"
        );
    }

    #[test]
    fn one_program_backs_every_socket_that_names_it() {
        let (_d, store) = store();
        for name in ["git", "hg", "docs/git"] {
            store
                .activate_socket(&SocketActivation::new(name, "code", "bin/gateway.o", 1))
                .unwrap();
        }
        store
            .activate_socket(&SocketActivation::new("other", "code", "bin/other.o", 1))
            .unwrap();

        let backed = store
            .activations_backed_by("code", "bin/gateway.o")
            .unwrap();
        assert_eq!(
            backed.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            ["docs/git", "git", "hg"],
            "the reverse lookup must name every dependent of one program"
        );
        assert!(store.is_program_path("code", "bin/gateway.o").unwrap());
        assert!(!store.is_program_path("code", "bin/absent.o").unwrap());
        assert!(store
            .activations_backed_by("code", "bin")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn scope_admits_members_always_and_delegates_by_space() {
        let members_only = SocketActivation::new("git", "code", "bin/gateway.o", 1);
        assert!(
            members_only.admits(None),
            "a rooted member opens any socket"
        );
        assert!(!members_only.admits(Some(&["code".to_string()])));

        let scoped = SocketActivation {
            scope: vec!["docs".into()],
            ..members_only
        };
        assert!(scoped.admits(None));
        assert!(scoped.admits(Some(&["docs".to_string(), "media".to_string()])));
        assert!(!scoped.admits(Some(&["code".to_string()])));
    }

    #[test]
    fn a_node_may_not_activate_more_sockets_than_the_bound() {
        let (_d, store) = store();
        for i in 0..MAX_SOCKETS_PER_NODE {
            store
                .activate_socket(&SocketActivation::new(
                    format!("s{i}"),
                    "code",
                    "bin/gateway.o",
                    0,
                ))
                .unwrap();
        }
        // Re-activating one already counted stays legal: the bound is on how
        // many exist, not on how often they are written.
        store
            .activate_socket(&SocketActivation::new("s0", "code", "bin/gateway.o", 0))
            .unwrap();
        let out = store.activate_socket(&SocketActivation::new(
            "one-too-many",
            "code",
            "bin/gateway.o",
            0,
        ));
        assert!(matches!(out, Err(StoreError::Invalid(_))), "{out:?}");
    }
}
