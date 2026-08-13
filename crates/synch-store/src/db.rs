//! The SQLite store: open, configuration, device keys, and the trie node store.

use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Mutex, MutexGuard, PoisonError},
};

use iroh_base::SecretKey;
use rusqlite::{params, Connection, OptionalExtension};
use synch_core::{Hash, NodeId, OriginId};
use synch_mpt::NodeStore;

use crate::{
    error::{Result, StoreError},
    schema::{Migration, MIGRATIONS},
};

/// Directory under the data dir holding blob payloads and outboards (§6.2).
pub const CAS_DIR: &str = "store";
/// The database file name (§10).
pub const DB_FILE: &str = "synchronicity.db";

/// The state of a locally held device key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// The key currently used for signing and for the primary endpoint.
    Active,
    /// A key kept alive through a rotation window (§3.4).
    Retiring,
}

impl KeyState {
    /// The `state` column value.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyState::Active => "active",
            KeyState::Retiring => "retiring",
        }
    }

    /// Parses the `state` column value.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "active" => Ok(KeyState::Active),
            "retiring" => Ok(KeyState::Retiring),
            other => Err(StoreError::column("device_keys.state", other)),
        }
    }
}

/// A locally held device key.
#[derive(Debug, Clone)]
pub struct DeviceKey {
    /// The public half, which is also the iroh endpoint id.
    pub node_id: NodeId,
    /// The secret half.
    pub secret: SecretKey,
    /// Whether the key is active or retiring.
    pub state: KeyState,
    /// When the key was generated, in unix nanoseconds.
    pub created_at: i64,
}

/// The node's metadata store.
///
/// All writes funnel through one mutex-guarded connection, which is how the
/// §10 "single writer task" discipline is realized here: every multi-step state
/// change (head flips, publish batches) runs inside one SQLite transaction on
/// that connection, so no partial state is ever observable.
#[derive(Debug)]
pub struct Store {
    conn: Mutex<Connection>,
    data_dir: PathBuf,
}

impl Store {
    /// Opens (creating if needed) the store rooted at `data_dir`.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Store> {
        let data_dir = data_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&data_dir)?;
        std::fs::create_dir_all(data_dir.join(CAS_DIR))?;
        let conn = Connection::open(data_dir.join(DB_FILE))?;
        let store = Store {
            conn: Mutex::new(conn),
            data_dir,
        };
        store.init()?;
        Ok(store)
    }

    /// Opens a purely in-memory store backed by a temporary CAS directory.
    ///
    /// Intended for tests; `data_dir` still receives blob payloads.
    pub fn open_in_memory(data_dir: impl AsRef<Path>) -> Result<Store> {
        let data_dir = data_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(data_dir.join(CAS_DIR))?;
        let store = Store {
            conn: Mutex::new(Connection::open_in_memory()?),
            data_dir,
        };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> Result<()> {
        let mut conn = self.conn();
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // WAL keeps readers off the writer's back; NORMAL is the §10 setting.
        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;
        migrate(&mut conn, MIGRATIONS)?;
        Ok(())
    }

    /// The data directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The CAS root directory.
    pub fn cas_dir(&self) -> PathBuf {
        self.data_dir.join(CAS_DIR)
    }

    pub(crate) fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `f` inside a single SQLite transaction, committing on `Ok`.
    ///
    /// This is the unit of atomicity for head flips and publish batches (§10).
    pub fn transaction<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    // ---- config -----------------------------------------------------------

    /// Reads a config value.
    pub fn config(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT value FROM config WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Writes a config value.
    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO config (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Deletes a config value.
    pub fn clear_config(&self, key: &str) -> Result<()> {
        self.conn()
            .execute("DELETE FROM config WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// This node's own [`OriginId`], if `synch init` has run.
    pub fn self_origin(&self) -> Result<Option<OriginId>> {
        match self.config("self_origin_id")? {
            None => Ok(None),
            Some(text) => OriginId::from_str(&text)
                .map(Some)
                .map_err(|e| StoreError::column("config.self_origin_id", e.to_string())),
        }
    }

    /// Sets this node's own [`OriginId`].
    pub fn set_self_origin(&self, origin: &OriginId) -> Result<()> {
        self.set_config("self_origin_id", &origin.canonical())
    }

    // ---- device keys ------------------------------------------------------

    /// Stores a device key.
    pub fn add_device_key(&self, secret: &SecretKey, state: KeyState, now: i64) -> Result<()> {
        self.conn().execute(
            "INSERT INTO device_keys (node_id, secret_key, state, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(node_id) DO UPDATE SET state = excluded.state",
            params![
                secret.public().as_bytes().to_vec(),
                secret.to_bytes().to_vec(),
                state.as_str(),
                now
            ],
        )?;
        Ok(())
    }

    /// Every locally held device key, active ones first.
    pub fn device_keys(&self) -> Result<Vec<DeviceKey>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT node_id, secret_key, state, created_at FROM device_keys
             ORDER BY state = 'active' DESC, created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (node_id, secret, state, created_at) = row?;
            let node_id: [u8; 32] = node_id
                .try_into()
                .map_err(|_| StoreError::column("device_keys.node_id", "not 32 bytes"))?;
            let secret: [u8; 32] = secret
                .try_into()
                .map_err(|_| StoreError::column("device_keys.secret_key", "not 32 bytes"))?;
            out.push(DeviceKey {
                node_id: NodeId::from_bytes(&node_id)
                    .map_err(|e| StoreError::column("device_keys.node_id", e.to_string()))?,
                secret: SecretKey::from_bytes(&secret),
                state: KeyState::parse(&state)?,
                created_at,
            });
        }
        Ok(out)
    }

    /// The key currently used for signing (§3.4: exactly one at any moment).
    pub fn active_device_key(&self) -> Result<Option<DeviceKey>> {
        Ok(self
            .device_keys()?
            .into_iter()
            .find(|k| k.state == KeyState::Active))
    }

    /// Marks a device key as retiring or active.
    pub fn set_device_key_state(&self, node_id: &NodeId, state: KeyState) -> Result<()> {
        self.conn().execute(
            "UPDATE device_keys SET state = ?2 WHERE node_id = ?1",
            params![node_id.as_bytes().to_vec(), state.as_str()],
        )?;
        Ok(())
    }

    /// Deletes a retired device key's secret (§3.4 step 4).
    pub fn remove_device_key(&self, node_id: &NodeId) -> Result<()> {
        self.conn().execute(
            "DELETE FROM device_keys WHERE node_id = ?1",
            params![node_id.as_bytes().to_vec()],
        )?;
        Ok(())
    }
}

// ---- migrations ------------------------------------------------------------

/// The version a database is stamped with, or 0 for an empty one.
///
/// A database with a `config` table but no stamp is refused rather than
/// guessed at: every database this software has ever written stamps itself
/// inside the transaction that shaped it (§10), so an unstamped one is not a
/// version this build can reason about.
fn stamped_version(conn: &Connection) -> Result<u32> {
    let bootstrapped = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'config'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !bootstrapped {
        return Ok(0);
    }
    let stamp: Option<String> = conn
        .query_row(
            "SELECT value FROM config WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match stamp {
        None => Err(StoreError::invalid(
            "this database has a config table but no schema_version stamp, \
             so its shape cannot be determined",
        )),
        Some(text) => text.trim().parse::<u32>().map_err(|_| {
            StoreError::invalid(format!(
                "database schema version {text:?} is not a version number this build understands"
            ))
        }),
    }
}

/// Replays `chain` from wherever `conn` currently is up to its end (§10).
///
/// Each step is one transaction that also carries the `schema_version` stamp,
/// so an interrupted upgrade leaves the database at some version of the chain
/// and never between two. A database stamped past the end of the chain is
/// refused: this build cannot know what it would be reading.
///
/// Takes the chain as an argument rather than reading [`MIGRATIONS`] directly
/// so that tests can drive a chain whose steps fail on purpose.
pub(crate) fn migrate(conn: &mut Connection, chain: &[Migration]) -> Result<u32> {
    let target = chain.len() as u32;
    let found = stamped_version(conn)?;
    if found > target {
        return Err(StoreError::invalid(format!(
            "database schema version {found} is newer than this build supports (expected {target}): \
             upgrade synchronicity rather than downgrading the database"
        )));
    }
    for version in found..target {
        let tx = conn.transaction()?;
        match &chain[version as usize] {
            Migration::Sql(sql) => tx.execute_batch(sql)?,
            Migration::Rust { name, run } => run(&tx).map_err(|e| {
                StoreError::invalid(format!(
                    "migration to version {} ({name}): {e}",
                    version + 1
                ))
            })?,
        }
        // Inside the same transaction as the change it describes: that is what
        // makes a crash land exactly on a version.
        tx.execute(
            "INSERT INTO config (key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![(version + 1).to_string()],
        )?;
        tx.commit()?;
    }
    if found != target {
        tracing::info!(from = found, to = target, "database schema migrated");
    }
    Ok(target)
}

// ---- the trie node store ---------------------------------------------------

impl NodeStore for Store {
    type Error = StoreError;

    fn get_node(&self, hash: &Hash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT data FROM trie_nodes WHERE hash = ?1",
                params![hash.as_bytes().to_vec()],
                |r| r.get(0),
            )
            .optional()?)
    }

    fn put_node(&self, hash: &Hash, data: &[u8]) -> Result<()> {
        self.conn().execute(
            "INSERT OR IGNORE INTO trie_nodes (hash, data) VALUES (?1, ?2)",
            params![hash.as_bytes().to_vec(), data],
        )?;
        Ok(())
    }

    fn get_value(&self, hash: &Hash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT data FROM trie_values WHERE hash = ?1",
                params![hash.as_bytes().to_vec()],
                |r| r.get(0),
            )
            .optional()?)
    }

    fn put_value(&self, hash: &Hash, data: &[u8]) -> Result<()> {
        self.conn().execute(
            "INSERT OR IGNORE INTO trie_values (hash, data) VALUES (?1, ?2)",
            params![hash.as_bytes().to_vec(), data],
        )?;
        Ok(())
    }

    fn has_node(&self, hash: &Hash) -> Result<bool> {
        Ok(self
            .conn()
            .query_row(
                "SELECT 1 FROM trie_nodes WHERE hash = ?1",
                params![hash.as_bytes().to_vec()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    fn has_value(&self, hash: &Hash) -> Result<bool> {
        Ok(self
            .conn()
            .query_row(
                "SELECT 1 FROM trie_values WHERE hash = ?1",
                params![hash.as_bytes().to_vec()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
}

/// Reads a 32-byte hash column.
pub(crate) fn hash_column(bytes: Vec<u8>, column: &'static str) -> Result<Hash> {
    Hash::from_slice(&bytes).map_err(|_| StoreError::column(column, "not 32 bytes"))
}

/// Reads a 32-byte device-key column.
pub(crate) fn key_column(bytes: Vec<u8>, column: &'static str) -> Result<NodeId> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StoreError::column(column, "not 32 bytes"))?;
    NodeId::from_bytes(&arr).map_err(|e| StoreError::column(column, e.to_string()))
}

/// Reads an origin-id column.
pub(crate) fn origin_column(text: String, column: &'static str) -> Result<OriginId> {
    OriginId::from_str(&text).map_err(|e| StoreError::column(column, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SCHEMA_VERSION;
    use rusqlite::Transaction;
    use synch_mpt::Trie;

    fn temp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn opens_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            store.set_config("hello", "world").unwrap();
        }
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.config("hello").unwrap().as_deref(), Some("world"));
        assert!(dir.path().join(DB_FILE).exists());
        assert!(dir.path().join(CAS_DIR).is_dir());
    }

    #[test]
    fn wal_mode_is_enabled() {
        let (_dir, store) = temp_store();
        let mode: String = store
            .conn()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn config_round_trip() {
        let (_dir, store) = temp_store();
        assert_eq!(store.config("missing").unwrap(), None);
        store.set_config("k", "v1").unwrap();
        store.set_config("k", "v2").unwrap();
        assert_eq!(store.config("k").unwrap().as_deref(), Some("v2"));
        store.clear_config("k").unwrap();
        assert_eq!(store.config("k").unwrap(), None);
    }

    #[test]
    fn self_origin_round_trip() {
        let (_dir, store) = temp_store();
        assert_eq!(store.self_origin().unwrap(), None);
        let origin = OriginId::named("nas", "cluster.example.com").unwrap();
        store.set_self_origin(&origin).unwrap();
        assert_eq!(store.self_origin().unwrap(), Some(origin));
    }

    #[test]
    fn device_keys_round_trip() {
        let (_dir, store) = temp_store();
        let old = SecretKey::generate();
        let new = SecretKey::generate();
        store.add_device_key(&old, KeyState::Active, 1).unwrap();
        assert_eq!(
            store.active_device_key().unwrap().unwrap().node_id,
            old.public()
        );

        // A rotation window has both keys present, exactly one active.
        store
            .set_device_key_state(&old.public(), KeyState::Retiring)
            .unwrap();
        store.add_device_key(&new, KeyState::Active, 2).unwrap();
        let keys = store.device_keys().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].node_id, new.public());
        assert_eq!(keys[0].state, KeyState::Active);
        assert_eq!(
            store.active_device_key().unwrap().unwrap().node_id,
            new.public()
        );
        assert_eq!(keys[0].secret.to_bytes(), new.to_bytes());

        store.remove_device_key(&old.public()).unwrap();
        assert_eq!(store.device_keys().unwrap().len(), 1);
    }

    #[test]
    fn store_is_a_trie_node_store() {
        let (_dir, store) = temp_store();
        let trie = Trie::new(&store);
        let mut root = Hash::EMPTY;
        for i in 0..50u8 {
            root = trie.insert(root, &[i], &[i; 200]).unwrap();
        }
        assert!(trie.is_complete(root).unwrap());
        assert_eq!(trie.get(root, &[7]).unwrap().unwrap(), [7u8; 200].to_vec());
        assert_eq!(trie.iter(root).unwrap().len(), 50);
    }

    #[test]
    fn transactions_roll_back_on_error() {
        let (_dir, store) = temp_store();
        let err = store.transaction(|tx| {
            tx.execute(
                "INSERT INTO config (key, value) VALUES ('a', 'b')",
                params![],
            )?;
            Err::<(), _>(StoreError::invalid("boom"))
        });
        assert!(err.is_err());
        assert_eq!(store.config("a").unwrap(), None);
    }

    #[test]
    fn schema_version_mismatch_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            store.set_config("schema_version", "999").unwrap();
        }
        let err = Store::open(dir.path()).unwrap_err().to_string();
        assert!(err.contains("newer than this build"), "{err}");

        // Nor is a version this build cannot even parse.
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            store.set_config("schema_version", "tomorrow").unwrap();
        }
        assert!(Store::open(dir.path()).is_err());

        // Nor one that never said what shape it is in.
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Store::open(dir.path()).unwrap();
            store.clear_config("schema_version").unwrap();
        }
        assert!(Store::open(dir.path()).is_err());
    }

    fn table_exists(store: &Store, name: &str) -> bool {
        store
            .conn()
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                params![name],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_some()
    }

    /// Every object `sqlite_master` holds, with its DDL normalized so that
    /// comments and line breaks do not count as differences.
    fn objects(conn: &Connection) -> Vec<(String, String, String)> {
        let mut stmt = conn
            .prepare(
                "SELECT type, name, COALESCE(sql, '') FROM sqlite_master
                 WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    normalize_ddl(&row.get::<_, String>(2)?),
                ))
            })
            .unwrap();
        rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    /// Drops SQL comments and collapses whitespace, so two spellings of the
    /// same declaration compare equal.
    fn normalize_ddl(sql: &str) -> String {
        sql.lines()
            .map(|line| match line.find("--") {
                Some(idx) => &line[..idx],
                None => line,
            })
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The chain is the only path to a database, and what it produces is what
    /// §10 documents — compared object by object over the whole of
    /// `sqlite_master`, not just by table name.
    #[test]
    fn the_chain_produces_the_documented_schema() {
        let mut chained = Connection::open_in_memory().unwrap();
        migrate(&mut chained, MIGRATIONS).unwrap();

        let documented = Connection::open_in_memory().unwrap();
        documented
            .execute_batch(crate::schema::FINAL_SCHEMA)
            .unwrap();

        assert_eq!(
            objects(&chained),
            objects(&documented),
            "replaying the chain must yield exactly the documented §10 schema"
        );
        // And the chain leaves nothing of the tables it retired behind.
        assert!(!objects(&chained).iter().any(|(_, name, _)| name == "want"));
    }

    /// A database at the version each historical step left it at upgrades to
    /// the current one with its data intact.
    ///
    /// The old shapes are built here from the chain itself — a database stamped
    /// `v` is exactly what replaying the first `v` steps produces — so the test
    /// exercises the real historical layouts rather than an approximation.
    fn database_at(dir: &Path, version: u32) -> Connection {
        let mut conn = Connection::open(dir.join(DB_FILE)).unwrap();
        migrate(&mut conn, &MIGRATIONS[..version as usize]).unwrap();
        conn
    }

    #[test]
    fn a_v2_database_upgrades_with_its_data() {
        let dir = tempfile::tempdir().unwrap();
        {
            let conn = database_at(dir.path(), 2);
            assert!(
                conn.query_row("SELECT COUNT(*) FROM want", [], |r| r.get::<_, i64>(0))
                    .is_ok(),
                "a v2 database still has the want table"
            );
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('keep', 'me')",
                params![],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO mirrors (origin_id, space, local_path) VALUES (?1, ?2, ?3)",
                params!["nas@x.example", "media", "/mnt/nas"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('s3_buckets', ?1)",
                params!["photos\tnas@x.example\tmedia"],
            )
            .unwrap();
        }

        let store = Store::open(dir.path()).unwrap();
        assert_eq!(
            store.config("schema_version").unwrap().as_deref(),
            Some(SCHEMA_VERSION.to_string().as_str())
        );
        assert!(!table_exists(&store, "want"), "v3 drops it");
        assert_eq!(store.config("keep").unwrap().as_deref(), Some("me"));
        // v4 carried the mirror over as an origin pin, preserving its behavior.
        let mirrors = store.mirrors().unwrap();
        assert_eq!(mirrors.len(), 1);
        assert_eq!(mirrors[0].local_path, "/mnt/nas");
        assert_eq!(mirrors[0].space, "media");
        assert_eq!(mirrors[0].policy.render(), "origin=nas@x.example");
        // v5 did the same for the s3 bucket map.
        assert_eq!(
            store.config("s3_buckets").unwrap().as_deref(),
            Some("photos\tmedia\torigin=nas@x.example")
        );
    }

    #[test]
    fn a_v3_database_upgrades_with_its_data() {
        let dir = tempfile::tempdir().unwrap();
        {
            let conn = database_at(dir.path(), 3);
            assert!(
                conn.query_row("SELECT COUNT(*) FROM want", [], |r| r.get::<_, i64>(0))
                    .is_err(),
                "a v3 database has already lost the want table"
            );
            conn.execute(
                "INSERT INTO mirrors (origin_id, space, local_path) VALUES (?1, ?2, ?3)",
                params!["laptop@x.example", "media", "/mnt/one"],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO observed_heads (origin_id, seq, root, complete, observed_at)
                 VALUES ('nas@x.example', 7, zeroblob(32), 1, 1)",
                params![],
            )
            .unwrap();
        }

        let store = Store::open(dir.path()).unwrap();
        assert_eq!(
            store.config("schema_version").unwrap().as_deref(),
            Some(SCHEMA_VERSION.to_string().as_str())
        );
        assert_eq!(
            store.mirrors().unwrap()[0].policy.render(),
            "origin=laptop@x.example"
        );
        // The v2 table and its rows are untouched by the later steps.
        assert_eq!(store.observed_heads().unwrap().len(), 1);
    }

    /// A step that fails takes its whole transaction with it, stamp included,
    /// so the database is left at the version before it rather than between two.
    #[test]
    fn a_failing_step_leaves_the_version_where_it_was() {
        fn explode(_tx: &Transaction<'_>) -> Result<()> {
            Err(StoreError::invalid("boom"))
        }
        let chain: &[Migration] = &[
            Migration::Sql(
                "CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE first (a TEXT);",
            ),
            Migration::Rust {
                name: "explodes",
                run: explode,
            },
            Migration::Sql("CREATE TABLE third (a TEXT);"),
        ];

        let mut conn = Connection::open_in_memory().unwrap();
        let err = migrate(&mut conn, chain).unwrap_err().to_string();
        assert!(err.contains("explodes"), "{err}");
        assert!(err.contains("boom"), "{err}");

        // Version 1 committed; the failing step's transaction rolled back
        // whole, so nothing it or the step after it would have created exists.
        let stamp: String = conn
            .query_row(
                "SELECT value FROM config WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stamp, "1");
        assert!(conn
            .query_row("SELECT COUNT(*) FROM first", [], |r| r.get::<_, i64>(0))
            .is_ok());
        assert!(conn
            .query_row("SELECT COUNT(*) FROM third", [], |r| r.get::<_, i64>(0))
            .is_err());

        // And resuming from that version replays the rest of the chain, so a
        // crashed upgrade is finished by the next open rather than repaired.
        let fixed: &[Migration] = &[
            Migration::Sql(
                "CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE first (a TEXT);",
            ),
            Migration::Sql("CREATE TABLE second (a TEXT);"),
            Migration::Sql("CREATE TABLE third (a TEXT);"),
        ];
        assert_eq!(migrate(&mut conn, fixed).unwrap(), 3);
        assert!(conn
            .query_row("SELECT COUNT(*) FROM third", [], |r| r.get::<_, i64>(0))
            .is_ok());
    }

    /// Re-opening a database at the current version changes nothing.
    #[test]
    fn migrating_a_current_database_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let before = objects(&store.conn());
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(objects(&store.conn()), before);
        assert_eq!(
            store.config("schema_version").unwrap().as_deref(),
            Some(SCHEMA_VERSION.to_string().as_str())
        );
    }
}
