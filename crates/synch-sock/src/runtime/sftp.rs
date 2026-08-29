//! A bounded, scope-confined SFTP v3 service over the immutable tree API.

use std::{collections::HashMap, sync::Arc};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};

use crate::{HostEntryKind, HostError, ListPage, ObjectInfo, SocketHost};

const ACCESS_READ: u32 = 0x01;
const ACCESS_RECURSIVE: u32 = 0x04;
const MAX_READ: u32 = 64 * 1024;
const MAX_OPEN_HANDLES: usize = 64;
const LIST_PAGE_ENTRIES: usize = 128;
const MAX_READDIR_ENTRIES: usize = 64;
const MAX_READDIR_BYTES: usize = 64 * 1024;
const MAX_READDIR_PAGES: usize = 32;

#[derive(Debug)]
struct DirectoryCursor {
    prefix: String,
    after: Option<String>,
    last_child: Option<String>,
    eof: bool,
}

#[derive(Debug)]
enum OpenHandle {
    File(ObjectInfo),
    Directory(DirectoryCursor),
}

pub(crate) struct TreeSftp {
    host: Arc<dyn SocketHost>,
    scope: String,
    access: u32,
    next_handle: u64,
    handles: HashMap<String, OpenHandle>,
}

impl std::fmt::Debug for TreeSftp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeSftp")
            .field("scope", &self.scope)
            .field("access", &self.access)
            .field("open_handles", &self.handles.len())
            .finish()
    }
}

impl TreeSftp {
    pub(crate) fn new(host: Arc<dyn SocketHost>, scope: String, access: u32) -> Self {
        Self {
            host,
            scope,
            access,
            next_handle: 1,
            handles: HashMap::new(),
        }
    }

    fn path(&self, requested: &str) -> Result<String, StatusCode> {
        let relative = requested.trim_start_matches('/');
        if relative.is_empty() || relative == "." {
            return Ok(self.scope.clone());
        }
        let normalized =
            synch_core::normalize_path(relative).map_err(|_| StatusCode::PermissionDenied)?;
        if self.access & ACCESS_RECURSIVE == 0 && normalized.contains('/') {
            return Err(StatusCode::PermissionDenied);
        }
        Ok(format!("{}/{}", self.scope, normalized))
    }

    fn allocate(&mut self, value: OpenHandle) -> Result<String, StatusCode> {
        if self.handles.len() >= MAX_OPEN_HANDLES {
            return Err(StatusCode::Failure);
        }
        let handle = format!("h{:016x}", self.next_handle);
        self.next_handle = self.next_handle.wrapping_add(1).max(1);
        self.handles.insert(handle.clone(), value);
        Ok(handle)
    }

    async fn open_info(&self, path: String) -> Result<ObjectInfo, StatusCode> {
        let host = self.host.clone();
        tokio::task::spawn_blocking(move || host.open(None, &path))
            .await
            .map_err(|_| StatusCode::Failure)?
            .map_err(host_error)
    }

    /// The entry kind of `path` without opening its content, so readdir can
    /// distinguish a directory (whose open() refusal is legitimate) from a
    /// socket, symlink, or tombstone the host deliberately refuses. A host
    /// without kind support fails here, and the caller then skips the entry —
    /// fail-closed, never a fabricated attribute.
    async fn entry_kind(&self, path: String) -> Result<HostEntryKind, StatusCode> {
        let host = self.host.clone();
        tokio::task::spawn_blocking(move || host.entry_kind(None, &path))
            .await
            .map_err(|_| StatusCode::Failure)?
            .map_err(host_error)
    }

    async fn list(&self, prefix: String, after: Option<String>) -> Result<ListPage, StatusCode> {
        let host = self.host.clone();
        tokio::task::spawn_blocking(move || {
            host.list_page(&prefix, after.as_deref(), LIST_PAGE_ENTRIES)
        })
        .await
        .map_err(|_| StatusCode::Failure)?
        .map_err(host_error)
    }

    async fn read_directory(
        &self,
        id: u32,
        cursor: &mut DirectoryCursor,
    ) -> Result<Name, StatusCode> {
        if cursor.eof {
            return Err(StatusCode::Eof);
        }
        let start = format!("{}/", cursor.prefix);
        let mut files = Vec::new();
        let mut response_bytes = 0usize;

        // A request scans a bounded number of storage pages. The cursor still
        // advances monotonically and any entries already found are returned;
        // if the whole budget contains only refused/filtered rows, fail the
        // request instead of returning an empty Name (which OpenSSH mistakes
        // for eof) or monopolizing the storage/blocking pools indefinitely.
        for _ in 0..MAX_READDIR_PAGES {
            let page = self
                .list(cursor.prefix.clone(), cursor.after.clone())
                .await?;
            if page.entries.len() > LIST_PAGE_ENTRIES
                || page
                    .next
                    .as_ref()
                    .is_some_and(|next| cursor.after.as_ref().is_some_and(|after| next <= after))
            {
                return Err(StatusCode::Failure);
            }

            let mut consumed_page = true;
            for full in page.entries {
                if cursor.after.as_ref().is_some_and(|after| full <= *after) {
                    return Err(StatusCode::Failure);
                }
                let Some(rest) = full.strip_prefix(&start) else {
                    cursor.after = Some(full);
                    continue;
                };
                let Some(name) = rest.split('/').next() else {
                    cursor.after = Some(full);
                    continue;
                };
                if name.is_empty() || cursor.last_child.as_deref() == Some(name) {
                    cursor.after = Some(full);
                    continue;
                }
                let encoded_bound = name.len().saturating_mul(2).saturating_add(256);
                if !files.is_empty()
                    && (files.len() >= MAX_READDIR_ENTRIES
                        || response_bytes.saturating_add(encoded_bound) > MAX_READDIR_BYTES)
                {
                    consumed_page = false;
                    break;
                }
                if encoded_bound > MAX_READDIR_BYTES {
                    return Err(StatusCode::Failure);
                }
                let child = format!("{start}{name}");
                let (attributes, subtree_end) = match self.open_info(child.clone()).await {
                    Ok(info) => (attrs(&info), None),
                    Err(_) => match self.entry_kind(child).await {
                        // A directory has no content, so open() refuses it;
                        // the kind is the honest source of its attributes.
                        Ok(HostEntryKind::Directory) => {
                            let mut attrs = FileAttributes {
                                permissions: Some(0o040555),
                                ..Default::default()
                            };
                            attrs.set_dir(true);
                            // All descendant storage keys start with
                            // `<start><name>/`. Replacing that trailing slash
                            // with `0` produces the first ASCII key after the
                            // whole subtree, so the next page can jump there
                            // instead of scanning every descendant row.
                            (attrs, Some(format!("{start}{name}0")))
                        }
                        // Anything else -- a socket, symlink, tombstone, or a
                        // path the host refused to classify -- must not be
                        // presented as a directory with fabricated attributes.
                        // Skip it; the cursor still advances past the row, so
                        // the scan keeps making progress.
                        _ => {
                            cursor.after = Some(full);
                            continue;
                        }
                    },
                };
                response_bytes = response_bytes.saturating_add(encoded_bound);
                files.push(File::new(name, attributes));
                cursor.last_child = Some(name.to_string());
                cursor.after = Some(full);
                if let Some(subtree_end) = subtree_end {
                    cursor.after = Some(subtree_end);
                    consumed_page = false;
                    break;
                }
            }

            if !consumed_page {
                break;
            }
            match page.next {
                Some(next) => cursor.after = Some(next),
                None => {
                    cursor.eof = true;
                    break;
                }
            }
            if files.len() >= MAX_READDIR_ENTRIES || response_bytes >= MAX_READDIR_BYTES {
                break;
            }
        }

        if files.is_empty() {
            if cursor.eof {
                Err(StatusCode::Eof)
            } else {
                Err(StatusCode::Failure)
            }
        } else {
            Ok(Name { id, files })
        }
    }
}

fn host_error(error: HostError) -> StatusCode {
    match error {
        HostError::NotFound => StatusCode::NoSuchFile,
        HostError::NotReadable(_) => StatusCode::PermissionDenied,
        HostError::Unavailable(_) => StatusCode::Failure,
    }
}

fn attrs(info: &ObjectInfo) -> FileAttributes {
    FileAttributes {
        size: Some(info.size),
        permissions: Some(if info.mode == 0 {
            0o100444
        } else {
            0o100000 | info.mode
        }),
        mtime: Some((info.mtime_ns.max(0) as u64 / 1_000_000_000).min(u32::MAX as u64) as u32),
        ..Default::default()
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

impl russh_sftp::server::Handler for TreeSftp {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        if self.access & ACCESS_READ == 0
            || !pflags.contains(OpenFlags::READ)
            || pflags.intersects(
                OpenFlags::WRITE
                    | OpenFlags::APPEND
                    | OpenFlags::CREATE
                    | OpenFlags::TRUNCATE
                    | OpenFlags::EXCLUDE,
            )
        {
            return Err(StatusCode::PermissionDenied);
        }
        let info = self.open_info(self.path(&filename)?).await?;
        let handle = self.allocate(OpenHandle::File(info))?;
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles
            .remove(&handle)
            .map(|_| ok(id))
            .ok_or(StatusCode::Failure)
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let info = match self.handles.get(&handle) {
            Some(OpenHandle::File(info)) => info.clone(),
            _ => return Err(StatusCode::Failure),
        };
        if offset >= info.size {
            return Err(StatusCode::Eof);
        }
        let bytes = self
            .host
            .pread(info.root, offset, u64::from(len.min(MAX_READ)))
            .await
            .map_err(host_error)?;
        if bytes.is_empty() {
            return Err(StatusCode::Eof);
        }
        Ok(Data { id, data: bytes })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        match self.handles.get(&handle) {
            Some(OpenHandle::File(info)) => Ok(Attrs {
                id,
                attrs: attrs(info),
            }),
            _ => Err(StatusCode::Failure),
        }
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let info = self.open_info(self.path(&path)?).await?;
        Ok(Attrs {
            id,
            attrs: attrs(&info),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let prefix = self.path(&path)?;
        // A flat scope's declared surface is its root listing: enumerating
        // inside a depth-1 child would disclose depth-2 names even though
        // the capability never granted recursion. The single-component
        // requests gate in path() still rejects anything deeper.
        if self.access & ACCESS_RECURSIVE == 0 && prefix != self.scope {
            return Err(StatusCode::PermissionDenied);
        }
        let handle = self.allocate(OpenHandle::Directory(DirectoryCursor {
            prefix,
            after: None,
            last_child: None,
            eof: false,
        }))?;
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(open) = self.handles.remove(&handle) else {
            return Err(StatusCode::Failure);
        };
        let OpenHandle::Directory(mut cursor) = open else {
            self.handles.insert(handle, open);
            return Err(StatusCode::Failure);
        };
        let result = self.read_directory(id, &mut cursor).await;
        self.handles.insert(handle, OpenHandle::Directory(cursor));
        result
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let normalized = if path == "." || path == "/" {
            "/".to_string()
        } else {
            format!(
                "/{}",
                synch_core::normalize_path(path.trim_start_matches('/'))
                    .map_err(|_| StatusCode::PermissionDenied)?
            )
        };
        // Validate confinement before reflecting the normalized path.
        self.path(&normalized)?;
        Ok(Name {
            id,
            files: vec![File::dummy(normalized)],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::server::Handler;
    use synch_core::Hash;

    /// An in-memory tree mirroring the integration harness's `FakeTree`
    /// semantics, with a `refused` set for entries the host deliberately
    /// refuses to open (sockets, tombstones).
    struct FakeHost {
        files: std::collections::HashMap<String, Vec<u8>>,
        keys: Vec<String>,
        refused: std::collections::HashSet<String>,
    }

    impl FakeHost {
        fn with_files(entries: &[(&str, &str)]) -> Self {
            let files: std::collections::HashMap<String, Vec<u8>> = entries
                .iter()
                .map(|(name, body)| (name.to_string(), body.as_bytes().to_vec()))
                .collect();
            let mut keys: Vec<String> = files.keys().cloned().collect();
            keys.sort();
            Self {
                files,
                keys,
                refused: std::collections::HashSet::new(),
            }
        }

        fn refuse(&mut self, path: &str) {
            self.refused.insert(path.to_string());
        }
    }

    #[async_trait::async_trait]
    impl SocketHost for FakeHost {
        fn open(&self, _origin: Option<&str>, path: &str) -> Result<ObjectInfo, HostError> {
            if self.refused.contains(path) {
                return Err(HostError::NotReadable("refused".into()));
            }
            let bytes = self.files.get(path).ok_or(HostError::NotFound)?;
            Ok(ObjectInfo {
                root: Hash::new(bytes),
                size: bytes.len() as u64,
                mtime_ns: 42,
                mode: 0o644,
                kind: 0,
            })
        }

        fn open_root(&self, root: &Hash) -> Result<ObjectInfo, HostError> {
            let bytes = self
                .files
                .values()
                .find(|b| Hash::new(b) == *root)
                .ok_or(HostError::NotFound)?;
            Ok(ObjectInfo {
                root: *root,
                size: bytes.len() as u64,
                mtime_ns: 42,
                mode: 0o644,
                kind: 0,
            })
        }

        fn list_page(
            &self,
            prefix: &str,
            start_after: Option<&str>,
            limit: usize,
        ) -> Result<ListPage, HostError> {
            let names: Vec<String> = self
                .keys
                .iter()
                .filter(|k| k.starts_with(prefix))
                .filter(|k| start_after.is_none_or(|after| k.as_str() > after))
                .take(limit)
                .cloned()
                .collect();
            let next = (names.len() == limit)
                .then(|| names.last().cloned())
                .flatten();
            Ok(ListPage {
                entries: names,
                next,
            })
        }

        fn entry_kind(
            &self,
            _origin: Option<&str>,
            path: &str,
        ) -> Result<HostEntryKind, HostError> {
            if self.refused.contains(path) {
                return Err(HostError::NotReadable("refused".into()));
            }
            if self.files.contains_key(path) {
                return Ok(HostEntryKind::File);
            }
            // A path with at least one descendant row is a directory.
            if self.keys.iter().any(|k| {
                k.len() > path.len() && k.starts_with(path) && k.as_bytes()[path.len()] == b'/'
            }) {
                return Ok(HostEntryKind::Directory);
            }
            Err(HostError::NotFound)
        }

        async fn pread(&self, root: Hash, offset: u64, len: u64) -> Result<Vec<u8>, HostError> {
            let bytes = self
                .files
                .values()
                .find(|b| Hash::new(b) == root)
                .ok_or(HostError::NotFound)?;
            let start = (offset as usize).min(bytes.len());
            let end = (start + len as usize).min(bytes.len());
            Ok(bytes[start..end].to_vec())
        }
    }

    fn names(name: &Name) -> Vec<String> {
        let mut names: Vec<String> = name.files.iter().map(|f| f.filename.clone()).collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn flat_scope_opendir_is_root_only() {
        // 0x01 = ACCESS_READ, no ACCESS_RECURSIVE: the declared surface is
        // the root listing alone.
        let mut sftp = TreeSftp::new(
            Arc::new(FakeHost::with_files(&[
                ("files/a.txt", "a"),
                ("files/sub/x", "x"),
            ])),
            "files".into(),
            ACCESS_READ,
        );
        assert!(sftp.opendir(1, ".".into()).await.is_ok());
        assert!(sftp.opendir(1, "/".into()).await.is_ok());
        assert!(sftp.opendir(1, "".into()).await.is_ok());
        assert_eq!(
            sftp.opendir(2, "sub".into()).await.unwrap_err(),
            StatusCode::PermissionDenied
        );
        // A recursive scope may still descend a single component.
        let mut recursive = TreeSftp::new(
            Arc::new(FakeHost::with_files(&[("files/sub/x", "x")])),
            "files".into(),
            ACCESS_READ | ACCESS_RECURSIVE,
        );
        assert!(recursive.opendir(3, "sub".into()).await.is_ok());
    }

    #[tokio::test]
    async fn readdir_skips_refused_entries_and_lists_directories_honestly() {
        let mut host = FakeHost::with_files(&[
            ("files/a.txt", "a"),
            ("files/sub/x", "x"),
            ("files/secret", ""),
        ]);
        host.refuse("files/secret");
        let mut sftp = TreeSftp::new(
            Arc::new(host),
            "files".into(),
            ACCESS_READ | ACCESS_RECURSIVE,
        );
        let handle = sftp.opendir(1, ".".into()).await.unwrap();
        let name = sftp.readdir(2, handle.handle.clone()).await.unwrap();
        assert_eq!(names(&name), vec!["a.txt", "sub"]);
        let a = name.files.iter().find(|f| f.filename == "a.txt").unwrap();
        assert_eq!(a.attrs.permissions, Some(0o100644));
        assert!(!a.attrs.is_dir());
        let sub = name.files.iter().find(|f| f.filename == "sub").unwrap();
        assert_eq!(sub.attrs.permissions, Some(0o040555));
        assert!(sub.attrs.is_dir());
        // The refused entry is skipped, not fabricated into a directory.
        assert!(!name.files.iter().any(|f| f.filename == "secret"));
        // The listing still terminates at eof.
        assert_eq!(
            sftp.readdir(3, handle.handle.clone()).await.unwrap_err(),
            StatusCode::Eof
        );
    }

    #[tokio::test]
    async fn deep_subtree_readdir_enumerates_completely() {
        // One child "a" whose subtree alone is far larger than one page
        // (128 rows), plus a later sibling "z": the historical bug returned
        // SSH_FX_FAILURE on the dupe-skipping pass. The cursor now jumps over
        // a recognized child subtree, so work stays bounded without emitting
        // an empty mid-listing Name batch.
        let owned: Vec<(String, String)> = (0..40000)
            .map(|index| (format!("files/a/x{index:05}"), String::new()))
            .chain(std::iter::once(("files/z".to_string(), String::new())))
            .collect();
        let borrowed: Vec<(&str, &str)> = owned
            .iter()
            .map(|(name, body)| (name.as_str(), body.as_str()))
            .collect();
        let mut sftp = TreeSftp::new(
            Arc::new(FakeHost::with_files(&borrowed)),
            "files".into(),
            ACCESS_READ | ACCESS_RECURSIVE,
        );
        let handle = sftp.opendir(1, ".".into()).await.unwrap();
        // The per-request scan budget may split the deep subtree across calls,
        // but every successful Name is nonempty and the cursor eventually
        // reaches the later sibling without rescanning.
        let mut seen = Vec::new();
        for id in 2..32 {
            match sftp.readdir(id, handle.handle.clone()).await {
                Ok(batch) => {
                    assert!(!batch.files.is_empty(), "no empty mid-listing Name batch");
                    seen.extend(names(&batch));
                }
                Err(StatusCode::Eof) => break,
                Err(error) => panic!("bounded readdir failed unexpectedly: {error:?}"),
            }
        }
        seen.sort();
        seen.dedup();
        assert_eq!(seen, vec!["a", "z"]);
    }

    #[tokio::test]
    async fn refused_rows_stop_at_the_per_request_scan_budget() {
        let owned: Vec<(String, String)> = (0..(LIST_PAGE_ENTRIES * (MAX_READDIR_PAGES + 1)))
            .map(|index| (format!("files/refused-{index:05}"), String::new()))
            .collect();
        let borrowed: Vec<(&str, &str)> = owned
            .iter()
            .map(|(name, body)| (name.as_str(), body.as_str()))
            .collect();
        let mut host = FakeHost::with_files(&borrowed);
        for (name, _) in &owned {
            host.refuse(name);
        }
        let mut sftp = TreeSftp::new(
            Arc::new(host),
            "files".into(),
            ACCESS_READ | ACCESS_RECURSIVE,
        );
        let handle = sftp.opendir(1, ".".into()).await.unwrap();
        assert_eq!(
            sftp.readdir(2, handle.handle).await.unwrap_err(),
            StatusCode::Failure,
            "a request may not scan past MAX_READDIR_PAGES filtered pages"
        );
    }
}
