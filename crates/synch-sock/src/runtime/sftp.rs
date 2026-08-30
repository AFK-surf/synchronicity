//! A bounded, scope-confined SFTP v3 service over the tree API.

use std::{collections::HashMap, sync::Arc};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};

use crate::{
    HostEntryKind, HostError, ListPage, ObjectInfo, PutCondition, SocketHost, SocketWriter,
};

const ACCESS_READ: u32 = 0x01;
const ACCESS_WRITE: u32 = 0x02;
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
    /// Include `after` itself on the next storage page. Subtree skipping uses
    /// the prefix's exclusive upper bound (for example `a/` -> `a0`); that
    /// bound can also be a real sibling, so the first page after a jump must
    /// probe and include the exact boundary before continuing strictly after
    /// it.
    include_after: bool,
    last_child: Option<String>,
    eof: bool,
}

enum OpenHandle {
    ReadFile(ObjectInfo),
    WriteFile(WriteFile),
    Directory(DirectoryCursor),
}

struct WriteFile {
    // Access remains sequential because a handle is removed from the map
    // before it is awaited. The mutex supplies `Sync` for russh-sftp's
    // sendable futures without imposing that bound on public host writers.
    writer: tokio::sync::Mutex<Box<dyn SocketWriter>>,
    _permit: WriterPermit,
    condition: PutCondition,
    size: u64,
    readable: bool,
    append: bool,
    dirty: bool,
    failed: bool,
    max_bytes: u64,
}

struct WriterPermit(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for WriterPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub(crate) struct TreeSftp {
    host: Arc<dyn SocketHost>,
    scope: String,
    access: u32,
    write_capability: Option<synch_core::TreeWriteCapability>,
    next_handle: u64,
    handles: HashMap<String, OpenHandle>,
    commits: Arc<std::sync::atomic::AtomicU32>,
    writer_count: Arc<std::sync::atomic::AtomicUsize>,
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
    pub(crate) fn new(
        host: Arc<dyn SocketHost>,
        scope: String,
        access: u32,
        write_capability: Option<synch_core::TreeWriteCapability>,
        commits: Arc<std::sync::atomic::AtomicU32>,
        writer_count: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        Self {
            host,
            scope,
            access,
            write_capability,
            next_handle: 1,
            handles: HashMap::new(),
            commits,
            writer_count,
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

    fn write_capability(&self, path: &str) -> Result<synch_core::TreeWriteCapability, StatusCode> {
        if self.access & ACCESS_WRITE == 0 {
            return Err(StatusCode::PermissionDenied);
        }
        let capability = self
            .write_capability
            .as_ref()
            .filter(|capability| capability.covers(path))
            .ok_or(StatusCode::PermissionDenied)?;
        Ok(capability.clone())
    }

    fn require_read(&self) -> Result<(), StatusCode> {
        if self.access & ACCESS_READ == 0 {
            return Err(StatusCode::PermissionDenied);
        }
        Ok(())
    }

    async fn open_writer(
        &self,
        path: String,
        capability: &synch_core::TreeWriteCapability,
    ) -> Result<(Box<dyn SocketWriter>, WriterPermit), StatusCode> {
        if self
            .writer_count
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |count| (count < crate::limits::MAX_OPEN_WRITERS).then_some(count + 1),
            )
            .is_err()
        {
            return Err(StatusCode::Failure);
        }
        let permit = WriterPermit(self.writer_count.clone());
        let host = self.host.clone();
        let modes = capability.modes;
        let writer = tokio::task::spawn_blocking(move || host.put_open(&path, modes))
            .await
            .map_err(|_| StatusCode::Failure)?
            .map_err(host_error)?;
        Ok((writer, permit))
    }

    async fn copy_into_writer(
        &self,
        info: &ObjectInfo,
        writer: &mut dyn SocketWriter,
        length: u64,
    ) -> Result<(), StatusCode> {
        let mut offset = 0;
        while offset < length {
            let bytes = self
                .host
                .pread(info.root, offset, u64::from(MAX_READ).min(length - offset))
                .await
                .map_err(host_error)?;
            if bytes.is_empty() {
                return Err(StatusCode::Failure);
            }
            offset = offset.saturating_add(bytes.len() as u64);
            writer.write(bytes).await.map_err(host_error)?;
        }
        writer.set_len(length).await.map_err(host_error)
    }

    fn reserve_commits(&self, count: u32) -> Result<(), StatusCode> {
        self.commits
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |used| {
                    used.checked_add(count)
                        .filter(|next| *next <= crate::limits::MAX_PUT_COMMITS)
                },
            )
            .map(|_| ())
            .map_err(|_| StatusCode::Failure)
    }

    fn count_commit(&self) -> Result<(), StatusCode> {
        self.reserve_commits(1)
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

    async fn path_attrs(&self, path: String) -> Result<FileAttributes, StatusCode> {
        // The declared scope is the virtual root of this SFTP view. It need
        // not have a concrete tree row of its own.
        if path == self.scope {
            return Ok(directory_attrs());
        }
        match self.open_info(path.clone()).await {
            Ok(info) => Ok(attrs(&info)),
            Err(error @ (StatusCode::NoSuchFile | StatusCode::PermissionDenied)) => {
                match self.entry_kind(path).await {
                    // Both implicit prefix directories and explicit directory
                    // rows have no readable content object.
                    Ok(HostEntryKind::Directory) => Ok(directory_attrs()),
                    Ok(_) | Err(_) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn list(
        &self,
        prefix: String,
        after: Option<String>,
        include_after: bool,
    ) -> Result<ListPage, StatusCode> {
        let exact = if include_after {
            let Some(path) = after.as_ref() else {
                return Err(StatusCode::Failure);
            };
            // `entry_kind` also recognizes implicit directories, which is the
            // desired SFTP view: if the boundary is the name of such a sibling,
            // emit it before jumping over its own descendants.
            match self.entry_kind(path.clone()).await {
                Ok(_) => Some(path.clone()),
                Err(StatusCode::NoSuchFile | StatusCode::PermissionDenied) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let tail_limit = LIST_PAGE_ENTRIES.saturating_sub(usize::from(exact.is_some()));
        let host = self.host.clone();
        let mut page = tokio::task::spawn_blocking(move || {
            host.list_page(&prefix, after.as_deref(), tail_limit)
        })
        .await
        .map_err(|_| StatusCode::Failure)?
        .map_err(host_error)?;
        if let Some(exact) = exact {
            page.entries.insert(0, exact);
        }
        Ok(page)
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
                .list(
                    cursor.prefix.clone(),
                    cursor.after.clone(),
                    cursor.include_after,
                )
                .await?;
            let included_after = cursor.include_after;
            cursor.include_after = false;
            if page.entries.len() > LIST_PAGE_ENTRIES
                || page
                    .next
                    .as_ref()
                    .is_some_and(|next| cursor.after.as_ref().is_some_and(|after| next <= after))
            {
                return Err(StatusCode::Failure);
            }

            let mut consumed_page = true;
            for (index, full) in page.entries.into_iter().enumerate() {
                let is_included_boundary = included_after
                    && index == 0
                    && cursor.after.as_ref().is_some_and(|after| full == *after);
                if !is_included_boundary
                    && cursor.after.as_ref().is_some_and(|after| full <= *after)
                {
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
                    cursor.include_after = true;
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
        HostError::NotReadable(_) | HostError::Denied(_) => StatusCode::PermissionDenied,
        HostError::Unavailable(_) | HostError::Conflict(_) | HostError::Io(_) => {
            StatusCode::Failure
        }
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

fn staged_file_attrs(size: u64) -> FileAttributes {
    FileAttributes {
        size: Some(size),
        ..Default::default()
    }
}

fn directory_attrs() -> FileAttributes {
    let mut attrs = FileAttributes {
        permissions: Some(0o040555),
        ..Default::default()
    };
    attrs.set_dir(true);
    attrs
}

fn has_unsupported_metadata(attrs: &FileAttributes) -> bool {
    attrs.uid.is_some()
        || attrs.user.is_some()
        || attrs.gid.is_some()
        || attrs.group.is_some()
        || attrs.permissions.is_some()
        || attrs.atime.is_some()
        || attrs.mtime.is_some()
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
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let wants_read = pflags.contains(OpenFlags::READ);
        let wants_write = pflags.intersects(OpenFlags::WRITE | OpenFlags::APPEND);
        let write_options =
            pflags.intersects(OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::EXCLUDE);
        if (!wants_read && !wants_write)
            || (wants_read && self.access & ACCESS_READ == 0)
            || (write_options && !wants_write)
            || (pflags.intersects(OpenFlags::EXCLUDE | OpenFlags::TRUNCATE)
                && !pflags.contains(OpenFlags::CREATE))
        {
            return Err(StatusCode::PermissionDenied);
        }
        if has_unsupported_metadata(&attrs)
            || (attrs.size.is_some() && !pflags.contains(OpenFlags::CREATE))
        {
            return Err(StatusCode::OpUnsupported);
        }

        let path = self.path(&filename)?;
        let existing = match self.open_info(path.clone()).await {
            Ok(info) => Some(info),
            Err(StatusCode::NoSuchFile) => None,
            Err(error) => return Err(error),
        };
        if !wants_write {
            let info = existing.ok_or(StatusCode::NoSuchFile)?;
            let handle = self.allocate(OpenHandle::ReadFile(info))?;
            return Ok(Handle { id, handle });
        }

        if existing.is_none() && !pflags.contains(OpenFlags::CREATE) {
            return Err(StatusCode::NoSuchFile);
        }
        if existing.is_some()
            && pflags.contains(OpenFlags::CREATE)
            && pflags.contains(OpenFlags::EXCLUDE)
        {
            return Err(StatusCode::Failure);
        }

        let capability = self.write_capability(&path)?;
        let truncated = pflags.contains(OpenFlags::TRUNCATE);
        let initial_size = if existing.is_none() {
            attrs.size.unwrap_or(0)
        } else if truncated {
            0
        } else {
            existing.as_ref().map_or(0, |info| info.size)
        };
        if capability.max_bytes > 0 && initial_size > capability.max_bytes {
            return Err(StatusCode::Failure);
        }
        let condition = existing
            .as_ref()
            .map_or(PutCondition::Absent, |info| PutCondition::Root(info.root));
        let (mut writer, permit) = self.open_writer(path, &capability).await?;
        if let Some(info) = existing.as_ref().filter(|_| !truncated) {
            self.copy_into_writer(info, writer.as_mut(), info.size)
                .await?;
        } else {
            writer.set_len(initial_size).await.map_err(host_error)?;
        }
        let handle = self.allocate(OpenHandle::WriteFile(WriteFile {
            writer: tokio::sync::Mutex::new(writer),
            _permit: permit,
            condition,
            size: initial_size,
            readable: wants_read,
            append: pflags.contains(OpenFlags::APPEND),
            dirty: truncated || existing.is_none(),
            failed: false,
            max_bytes: capability.max_bytes,
        }))?;
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        let open = self.handles.remove(&handle).ok_or(StatusCode::Failure)?;
        if let OpenHandle::WriteFile(mut file) = open {
            if file.failed {
                return Err(StatusCode::Failure);
            }
            if file.dirty {
                self.count_commit()?;
                file.writer
                    .get_mut()
                    .commit(file.condition)
                    .await
                    .map_err(host_error)?;
            }
        }
        Ok(ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let open = self.handles.remove(&handle).ok_or(StatusCode::Failure)?;
        let (result, open) = match open {
            OpenHandle::ReadFile(info) => {
                let result = if offset >= info.size {
                    Err(StatusCode::Eof)
                } else {
                    self.host
                        .pread(info.root, offset, u64::from(len.min(MAX_READ)))
                        .await
                        .map_err(host_error)
                };
                (result, OpenHandle::ReadFile(info))
            }
            OpenHandle::WriteFile(file) if file.failed => {
                (Err(StatusCode::Failure), OpenHandle::WriteFile(file))
            }
            OpenHandle::WriteFile(mut file) if file.readable => {
                let result = if offset >= file.size {
                    Err(StatusCode::Eof)
                } else {
                    file.writer
                        .get_mut()
                        .read_at(offset, u64::from(len.min(MAX_READ)).min(file.size - offset))
                        .await
                        .map_err(host_error)
                };
                (result, OpenHandle::WriteFile(file))
            }
            other => (Err(StatusCode::PermissionDenied), other),
        };
        self.handles.insert(handle, open);
        let bytes = result?;
        if bytes.is_empty() {
            return Err(StatusCode::Eof);
        }
        Ok(Data { id, data: bytes })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let open = self.handles.remove(&handle).ok_or(StatusCode::Failure)?;
        let OpenHandle::WriteFile(mut file) = open else {
            self.handles.insert(handle, open);
            return Err(StatusCode::PermissionDenied);
        };
        if file.failed {
            self.handles.insert(handle, OpenHandle::WriteFile(file));
            return Err(StatusCode::Failure);
        }
        let offset = if file.append { file.size } else { offset };
        let Some(end) = offset.checked_add(data.len() as u64) else {
            self.handles.insert(handle, OpenHandle::WriteFile(file));
            return Err(StatusCode::Failure);
        };
        if file.max_bytes > 0 && end > file.max_bytes {
            self.handles.insert(handle, OpenHandle::WriteFile(file));
            return Err(StatusCode::Failure);
        }
        let result = file
            .writer
            .get_mut()
            .write_at(offset, data)
            .await
            .map_err(host_error);
        if result.is_ok() {
            file.size = file.size.max(end);
            file.dirty = true;
        } else {
            file.failed = true;
        }
        self.handles.insert(handle, OpenHandle::WriteFile(file));
        result.map(|_| ok(id))
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        self.require_read()?;
        match self.handles.get(&handle) {
            Some(OpenHandle::ReadFile(info)) => Ok(Attrs {
                id,
                attrs: attrs(info),
            }),
            Some(OpenHandle::WriteFile(file)) if !file.failed => Ok(Attrs {
                id,
                attrs: staged_file_attrs(file.size),
            }),
            Some(OpenHandle::WriteFile(_)) => Err(StatusCode::Failure),
            Some(OpenHandle::Directory(_)) => Ok(Attrs {
                id,
                attrs: directory_attrs(),
            }),
            None => Err(StatusCode::Failure),
        }
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        match self.handles.get(&handle) {
            Some(OpenHandle::WriteFile(_)) => {}
            Some(_) => return Err(StatusCode::PermissionDenied),
            None => return Err(StatusCode::Failure),
        }
        if has_unsupported_metadata(&attrs) {
            return Err(StatusCode::OpUnsupported);
        }
        let Some(size) = attrs.size else {
            return Ok(ok(id));
        };
        let open = self.handles.remove(&handle).ok_or(StatusCode::Failure)?;
        let OpenHandle::WriteFile(mut file) = open else {
            self.handles.insert(handle, open);
            return Err(StatusCode::PermissionDenied);
        };
        if file.failed {
            self.handles.insert(handle, OpenHandle::WriteFile(file));
            return Err(StatusCode::Failure);
        }
        if file.max_bytes > 0 && size > file.max_bytes {
            self.handles.insert(handle, OpenHandle::WriteFile(file));
            return Err(StatusCode::Failure);
        }
        let result = file
            .writer
            .get_mut()
            .set_len(size)
            .await
            .map_err(host_error);
        if result.is_ok() {
            file.size = size;
            file.dirty = true;
        } else {
            file.failed = true;
        }
        self.handles.insert(handle, OpenHandle::WriteFile(file));
        result.map(|_| ok(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = self.path(&path)?;
        let capability = self.write_capability(&path)?;
        let info = self.open_info(path.clone()).await?;
        if has_unsupported_metadata(&attrs) {
            return Err(StatusCode::OpUnsupported);
        }
        let Some(size) = attrs.size else {
            return Ok(ok(id));
        };
        if capability.max_bytes > 0 && size > capability.max_bytes {
            return Err(StatusCode::Failure);
        }
        let (mut writer, _permit) = self.open_writer(path, &capability).await?;
        self.copy_into_writer(&info, writer.as_mut(), info.size.min(size))
            .await?;
        writer.set_len(size).await.map_err(host_error)?;
        self.count_commit()?;
        writer
            .commit(PutCondition::Root(info.root))
            .await
            .map_err(host_error)?;
        Ok(ok(id))
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.require_read()?;
        let attrs = self.path_attrs(self.path(&path)?).await?;
        Ok(Attrs { id, attrs })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        self.require_read()?;
        let prefix = self.path(&path)?;
        // A flat scope's declared surface is its root listing: enumerating
        // inside a depth-1 child would disclose depth-2 names even though
        // the capability never granted recursion. The single-component
        // requests gate in path() still rejects anything deeper.
        if self.access & ACCESS_RECURSIVE == 0 && prefix != self.scope {
            return Err(StatusCode::PermissionDenied);
        }
        if prefix != self.scope {
            match self.entry_kind(prefix.clone()).await? {
                HostEntryKind::Directory => {}
                HostEntryKind::File => return Err(StatusCode::Failure),
                HostEntryKind::Socket | HostEntryKind::Symlink | HostEntryKind::Tombstone => {
                    return Err(StatusCode::PermissionDenied)
                }
            }
        }
        let handle = self.allocate(OpenHandle::Directory(DirectoryCursor {
            prefix,
            after: None,
            include_after: false,
            last_child: None,
            eof: false,
        }))?;
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        self.require_read()?;
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

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let path = self.path(&filename)?;
        let capability = self.write_capability(&path)?;
        if capability.modes & synch_core::TREE_WRITE_DELETE == 0 {
            return Err(StatusCode::PermissionDenied);
        }
        if path == self.scope {
            return Err(StatusCode::Failure);
        }
        match self.entry_kind(path.clone()).await? {
            HostEntryKind::File => {}
            HostEntryKind::Directory => return Err(StatusCode::Failure),
            HostEntryKind::Socket | HostEntryKind::Symlink | HostEntryKind::Tombstone => {
                return Err(StatusCode::PermissionDenied)
            }
        }
        let source = self.open_info(path.clone()).await?;
        self.count_commit()?;
        let (mut writer, _permit) = self.open_writer(path, &capability).await?;
        writer
            .delete_if(PutCondition::Root(source.root))
            .await
            .map_err(host_error)?;
        Ok(ok(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let oldpath = self.path(&oldpath)?;
        let newpath = self.path(&newpath)?;
        let old_capability = self.write_capability(&oldpath)?;
        match self.entry_kind(oldpath.clone()).await? {
            HostEntryKind::File => {}
            HostEntryKind::Directory => return Err(StatusCode::Failure),
            HostEntryKind::Socket | HostEntryKind::Symlink | HostEntryKind::Tombstone => {
                return Err(StatusCode::PermissionDenied)
            }
        }
        let source = self.open_info(oldpath.clone()).await?;
        if oldpath == newpath {
            return Ok(ok(id));
        }
        let new_capability = self.write_capability(&newpath)?;
        if old_capability.modes & synch_core::TREE_WRITE_DELETE == 0 {
            return Err(StatusCode::PermissionDenied);
        }
        if new_capability.max_bytes > 0 && source.size > new_capability.max_bytes {
            return Err(StatusCode::Failure);
        }
        match self.open_info(newpath.clone()).await {
            // Baseline SFTP v3 rename never overwrites. Overwrite semantics
            // belong to an explicitly negotiated extension, which this
            // server does not advertise.
            Ok(_) => return Err(StatusCode::Failure),
            Err(StatusCode::NoSuchFile) => {}
            Err(error) => return Err(error),
        }
        self.reserve_commits(2)?;

        // The tree API has one-path atomic commits. Rename is therefore the
        // documented composition: conditionally publish the copy, then
        // conditionally tombstone the exact source version that was copied,
        // under the independently checked delete grant.
        let (mut target, _target_permit) = self.open_writer(newpath, &new_capability).await?;
        self.copy_into_writer(&source, target.as_mut(), source.size)
            .await?;
        target
            .commit(PutCondition::Absent)
            .await
            .map_err(host_error)?;

        drop(target);
        drop(_target_permit);
        let (mut old, _old_permit) = self.open_writer(oldpath, &old_capability).await?;
        old.delete_if(PutCondition::Root(source.root))
            .await
            .map_err(host_error)?;
        Ok(ok(id))
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

    type CommitReplacement = Arc<std::sync::Mutex<Option<(String, String, Vec<u8>)>>>;
    type PartialWriteFailure = Arc<std::sync::Mutex<Option<usize>>>;

    /// An in-memory tree mirroring the integration harness's `FakeTree`
    /// semantics, with a `refused` set for entries the host deliberately
    /// refuses to open (sockets, tombstones).
    struct FakeHost {
        files: Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
        directories: std::collections::HashSet<String>,
        kinds: std::collections::HashMap<String, HostEntryKind>,
        refused: std::collections::HashSet<String>,
        replace_on_commit: CommitReplacement,
        fail_write_after: PartialWriteFailure,
    }

    impl FakeHost {
        fn with_files(entries: &[(&str, &str)]) -> Self {
            let files: std::collections::HashMap<String, Vec<u8>> = entries
                .iter()
                .map(|(name, body)| (name.to_string(), body.as_bytes().to_vec()))
                .collect();
            Self {
                files: Arc::new(std::sync::Mutex::new(files)),
                directories: std::collections::HashSet::new(),
                kinds: std::collections::HashMap::new(),
                refused: std::collections::HashSet::new(),
                replace_on_commit: Arc::new(std::sync::Mutex::new(None)),
                fail_write_after: Arc::new(std::sync::Mutex::new(None)),
            }
        }

        fn refuse(&mut self, path: &str) {
            self.refused.insert(path.to_string());
        }

        fn add_directory(&mut self, path: &str) {
            self.directories.insert(path.to_string());
        }

        fn mark_kind(&mut self, path: &str, kind: HostEntryKind) {
            self.kinds.insert(path.to_string(), kind);
        }

        fn replace_after_commit(&self, trigger: &str, target: &str, bytes: &[u8]) {
            *self.replace_on_commit.lock().unwrap() =
                Some((trigger.to_string(), target.to_string(), bytes.to_vec()));
        }

        fn fail_next_write_after(&self, bytes: usize) {
            *self.fail_write_after.lock().unwrap() = Some(bytes);
        }
    }

    #[async_trait::async_trait]
    impl SocketHost for FakeHost {
        fn open(&self, _origin: Option<&str>, path: &str) -> Result<ObjectInfo, HostError> {
            if self.refused.contains(path) {
                return Err(HostError::NotReadable("refused".into()));
            }
            if self.directories.contains(path) {
                return Err(HostError::NotReadable("directory has no content".into()));
            }
            let files = self.files.lock().unwrap();
            let bytes = files.get(path).ok_or(HostError::NotFound)?;
            Ok(ObjectInfo {
                root: Hash::new(bytes),
                size: bytes.len() as u64,
                mtime_ns: 42,
                mode: 0o644,
                kind: 0,
            })
        }

        fn open_root(&self, root: &Hash) -> Result<ObjectInfo, HostError> {
            let files = self.files.lock().unwrap();
            let bytes = files
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
            let mut names: Vec<String> = self
                .files
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .filter(|k| start_after.is_none_or(|after| k.as_str() > after))
                .cloned()
                .collect();
            names.sort();
            names.truncate(limit);
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
            if self.directories.contains(path) {
                return Ok(HostEntryKind::Directory);
            }
            if let Some(kind) = self.kinds.get(path) {
                return Ok(*kind);
            }
            let files = self.files.lock().unwrap();
            if files.contains_key(path) {
                return Ok(HostEntryKind::File);
            }
            // A path with at least one descendant row is a directory.
            if files.keys().any(|k| {
                k.len() > path.len() && k.starts_with(path) && k.as_bytes()[path.len()] == b'/'
            }) {
                return Ok(HostEntryKind::Directory);
            }
            Err(HostError::NotFound)
        }

        async fn pread(&self, root: Hash, offset: u64, len: u64) -> Result<Vec<u8>, HostError> {
            let files = self.files.lock().unwrap();
            let bytes = files
                .values()
                .find(|b| Hash::new(b) == root)
                .ok_or(HostError::NotFound)?;
            let start = (offset as usize).min(bytes.len());
            let end = (start + len as usize).min(bytes.len());
            Ok(bytes[start..end].to_vec())
        }

        fn put_open(&self, path: &str, modes: u32) -> Result<Box<dyn SocketWriter>, HostError> {
            if self.refused.contains(path) {
                return Err(HostError::Denied("refused".into()));
            }
            Ok(Box::new(FakeWriter {
                path: path.to_string(),
                modes,
                staged: Vec::new(),
                files: self.files.clone(),
                replace_on_commit: self.replace_on_commit.clone(),
                fail_write_after: self.fail_write_after.clone(),
            }))
        }
    }

    struct FakeWriter {
        path: String,
        modes: u32,
        staged: Vec<u8>,
        files: Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
        replace_on_commit: CommitReplacement,
        fail_write_after: PartialWriteFailure,
    }

    #[async_trait::async_trait]
    impl SocketWriter for FakeWriter {
        async fn write(&mut self, data: Vec<u8>) -> Result<(), HostError> {
            self.staged.extend(data);
            Ok(())
        }

        async fn read_at(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, HostError> {
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(self.staged.len());
            let end = start
                .saturating_add(usize::try_from(len).unwrap_or(usize::MAX))
                .min(self.staged.len());
            Ok(self.staged[start..end].to_vec())
        }

        async fn write_at(&mut self, offset: u64, data: Vec<u8>) -> Result<(), HostError> {
            let start = usize::try_from(offset)
                .map_err(|_| HostError::Denied("offset too large".into()))?;
            if let Some(prefix) = self.fail_write_after.lock().unwrap().take() {
                let prefix = prefix.min(data.len());
                let partial_end = start
                    .checked_add(prefix)
                    .ok_or_else(|| HostError::Denied("write too large".into()))?;
                self.staged.resize(self.staged.len().max(partial_end), 0);
                self.staged[start..partial_end].copy_from_slice(&data[..prefix]);
                return Err(HostError::Io("injected partial write failure".into()));
            }
            let end = start
                .checked_add(data.len())
                .ok_or_else(|| HostError::Denied("write too large".into()))?;
            self.staged.resize(self.staged.len().max(end), 0);
            self.staged[start..end].copy_from_slice(&data);
            Ok(())
        }

        async fn set_len(&mut self, len: u64) -> Result<(), HostError> {
            let len =
                usize::try_from(len).map_err(|_| HostError::Denied("length too large".into()))?;
            self.staged.resize(len, 0);
            Ok(())
        }

        async fn commit(&mut self, expected: PutCondition) -> Result<crate::PutReceipt, HostError> {
            let mut files = self.files.lock().unwrap();
            let current = files.get(&self.path);
            let allowed = match expected {
                PutCondition::Any => {
                    (current.is_some() && self.modes & synch_core::TREE_WRITE_REPLACE != 0)
                        || (current.is_none() && self.modes & synch_core::TREE_WRITE_CREATE != 0)
                }
                PutCondition::Absent => {
                    current.is_none() && self.modes & synch_core::TREE_WRITE_CREATE != 0
                }
                PutCondition::Root(root) => {
                    current.is_some_and(|bytes| Hash::new(bytes) == root)
                        && self.modes & synch_core::TREE_WRITE_REPLACE != 0
                }
            };
            if !allowed {
                return Err(HostError::Conflict("condition changed".into()));
            }
            let bytes = self.staged.clone();
            let receipt = crate::PutReceipt {
                root: Hash::new(&bytes),
                size: bytes.len() as u64,
            };
            files.insert(self.path.clone(), bytes);
            let replacement = {
                let mut hook = self.replace_on_commit.lock().unwrap();
                if hook
                    .as_ref()
                    .is_some_and(|(trigger, _, _)| trigger == &self.path)
                {
                    hook.take()
                } else {
                    None
                }
            };
            if let Some((_, target, replacement)) = replacement {
                files.insert(target, replacement);
            }
            Ok(receipt)
        }

        async fn delete(&mut self) -> Result<(), HostError> {
            self.delete_if(PutCondition::Any).await
        }

        async fn delete_if(&mut self, expected: PutCondition) -> Result<(), HostError> {
            if self.modes & synch_core::TREE_WRITE_DELETE == 0 {
                return Err(HostError::Denied("delete is not allowed".into()));
            }
            let mut files = self.files.lock().unwrap();
            let current = files.get(&self.path);
            let allowed = match expected {
                PutCondition::Any => true,
                PutCondition::Absent => current.is_none(),
                PutCondition::Root(root) => current.is_some_and(|bytes| Hash::new(bytes) == root),
            };
            if !allowed {
                return Err(HostError::Conflict("delete condition changed".into()));
            }
            files.remove(&self.path);
            Ok(())
        }
    }

    fn names(name: &Name) -> Vec<String> {
        let mut names: Vec<String> = name.files.iter().map(|f| f.filename.clone()).collect();
        names.sort();
        names
    }

    fn commit_budget() -> Arc<std::sync::atomic::AtomicU32> {
        Arc::new(std::sync::atomic::AtomicU32::new(0))
    }

    fn writer_budget() -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::new(std::sync::atomic::AtomicUsize::new(0))
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
            None,
            commit_budget(),
            writer_budget(),
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
            None,
            commit_budget(),
            writer_budget(),
        );
        assert!(recursive.opendir(3, "sub".into()).await.is_ok());
    }

    #[tokio::test]
    async fn opendir_requires_an_existing_directory() {
        let mut sftp = TreeSftp::new(
            Arc::new(FakeHost::with_files(&[
                ("files/file.txt", "body"),
                ("files/sub/item", "nested"),
            ])),
            "files".into(),
            ACCESS_READ | ACCESS_RECURSIVE,
            None,
            commit_budget(),
            writer_budget(),
        );

        assert_eq!(
            sftp.opendir(1, "file.txt".into()).await.unwrap_err(),
            StatusCode::Failure
        );
        assert_eq!(
            sftp.opendir(2, "missing".into()).await.unwrap_err(),
            StatusCode::NoSuchFile
        );
        assert!(sftp.opendir(3, "sub".into()).await.is_ok());
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
            None,
            commit_budget(),
            writer_budget(),
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
            None,
            commit_budget(),
            writer_budget(),
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
    async fn subtree_jump_keeps_a_sibling_equal_to_the_upper_bound() {
        let mut sftp = TreeSftp::new(
            Arc::new(FakeHost::with_files(&[
                ("files/a/child", "nested"),
                ("files/a0", "sibling"),
                ("files/z", "last"),
            ])),
            "files".into(),
            ACCESS_READ | ACCESS_RECURSIVE,
            None,
            commit_budget(),
            writer_budget(),
        );
        let handle = sftp.opendir(1, ".".into()).await.unwrap();
        let mut seen = Vec::new();
        for id in 2..16 {
            match sftp.readdir(id, handle.handle.clone()).await {
                Ok(batch) => seen.extend(names(&batch)),
                Err(StatusCode::Eof) => break,
                Err(error) => panic!("bounded readdir failed unexpectedly: {error:?}"),
            }
        }
        seen.sort();
        seen.dedup();
        assert_eq!(seen, vec!["a", "a0", "z"]);
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
            None,
            commit_budget(),
            writer_budget(),
        );
        let handle = sftp.opendir(1, ".".into()).await.unwrap();
        assert_eq!(
            sftp.readdir(2, handle.handle).await.unwrap_err(),
            StatusCode::Failure,
            "a request may not scan past MAX_READDIR_PAGES filtered pages"
        );
    }

    #[tokio::test]
    async fn stat_reports_virtual_root_and_implicit_directories() {
        let mut host = FakeHost::with_files(&[("files/sub/item", "body")]);
        host.add_directory("files/explicit");
        let mut sftp = TreeSftp::new(
            Arc::new(host),
            "files".into(),
            ACCESS_READ | ACCESS_RECURSIVE,
            None,
            commit_budget(),
            writer_budget(),
        );

        let root = sftp.stat(1, ".".into()).await.unwrap();
        assert!(root.attrs.is_dir());
        assert_eq!(root.attrs.permissions, Some(0o040555));
        let sub = sftp.lstat(2, "sub".into()).await.unwrap();
        assert!(sub.attrs.is_dir());
        assert_eq!(sub.attrs.permissions, Some(0o040555));
        let explicit = sftp.stat(3, "explicit".into()).await.unwrap();
        assert!(explicit.attrs.is_dir());
        assert_eq!(explicit.attrs.permissions, Some(0o040555));

        let handle = sftp.opendir(4, "sub".into()).await.unwrap();
        let opened = sftp.fstat(5, handle.handle).await.unwrap();
        assert!(opened.attrs.is_dir());
        assert_eq!(opened.attrs.permissions, Some(0o040555));
    }

    #[tokio::test]
    async fn write_only_scope_cannot_stat_or_enumerate() {
        let capability = synch_core::TreeWriteCapability {
            id: 1,
            modes: synch_core::TREE_WRITE_CREATE,
            prefix: "files".into(),
            max_bytes: 1024,
        };
        let mut sftp = TreeSftp::new(
            Arc::new(FakeHost::with_files(&[("files/item", "body")])),
            "files".into(),
            ACCESS_WRITE | ACCESS_RECURSIVE,
            Some(capability),
            commit_budget(),
            writer_budget(),
        );

        assert_eq!(
            sftp.stat(1, "item".into()).await.unwrap_err(),
            StatusCode::PermissionDenied
        );
        assert_eq!(
            sftp.opendir(2, ".".into()).await.unwrap_err(),
            StatusCode::PermissionDenied
        );
        let opened = sftp
            .open(
                3,
                "new".into(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::empty(),
            )
            .await
            .unwrap();
        assert_eq!(
            sftp.fstat(4, opened.handle).await.unwrap_err(),
            StatusCode::PermissionDenied
        );

        // Defense in depth: a directory handle created while read access was
        // present must stop working if the effective access is withdrawn.
        sftp.access |= ACCESS_READ;
        let handle = sftp.opendir(5, ".".into()).await.unwrap();
        sftp.access &= !ACCESS_READ;
        assert_eq!(
            sftp.readdir(6, handle.handle).await.unwrap_err(),
            StatusCode::PermissionDenied
        );
    }

    #[tokio::test]
    async fn remove_requires_an_existing_regular_file() {
        let host = Arc::new(FakeHost::with_files(&[("files/sub/item", "body")]));
        let capability = synch_core::TreeWriteCapability {
            id: 1,
            modes: synch_core::TREE_WRITE_DELETE,
            prefix: "files".into(),
            max_bytes: 1024,
        };
        let commits = commit_budget();
        let mut sftp = TreeSftp::new(
            host.clone(),
            "files".into(),
            ACCESS_WRITE | ACCESS_RECURSIVE,
            Some(capability),
            commits.clone(),
            writer_budget(),
        );

        assert_eq!(
            sftp.remove(1, "missing".into()).await.unwrap_err(),
            StatusCode::NoSuchFile
        );
        assert_eq!(
            sftp.remove(2, "sub".into()).await.unwrap_err(),
            StatusCode::Failure
        );
        assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(host.files.lock().unwrap().contains_key("files/sub/item"));
    }

    #[tokio::test]
    async fn rename_never_deletes_a_concurrently_replaced_source() {
        let host = Arc::new(FakeHost::with_files(&[("files/source", "version-a")]));
        host.replace_after_commit("files/destination", "files/source", b"version-b");
        let capability = synch_core::TreeWriteCapability {
            id: 1,
            modes: synch_core::TREE_WRITE_CREATE
                | synch_core::TREE_WRITE_REPLACE
                | synch_core::TREE_WRITE_DELETE,
            prefix: "files".into(),
            max_bytes: 1024,
        };
        let mut sftp = TreeSftp::new(
            host.clone(),
            "files".into(),
            ACCESS_READ | ACCESS_WRITE | ACCESS_RECURSIVE,
            Some(capability),
            commit_budget(),
            writer_budget(),
        );

        assert_eq!(
            sftp.rename(1, "source".into(), "destination".into())
                .await
                .unwrap_err(),
            StatusCode::Failure
        );
        let files = host.files.lock().unwrap();
        assert_eq!(files.get("files/source").unwrap(), b"version-b");
        assert_eq!(files.get("files/destination").unwrap(), b"version-a");
    }

    #[tokio::test]
    async fn rename_validates_source_before_any_destination_commit() {
        let mut host =
            FakeHost::with_files(&[("files/source", "target"), ("files/existing", "body")]);
        host.mark_kind("files/source", HostEntryKind::Symlink);
        let host = Arc::new(host);
        let capability = synch_core::TreeWriteCapability {
            id: 1,
            modes: synch_core::TREE_WRITE_CREATE
                | synch_core::TREE_WRITE_REPLACE
                | synch_core::TREE_WRITE_DELETE,
            prefix: "files".into(),
            max_bytes: 1024,
        };
        let commits = commit_budget();
        let mut sftp = TreeSftp::new(
            host.clone(),
            "files".into(),
            ACCESS_READ | ACCESS_WRITE | ACCESS_RECURSIVE,
            Some(capability),
            commits.clone(),
            writer_budget(),
        );

        assert_eq!(
            sftp.rename(1, "source".into(), "destination".into())
                .await
                .unwrap_err(),
            StatusCode::PermissionDenied
        );
        assert!(!host.files.lock().unwrap().contains_key("files/destination"));
        assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(
            sftp.rename(2, "missing".into(), "missing".into())
                .await
                .unwrap_err(),
            StatusCode::NoSuchFile
        );
        assert!(sftp
            .rename(3, "existing".into(), "existing".into())
            .await
            .is_ok());

        let narrow = synch_core::TreeWriteCapability {
            id: 1,
            modes: synch_core::TREE_WRITE_CREATE,
            prefix: "files/allowed".into(),
            max_bytes: 1024,
        };
        let mut narrow_sftp = TreeSftp::new(
            host,
            "files".into(),
            ACCESS_READ | ACCESS_WRITE | ACCESS_RECURSIVE,
            Some(narrow),
            commit_budget(),
            writer_budget(),
        );
        assert_eq!(
            narrow_sftp
                .rename(4, "existing".into(), "existing".into())
                .await
                .unwrap_err(),
            StatusCode::PermissionDenied
        );
    }

    #[tokio::test]
    async fn baseline_rename_refuses_an_occupied_destination() {
        let host = Arc::new(FakeHost::with_files(&[
            ("files/source", "source-body"),
            ("files/destination", "destination-body"),
        ]));
        let capability = synch_core::TreeWriteCapability {
            id: 1,
            modes: synch_core::TREE_WRITE_CREATE
                | synch_core::TREE_WRITE_REPLACE
                | synch_core::TREE_WRITE_DELETE,
            prefix: "files".into(),
            max_bytes: 1024,
        };
        let commits = commit_budget();
        let mut sftp = TreeSftp::new(
            host.clone(),
            "files".into(),
            ACCESS_READ | ACCESS_WRITE | ACCESS_RECURSIVE,
            Some(capability),
            commits.clone(),
            writer_budget(),
        );

        assert_eq!(
            sftp.rename(1, "source".into(), "destination".into())
                .await
                .unwrap_err(),
            StatusCode::Failure
        );
        let files = host.files.lock().unwrap();
        assert_eq!(files.get("files/source").unwrap(), b"source-body");
        assert_eq!(files.get("files/destination").unwrap(), b"destination-body");
        assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn open_enforces_v3_flags_and_initial_attributes() {
        let host = Arc::new(FakeHost::with_files(&[("files/existing", "body")]));
        let capability = synch_core::TreeWriteCapability {
            id: 1,
            modes: synch_core::TREE_WRITE_CREATE | synch_core::TREE_WRITE_REPLACE,
            prefix: "files".into(),
            max_bytes: 1024,
        };
        let mut sftp = TreeSftp::new(
            host.clone(),
            "files".into(),
            ACCESS_READ | ACCESS_WRITE | ACCESS_RECURSIVE,
            Some(capability),
            commit_budget(),
            writer_budget(),
        );

        assert_eq!(
            sftp.open(
                1,
                "existing".into(),
                OpenFlags::WRITE | OpenFlags::TRUNCATE,
                FileAttributes::empty(),
            )
            .await
            .unwrap_err(),
            StatusCode::PermissionDenied
        );
        assert_eq!(
            sftp.open(
                2,
                "new-with-mode".into(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes {
                    permissions: Some(0o600),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err(),
            StatusCode::OpUnsupported
        );
        assert_eq!(
            sftp.open(
                3,
                "existing".into(),
                OpenFlags::WRITE,
                FileAttributes {
                    size: Some(1),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err(),
            StatusCode::OpUnsupported
        );

        let opened = sftp
            .open(
                4,
                "sized".into(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes {
                    size: Some(4),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let staged = sftp.fstat(5, opened.handle.clone()).await.unwrap();
        assert_eq!(staged.attrs.size, Some(4));
        assert_eq!(staged.attrs.permissions, None);
        sftp.close(6, opened.handle).await.unwrap();
        assert_eq!(
            host.files.lock().unwrap().get("files/sized").unwrap(),
            &[0, 0, 0, 0]
        );
        assert_eq!(
            host.files.lock().unwrap().get("files/existing").unwrap(),
            b"body"
        );
    }

    #[tokio::test]
    async fn a_partial_write_failure_poisoned_handle_never_commits() {
        let host = Arc::new(FakeHost::with_files(&[]));
        host.fail_next_write_after(3);
        let capability = synch_core::TreeWriteCapability {
            id: 1,
            modes: synch_core::TREE_WRITE_CREATE,
            prefix: "files".into(),
            max_bytes: 1024,
        };
        let commits = commit_budget();
        let mut sftp = TreeSftp::new(
            host.clone(),
            "files".into(),
            ACCESS_READ | ACCESS_WRITE | ACCESS_RECURSIVE,
            Some(capability),
            commits.clone(),
            writer_budget(),
        );
        let opened = sftp
            .open(
                1,
                "partial".into(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::empty(),
            )
            .await
            .unwrap();

        assert_eq!(
            sftp.write(2, opened.handle.clone(), 0, b"abcdef".to_vec())
                .await
                .unwrap_err(),
            StatusCode::Failure
        );
        assert_eq!(
            sftp.fstat(3, opened.handle.clone()).await.unwrap_err(),
            StatusCode::Failure
        );
        assert_eq!(
            sftp.close(4, opened.handle).await.unwrap_err(),
            StatusCode::Failure
        );
        assert!(!host.files.lock().unwrap().contains_key("files/partial"));
        assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn setstat_rejects_metadata_instead_of_silently_dropping_it() {
        let host = Arc::new(FakeHost::with_files(&[("files/note", "body")]));
        let capability = synch_core::TreeWriteCapability {
            id: 1,
            modes: synch_core::TREE_WRITE_REPLACE,
            prefix: "files".into(),
            max_bytes: 1024,
        };
        let commits = commit_budget();
        let mut sftp = TreeSftp::new(
            host,
            "files".into(),
            ACCESS_READ | ACCESS_WRITE | ACCESS_RECURSIVE,
            Some(capability),
            commits.clone(),
            writer_budget(),
        );
        let opened = sftp
            .open(
                1,
                "note".into(),
                OpenFlags::READ | OpenFlags::WRITE,
                FileAttributes::empty(),
            )
            .await
            .unwrap();

        assert_eq!(
            sftp.fsetstat(
                2,
                opened.handle.clone(),
                FileAttributes {
                    size: Some(1),
                    permissions: Some(0o600),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err(),
            StatusCode::OpUnsupported
        );
        assert_eq!(
            sftp.read(3, opened.handle.clone(), 0, 64)
                .await
                .unwrap()
                .data,
            b"body"
        );
        assert_eq!(
            sftp.setstat(
                4,
                "note".into(),
                FileAttributes {
                    mtime: Some(123),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err(),
            StatusCode::OpUnsupported
        );
        assert_eq!(commits.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn writable_handles_replace_read_back_and_delete_in_scope() {
        let host = Arc::new(FakeHost::with_files(&[("files/note.txt", "hello world")]));
        let capability = synch_core::TreeWriteCapability {
            id: 1,
            modes: synch_core::TREE_WRITE_CREATE
                | synch_core::TREE_WRITE_REPLACE
                | synch_core::TREE_WRITE_DELETE,
            prefix: "files".into(),
            max_bytes: 1024,
        };
        let mut sftp = TreeSftp::new(
            host.clone(),
            "files".into(),
            ACCESS_READ | ACCESS_WRITE | ACCESS_RECURSIVE,
            Some(capability),
            commit_budget(),
            writer_budget(),
        );

        let opened = sftp
            .open(
                1,
                "note.txt".into(),
                OpenFlags::READ | OpenFlags::WRITE,
                FileAttributes::empty(),
            )
            .await
            .unwrap();
        sftp.write(2, opened.handle.clone(), 6, b"tree".to_vec())
            .await
            .unwrap();
        assert_eq!(
            sftp.read(3, opened.handle.clone(), 0, 64)
                .await
                .unwrap()
                .data,
            b"hello treed"
        );
        sftp.close(4, opened.handle).await.unwrap();

        let reopened = sftp
            .open(
                5,
                "note.txt".into(),
                OpenFlags::READ,
                FileAttributes::empty(),
            )
            .await
            .unwrap();
        assert_eq!(
            sftp.read(6, reopened.handle.clone(), 0, 64)
                .await
                .unwrap()
                .data,
            b"hello treed"
        );
        sftp.close(7, reopened.handle).await.unwrap();
        sftp.rename(8, "note.txt".into(), "moved.txt".into())
            .await
            .unwrap();
        assert_eq!(
            host.files.lock().unwrap().get("files/moved.txt").cloned(),
            Some(b"hello treed".to_vec())
        );
        sftp.remove(9, "moved.txt".into()).await.unwrap();
        assert!(!host.files.lock().unwrap().contains_key("files/moved.txt"));
    }
}
