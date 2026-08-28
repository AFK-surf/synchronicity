//! A bounded, scope-confined SFTP v3 service over the immutable tree API.

use std::{collections::HashMap, sync::Arc};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};

use crate::{HostError, ListPage, ObjectInfo, SocketHost};

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
                let attributes = match self.open_info(child).await {
                    Ok(info) => attrs(&info),
                    Err(_) => {
                        let mut attrs = FileAttributes {
                            permissions: Some(0o040555),
                            ..Default::default()
                        };
                        attrs.set_dir(true);
                        attrs
                    }
                };
                response_bytes = response_bytes.saturating_add(encoded_bound);
                files.push(File::new(name, attributes));
                cursor.last_child = Some(name.to_string());
                cursor.after = Some(full);
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
                // A pathological directory can contain an enormous nested
                // subtree under one child. Bound work per request rather than
                // scanning it all merely to discover the next sibling.
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
