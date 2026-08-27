//! A bounded, scope-confined SFTP v3 service over the immutable tree API.

use std::{collections::HashMap, sync::Arc};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};

use crate::{HostError, ObjectInfo, SocketHost};

const ACCESS_READ: u32 = 0x01;
const ACCESS_RECURSIVE: u32 = 0x04;
const MAX_READ: u32 = 64 * 1024;
const MAX_OPEN_HANDLES: usize = 64;

#[derive(Debug)]
enum OpenHandle {
    File(ObjectInfo),
    Directory { entries: Vec<File>, read: bool },
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

    async fn list(&self, prefix: String) -> Result<Vec<String>, StatusCode> {
        let host = self.host.clone();
        tokio::task::spawn_blocking(move || host.list(&prefix))
            .await
            .map_err(|_| StatusCode::Failure)?
            .map_err(host_error)
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
        let listed = self.list(prefix.clone()).await?;
        let start = format!("{prefix}/");
        let mut entries = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for full in listed {
            let Some(rest) = full.strip_prefix(&start) else {
                continue;
            };
            let Some(name) = rest.split('/').next() else {
                continue;
            };
            if name.is_empty() || !seen.insert(name.to_string()) {
                continue;
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
            entries.push(File::new(name, attributes));
        }
        let handle = self.allocate(OpenHandle::Directory {
            entries,
            read: false,
        })?;
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        match self.handles.get_mut(&handle) {
            Some(OpenHandle::Directory { read, .. }) if *read => Err(StatusCode::Eof),
            Some(OpenHandle::Directory { entries, read }) => {
                *read = true;
                Ok(Name {
                    id,
                    files: entries.clone(),
                })
            }
            _ => Err(StatusCode::Failure),
        }
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
