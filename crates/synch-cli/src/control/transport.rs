//! The local control transport (§9.3).
//!
//! On Unix that is a domain socket at `<data_dir>/control.sock`, created `0600`
//! inside a `0700` data directory. On Windows it is a named pipe,
//! `\\.\pipe\synchronicity-<16 hex of the data dir path hash>`, so several
//! nodes on one machine do not collide.
//!
//! Both platforms authenticate with the 32-byte token in
//! `<data_dir>/control.token`. On Unix the directory permissions are the
//! primary control and the token is a second check; on Windows, where pipe ACLs
//! are easy to get subtly wrong, the token is what actually carries it.

use std::{
    io,
    path::{Path, PathBuf},
};

use iroh_base::SecretKey;

/// The Unix socket file inside the data directory.
pub const SOCKET_FILE: &str = "control.sock";

/// The token file inside the data directory.
pub const TOKEN_FILE: &str = "control.token";

/// How many bytes the control token has.
pub const TOKEN_LEN: usize = 32;

/// The error a client gets when nothing is listening (§9.1).
pub fn no_daemon_error(data_dir: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "no daemon is running for {}: nothing is listening on {}. \
             Start one with `synch daemon run`",
            data_dir.display(),
            endpoint_name(data_dir),
        ),
    )
}

/// The error a daemon gets when one is already running for this datadir.
fn already_running_error(data_dir: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "a daemon is already running for this datadir ({})",
            data_dir.display()
        ),
    )
}

// ---- the token --------------------------------------------------------------

/// Generates a fresh control token and writes it `0600`, replacing any
/// previous one.
///
/// Regenerated on every daemon start, so a token captured from an earlier run
/// is worthless (§9.3). The bytes come from the same OS CSPRNG that generates
/// device keys.
pub fn write_token(data_dir: &Path) -> io::Result<Vec<u8>> {
    harden_data_dir(data_dir)?;
    let token = SecretKey::generate().to_bytes().to_vec();
    let path = token_path(data_dir);
    // Remove first: rewriting in place would keep a previous file's mode.
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    write_private(&path, &token)?;
    Ok(token)
}

/// Reads the control token a running daemon wrote.
pub fn read_token(data_dir: &Path) -> io::Result<Vec<u8>> {
    match std::fs::read(token_path(data_dir)) {
        Ok(token) => Ok(token),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(no_daemon_error(data_dir)),
        Err(e) => Err(e),
    }
}

/// Removes the token file, so a stopped daemon leaves no credential behind.
pub fn remove_token(data_dir: &Path) {
    let _ = std::fs::remove_file(token_path(data_dir));
}

/// Where the token lives.
pub fn token_path(data_dir: &Path) -> PathBuf {
    data_dir.join(TOKEN_FILE)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(windows)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // Windows has no chmod. The data directory sits under the user's profile,
    // whose default ACL already excludes other users, and the token is checked
    // on every request regardless.
    std::fs::write(path, bytes)
}

/// Restricts the data directory to its owner (`0700`), where the platform has
/// such a notion.
pub fn harden_data_dir(data_dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

// ---- unix -------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use super::*;
    use tokio::net::{UnixListener, UnixStream};

    /// A connection as the daemon sees it.
    pub type ServerConn = UnixStream;
    /// A connection as the CLI sees it.
    pub type ClientConn = UnixStream;

    /// The socket path for a data directory.
    pub fn endpoint_name(data_dir: &Path) -> String {
        socket_path(data_dir).display().to_string()
    }

    /// Where the socket lives.
    pub fn socket_path(data_dir: &Path) -> PathBuf {
        data_dir.join(SOCKET_FILE)
    }

    /// The daemon's listening socket.
    #[derive(Debug)]
    pub struct Listener {
        inner: UnixListener,
        path: PathBuf,
    }

    impl Listener {
        /// Binds the socket, clearing a stale one left by a crashed daemon.
        ///
        /// Staleness is decided by connecting: a socket that accepts belongs to
        /// a live daemon and this fails; one that refuses is removed.
        pub async fn bind(data_dir: &Path) -> io::Result<Listener> {
            harden_data_dir(data_dir)?;
            let path = socket_path(data_dir);
            if path.exists() {
                match UnixStream::connect(&path).await {
                    Ok(_) => return Err(already_running_error(data_dir)),
                    Err(_) => {
                        tracing::debug!(path = %path.display(), "removing a stale control socket");
                        std::fs::remove_file(&path)?;
                    }
                }
            }
            let inner = UnixListener::bind(&path)?;
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(Listener { inner, path })
        }

        /// Accepts one connection.
        pub async fn accept(&mut self) -> io::Result<ServerConn> {
            let (stream, _addr) = self.inner.accept().await?;
            Ok(stream)
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Connects to a running daemon.
    pub async fn connect(data_dir: &Path) -> io::Result<ClientConn> {
        let path = socket_path(data_dir);
        match UnixStream::connect(&path).await {
            Ok(stream) => Ok(stream),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                Err(no_daemon_error(data_dir))
            }
            Err(e) => Err(e),
        }
    }
}

// ---- windows ----------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::*;
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };

    /// A connection as the daemon sees it.
    pub type ServerConn = NamedPipeServer;
    /// A connection as the CLI sees it.
    pub type ClientConn = NamedPipeClient;

    /// `ERROR_PIPE_BUSY`: every instance of the pipe is currently serving a
    /// client, so the caller should wait for a free one.
    const ERROR_PIPE_BUSY: i32 = 231;

    /// The pipe name for a data directory.
    ///
    /// `\\.\pipe\synchronicity-<16 hex>`, where the hex is the first 8 bytes of
    /// the blake3 hash of the data directory path. The path is canonicalized
    /// first when it exists, so `C:\data` and `C:\data\.` name one pipe; when it
    /// does not exist yet the raw text is hashed, which is enough because the
    /// daemon creates the directory before it binds.
    pub fn endpoint_name(data_dir: &Path) -> String {
        let resolved = std::fs::canonicalize(data_dir).unwrap_or_else(|_| data_dir.to_path_buf());
        let hash = synch_core::Hash::new(resolved.to_string_lossy().as_bytes());
        format!("\\\\.\\pipe\\synchronicity-{}", &hash.to_hex()[..16])
    }

    /// The daemon's listening pipe.
    ///
    /// A named pipe has no on-disk presence, so there is no stale instance to
    /// clean up: when the owning process dies its instances go with it. The
    /// live-daemon check is the same connect attempt Unix makes.
    #[derive(Debug)]
    pub struct Listener {
        name: String,
        next: Option<NamedPipeServer>,
    }

    impl Listener {
        /// Creates the first pipe instance.
        pub async fn bind(data_dir: &Path) -> io::Result<Listener> {
            harden_data_dir(data_dir)?;
            let name = endpoint_name(data_dir);
            if ClientOptions::new().open(&name).is_ok() {
                return Err(already_running_error(data_dir));
            }
            let next = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&name)
                .map_err(|e| {
                    // `first_pipe_instance` fails with ACCESS_DENIED when
                    // another process already owns the name — a daemon that
                    // exists but was busy during the connect above.
                    if e.kind() == io::ErrorKind::PermissionDenied {
                        already_running_error(data_dir)
                    } else {
                        e
                    }
                })?;
            Ok(Listener {
                name,
                next: Some(next),
            })
        }

        /// Waits for a client, then re-arms the next instance.
        pub async fn accept(&mut self) -> io::Result<ServerConn> {
            let server = match self.next.take() {
                Some(server) => server,
                None => ServerOptions::new().create(&self.name)?,
            };
            server.connect().await?;
            self.next = Some(ServerOptions::new().create(&self.name)?);
            Ok(server)
        }
    }

    /// Connects to a running daemon, waiting briefly if every instance is busy.
    pub async fn connect(data_dir: &Path) -> io::Result<ClientConn> {
        let name = endpoint_name(data_dir);
        for _ in 0..40 {
            match ClientOptions::new().open(&name) {
                Ok(client) => return Ok(client),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(no_daemon_error(data_dir))
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("the daemon at {name} stayed busy"),
        ))
    }
}

#[cfg(unix)]
pub use imp::socket_path;
pub use imp::{connect, endpoint_name, ClientConn, Listener, ServerConn};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_32_random_bytes_and_replaceable() {
        let dir = tempfile::tempdir().unwrap();
        let first = write_token(dir.path()).unwrap();
        assert_eq!(first.len(), TOKEN_LEN);
        assert_eq!(read_token(dir.path()).unwrap(), first);

        let second = write_token(dir.path()).unwrap();
        assert_ne!(first, second, "every daemon start mints a new token");
        assert_eq!(read_token(dir.path()).unwrap(), second);

        remove_token(dir.path());
        let err = read_token(dir.path()).unwrap_err();
        assert!(err.to_string().contains("synch daemon run"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn the_datadir_is_0700_and_the_token_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        write_token(dir.path()).unwrap();
        let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "{dir_mode:o}");
        let token_mode = std::fs::metadata(token_path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(token_mode & 0o777, 0o600, "{token_mode:o}");
    }

    #[test]
    fn the_endpoint_name_is_per_datadir() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        assert_ne!(endpoint_name(a.path()), endpoint_name(b.path()));
        assert_eq!(endpoint_name(a.path()), endpoint_name(a.path()));
    }

    #[cfg(windows)]
    #[test]
    fn the_pipe_name_has_the_documented_shape() {
        let dir = tempfile::tempdir().unwrap();
        let name = endpoint_name(dir.path());
        let suffix = name
            .strip_prefix("\\\\.\\pipe\\synchronicity-")
            .unwrap_or_else(|| panic!("{name}"));
        assert_eq!(suffix.len(), 16, "{name}");
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()), "{name}");
    }
}
