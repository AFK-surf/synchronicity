//! The local control transport (§9.3).
//!
//! gRPC needs a byte stream under it, and this is where that stream comes from.
//! On Unix it is a domain socket at `<data_dir>/control.sock`, `0600` inside a
//! `0700` data directory; on Windows a named pipe,
//! `\\.\pipe\synchronicity-<16 hex of the data dir path hash>`, so several
//! nodes on one machine do not collide.
//!
//! Both platforms authenticate with the 32-byte token in
//! `<data_dir>/control.token`, sent as a header on every call. On Unix the
//! directory permissions are the primary control and the token is a second
//! check; on Windows, where pipe ACLs are easy to get subtly wrong, the token
//! is what actually carries it.

use std::{
    io,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
};

use hyper_util::rt::TokioIo;
use iroh_base::SecretKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::{server::Connected, Channel, Endpoint, Uri};

/// The Unix socket file inside the data directory.
pub const SOCKET_FILE: &str = "control.sock";

/// The token file inside the data directory.
pub const TOKEN_FILE: &str = "control.token";

/// Stable inode used to exclude daemon startup and offline CAS migration.
const LIFECYCLE_FILE: &str = "lifecycle.lock";

/// How many bytes the control token has.
pub const TOKEN_LEN: usize = 32;

/// Process-held exclusive ownership of a data directory's mutable lifecycle.
#[derive(Debug)]
pub struct LifecycleLock(std::fs::File);

impl LifecycleLock {
    /// Acquires the lock before opening the Store or any network endpoint.
    pub fn acquire(data_dir: &Path) -> io::Result<Self> {
        use fs2::FileExt;
        harden_data_dir(data_dir)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(data_dir.join(LIFECYCLE_FILE))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.try_lock_exclusive()
            .map_err(|_| already_running_error(data_dir))?;
        Ok(Self(file))
    }
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

/// The authority every control channel claims.
///
/// HTTP/2 wants one and the local transport has none to offer — the data
/// directory, not a host and a port, is what says which daemon this is. It is
/// never resolved: the connector hands back an already-open stream.
const LOCAL_AUTHORITY: &str = "http://synchronicity.local";

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
/// is worthless (§9.3); the bytes come from the same CSPRNG that generates
/// device keys.
pub fn write_token(data_dir: &Path) -> io::Result<Vec<u8>> {
    harden_data_dir(data_dir)?;
    let token = SecretKey::generate().to_bytes().to_vec();
    let path = token_path(data_dir);
    // Written to a sibling and renamed over, so a reader never sees a partial
    // token.
    //
    // `Server::bind` binds the listener *before* minting this, deliberately —
    // the other order lets a refused replacement daemon clobber the running
    // one's token (see the shutdown path). So the socket answers while this
    // file is mid-write, and writing in place made that window observable: a
    // client that read a created-but-empty file was refused `Unauthorized` on
    // a daemon that had just started correctly. A rename closes it without
    // disturbing the bind order, because the name only ever appears with the
    // whole token behind it.
    //
    // The temp file is created fresh rather than rewritten, which is also what
    // keeps the private mode from being inherited from a previous file's.
    let staged = path.with_extension("token.new");
    match std::fs::remove_file(&staged) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    write_private(&staged, &token)?;
    std::fs::rename(&staged, &path)?;
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
    let path = token_path(data_dir);
    // The staging name too: a crash between the write and the rename leaves a
    // file that looks exactly like a credential, and "leaves no credential
    // behind" has to mean that one as well. It authenticates nothing — no
    // listener ever saw it — but it should not be lying around.
    let _ = std::fs::remove_file(path.with_extension("token.new"));
    let _ = std::fs::remove_file(path);
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

    /// The byte stream the daemon serves gRPC over.
    pub type Transport = UnixStream;

    /// The longest socket path `bind` accepts: `sun_path` minus its NUL.
    const MAX_SOCKET_PATH: usize = 107;

    /// Refuses a data directory whose control socket could never be bound.
    ///
    /// The kernel's own answer is "path must be shorter than SUN_LEN" — an
    /// acronym, no measurement, no remedy — one command *after* `synch init`
    /// said everything was fine. This check runs at init and at bind, so the
    /// answer names the length, the limit, and the fix.
    pub fn check_socket_path(data_dir: &Path) -> io::Result<()> {
        let path = socket_path(data_dir);
        let len = path.as_os_str().len();
        if len > MAX_SOCKET_PATH {
            return Err(io::Error::other(format!(
                "the control socket path {} is {len} bytes and the OS limit \
                 is {MAX_SOCKET_PATH}: use a shorter --data-dir",
                path.display()
            )));
        }
        Ok(())
    }

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
            check_socket_path(data_dir)?;
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
        pub async fn accept(&mut self) -> io::Result<Transport> {
            let (stream, _addr) = self.inner.accept().await?;
            Ok(stream)
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Opens one connection to a running daemon.
    pub async fn dial(data_dir: &Path) -> io::Result<Transport> {
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
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

    /// The byte stream the daemon serves gRPC over.
    pub type Transport = NamedPipeServer;

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

    /// Pipe names are hashed to a fixed length; there is nothing to check.
    pub fn check_socket_path(_data_dir: &Path) -> io::Result<()> {
        Ok(())
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
        pub async fn accept(&mut self) -> io::Result<Transport> {
            let server = match self.next.take() {
                Some(server) => server,
                None => ServerOptions::new().create(&self.name)?,
            };
            server.connect().await?;
            self.next = Some(ServerOptions::new().create(&self.name)?);
            Ok(server)
        }
    }

    /// Opens one connection to a running daemon, waiting briefly if every
    /// instance is busy.
    pub async fn dial(
        data_dir: &Path,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
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
pub use imp::{check_socket_path, dial, endpoint_name, Listener, Transport};

/// One accepted connection, ready to be served gRPC over.
///
/// The wrapper exists to say what the platform stream cannot: [`Connected`] is
/// how a tonic server learns about a connection, and neither a Unix socket nor
/// a named pipe has anything to tell it — the peer is on this machine, holding
/// this datadir's token, and that is the whole of its identity.
#[derive(Debug)]
pub struct Accepted(Transport);

impl Accepted {
    /// Wraps an accepted connection.
    pub fn new(transport: Transport) -> Accepted {
        Accepted(transport)
    }
}

impl Connected for Accepted {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for Accepted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Accepted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Connects to the daemon owning `data_dir`.
///
/// The channel dials once, here, so "nothing is listening" is answered by this
/// call rather than by the first request made over it.
pub async fn connect(data_dir: &Path) -> io::Result<Channel> {
    let data_dir = data_dir.to_path_buf();
    let connector = tower::service_fn(move |_: Uri| {
        let data_dir = data_dir.clone();
        async move { Ok::<_, io::Error>(TokioIo::new(dial(&data_dir).await?)) }
    });
    Endpoint::from_static(LOCAL_AUTHORITY)
        .connect_with_connector(connector)
        .await
        .map_err(unwrap_io)
}

/// Recovers the connector's own error from the transport failure wrapping it.
///
/// The wrapper's message is "transport error", which names neither the socket
/// nor the command that starts a daemon; the error underneath names both.
fn unwrap_io(e: tonic::transport::Error) -> io::Error {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
    while let Some(link) = source {
        if let Some(inner) = link.downcast_ref::<io::Error>() {
            return io::Error::new(inner.kind(), inner.to_string());
        }
        source = link.source();
    }
    io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The kernel's own refusal is "SUN_LEN", one command after init said
    // everything was fine; the check names the length, the limit, and the fix.
    #[cfg(unix)]
    #[test]
    fn a_socket_path_over_the_os_limit_is_refused_by_name() {
        check_socket_path(Path::new("/tmp/short")).unwrap();
        let long = PathBuf::from(format!("/tmp/{}", "x".repeat(120)));
        let text = check_socket_path(&long).unwrap_err().to_string();
        assert!(
            text.contains("bytes") && text.contains("--data-dir"),
            "{text}"
        );
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

    // Nothing is listening, and the answer has to name the socket and the
    // command that starts one rather than "transport error" (§9.1).
    #[tokio::test]
    async fn connecting_to_nothing_names_the_socket_and_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let err = connect(dir.path()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
        assert!(err.to_string().contains("synch daemon run"), "{err}");
        assert!(
            err.to_string().contains(&endpoint_name(dir.path())),
            "{err}"
        );
    }

    #[test]
    fn lifecycle_lock_excludes_daemon_and_migration_before_open() {
        let dir = tempfile::tempdir().unwrap();
        let held = LifecycleLock::acquire(dir.path()).unwrap();
        let error = LifecycleLock::acquire(dir.path()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse, "{error}");
        drop(held);
        LifecycleLock::acquire(dir.path()).unwrap();
    }
}
