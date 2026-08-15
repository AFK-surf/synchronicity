//! The CLI side of the control socket (§9.3).
//!
//! Every command except `synch init` and `synch daemon run` goes through here.
//! There is no in-process fallback: with no daemon running, [`Client::connect`]
//! fails with a message naming the socket and `synch daemon run` (§9.1).

use std::path::Path;

use crate::control::{
    proto::{
        read_frame, write_frame, ControlError, ErrorCode, Hello, Request, Response, Upload,
        CONTROL_VERSION,
    },
    transport::{self, ClientConn},
};

/// A connected control client, past the version and token handshake.
#[derive(Debug)]
pub struct Client {
    stream: ClientConn,
    done: bool,
}

impl Client {
    /// Connects to the daemon owning `data_dir` and completes the handshake.
    pub async fn connect(data_dir: &Path) -> Result<Client, ControlError> {
        Client::connect_as(data_dir, CONTROL_VERSION).await
    }

    /// Connects while claiming a specific protocol version.
    ///
    /// Only the version handshake needs this; ordinary clients use
    /// [`Client::connect`].
    pub async fn connect_as(data_dir: &Path, version: u32) -> Result<Client, ControlError> {
        let token = transport::read_token(data_dir).map_err(no_daemon)?;
        let stream = transport::connect(data_dir).await.map_err(no_daemon)?;
        let mut client = Client {
            stream,
            done: false,
        };
        write_frame(&mut client.stream, &Hello { version, token }).await?;
        match read_frame::<Response, _>(&mut client.stream).await? {
            Response::Ready => Ok(client),
            Response::Error(error) => Err(error),
            other => Err(ControlError::internal(format!(
                "the daemon answered the handshake with {other:?}"
            ))),
        }
    }

    /// Connects with a token of the caller's choosing, for testing the check.
    pub async fn connect_with_token(
        data_dir: &Path,
        token: Vec<u8>,
    ) -> Result<Client, ControlError> {
        let stream = transport::connect(data_dir).await.map_err(no_daemon)?;
        let mut client = Client {
            stream,
            done: false,
        };
        write_frame(
            &mut client.stream,
            &Hello {
                version: CONTROL_VERSION,
                token,
            },
        )
        .await?;
        match read_frame::<Response, _>(&mut client.stream).await? {
            Response::Ready => Ok(client),
            Response::Error(error) => Err(error),
            other => Err(ControlError::internal(format!(
                "the daemon answered the handshake with {other:?}"
            ))),
        }
    }

    /// Sends the request. One connection carries one command.
    pub async fn send(&mut self, request: &Request) -> Result<(), ControlError> {
        write_frame(&mut self.stream, request).await?;
        Ok(())
    }

    /// Sends one frame of a client-streamed payload.
    ///
    /// Only [`Request::TreePut`] takes these, and it takes them until an
    /// [`Upload::End`] or [`Upload::Abort`]: the daemon is reading, not
    /// answering, until one of the two arrives.
    pub async fn upload(&mut self, frame: &Upload) -> Result<(), ControlError> {
        write_frame(&mut self.stream, frame).await?;
        Ok(())
    }

    /// Reads the next response frame.
    ///
    /// `Ok(None)` is the `End` frame; a daemon-side failure comes back as
    /// `Err` carrying its code and message, never as a transport error.
    pub async fn next(&mut self) -> Result<Option<Response>, ControlError> {
        if self.done {
            return Ok(None);
        }
        match read_frame::<Response, _>(&mut self.stream).await {
            Ok(Response::End) => {
                self.done = true;
                Ok(None)
            }
            Ok(Response::Error(error)) => {
                self.done = true;
                Err(error)
            }
            Ok(frame) => Ok(Some(frame)),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                self.done = true;
                Err(ControlError::internal(
                    "the daemon closed the connection before finishing the response",
                ))
            }
            Err(e) => {
                self.done = true;
                Err(e.into())
            }
        }
    }
}

/// Opens a connection and sends one request in a single step.
pub async fn request(data_dir: &Path, request: Request) -> Result<Client, ControlError> {
    let mut client = Client::connect(data_dir).await?;
    client.send(&request).await?;
    Ok(client)
}

/// Turns a failure to reach the daemon into a structured error.
///
/// [`ErrorCode::Unavailable`] rather than `NotFound`: nothing the caller asked
/// for is missing — the daemon is, and the message names the socket and the
/// command that starts one (§9.1). A client that renders codes as protocol
/// statuses, as the S3 gateway does, would otherwise answer "no such key" to
/// every request made while the daemon was down.
fn no_daemon(e: std::io::Error) -> ControlError {
    let code = match e.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::AddrNotAvailable => ErrorCode::Unavailable,
        _ => ErrorCode::Internal,
    };
    ControlError::new(code, e.to_string())
}
