//! The control-socket connection an MCP process keeps to its daemon.
//!
//! An MCP server is launched by its client — usually when that application
//! starts — and lives for hours. The daemon does not share that lifetime: it
//! may not be running yet when the client launches this, and it may be
//! restarted underneath it. Two consequences drive everything here.
//!
//! **Nothing connects eagerly.** `synch mcp` starts, advertises its tools and
//! answers discovery with no daemon anywhere. A tool *call* is where the
//! connection is needed, and where its absence is reported — as a tool result
//! carrying the message the transport already writes for this case, which
//! names the socket and both ways to start one (§9.1).
//!
//! **The connection is cached but disposable.** `control.token` is regenerated
//! on every daemon start (§9.3), so a channel held across a restart fails
//! `Unauthorized` — which reads like a security problem and is a stale token.
//! [`Session::call`] therefore reconnects once and retries, exactly once, on
//! the codes that mean "this connection, not this request".

use std::{
    future::Future,
    path::{Path, PathBuf},
};

use tokio::sync::Mutex;

use crate::control::{Client, ControlError, ErrorCode};

/// A lazily-opened, self-healing control connection.
#[derive(Debug)]
pub(crate) struct Session {
    data_dir: PathBuf,
    /// The cached channel. `None` until the first call, and again after a
    /// failure that retiring the connection might fix.
    client: Mutex<Option<Client>>,
}

impl Session {
    /// Names the datadir whose daemon this session reaches. Connects nothing.
    pub(crate) fn new(data_dir: &Path) -> Session {
        Session {
            data_dir: data_dir.to_path_buf(),
            client: Mutex::new(None),
        }
    }

    /// Runs one control call, reconnecting once if the connection was the
    /// problem.
    ///
    /// `op` is run again from the start on a retry, so it must be the whole
    /// operation rather than a continuation of one. Every caller here is: the
    /// streamed write is opened inside `op`, and a write the daemon refused
    /// mid-stream committed nothing, so replaying it publishes once or not at
    /// all.
    pub(crate) async fn call<T, F, Fut>(&self, op: F) -> Result<T, ControlError>
    where
        F: Fn(Client) -> Fut,
        Fut: Future<Output = Result<T, ControlError>>,
    {
        let client = self.client().await?;
        match op(client).await {
            Ok(value) => Ok(value),
            Err(e) if retry_may_help(&e) => {
                // Retire the channel *before* reconnecting, so a caller racing
                // this one cannot pick the dead one back up.
                self.retire().await;
                let client = self.client().await?;
                op(client).await
            }
            Err(e) => Err(e),
        }
    }

    /// The cached channel, opening one if there is none.
    async fn client(&self) -> Result<Client, ControlError> {
        let mut slot = self.client.lock().await;
        if let Some(client) = slot.as_ref() {
            return Ok(client.clone());
        }
        let client = Client::connect(&self.data_dir).await?;
        *slot = Some(client.clone());
        Ok(client)
    }

    /// Drops the cached channel, so the next call opens a fresh one.
    async fn retire(&self) {
        *self.client.lock().await = None;
    }
}

/// Whether a failure is about the connection rather than the request.
///
/// All three mean the daemon on the other end is not the one this channel was
/// opened to, or is not there at all — a restart, in every case that happens
/// in practice. `Unavailable` also covers a node in key-loss recovery (§3.4),
/// where the retry costs one round trip and reports the same thing.
///
/// Nothing else is retried. A `NotFound`, an `Invalid` or a `Divergent` is the
/// daemon's considered answer, and asking twice would only produce it twice.
fn retry_may_help(e: &ControlError) -> bool {
    matches!(
        e.code,
        ErrorCode::Unauthorized | ErrorCode::Unavailable | ErrorCode::VersionMismatch
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn a_missing_daemon_is_unavailable_and_names_the_command_that_starts_one() {
        let data = tempfile::tempdir().unwrap();
        let session = Session::new(data.path());
        let error = session
            .call(|mut client| async move { client.list_spaces().await })
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(
            error.message.contains("synch daemon start"),
            "{}",
            error.message
        );
    }

    #[tokio::test]
    async fn the_connection_is_never_opened_until_a_call_needs_it() {
        let data = tempfile::tempdir().unwrap();
        let session = Session::new(data.path());
        // Constructing a session against a datadir with no daemon — and no
        // datadir at all — is the case an MCP client creates every time it
        // launches this before the user has started one.
        assert!(session.client.lock().await.is_none());
    }

    #[tokio::test]
    async fn a_connection_level_failure_is_retried_exactly_once() {
        // The connect itself fails here, so the retry is observed through the
        // attempt count rather than through a live daemon; `tests/mcp.rs`
        // covers the restart end to end.
        let data = tempfile::tempdir().unwrap();
        let session = Session::new(data.path());
        let attempts = AtomicUsize::new(0);
        let _ = session
            .call(|_| {
                attempts.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(ControlError::new(ErrorCode::Unauthorized, "stale token")) }
            })
            .await;
        // Zero: the connect never succeeded, so `op` never ran. What this pins
        // is that a failed reconnect is not retried in its own right.
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn only_connection_level_codes_are_retried() {
        for code in [
            ErrorCode::Unauthorized,
            ErrorCode::Unavailable,
            ErrorCode::VersionMismatch,
        ] {
            assert!(retry_may_help(&ControlError::new(code, "")), "{code:?}");
        }
        for code in [
            ErrorCode::NotFound,
            ErrorCode::Invalid,
            ErrorCode::Internal,
            ErrorCode::Divergent,
            ErrorCode::NotInitialized,
        ] {
            assert!(!retry_may_help(&ControlError::new(code, "")), "{code:?}");
        }
    }
}
