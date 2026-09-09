//! Whole reconciliation commands; the facade binds raw services only.
pub use crate::generated::FetchReport;
pub use crate::generated::{Acceptance, Head, Promotion, PromotionReport, ReconcileDomainError};
use crate::{
    host,
    operation::{run, Capabilities, Command},
    CommandError,
};

/// Diagnostic memo key: pending version and displaced complete root.
pub type Refused = (u64, (Vec<u8>, Vec<u8>));
/// One interval of reconciliation, retaining the Lean continuation across waits.
pub type FetchStep<E> = crate::suspend::Step<Result<FetchReport, ReconcileDomainError>, E>;

/// Start reconciliation of the current pending head with an optional exact target.
pub fn fetch<S: host::Storage>(
    storage: &mut S,
    resources: Resources<'_, S::Error>,
    origin: crate::authorization::Origin,
    expected: Option<(u64, Vec<u8>)>,
    refused: Vec<Refused>,
    maximum: u64,
    retry_limit: u64,
) -> Result<FetchStep<S::Error>, crate::trie::OperationError<S::Error>> {
    crate::operation::run_suspending(
        storage,
        resources.capabilities(),
        &Command::FetchPending {
            origin,
            expected,
            refused,
            maximum,
            retry_limit,
        },
        crate::operation::terminal,
    )
}
/// Resume the same operation after an owned peer reply, on its original worker.
pub fn resume<S: host::Storage>(
    suspended: crate::suspend::Suspension<Result<FetchReport, ReconcileDomainError>, S::Error>,
    reply: crate::suspend::PeerReply<S::Error>,
    storage: &mut S,
    resources: Resources<'_, S::Error>,
) -> Result<FetchStep<S::Error>, crate::trie::OperationError<S::Error>> {
    suspended.continue_with(reply, storage, resources.capabilities())
}

/// Raw services used during atomic promotion and view materialization.
pub struct Resources<'a, E> {
    pub crypto: &'a mut dyn host::Crypto<Error = E>,
    pub unicode: &'a mut dyn host::Unicode<Error = E>,
    pub digest: &'a mut dyn host::Digest<Error = E>,
    pub clock: &'a mut dyn host::Clock<Error = E>,
    pub memo: &'a mut dyn host::Memo<Error = E>,
    pub redaction: &'a mut dyn host::Redaction<Error = E>,
}
impl<E> std::fmt::Debug for Resources<'_, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resources").finish_non_exhaustive()
    }
}
impl<'a, E> Resources<'a, E> {
    fn capabilities(self) -> Capabilities<'a, E> {
        Capabilities {
            crypto: Some(self.crypto),
            unicode: Some(self.unicode),
            digest: Some(self.digest),
            clock: Some(self.clock),
            memo: Some(self.memo),
            redaction: Some(self.redaction),
            ..Capabilities::default()
        }
    }
}
/// Validate and durably accept an offered signed head.
pub fn accept<S: host::Storage>(
    storage: &mut S,
    crypto: &mut dyn host::Crypto<Error = S::Error>,
    head: Head,
    now: i64,
    keep: u64,
) -> Result<Acceptance, crate::history::Error<S::Error>> {
    CommandError::finish(run(
        storage,
        Capabilities {
            crypto: Some(crypto),
            ..Capabilities::default()
        },
        &[],
        &Command::AcceptHead { head, now, keep },
    ))
}
/// Atomically promote the current pending version, or retire a refused version.
pub fn promote<S: host::Storage>(
    storage: &mut S,
    resources: Resources<'_, S::Error>,
    origin: crate::authorization::Origin,
    now: i64,
    refused: Vec<Refused>,
) -> Result<PromotionReport, CommandError<S::Error, ReconcileDomainError>> {
    CommandError::finish(run(
        storage,
        resources.capabilities(),
        &[],
        &Command::PromoteHead {
            origin,
            now,
            refused,
        },
    ))
}
/// Apply a streamed view delta inside a borrowed publication transaction.
pub fn materialize<S: host::Storage>(
    storage: &mut S,
    resources: Resources<'_, S::Error>,
    tx: u64,
    origin: crate::authorization::Origin,
    old_root: Vec<u8>,
    new_root: Vec<u8>,
) -> Result<u64, CommandError<S::Error, ReconcileDomainError>> {
    CommandError::finish(run(
        storage,
        resources.capabilities(),
        &[],
        &Command::MaterializeView {
            tx,
            origin,
            old_root,
            new_root,
        },
    ))
}

/// Atomically change the node's read permission and invalidate every derived
/// foreign view, completion claim and retry age established under the old one.
pub fn change_scope<S: host::Storage>(
    storage: &mut S,
    crypto: &mut dyn host::Crypto<Error = S::Error>,
    spaces: Option<Vec<String>>,
    now: i64,
) -> Result<bool, crate::history::Error<S::Error>> {
    CommandError::finish(run(
        storage,
        Capabilities {
            crypto: Some(crypto),
            ..Capabilities::default()
        },
        &[],
        &Command::AuthChangeScope { spaces, now },
    ))
}
