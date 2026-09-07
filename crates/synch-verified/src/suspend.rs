//! Runs that wait on a peer. A command whose effects include the peer's round
//! trips does not complete in one call: the runner hands its continuation
//! back at each request as a [`Suspension`], the caller makes the round trip
//! however it likes, and resumes the run with the answer, supplying storage
//! again at that point. The continuation is confined to the thread that
//! started the run, and the runner only suspends while no storage transaction
//! is open, so nothing storage-bound is ever held across a network wait.
pub use crate::generated::Probed;
pub use crate::operation::{OperationError, PeerReply, PeerRequest, Step, Suspension};

use crate::host::Storage;
use crate::operation::{run_suspending, terminal, Capabilities, Command};

impl<T, E> Suspension<T, E> {
    /// Answer the request and run on until the next suspension or the end.
    /// A reply of the other kind is a protocol failure delivered into the
    /// program, so its own cleanup runs; a failed round trip is the host
    /// error it carries, delivered the same way.
    pub fn resume<S: Storage<Error = E>>(
        self,
        answer: PeerReply<E>,
        storage: &mut S,
    ) -> Result<Step<T, E>, OperationError<E>> {
        self.continue_with(answer, storage, Capabilities::default())
    }
}

/// The runner's self-test: ask a peer for `wants` under `root` across two
/// suspensions and count what came back. Inside a transaction when told to,
/// which the runner refuses rather than holding a connection across the
/// wait; the refusal then rolls the transaction back and the run fails as a
/// protocol failure.
pub fn probe<S: Storage>(
    storage: &mut S,
    root: &[u8],
    wants: &[(Vec<u8>, Vec<u8>)],
    in_transaction: bool,
) -> Result<Step<Probed, S::Error>, OperationError<S::Error>> {
    let command = Command::PeerProbe {
        root: root.to_vec(),
        wants: wants.to_vec(),
        in_transaction,
    };
    run_suspending(storage, Capabilities::default(), &command, terminal)
}
