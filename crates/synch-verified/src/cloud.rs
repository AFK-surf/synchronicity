//! Whole cloud cache restoration. Provider waits return owned raw requests;
//! the caller retains local resource owners until completion or abandonment.

pub use crate::generated::{CloudDomainError as DomainError, ProviderProbed};
pub use crate::operation::{
    OperationError, ProviderReply, ProviderRequest, ProviderStep, ProviderSuspension,
};

use crate::host::{Bao, CacheIO, Clock, Lease, Storage, TemporaryFiles};
use crate::operation::{run_provider_suspending, terminal, Capabilities, Command, Decode};

/// A restoration result or its next raw provider request. Domain refusals
/// stay distinct from original host errors raised by the outer result.
pub type Outcome<T, E> = Result<ProviderStep<Result<T, DomainError>, E>, OperationError<E>>;

/// Raw capabilities retained by the caller across provider suspensions.
pub struct Resources<'a, E> {
    pub clock: &'a mut dyn Clock<Error = E>,
    pub bao: &'a mut dyn Bao<Error = E>,
    pub leases: &'a mut dyn Lease<Error = E>,
    pub temporary: &'a mut dyn TemporaryFiles<Error = E>,
    pub access: &'a mut dyn crate::host::Resources<Error = E>,
    pub cache: &'a mut dyn CacheIO<Error = E>,
}

impl<E> std::fmt::Debug for Resources<'_, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resources").finish_non_exhaustive()
    }
}

impl<'a, E> Resources<'a, E> {
    fn capabilities(self) -> Capabilities<'a, E> {
        Capabilities {
            clock: Some(self.clock),
            bao: Some(self.bao),
            leases: Some(self.leases),
            temporary: Some(self.temporary),
            resources: Some(self.access),
            cache: Some(self.cache),
            ..Capabilities::default()
        }
    }
}

fn start<T: Decode, S: Storage>(
    storage: &mut S,
    resources: Resources<'_, S::Error>,
    command: Command,
) -> Outcome<T, S::Error> {
    run_provider_suspending(storage, resources.capabilities(), &command, terminal)
}

/// Continue the same operation after one raw provider reply. The resources
/// belong to this invocation and must outlive its final suspension.
pub fn resume<T, S: Storage>(
    waiting: ProviderSuspension<T, S::Error>,
    answer: ProviderReply<S::Error>,
    storage: &mut S,
    resources: Resources<'_, S::Error>,
) -> Result<ProviderStep<T, S::Error>, OperationError<S::Error>> {
    waiting.continue_provider_with(answer, storage, resources.capabilities())
}

/// Restore a complete durable object into local cache.
pub fn ensure_cached<S: Storage>(
    storage: &mut S,
    resources: Resources<'_, S::Error>,
    root: &[u8; 32],
    size: u64,
) -> Outcome<(), S::Error> {
    start(
        storage,
        resources,
        Command::CloudEnsureCached {
            root: root.to_vec(),
            size,
        },
    )
}

/// Adopt available remote content and restore requested groups absent locally.
pub fn ensure_ranges<S: Storage>(
    storage: &mut S,
    resources: Resources<'_, S::Error>,
    root: &[u8; 32],
    size: u64,
    ranges: &[(u64, u64)],
) -> Outcome<(), S::Error> {
    start(
        storage,
        resources,
        Command::CloudEnsureRanges {
            root: root.to_vec(),
            size,
            ranges: ranges.to_vec(),
        },
    )
}

/// Hydrate these groups from trusted immutable provider objects. Lean owns
/// the writer lease, outboard cache, bounded reads, flush and group commit.
pub fn hydrate<S: Storage>(
    storage: &mut S,
    resources: Resources<'_, S::Error>,
    root: &[u8; 32],
    size: u64,
    ranges: &[(u64, u64)],
) -> Outcome<(), S::Error> {
    start(
        storage,
        resources,
        Command::CloudHydrate {
            root: root.to_vec(),
            size,
            ranges: ranges.to_vec(),
        },
    )
}

/// Read and cache the outboard, optionally bypassing a damaged cache copy.
pub fn outboard<S: Storage>(
    storage: &mut S,
    resources: Resources<'_, S::Error>,
    root: &[u8; 32],
    force: bool,
) -> Outcome<Vec<u8>, S::Error> {
    start(
        storage,
        resources,
        Command::CloudOutboard {
            root: root.to_vec(),
            force,
        },
    )
}
