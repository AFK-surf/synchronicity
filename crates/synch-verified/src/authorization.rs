//! Complete authorization operations executed by Lean over raw storage.
//! Rust transports typed requests/results and supplies primitive point validation.
use crate::{
    host::{Crypto, Storage},
    operation::{run, Capabilities, Command, Decode},
};

pub use crate::generated::{
    AuthorizationBinding as Binding, AuthorizationDomainError as DomainError,
    AuthorizationPublishScope as PublishScope, AuthorizationSource as Source,
    AuthorizationTrieScope as TrieScope, BindingSelection, BindingStatus, CellType, LocalAuthority,
    MetadataRefusal, OriginAuthority, ParsedOrigin as Origin, PeerAuthority, SocketAuthority,
};

pub type Error<E> = crate::CommandError<E, DomainError>;

fn execute<S: Storage, A: Decode>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    command: Command,
) -> Result<A, Error<S::Error>> {
    let capabilities = Capabilities {
        crypto: Some(crypto),
        ..Capabilities::default()
    };
    Error::finish(run(storage, capabilities, &[], &command))
}

pub fn bindings<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    selection: BindingSelection,
    only_live: bool,
    reading: i64,
) -> Result<Vec<Binding>, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthBindings {
            selection,
            only_live,
            reading,
        },
    )
}

pub fn binding_statuses<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    reading: i64,
) -> Result<Vec<BindingStatus>, Error<S::Error>> {
    execute(storage, crypto, Command::AuthBindingStatuses(reading))
}

pub fn trusted_keys<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    reading: i64,
) -> Result<Vec<Vec<u8>>, Error<S::Error>> {
    execute(storage, crypto, Command::AuthTrustedKeys(reading))
}

pub fn trusted_origins<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    reading: i64,
) -> Result<Vec<Origin>, Error<S::Error>> {
    execute(storage, crypto, Command::AuthTrustedOrigins(reading))
}

pub fn trusted_key<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    key: &[u8],
    reading: i64,
) -> Result<bool, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthTrustedKey {
            key: key.to_vec(),
            reading,
        },
    )
}

pub fn bound<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    origin: &Origin,
    key: &[u8],
    reading: i64,
) -> Result<bool, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthBound {
            origin: origin.clone(),
            key: key.to_vec(),
            reading,
        },
    )
}

pub fn peer_authority<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    key: &[u8],
    reading: i64,
) -> Result<PeerAuthority, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthPeerAuthority {
            key: key.to_vec(),
            reading,
        },
    )
}

pub fn origin_publication<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    origin: &Origin,
    reading: i64,
) -> Result<PublishScope, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthOriginPublication {
            origin: origin.clone(),
            reading,
        },
    )
}

pub fn origin_authority<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    origin: &Origin,
    reading: i64,
) -> Result<OriginAuthority, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthOriginAuthority {
            origin: origin.clone(),
            reading,
        },
    )
}

pub fn origin_authority_in<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    tx: u64,
    origin: &Origin,
    reading: i64,
) -> Result<OriginAuthority, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthOriginAuthorityIn {
            tx,
            origin: origin.clone(),
            reading,
        },
    )
}

pub fn local_authority<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    reading: i64,
) -> Result<LocalAuthority, Error<S::Error>> {
    execute(storage, crypto, Command::AuthLocalAuthority(reading))
}

pub fn local_spaces<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
) -> Result<Option<Vec<String>>, Error<S::Error>> {
    execute(storage, crypto, Command::AuthLocalSpaces)
}

pub fn local_scope<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
) -> Result<TrieScope, Error<S::Error>> {
    execute(storage, crypto, Command::AuthLocalScope)
}

pub fn materialization_scope<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    origin: &Origin,
) -> Result<TrieScope, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthMaterializationScope(origin.clone()),
    )
}

pub fn materialization_scope_in<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    tx: u64,
    origin: &Origin,
) -> Result<TrieScope, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthMaterializationScopeIn {
            tx,
            origin: origin.clone(),
        },
    )
}

pub fn metadata_peer<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    key: &[u8],
    reading: i64,
) -> Result<Option<MetadataRefusal>, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthMetadataPeer {
            key: key.to_vec(),
            reading,
        },
    )
}

pub fn socket_authority<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    key: &[u8],
    reading: i64,
) -> Result<Option<SocketAuthority>, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthSocketAuthority {
            key: key.to_vec(),
            reading,
        },
    )
}

pub fn sole_dns_hint_source<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    key: &[u8],
    domain: &str,
    reading: i64,
) -> Result<bool, Error<S::Error>> {
    execute(
        storage,
        crypto,
        Command::AuthSoleDnsHintSource {
            key: key.to_vec(),
            domain: domain.to_owned(),
            reading,
        },
    )
}

pub fn has_delegations<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
) -> Result<bool, Error<S::Error>> {
    execute(storage, crypto, Command::AuthHasDelegations)
}

pub fn expire_dns<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    reading: i64,
) -> Result<u64, Error<S::Error>> {
    execute(storage, crypto, Command::AuthExpireDns(reading))
}

pub fn local_scope_in<S: Storage>(
    storage: &mut S,
    crypto: &mut dyn Crypto<Error = S::Error>,
    tx: u64,
) -> Result<TrieScope, Error<S::Error>> {
    execute(storage, crypto, Command::AuthLocalScopeIn(tx))
}
