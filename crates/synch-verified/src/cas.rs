//! CAS domain planning. No SQL, trie types, or per-predicate callbacks.

/// Snapshot for one holder's acquisition, read under the transaction lock.
#[derive(Debug, Clone, Copy)]
pub struct AcquisitionSnapshot {
    pub row: bool,
    pub durable: bool,
    pub wanted: bool,
}

/// Snapshot for one object's deletion, protected through post-commit cleanup.
#[derive(Debug, Clone, Copy)]
pub struct DeletionSnapshot {
    pub row: bool,
    pub writing: bool,
    pub pinned: bool,
    pub referenced: bool,
    pub last_access: i64,
}

/// Supported lifecycle operations and their operation-specific facts.
#[derive(Debug, Clone, Copy)]
pub enum LifecycleRequest {
    Acquire {
        snapshot: AcquisitionSnapshot,
        possession: bool,
    },
    Delete {
        snapshot: DeletionSnapshot,
        before: Option<i64>,
    },
}

/// Keyed mutations; apply the entire slice in one atomic transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    DeleteRow,
    DeleteWant,
    UpsertPin,
}

/// Best-effort file cleanup, executed only after a successful commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cleanup {
    Payload,
    Outboard,
}

/// Semantic result; not an internal state-machine tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Skipped,
    Writing,
    Protected,
    Applied,
}

/// A complete operation plan. The executor must preserve phase order and keep
/// the snapshot's ordering locks until post-commit cleanup finishes.
#[derive(Debug)]
pub struct LifecyclePlan {
    outcome: Outcome,
    transaction: Vec<Mutation>,
    after_commit: Vec<Cleanup>,
}

impl LifecyclePlan {
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }
    pub fn transaction(&self) -> &[Mutation] {
        &self.transaction
    }
    pub fn after_commit(&self) -> &[Cleanup] {
        &self.after_commit
    }
}

unsafe extern "C" {
    fn synch_adapter_cas_lifecycle(
        command: u8,
        row: u8,
        a: u8,
        b: u8,
        c: u8,
        d: u8,
        accessed: u64,
        before: u64,
        output: *mut u8,
    ) -> u8;
}

/// Plan an operation in Lean with one native call. The fixed-width private ABI
/// is only encoding; callers use the typed domain command and effect slices.
pub fn plan_lifecycle(request: LifecycleRequest) -> LifecyclePlan {
    super::native::enter();
    let (command, row, a, b, c, d, accessed, before) = match request {
        LifecycleRequest::Acquire {
            snapshot: s,
            possession,
        } => (0, s.row, s.durable, s.wanted, possession, false, 0, 0),
        LifecycleRequest::Delete {
            snapshot: s,
            before,
        } => (
            1,
            s.row,
            s.writing,
            s.pinned,
            s.referenced,
            before.is_some(),
            s.last_access,
            before.unwrap_or(0),
        ),
    };
    let mut bytes = [0u8; 5];
    // SAFETY: exact scalar ABI, normalized Booleans, five writable bytes.
    // Int64's generated uint64_t ABI preserves signed timestamp bits.
    let valid = unsafe {
        synch_adapter_cas_lifecycle(
            command,
            row.into(),
            a.into(),
            b.into(),
            c.into(),
            d.into(),
            accessed as u64,
            before as u64,
            bytes.as_mut_ptr(),
        )
    };
    assert_eq!(valid, 1, "invalid Lean lifecycle record width");
    let outcome = match bytes[0] {
        0 => Outcome::Skipped,
        1 => Outcome::Writing,
        2 => Outcome::Protected,
        3 => Outcome::Applied,
        _ => panic!("invalid Lean lifecycle outcome"),
    };
    let transaction = bytes[1..3]
        .iter()
        .filter_map(|tag| match tag {
            0 => None,
            1 => Some(Mutation::DeleteRow),
            2 => Some(Mutation::DeleteWant),
            3 => Some(Mutation::UpsertPin),
            _ => panic!("invalid Lean transaction action"),
        })
        .collect();
    let after_commit = bytes[3..5]
        .iter()
        .filter_map(|tag| match tag {
            0 => None,
            1 => Some(Cleanup::Payload),
            2 => Some(Cleanup::Outboard),
            _ => panic!("invalid Lean cleanup action"),
        })
        .collect();
    LifecyclePlan {
        outcome,
        transaction,
        after_commit,
    }
}
