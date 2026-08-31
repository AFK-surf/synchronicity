//! Turning "host this network" into replicas (`docs/CLOUD-DATAPLANE.md` §4.5).
//!
//! `docs/REPLICATION.md` makes a replica per-space and explicit; hosting is
//! per-network and total. This module is the bridge: every space any origin
//! publishes gets a replica, with the org's policy on it.

use synch_engine::Node;

use crate::control::HostedNetwork;
use crate::error::Result;

/// What a tenant holds across all of its spaces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Coverage {
    /// Objects durably held.
    pub held_roots: u64,
    /// Bytes they account for.
    pub held_bytes: u64,
    /// Objects wanted and not yet held.
    pub wanted: u64,
    /// When this was measured.
    pub last_sync_ns: i64,
}

/// Adds a replica for every space the network publishes.
///
/// Replicas are added and **never removed here**. Removing one releases its
/// holds immediately, bypassing the grace period, so auto-removing on "the
/// space left the view" would let a transient view glitch — or a customer
/// briefly unpublishing — drop the hosted copy this service exists to keep.
/// And it would buy nothing: a replica of a space with no current entries
/// holds no roots and costs nothing, while retention already shrinks what
/// leaves the tree. Standing policies leave with the tenant, at teardown.
pub async fn ensure_replicas(node: &Node, network: &HostedNetwork) -> Result<()> {
    let policy = network.replica_policy();
    let budget = network.budget_bytes;
    let node = node.clone();
    let tenant = network.key();
    synch_core::offload(move || {
        let spaces = node.store().known_spaces()?;
        let existing: Vec<synch_store::ReplicaRow> = node.store().replicas()?;
        // The engine's budget is a per-replica admission ceiling and there is
        // no org-level one, so the org's budget is re-derived per space on
        // every pass: what is left of it once the tenant's *other* replicas
        // are accounted for. Approximate under concurrent admissions, and
        // convergent, which is what a quota needs to be (§4.5).
        let mut held_elsewhere: u64 = 0;
        for replica in &existing {
            let coverage = node
                .store()
                .replica_coverage(&replica.holder(), UNREACHABLE_ATTEMPTS)?;
            held_elsewhere = held_elsewhere.saturating_add(coverage.held_bytes);
        }
        for space in spaces {
            let known = existing.iter().find(|replica| replica.space == space);
            let share = share_for(budget, held_elsewhere, known, &node)?;
            match known {
                None => {
                    // `forever` refuses a grace, so it is never passed with it.
                    let grace = None;
                    node.add_replica(&space, policy, grace, share, None)?;
                    tracing::info!(%tenant, %space, "replicating a space");
                }
                // Compared against what the replica *has*, not against
                // whether a budget exists. An org moving to an unlimited plan
                // sends `budget_bytes: 0`, which derives `None`; a guard that
                // only fired when a budget was present would leave every
                // replica pinned at its old ceiling for ever, admitting
                // nothing and reporting `held_back` with no explanation. It
                // also stops this writing a row for every space on every tick
                // whenever any budget is set.
                Some(replica) if replica.retention != policy || replica.budget != share => {
                    node.set_replica(&space, Some(policy), None, Some(share), None)?;
                }
                Some(_) => {}
            }
        }
        Ok::<_, synch_engine::EngineError>(())
    })
    .await?;
    Ok(())
}

/// How much of the org's budget this space may still admit.
///
/// `None` when the org set no budget, which is the engine's "no ceiling".
fn share_for(
    budget: u64,
    held_elsewhere: u64,
    known: Option<&synch_store::ReplicaRow>,
    node: &Node,
) -> synch_engine::Result<Option<u64>> {
    if budget == 0 {
        return Ok(None);
    }
    let own = match known {
        Some(replica) => {
            node.store()
                .replica_coverage(&replica.holder(), UNREACHABLE_ATTEMPTS)?
                .held_bytes
        }
        None => 0,
    };
    // What the others hold is off the table; what this one already holds is
    // still its own, so it is added back rather than counted against it.
    let others = held_elsewhere.saturating_sub(own);
    Ok(Some(budget.saturating_sub(others)))
}

/// How many failures make a want "unreachable" for reporting.
///
/// The engine's own threshold for the same question.
const UNREACHABLE_ATTEMPTS: i64 = 3;

/// Totals what this tenant holds, for the heartbeat (§3.3).
pub async fn coverage(node: &Node) -> Result<Coverage> {
    let node = node.clone();
    let coverage = synch_core::offload(move || {
        let mut total = Coverage::default();
        for replica in node.store().replicas()? {
            let one = node
                .store()
                .replica_coverage(&replica.holder(), UNREACHABLE_ATTEMPTS)?;
            total.held_roots = total.held_roots.saturating_add(one.held);
            total.held_bytes = total.held_bytes.saturating_add(one.held_bytes);
            total.wanted = total.wanted.saturating_add(one.wanted);
        }
        total.last_sync_ns = node.store().read_instant()?;
        Ok::<_, synch_engine::EngineError>(total)
    })
    .await?;
    Ok(coverage)
}
