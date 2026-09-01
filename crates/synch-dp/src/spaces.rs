//! Turning "host this network" into replicas (`docs/CLOUD-DATAPLANE.md` §4.5).
//!
//! `docs/REPLICATION.md` makes a replica per-space and explicit; hosting is
//! per-network and total. This module is the bridge: every space any origin
//! publishes gets a replica, with the org's policy on it — up to a ceiling,
//! because "every space any origin publishes" is a number a member chooses
//! and this pod is shared (§9.1).

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

/// How many spaces this service will replicate for one tenant.
///
/// A space is a plain string in the trie key that any member may publish
/// under (DESIGN §12), so the number of them is a member's to choose — and
/// this module's job is to turn each one into a standing replica, which is a
/// row that rides the tenant's database to object storage and costs a
/// coverage query on every converge pass. Unbounded, that is one network
/// deciding how much of this pod every other network gets.
///
/// The ceiling is therefore about the pod, and only about the pod. **Which
/// spaces land under it is not defended**: they arrive in whatever order the
/// store returns them, so a member publishing thousands can take the
/// allowance from its own org's real shares. That is a member degrading its
/// own network, which is where DESIGN §12 leaves it — the org that holds the
/// membership holds the remedy, and this service has no business ranking one
/// of an org's own devices above another.
///
/// Four thousand is three orders of magnitude past any real deployment — an
/// org's spaces are its shares, and there are tens — so a tenant that reaches
/// it is not a tenant with a lot of shares, and the error-level log says so.
const MAX_REPLICATED_SPACES: usize = 4096;

/// Adds a replica for every space the network publishes.
///
/// Replicas are added and **never removed here**. Removing one releases its
/// holds immediately, bypassing the grace period, so auto-removing on "the
/// space left the view" would let a transient view glitch — or a customer
/// briefly unpublishing — drop the hosted copy this service exists to keep.
/// And it would buy nothing: a replica of a space with no current entries
/// holds no roots and costs nothing, while retention already shrinks what
/// leaves the tree. Standing policies leave with the tenant, at teardown.
///
/// That rule is also why the ceiling above exists: what is never removed had
/// better be bounded when a member chooses how much of it there is.
pub async fn ensure_replicas(node: &Node, network: &HostedNetwork) -> Result<()> {
    ensure_replicas_capped(node, network, MAX_REPLICATED_SPACES).await
}

/// [`ensure_replicas`] with the ceiling named, so a test can reach one
/// without publishing four thousand spaces to get there.
async fn ensure_replicas_capped(
    node: &Node,
    network: &HostedNetwork,
    ceiling: usize,
) -> Result<()> {
    let policy = network.replica_policy();
    let budget = network.budget_bytes;
    let node = node.clone();
    let tenant = network.key();
    synch_core::offload(move || {
        let spaces = node.store().known_spaces()?;
        let existing: Vec<synch_store::ReplicaRow> = node.store().replicas()?;
        // Decided before the loop and applied inside it as a stop rather than
        // as a filter over the result: a cap after the work is not a cap on
        // the work (DESIGN §12).
        let room = ceiling.saturating_sub(existing.len());
        if spaces.len() > existing.len() + room {
            tracing::error!(
                %tenant,
                spaces = spaces.len(),
                replicas = existing.len(),
                ceiling,
                "this network publishes more spaces than the service will replicate; \
                 no further spaces will be taken on"
            );
        }
        let mut added = 0usize;
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
        // Indexed rather than scanned. The linear `find` this replaces made
        // the pass quadratic in two numbers a member chooses — spaces on one
        // side, replicas on the other — so a network with a great many of
        // both spent the cost of *both* on every converge, before the ceiling
        // above had anything to say about it.
        let by_space: std::collections::HashMap<&str, &synch_store::ReplicaRow> = existing
            .iter()
            .map(|replica| (replica.space.as_str(), replica))
            .collect();
        for space in spaces {
            let known = by_space.get(space.as_str()).copied();
            let share = share_for(budget, held_elsewhere, known, &node)?;
            match known {
                None if added >= room => continue,
                None => {
                    // `forever` refuses a grace, so it is never passed with it.
                    let grace = None;
                    node.add_replica(&space, policy, grace, share, None)?;
                    added += 1;
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

#[cfg(test)]
mod tests {
    use super::*;
    use synch_engine::NodeConfig;

    /// A member cannot publish its way past the ceiling.
    ///
    /// A space is a plain string any member may publish under, and this
    /// module turns each one into a standing replica that is never removed —
    /// so without a ceiling the size of the replica table, the length of
    /// every converge pass, and the size of the database riding the replica
    /// stream are all a member's to choose, which is one network deciding how
    /// much of this pod every other network gets. Both halves are asserted,
    /// because a ceiling that also stopped the ordinary case would be worse
    /// than none: the spaces under it are replicated, and only what is past
    /// it is not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_member_cannot_publish_its_way_past_the_ceiling() {
        let _blocking = synch_core::BlockingScope::enter();
        let base = tempfile::tempdir().expect("a base dir");
        let dir = base.path().join("node");
        {
            let dir = dir.clone();
            synch_core::offload(move || Node::init(&dir, None))
                .await
                .expect("the node initializes");
        }
        let node = Node::open(NodeConfig::loopback(&dir))
            .await
            .expect("the node opens");

        // Three spaces, published the ordinary way, so `known_spaces` sees
        // what a member publishing under three names would produce.
        let sources = tempfile::tempdir().expect("the sources");
        for space in ["one", "two", "three"] {
            let path = sources.path().join(space);
            std::fs::create_dir_all(&path).expect("a source directory");
            std::fs::write(path.join("f.txt"), space.as_bytes()).expect("a file");
            node.add_filesystem_source(space, &path).expect("a source");
        }
        {
            let node = node.clone();
            synch_core::offload(move || node.scan_and_publish())
                .await
                .expect("the publish");
        }
        let network = HostedNetwork {
            org: "acme".into(),
            network: "prod".into(),
            domain: "prod.acme.example".into(),
            budget_bytes: 0,
            retention: "current".into(),
            device: None,
        };

        let replicas = |node: Node| async move {
            synch_core::offload(move || node.store().replicas())
                .await
                .expect("the replica rows")
                .len()
        };

        ensure_replicas_capped(&node, &network, 2)
            .await
            .expect("the pass runs");
        assert_eq!(
            replicas(node.clone()).await,
            2,
            "the ceiling holds, and it holds on the first pass rather than \
             after the rows are already written"
        );

        // And it goes on holding: a second pass must not creep past it one
        // replica at a time, which is what a ceiling counted against the
        // additions of a single pass would do.
        ensure_replicas_capped(&node, &network, 2)
            .await
            .expect("the second pass runs");
        assert_eq!(replicas(node.clone()).await, 2);

        // Raised, the spaces that were held back are taken on — the ceiling
        // is a bound on what this pod carries, not a decision that those
        // spaces are unwanted.
        ensure_replicas_capped(&node, &network, 8)
            .await
            .expect("the third pass runs");
        assert_eq!(replicas(node.clone()).await, 3);

        node.shutdown().await.expect("the node shuts down");
    }
}
