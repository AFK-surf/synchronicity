//! Driving the hosted device's key rotation (`docs/CLOUD-DATAPLANE.md` §6).
//!
//! The engine has the whole mechanism already (DESIGN §3.4): generate a key,
//! publish it beside the old one, switch signing, and drop the old one once
//! peers have had a TTL to move. What was missing is anybody deciding *when*,
//! which is this module: a standing check on the reconciler's tick that starts
//! a rotation when the active key is old enough and finishes one whose window
//! has run.
//!
//! # Why the schedule lives in the tenant's database
//!
//! A rotation is two moves separated by a wait, and the pod running it is
//! ephemeral (§5.3) — it can be rescheduled between them. So the deadline is a
//! row in the tenant's own database rather than a timer in memory: it rides
//! the replica stream, and a replacement pod picks the rotation up exactly
//! where the last one left it. Nothing is lost by a restart, and nothing has
//! to be reconstructed by guessing from key states.
//!
//! # The order, and why it is that order
//!
//! ```text
//! rotate_key()      the new key exists, staged, signing nothing
//! PUT device        the zone names BOTH keys under `cloud-1`
//! activate_key()    heads are signed by the new key
//! record deadline   in the tenant's own database, before asking anybody
//! DELETE key        the old key is `retiring` — still published
//! ... one window ...
//! retire_key()      the old endpoint closes, the secret is deleted
//! DELETE ?revoke=1  the zone stops naming it
//! ```
//!
//! The publish comes before the activation because a peer refuses a head
//! signed by a key its zone does not name; the revoke comes a window after
//! the activation because a peer whose DNS has not refreshed still believes
//! the old key. Both halves are the overlap the rotation design bought, and
//! doing either out of order locks somebody out for a TTL.

use std::time::Duration;

use synch_engine::Node;

use crate::config::{slot_label, DpConfig};
use crate::control::{ControlPlane, HostedNetwork};
use crate::error::Result;

/// Where the pending retirement's deadline is kept.
///
/// In the tenant's `config` table, so it rides the replica stream (§5.3).
const RETIRE_DUE_KEY: &str = "dp.rotation.retire_due_ns";

/// The key being retired, beside its deadline.
///
/// Recorded rather than re-derived: after a restart the node holds two keys
/// and "which one is going" is not a question its states can answer on their
/// own — `Retiring` is also what a half-finished rotation looks like.
const RETIRING_KEY: &str = "dp.rotation.retiring_key";

/// Rotates the hosted key when the active one reaches this age.
///
/// Ninety days: often enough that a compromise has a bounded life, rare
/// enough that the zone is not churning. An operator forcing one early does
/// it by clearing the key, not by tuning this.
pub const DEFAULT_ROTATE_AFTER: Duration = Duration::from_secs(90 * 24 * 3600);

/// How long the old key stays published after the new one starts signing.
///
/// The membership TTL is 300 s, so an hour is many refreshes' worth of margin
/// for a peer whose resolver is lagging. The cost of being generous here is a
/// second TXT record on one label; the cost of being mean is a peer that
/// cannot verify this node's heads until its cache expires.
pub const DEFAULT_RETIRE_AFTER: Duration = Duration::from_secs(3600);

/// What one rotation check did, for logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing was due.
    Idle,
    /// A rotation started: a new key is signing, the old one is retiring.
    Started,
    /// A rotation finished: the old key is gone from this node and the zone.
    Completed,
}

/// Runs one rotation check for a tenant.
///
/// Completing an overdue retirement is tried *before* starting a new
/// rotation, because the zone caps a label at two keys: with a retirement
/// still outstanding there is no room to publish a third, and starting one
/// would fail at the control plane rather than here.
pub async fn tick(
    node: &Node,
    control: &ControlPlane,
    network: &HostedNetwork,
    config: &DpConfig,
    now_ns: i64,
) -> Result<Outcome> {
    // Before either: repair a rotation that activated and then lost its
    // deadline. Nothing downstream would ever notice it — see
    // `adopt_orphan_retirement`.
    adopt_orphan_retirement(node, network, config, now_ns).await?;
    if complete_if_due(node, control, network, now_ns).await? {
        return Ok(Outcome::Completed);
    }
    if start_if_due(node, control, network, config, now_ns).await? {
        return Ok(Outcome::Started);
    }
    Ok(Outcome::Idle)
}

/// Gives a deadline to a retirement that has one owed and none recorded.
///
/// `start_if_due` activates the new key and *then* writes the deadline, and
/// those are two commits. A pod that dies in between — or one whose
/// `set_config` fails — leaves the node holding a key in
/// [`Retiring`](synch_store::KeyState::Retiring) with nothing scheduled to
/// finish it, and neither half of `tick` can see it: `complete_if_due` finds
/// no deadline and returns, `start_if_due` finds a freshly created active key
/// and returns. The rotation is stuck open for ever, and a quarter later the
/// next one is refused because the label already holds two live keys.
///
/// Writing the deadline the moment a retiring key is found with none closes
/// that. It cannot fire spuriously: only `activate_key` produces a `Retiring`
/// key, so the state it repairs is one an interrupted rotation really did
/// create, and the retirement it schedules is the one that was already owed.
///
/// The order is deliberately *not* fixed by writing the deadline before
/// activating instead. That trades this hole for a worse one: a deadline
/// recorded against a key that is still `Active` would have `complete_if_due`
/// retire the key the node is signing with.
async fn adopt_orphan_retirement(
    node: &Node,
    network: &HostedNetwork,
    config: &DpConfig,
    now_ns: i64,
) -> Result<bool> {
    let recorded = {
        let node = node.clone();
        synch_core::offload(move || {
            let due = node
                .store()
                .config(RETIRE_DUE_KEY)?
                .filter(|v| !v.is_empty());
            Ok::<_, synch_store::StoreError>(due)
        })
        .await?
    };
    if recorded.is_some() {
        return Ok(false);
    }
    let Some(orphan) = node
        .device_keys()?
        .into_iter()
        .find(|key| key.state == synch_store::KeyState::Retiring)
    else {
        return Ok(false);
    };
    let retiring = orphan.node_id.to_z32();
    let due = now_ns.saturating_add(config.retire_after.as_nanos() as i64);
    tracing::warn!(
        tenant = %network.key(),
        key = %retiring,
        "found a retiring key with no deadline; a rotation was interrupted \
         after activation — scheduling its retirement now"
    );
    {
        let node = node.clone();
        let retiring = retiring.clone();
        synch_core::offload(move || {
            node.store().set_config(RETIRE_DUE_KEY, &due.to_string())?;
            node.store().set_config(RETIRING_KEY, &retiring)
        })
        .await?;
    }
    Ok(true)
}

/// Finishes a rotation whose overlap window has run.
async fn complete_if_due(
    node: &Node,
    control: &ControlPlane,
    network: &HostedNetwork,
    now_ns: i64,
) -> Result<bool> {
    let pending = {
        let node = node.clone();
        synch_core::offload(move || {
            // Cleared is stored as empty rather than deleted (the config API
            // has no delete), so empty has to read as absent here — otherwise
            // every tick after a completed rotation parses `""`, fails, and
            // "clears" it again, forever.
            let due = node
                .store()
                .config(RETIRE_DUE_KEY)?
                .filter(|v| !v.is_empty());
            let key = node.store().config(RETIRING_KEY)?.filter(|v| !v.is_empty());
            Ok::<_, synch_store::StoreError>(due.zip(key))
        })
        .await?
    };
    let Some((due, retiring)) = pending else {
        return Ok(false);
    };
    let Ok(due_ns) = due.parse::<i64>() else {
        // Unparseable is not a reason to keep an old key alive forever, and
        // not a reason to act on a value we cannot read either. Clear it and
        // let the age check start a fresh rotation if one is owed.
        tracing::warn!(tenant = %network.key(), %due, "unreadable retirement deadline; clearing");
        clear_pending(node).await?;
        return Ok(false);
    };
    if now_ns < due_ns {
        return Ok(false);
    }

    // Local first. Dropping the endpoint and the secret is this node's own
    // business and cannot be undone by anybody else; withdrawing the record
    // is the control plane's, and doing it first would leave a window where
    // the zone denies a key this node is still serving under.
    let held = node.device_keys()?;
    if let Some(key) = held.iter().find(|key| key.node_id.to_z32() == retiring) {
        node.retire_key(&key.node_id).await?;
    }
    // A 404 here is the desired end state, not a failure. The three steps are
    // not one transaction, so a completion that revoked the key and then lost
    // the local write comes back through here with the control plane already
    // holding nothing under that `nk` — and treating "it is already gone" as
    // an error is what would leave `clear_pending` forever unreachable and
    // the tenant unable to rotate again.
    match control
        .retire_key(&network.org, &network.network, &retiring, true)
        .await
    {
        Ok(()) => {}
        Err(error) if error.is_control_not_found() => tracing::info!(
            tenant = %network.key(),
            key = %retiring,
            "the control plane already holds no live key here; finishing the rotation"
        ),
        Err(error) => return Err(error),
    }
    clear_pending(node).await?;
    tracing::info!(
        tenant = %network.key(),
        key = %retiring,
        "completed a hosted key rotation"
    );
    Ok(true)
}

/// Starts a rotation when the active key is old enough.
async fn start_if_due(
    node: &Node,
    control: &ControlPlane,
    network: &HostedNetwork,
    config: &DpConfig,
    now_ns: i64,
) -> Result<bool> {
    let active = node
        .device_keys()?
        .into_iter()
        .find(|key| key.state == synch_store::KeyState::Active);
    let Some(active) = active else {
        return Ok(false);
    };
    let age = now_ns.saturating_sub(active.created_at);
    if age < config.rotate_after.as_nanos() as i64 {
        return Ok(false);
    }

    // A key already staged is one a previous attempt generated and could not
    // publish. Reusing it matters: `rotate_key` mints a fresh secret every
    // time it is called, so a control plane that is down for an hour would
    // otherwise leave sixty orphaned device secrets in the tenant's database,
    // every one of them riding the replica stream.
    let staged = node
        .device_keys()?
        .into_iter()
        .find(|key| key.state == synch_store::KeyState::Staged);
    let new_key_id = match staged {
        Some(key) => {
            tracing::info!(
                tenant = %network.key(),
                "reusing the key a previous rotation attempt staged"
            );
            key.node_id
        }
        None => node.rotate_key()?.new_key,
    };
    let new_key = new_key_id.to_z32();
    control
        .register_device(&network.org, &network.network, &slot_label(), &new_key)
        .await?;
    let activation = node.activate_key(&new_key_id, None).await?;
    let previous = activation.previous_key.to_z32();

    // The deadline is recorded *before* the control plane is asked to mark
    // the old key retiring, and that order is the whole of the recovery. A
    // deadline written for a retirement that was never requested costs one
    // extra call at the deadline, which is idempotent. A retirement requested
    // with no deadline recorded is a rotation nothing will ever finish: the
    // age check sees a young key and never fires, and the label keeps two
    // live keys until a quarter later, when the next rotation is refused for
    // having no room.
    let due = now_ns.saturating_add(config.retire_after.as_nanos() as i64);
    {
        let node = node.clone();
        let previous = previous.clone();
        synch_core::offload(move || {
            node.store().set_config(RETIRE_DUE_KEY, &due.to_string())?;
            node.store().set_config(RETIRING_KEY, &previous)
        })
        .await?;
    }
    control
        .retire_key(&network.org, &network.network, &previous, false)
        .await?;
    tracing::info!(
        tenant = %network.key(),
        new_key = %new_key,
        retiring = %previous,
        "started a hosted key rotation"
    );
    Ok(true)
}

/// Forgets a pending retirement.
async fn clear_pending(node: &Node) -> Result<()> {
    let node = node.clone();
    synch_core::offload(move || {
        node.store().set_config(RETIRE_DUE_KEY, "")?;
        node.store().set_config(RETIRING_KEY, "")
    })
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The window has to outlast the membership TTL, or a peer that has not
    /// refreshed loses the key it is verifying heads with.
    #[test]
    fn the_overlap_window_outlasts_the_membership_ttl() {
        // `_synchronicity` records are served at TTL 300 (the control plane's
        // `ttl_data`), so anything at or below that is a rotation that can
        // strand a lagging resolver.
        assert!(DEFAULT_RETIRE_AFTER > Duration::from_secs(300));
    }

    /// And a rotation must not start more often than one can finish.
    #[test]
    fn rotations_are_rarer_than_the_window_that_completes_them() {
        assert!(DEFAULT_ROTATE_AFTER > DEFAULT_RETIRE_AFTER * 24);
    }
}
