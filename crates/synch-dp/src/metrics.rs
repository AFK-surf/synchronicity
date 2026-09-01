//! Prometheus exposition (`docs/CLOUD-DATAPLANE.md` §10).
//!
//! Hand-rolled rather than pulled from a client library: the whole surface is
//! a handful of gauges and counters rendered once per scrape, and a registry
//! would be more machinery than the thing it registers.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::control::Status;

/// Everything this shard reports.
#[derive(Debug, Default)]
pub struct Metrics {
    tenants_running: AtomicU64,
    tenants_parked: AtomicU64,
    poll_failures: AtomicU64,
    reconcile_failures: AtomicU64,
    generation: AtomicU64,
    collected: AtomicU64,
    per_tenant: Mutex<BTreeMap<String, Status>>,
    /// Per tenant: how many consecutive ship attempts have failed.
    ///
    /// The one number that makes a stalled replica stream visible. Without it
    /// a tenant whose uploads are all failing — a bucket policy that grants
    /// `ListBucket` but denies `PutObject` on `db/` is enough — goes on
    /// reporting `running`, heartbeating healthy held-byte counts, and
    /// logging one warning a second that nothing alerts on, until a
    /// reschedule finds an empty stream and mints a fresh identity over the
    /// network. §10 promised an operator could alert on this; this is what
    /// they alert on.
    replication_failures: Mutex<BTreeMap<String, u64>>,
    /// Per tenant: how much of the shard's volume its database occupies.
    ///
    /// The shard's one unbudgeted resource, and the only cross-tenant failure
    /// left that no ceiling in this service prevents — see
    /// [`Tenant::db_bytes`](crate::tenant::Tenant::db_bytes). Content is
    /// bounded twice over (the org's `budget_bytes` on admission, the
    /// per-tenant `cache_bytes` on the local footprint); the metadata a
    /// network's members publish is bounded by neither, lands in one SQLite
    /// file, and shares a volume with every other tenant on the pod. An
    /// operator alerts on this climbing against a flat `held_bytes`.
    db_bytes: Mutex<BTreeMap<String, u64>>,
}

impl Metrics {
    /// Records how many tenants are running and how many are waiting.
    pub fn tenants(&self, running: usize, parked: usize) {
        self.tenants_running
            .store(running as u64, Ordering::Relaxed);
        self.tenants_parked.store(parked as u64, Ordering::Relaxed);
    }

    /// Records a poll that did not reach the control plane.
    pub fn poll_failed(&self) {
        self.poll_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a reconcile pass that failed.
    pub fn reconcile_failed(&self) {
        self.reconcile_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Records the generation of the last desired document acted on.
    pub fn observed_generation(&self, generation: u64) {
        self.generation.store(generation, Ordering::Relaxed);
    }

    /// Records one offboarded tenant's storage deleted (§6).
    pub fn collected(&self) {
        self.collected.fetch_add(1, Ordering::Relaxed);
    }

    /// Records what one tenant holds.
    pub fn tenant_status(&self, key: &str, status: &Status) {
        if let Ok(mut per_tenant) = self.per_tenant.lock() {
            per_tenant.insert(key.to_string(), status.clone());
        }
    }

    /// Records the outcome of one tenant's ship attempt.
    ///
    /// A success resets the run to zero rather than counting, because the
    /// question an operator asks is "is this stream stuck *now*", not "has it
    /// ever failed".
    pub fn replication_attempt(&self, key: &str, ok: bool) {
        if let Ok(mut failures) = self.replication_failures.lock() {
            let run = failures.entry(key.to_string()).or_insert(0);
            *run = if ok { 0 } else { run.saturating_add(1) };
        }
    }

    /// Records how much of the shard's volume one tenant's database occupies.
    pub fn tenant_db_bytes(&self, key: &str, bytes: u64) {
        if let Ok(mut sizes) = self.db_bytes.lock() {
            sizes.insert(key.to_string(), bytes);
        }
    }

    /// Forgets a tenant this shard no longer runs.
    ///
    /// Called on every drain. Without it a pod that has rebalanced a few
    /// times keeps exporting `held_bytes` for tenants whose bucket prefix has
    /// since been deleted, and both maps grow for the life of the process.
    pub fn forget_tenant(&self, key: &str) {
        if let Ok(mut per_tenant) = self.per_tenant.lock() {
            per_tenant.remove(key);
        }
        if let Ok(mut failures) = self.replication_failures.lock() {
            failures.remove(key);
        }
        if let Ok(mut sizes) = self.db_bytes.lock() {
            sizes.remove(key);
        }
    }

    /// Renders the exposition format.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP synch_dp_tenants_running Tenants currently replicating.\n");
        out.push_str("# TYPE synch_dp_tenants_running gauge\n");
        out.push_str(&format!(
            "synch_dp_tenants_running {}\n",
            self.tenants_running.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP synch_dp_tenants_parked Tenants waiting to be provisioned.\n");
        out.push_str("# TYPE synch_dp_tenants_parked gauge\n");
        out.push_str(&format!(
            "synch_dp_tenants_parked {}\n",
            self.tenants_parked.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP synch_dp_poll_failures Polls that did not reach the control plane.\n");
        out.push_str("# TYPE synch_dp_poll_failures counter\n");
        out.push_str(&format!(
            "synch_dp_poll_failures {}\n",
            self.poll_failures.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP synch_dp_reconcile_failures Reconcile passes that failed.\n");
        out.push_str("# TYPE synch_dp_reconcile_failures counter\n");
        out.push_str(&format!(
            "synch_dp_reconcile_failures {}\n",
            self.reconcile_failures.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP synch_dp_desired_generation Generation of the last desired state.\n");
        out.push_str("# TYPE synch_dp_desired_generation gauge\n");
        out.push_str(&format!(
            "synch_dp_desired_generation {}\n",
            self.generation.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP synch_dp_storage_collected Offboarded tenants whose storage was deleted.\n",
        );
        out.push_str("# TYPE synch_dp_storage_collected counter\n");
        out.push_str(&format!(
            "synch_dp_storage_collected {}\n",
            self.collected.load(Ordering::Relaxed)
        ));

        let failures = match self.replication_failures.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        out.push_str(
            "# HELP synch_dp_replication_failures Consecutive failed ship attempts for a tenant.\n",
        );
        out.push_str("# TYPE synch_dp_replication_failures gauge\n");
        for (key, run) in &failures {
            let (org, network) = split_key(key);
            out.push_str(&format!(
                "synch_dp_replication_failures{{org=\"{org}\",network=\"{network}\"}} {run}\n"
            ));
        }

        let db_bytes = match self.db_bytes.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        out.push_str(
            "# HELP synch_dp_tenant_db_bytes Bytes this tenant's database occupies on the shard's volume.\n",
        );
        out.push_str("# TYPE synch_dp_tenant_db_bytes gauge\n");
        for (key, bytes) in &db_bytes {
            let (org, network) = split_key(key);
            out.push_str(&format!(
                "synch_dp_tenant_db_bytes{{org=\"{org}\",network=\"{network}\"}} {bytes}\n"
            ));
        }

        let per_tenant = match self.per_tenant.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        out.push_str("# HELP synch_dp_held_bytes Bytes durably held for a tenant.\n");
        out.push_str("# TYPE synch_dp_held_bytes gauge\n");
        for (key, status) in &per_tenant {
            let (org, network) = split_key(key);
            out.push_str(&format!(
                "synch_dp_held_bytes{{org=\"{org}\",network=\"{network}\"}} {}\n",
                status.held_bytes
            ));
        }
        out.push_str("# HELP synch_dp_held_roots Objects durably held for a tenant.\n");
        out.push_str("# TYPE synch_dp_held_roots gauge\n");
        for (key, status) in &per_tenant {
            let (org, network) = split_key(key);
            out.push_str(&format!(
                "synch_dp_held_roots{{org=\"{org}\",network=\"{network}\"}} {}\n",
                status.held_roots
            ));
        }
        out.push_str("# HELP synch_dp_wanted Objects wanted and not yet held.\n");
        out.push_str("# TYPE synch_dp_wanted gauge\n");
        for (key, status) in &per_tenant {
            let (org, network) = split_key(key);
            out.push_str(&format!(
                "synch_dp_wanted{{org=\"{org}\",network=\"{network}\"}} {}\n",
                status.wanted
            ));
        }
        out
    }
}

/// Splits `org/network` for labelling.
fn split_key(key: &str) -> (&str, &str) {
    key.split_once('/').unwrap_or((key, ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exposition_carries_per_tenant_labels() {
        let metrics = Metrics::default();
        metrics.tenants(2, 1);
        metrics.tenant_status(
            "acme/prod",
            &Status {
                held_roots: 12,
                held_bytes: 3400,
                wanted: 1,
                last_sync_ns: 5,
                dp: "dp-1".into(),
                slot: 1,
            },
        );
        let rendered = metrics.render();
        assert!(rendered.contains("synch_dp_tenants_running 2"));
        assert!(rendered.contains("synch_dp_held_bytes{org=\"acme\",network=\"prod\"} 3400"));
    }
}
