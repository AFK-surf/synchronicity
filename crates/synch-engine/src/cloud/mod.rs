//! Cloud attach: the daemon's outbound tunnel to the control plane.
//!
//! A node behind NAT has no inbound path, so the only connection that can
//! exist is one it opens itself. This module is that connection: a supervised
//! task beside the scanner and the fetcher which, unless the operator has
//! opted it out, discovers where its base's control plane lives from the same
//! DNSSEC-validated zone that names the membership, dials out, proves itself
//! with the device key it already holds, and answers listing and read requests
//! through the same entry points the S3 gateway reads through.
//!
//! Two facts hold it in place:
//!
//! * **What is served is the control plane's call.** The tunnel is on by
//!   default and answers for every space this node holds; which spaces a
//!   dashboard may browse is decided on the other end, by the org admin's
//!   toggle and the RBAC around it. The one local act is an opt-out —
//!   `synch cloud disable` — and the supervisor drops an open tunnel on its
//!   next pass, seconds later, not at the next reconnect.
//! * **Nothing here can write.** [`frame`] encodes no write opcode, and the
//!   handlers below call `unified_listing`, `versions`, `resolve_set`,
//!   `providers_for`, `fetch_range` and `Store::read_range` and nothing else.

pub mod attach;
pub mod frame;

use crate::{error::Result, node::Node};

/// Where the opt-out lives in the daemon's config namespace.
///
/// `cloud.*`, exactly as the gateway keeps `s3.*`: one row per setting, in the
/// table that already survives restarts, so an operator's choice is not a
/// process's memory of it. No row at all is the default state, and the
/// default is attached — on is where a node starts, not a state it reaches.
const OPT_OUT_KEY: &str = "cloud.disabled";

/// What the operator has said about cloud attach on this node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudSettings {
    /// Whether the operator has opted this node out. `false` — the derived
    /// default, and the state of a node nobody has configured — is attached.
    pub disabled: bool,
}

/// What the attach task has achieved for one membership domain.
///
/// Reported by `synch cloud status` and by nothing else: it is a running
/// process's account of itself, so it lives in memory and dies with the
/// daemon rather than pretending to be durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudDomainStatus {
    /// The membership domain this attach is for.
    pub domain: String,
    /// The attach URL discovered from the zone, if the lookup validated.
    pub endpoint: Option<String>,
    /// Whether a tunnel is open right now.
    pub attached: bool,
    /// The last failure, kept until something succeeds.
    pub last_error: Option<String>,
    /// When this state was last changed, unix nanoseconds.
    pub since_ns: i64,
}

impl Node {
    /// What the operator has said about cloud attach on this node.
    pub fn cloud_settings(&self) -> Result<CloudSettings> {
        let disabled = self.store().config(OPT_OUT_KEY)?.as_deref() == Some("1");
        Ok(CloudSettings { disabled })
    }

    /// Reopens the tunnel after [`Self::disable_cloud`].
    ///
    /// There is nothing to name and nothing to choose: the tunnel is on by
    /// default and serves whatever the control plane requests, so this is
    /// only ever the undo of an opt-out.
    pub fn enable_cloud(&self) -> Result<CloudSettings> {
        self.store().set_config(OPT_OUT_KEY, "0")?;
        self.cloud_settings()
    }

    /// Opts this node out: no tunnel is opened, and one that is open is
    /// dropped by the supervisor on its next pass.
    pub fn disable_cloud(&self) -> Result<()> {
        self.store().set_config(OPT_OUT_KEY, "1")?;
        Ok(())
    }

    /// What the attach task has achieved, per membership domain.
    pub fn cloud_status(&self) -> Vec<CloudDomainStatus> {
        let mut out: Vec<CloudDomainStatus> = self
            .cloud_slot()
            .values()
            .cloned()
            .collect::<Vec<CloudDomainStatus>>();
        out.sort_by(|a, b| a.domain.cmp(&b.domain));
        out
    }

    /// Records what one domain's attach is doing now.
    pub(crate) fn set_cloud_status(
        &self,
        domain: &str,
        endpoint: Option<String>,
        attached: bool,
        last_error: Option<String>,
    ) {
        self.cloud_slot().insert(
            domain.to_string(),
            CloudDomainStatus {
                domain: domain.to_string(),
                endpoint,
                attached,
                last_error,
                since_ns: synch_core::now_ns(),
            },
        );
    }

    /// Forgets a domain the operator has removed, so `cloud status` does not
    /// report on something that is no longer configured.
    pub(crate) fn forget_cloud_status(&self, domain: &str) {
        self.cloud_slot().remove(domain);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;

    async fn node() -> (tempfile::TempDir, Node) {
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        (dir, node)
    }

    #[tokio::test]
    async fn attach_is_on_by_default_until_opted_out() {
        let (_d, node) = node().await;
        // No row was ever written, and the node is still attached: on is the
        // default, not a state to reach.
        assert_eq!(node.cloud_settings().unwrap(), CloudSettings::default());
        assert!(!node.cloud_settings().unwrap().disabled);

        node.disable_cloud().unwrap();
        assert!(node.cloud_settings().unwrap().disabled);

        node.enable_cloud().unwrap();
        assert!(!node.cloud_settings().unwrap().disabled);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn status_is_reported_per_domain_and_sorted() {
        let (_d, node) = node().await;
        assert!(node.cloud_status().is_empty());
        node.set_cloud_status("b.example", None, false, Some("no record".into()));
        node.set_cloud_status("a.example", Some("https://sync.example".into()), true, None);
        let status = node.cloud_status();
        assert_eq!(status.len(), 2);
        assert_eq!(status[0].domain, "a.example");
        assert!(status[0].attached);
        assert_eq!(status[1].last_error.as_deref(), Some("no record"));

        node.forget_cloud_status("b.example");
        assert_eq!(node.cloud_status().len(), 1);
        node.shutdown().await.unwrap();
    }
}
