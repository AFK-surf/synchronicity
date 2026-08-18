//! Cloud attach: the daemon's outbound tunnel to the control plane.
//!
//! A node behind NAT has no inbound path, so the only connection that can
//! exist is one it opens itself. This module is that connection: a supervised
//! task beside the scanner and the fetcher which, when the operator has turned
//! it on, discovers where its base's control plane lives from the same
//! DNSSEC-validated zone that names the membership, dials out, proves itself
//! with the device key it already holds, and answers listing and read requests
//! through the same entry points the S3 gateway reads through.
//!
//! Two facts hold it in place:
//!
//! * **Nothing is exposed unnamed.** `synch cloud enable --space <id>` states
//!   the whole of what the tunnel can see, and the allowlist is re-checked on
//!   every frame rather than captured at attach time — so `cloud disable` and
//!   a narrowed list both take effect on the next request, not on the next
//!   reconnect.
//! * **Nothing here can write.** [`frame`] encodes no write opcode, and the
//!   handlers below call `unified_listing`, `versions`, `resolve_set`,
//!   `providers_for`, `fetch_range` and `Store::read_range` and nothing else.

pub mod attach;
pub mod frame;

use crate::{
    error::{EngineError, Result},
    node::Node,
};

/// Where the enablement flag lives in the daemon's config namespace.
///
/// `cloud.*`, exactly as the gateway keeps `s3.*`: one row per setting, in the
/// table that already survives restarts, so an operator's choice is not a
/// process's memory of it.
const ENABLED_KEY: &str = "cloud.enabled";

/// Where the space allowlist lives, one id per line.
const SPACES_KEY: &str = "cloud.spaces";

/// What the operator has said about cloud attach on this node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudSettings {
    /// Whether the attach task should be running at all.
    pub enabled: bool,
    /// The spaces the tunnel may see, and no others.
    pub spaces: Vec<String>,
}

impl CloudSettings {
    /// Whether a space may be reached through the tunnel.
    pub fn exposes(&self, space: &str) -> bool {
        self.enabled && self.spaces.iter().any(|id| id == space)
    }
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
        let enabled = self.store().config(ENABLED_KEY)?.as_deref() == Some("1");
        let spaces = self
            .store()
            .config(SPACES_KEY)?
            .map(|text| {
                text.lines()
                    .filter(|line| !line.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Ok(CloudSettings { enabled, spaces })
    }

    /// Exposes exactly these spaces through the tunnel.
    ///
    /// A replacement, never an addition: `cloud enable` is the operator
    /// stating what is exposed, and a command that accumulated would make
    /// "what is shared right now" a question only the database can answer.
    pub fn enable_cloud(&self, spaces: &[String]) -> Result<CloudSettings> {
        if spaces.is_empty() {
            return Err(EngineError::invalid(
                "name at least one space with --space: nothing is exposed unnamed",
            ));
        }
        let known = self.store().spaces()?;
        for space in spaces {
            if !known.iter().any(|local| &local.id == space) {
                return Err(EngineError::not_found(format!(
                    "{space} is not a local space: `synch space add` it first, or name one of {}",
                    known
                        .iter()
                        .map(|s| s.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
        self.store().set_config(SPACES_KEY, &spaces.join("\n"))?;
        self.store().set_config(ENABLED_KEY, "1")?;
        self.cloud_settings()
    }

    /// Stops answering the control plane.
    ///
    /// The allowlist is kept, so re-enabling does not silently expose a
    /// different set than the one that was turned off.
    pub fn disable_cloud(&self) -> Result<()> {
        self.store().set_config(ENABLED_KEY, "0")?;
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
    async fn nothing_is_exposed_until_a_space_is_named() {
        let (dir, node) = node().await;
        assert_eq!(node.cloud_settings().unwrap(), CloudSettings::default());
        assert!(!node.cloud_settings().unwrap().exposes("media"));

        // An empty list is refused rather than read as "everything".
        assert!(node.enable_cloud(&[]).is_err());
        // So is a space that does not exist: the tunnel would silently show
        // nothing, and the operator would have no way to tell that from an
        // empty space.
        assert!(node.enable_cloud(&["media".to_string()]).is_err());

        node.add_space("media", dir.path().join("media")).unwrap();
        node.add_space("docs", dir.path().join("docs")).unwrap();
        let settings = node.enable_cloud(&["media".to_string()]).unwrap();
        assert!(settings.enabled);
        assert!(settings.exposes("media"));
        assert!(
            !settings.exposes("docs"),
            "a space nobody named is not shared"
        );

        // Enabling states the list rather than growing it.
        let settings = node.enable_cloud(&["docs".to_string()]).unwrap();
        assert!(settings.exposes("docs"));
        assert!(!settings.exposes("media"));

        // Disabling closes everything, and keeps the list for next time.
        node.disable_cloud().unwrap();
        let settings = node.cloud_settings().unwrap();
        assert!(!settings.enabled);
        assert!(!settings.exposes("docs"));
        assert_eq!(settings.spaces, ["docs"]);
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
