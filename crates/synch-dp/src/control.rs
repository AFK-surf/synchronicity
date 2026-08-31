//! The `/dp/v1` client (`docs/CLOUD-DATAPLANE.md` §3.3).
//!
//! Four calls: what to host, register a device key, retire one, and say how
//! much is held. The control plane is the authority; nothing here decides
//! anything, and every response is data this service acts on rather than
//! trusts blindly — a network it does not own a slot in is still one it will
//! refuse to touch.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{DpError, Result};

/// How long any one call may take before it is a failure.
///
/// Short, because a poll that hangs is indistinguishable from a control plane
/// that is down, and the fail-static path (§4.2) handles the latter well.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// One network the control plane wants hosted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HostedNetwork {
    /// The org's slug.
    pub org: String,
    /// The network's name within it.
    pub network: String,
    /// The membership domain, verbatim what `Node::set_domain` takes.
    pub domain: String,
    /// The org's storage ceiling for this network, in bytes. Zero means none.
    #[serde(default)]
    pub budget_bytes: u64,
    /// `current` or `forever`.
    #[serde(default = "default_retention")]
    pub retention: String,
    /// The device this service has already registered, when it has.
    #[serde(default)]
    pub device: Option<HostedDevice>,
}

fn default_retention() -> String {
    "current".to_string()
}

impl HostedNetwork {
    /// The key a tenant is filed under, everywhere: the reconciler's map, the
    /// data directory, the bucket prefixes, the metrics labels.
    pub fn key(&self) -> String {
        format!("{}/{}", self.org, self.network)
    }

    /// The retention policy this network asks for.
    ///
    /// An unknown value is treated as `current` rather than refused: the
    /// control plane may learn a new policy before this build does, and
    /// hosting the network conservatively beats not hosting it at all.
    pub fn replica_policy(&self) -> synch_store::ReplicaPolicy {
        match self.retention.as_str() {
            "forever" => synch_store::ReplicaPolicy::Forever,
            other => {
                if other != "current" {
                    tracing::warn!(retention = %other, "unknown retention; using `current`");
                }
                synch_store::ReplicaPolicy::Current
            }
        }
    }
}

/// The device record the control plane holds for a hosted network.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HostedDevice {
    /// The slot label, `cloud-<n>`.
    pub label: String,
    /// The device key, z-base-32.
    pub nk: String,
    /// `active`, `retiring`, or `revoked`.
    #[serde(default)]
    pub state: String,
}

/// The desired-state document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Desired {
    /// Bumped by any change to the set or its fields.
    #[serde(default)]
    pub generation: u64,
    /// Every network with cloud hosting enabled.
    pub networks: Vec<HostedNetwork>,
}

/// What a poll produced.
#[derive(Debug)]
pub enum Poll {
    /// A new document, and the entity tag to send next time.
    Changed {
        /// The document.
        desired: Desired,
        /// Its `ETag`, when the control plane gave one.
        etag: Option<String>,
    },
    /// Nothing changed since the tag we sent.
    Unchanged,
}

/// A client for one control-plane deployment.
#[derive(Debug, Clone)]
pub struct ControlPlane {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl ControlPlane {
    /// Builds a client against `base` (no trailing slash), authenticating with
    /// a `synchdp_…` token.
    pub fn new(base: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| DpError::Control(error.to_string()))?;
        Ok(Self {
            http,
            base: base.into().trim_end_matches('/').to_string(),
            token: token.into(),
        })
    }

    /// Asks what should be hosted, sending `etag` when we have one.
    pub async fn poll(&self, etag: Option<&str>) -> Result<Poll> {
        let mut request = self
            .http
            .get(format!("{}/dp/v1/networks", self.base))
            .bearer_auth(&self.token);
        if let Some(etag) = etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let response = request
            .send()
            .await
            .map_err(|error| DpError::Control(error.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Poll::Unchanged);
        }
        let response = self.check(response).await?;
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        let desired = response
            .json::<Desired>()
            .await
            .map_err(|error| DpError::Control(format!("unreadable desired state: {error}")))?;
        Ok(Poll::Changed { desired, etag })
    }

    /// Registers this service's device key for a network. Idempotent.
    pub async fn register_device(
        &self,
        org: &str,
        network: &str,
        label: &str,
        nk: &str,
    ) -> Result<()> {
        let response = self
            .http
            .put(format!(
                "{}/dp/v1/networks/{org}/{network}/device",
                self.base
            ))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "label": label, "nk": nk }))
            .send()
            .await
            .map_err(|error| DpError::Control(error.to_string()))?;
        self.check(response).await.map(|_| ())
    }

    /// Retires (or revokes) a key this service registered.
    pub async fn retire_key(&self, org: &str, network: &str, nk: &str, revoke: bool) -> Result<()> {
        let mut url = format!(
            "{}/dp/v1/networks/{org}/{network}/device/keys/{nk}",
            self.base
        );
        if revoke {
            url.push_str("?revoke=1");
        }
        let response = self
            .http
            .delete(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|error| DpError::Control(error.to_string()))?;
        self.check(response).await.map(|_| ())
    }

    /// Reports what this tenant holds, for metering and alerting.
    pub async fn report_status(&self, org: &str, network: &str, status: &Status) -> Result<()> {
        let response = self
            .http
            .post(format!(
                "{}/dp/v1/networks/{org}/{network}/status",
                self.base
            ))
            .bearer_auth(&self.token)
            .json(status)
            .send()
            .await
            .map_err(|error| DpError::Control(error.to_string()))?;
        self.check(response).await.map(|_| ())
    }

    /// Turns a non-2xx into an error carrying the body, which is where the
    /// control plane puts the reason.
    async fn check(&self, response: reqwest::Response) -> Result<reqwest::Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let body = response.text().await.unwrap_or_default();
        Err(DpError::Control(format!("{status}: {}", body.trim())))
    }
}

/// The metering heartbeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Status {
    /// Content roots this tenant durably holds.
    pub held_roots: u64,
    /// Their total size.
    pub held_bytes: u64,
    /// Roots wanted but not yet acquired.
    pub wanted: u64,
    /// When this tenant last completed a sync round.
    pub last_sync_ns: i64,
    /// Which shard is serving the slot. Operational metadata, never in the
    /// zone — a slot is durable, a shard is a pod (§3.4).
    pub shard: String,
    /// The hosting slot this report is for.
    pub slot: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The document shape in §3.3 must parse, including a network this
    /// service has never registered a device for.
    #[test]
    fn the_desired_document_parses() {
        let json = serde_json::json!({
            "generation": 4183,
            "networks": [
                { "org": "acme", "network": "prod",
                  "domain": "prod.acme.synchronicity.example",
                  "budget_bytes": 2199023255552u64,
                  "retention": "forever",
                  "device": { "label": "cloud-1", "nk": "abc", "state": "active" } },
                { "org": "beta", "network": "dev",
                  "domain": "dev.beta.synchronicity.example" }
            ]
        });
        let desired: Desired = serde_json::from_value(json).unwrap();
        assert_eq!(desired.generation, 4183);
        assert_eq!(desired.networks[0].key(), "acme/prod");
        assert_eq!(
            desired.networks[0].replica_policy(),
            synch_store::ReplicaPolicy::Forever
        );
        // A network with no device yet is one never joined — the field's whole
        // purpose (§3.3).
        assert!(desired.networks[1].device.is_none());
        assert_eq!(
            desired.networks[1].replica_policy(),
            synch_store::ReplicaPolicy::Current
        );
    }

    #[test]
    fn an_unknown_retention_falls_back_to_current() {
        let network = HostedNetwork {
            org: "a".into(),
            network: "b".into(),
            domain: "b.a.example".into(),
            budget_bytes: 0,
            retention: "eternal".into(),
            device: None,
        };
        assert_eq!(
            network.replica_policy(),
            synch_store::ReplicaPolicy::Current
        );
    }
}
