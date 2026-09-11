//! Generic delegation mutations on the hosted member's existing signed trie.
//! There is no invitation/token entity: callers submit the device public key.

use serde::{Deserialize, Serialize};
use synch_core::NodeId;
use synch_engine::{EngineError, Node};

/// An authenticated network member's requested delegation change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
pub enum Mutation {
    /// Create or replace this hosted member's delegation of a device key.
    Put {
        /// The delegate's public key, z-base-32.
        key: String,
        /// Explicit space names; the engine validates the closed list.
        spaces: Vec<String>,
        /// Absolute Unix seconds; retries never extend the requested expiry.
        expires_at: i64,
    },
    /// Withdraw only the delegation issued by this hosted member.
    Delete {
        /// The delegate's public key, z-base-32.
        key: String,
    },
}

/// Publish through the same engine operations as the CLI. No membership zone
/// records or other members' grants are changed. Missing removals are success.
pub fn apply(node: &Node, mutation: Mutation) -> Result<(), EngineError> {
    let key = match &mutation {
        Mutation::Put { key, .. } | Mutation::Delete { key } => key,
    };
    let subject =
        NodeId::from_z32(key).map_err(|_| EngineError::invalid("invalid delegate public key"))?;
    let change = match mutation {
        Mutation::Put {
            spaces, expires_at, ..
        } => {
            let until = expires_at
                .checked_mul(1_000_000_000)
                .ok_or_else(|| EngineError::invalid("expiry overflows Unix nanoseconds"))?;
            // Hosted grants are read-write; the control plane has no
            // read-only surface yet, and a mutation that named none would
            // keep the version-1 record every member reads.
            node.delegate_add(subject, &spaces, &[], until, None)?
        }
        Mutation::Delete { .. } => match node.delegate_remove(&subject) {
            Ok(change) => change,
            Err(EngineError::NotFound(_)) => return Ok(()),
            Err(error) => return Err(error),
        },
    };
    node.publish(&[change])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use synch_core::now_ns;
    use synch_engine::NodeConfig;

    #[tokio::test(flavor = "multi_thread")]
    async fn existing_records_cover_registration_replacement_and_revocation() {
        let _scope = synch_core::BlockingScope::enter();
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        let key = iroh_base::SecretKey::generate().public().to_z32();
        let until = now_ns() / 1_000_000_000 + 600;
        let put = Mutation::Put {
            key: key.clone(),
            spaces: vec!["docs".into()],
            expires_at: until,
        };
        apply(&node, put.clone()).unwrap();
        apply(&node, put).unwrap();
        let grants = node.delegations().unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].spaces, ["docs"]);
        assert_eq!(grants[0].expires_at, Some(until * 1_000_000_000));
        assert_eq!(grants[0].issuer.as_ref(), Some(node.origin()));
        apply(
            &node,
            Mutation::Put {
                key: key.clone(),
                spaces: vec!["photos".into()],
                expires_at: until,
            },
        )
        .unwrap();
        assert_eq!(node.delegations().unwrap()[0].spaces, ["photos"]);
        node.shutdown().await.unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        assert_eq!(node.delegations().unwrap().len(), 1);
        apply(&node, Mutation::Delete { key: key.clone() }).unwrap();
        apply(&node, Mutation::Delete { key }).unwrap();
        assert!(node.delegations().unwrap().is_empty());
        node.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_or_expired_grants_never_publish() {
        let _scope = synch_core::BlockingScope::enter();
        let dir = tempfile::tempdir().unwrap();
        Node::init(dir.path(), None).unwrap();
        let node = Node::open(NodeConfig::loopback(dir.path())).await.unwrap();
        let key = iroh_base::SecretKey::generate().public().to_z32();
        let future = now_ns() / 1_000_000_000 + 600;
        for (key, spaces, expires_at) in [
            ("bad".into(), vec!["docs".into()], future),
            (node.node_id().to_z32(), vec!["docs".into()], future),
            (key.clone(), vec![], future),
            (key.clone(), vec!["*".into()], future),
            (key.clone(), vec!["docs".into(), "docs".into()], future),
            (key.clone(), vec!["docs".into()], 0),
            (key.clone(), vec!["docs".into()], i64::MAX),
        ] {
            assert!(apply(
                &node,
                Mutation::Put {
                    key,
                    spaces,
                    expires_at
                }
            )
            .is_err());
        }
        assert!(node.delegations().unwrap().is_empty());
        node.shutdown().await.unwrap();
    }
}
