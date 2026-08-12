//! [`OriginId`] — the stable identity that owns a trie (§3.1).

use std::{fmt, str::FromStr};

use iroh_base::PublicKey;
use serde::{Deserialize, Serialize};

/// A device key: the ed25519 public key that is also the iroh endpoint id.
pub type NodeId = PublicKey;

/// The stable identity that owns a trie and keys all replicated state.
///
/// It never changes for the lifetime of a node, across any number of device-key
/// rotations (§3.1). Canonical text rendering is `key:<z-base-32>` for
/// key-identified origins and `<id>@<domain>` for named ones.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OriginId {
    /// No name: the device key is the identity (not rotatable).
    Key(NodeId),
    /// A named origin, scoped by a membership domain (rotatable).
    Named {
        /// The membership domain, lowercased.
        domain: String,
        /// The member label, lowercased, matching `[a-z0-9-]{1,63}`.
        id: String,
    },
}

impl OriginId {
    /// Builds a named origin, validating and normalizing both parts.
    pub fn named(id: &str, domain: &str) -> Result<Self, OriginParseError> {
        let id = normalize_label(id)?;
        let domain = normalize_domain(domain)?;
        Ok(OriginId::Named { domain, id })
    }

    /// The canonical text rendering, as stored in the `origin_id` SQL columns (§10).
    pub fn canonical(&self) -> String {
        match self {
            OriginId::Key(k) => format!("key:{}", k.to_z32()),
            OriginId::Named { domain, id } => format!("{id}@{domain}"),
        }
    }

    /// The device key, if this origin is key-identified.
    pub fn as_key(&self) -> Option<&NodeId> {
        match self {
            OriginId::Key(k) => Some(k),
            OriginId::Named { .. } => None,
        }
    }

    /// The membership domain, if this origin is named.
    pub fn domain(&self) -> Option<&str> {
        match self {
            OriginId::Key(_) => None,
            OriginId::Named { domain, .. } => Some(domain),
        }
    }

    /// A short human-facing rendering for logs and CLI output.
    pub fn short(&self) -> String {
        match self {
            OriginId::Key(k) => {
                let z = k.to_z32();
                format!("key:{}", &z[..10.min(z.len())])
            }
            OriginId::Named { .. } => self.canonical(),
        }
    }
}

impl fmt::Display for OriginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

impl fmt::Debug for OriginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OriginId({})", self.canonical())
    }
}

/// Error parsing an [`OriginId`] or one of its components.
#[derive(Debug, thiserror::Error)]
pub enum OriginParseError {
    /// The label was empty, too long, or contained characters outside `[a-z0-9-]`.
    #[error("invalid member id {0:?}: must match [a-z0-9-]{{1,63}}")]
    Label(String),
    /// The domain was empty, too long, or had an invalid label.
    #[error("invalid domain {0:?}")]
    Domain(String),
    /// The `key:` form did not carry a valid z-base-32 device key.
    #[error("invalid device key: {0}")]
    Key(String),
    /// The string was neither `key:<...>` nor `<id>@<domain>`.
    #[error("origin must be '<id>@<domain>' or 'key:<z-base-32>', got {0:?}")]
    Shape(String),
}

/// Normalizes and validates a member label (`id=` in the TXT record, §3.2).
pub fn normalize_label(id: &str) -> Result<String, OriginParseError> {
    let lower = id.to_ascii_lowercase();
    let ok = !lower.is_empty()
        && lower.len() <= 63
        && lower
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(lower)
    } else {
        Err(OriginParseError::Label(id.to_string()))
    }
}

/// Normalizes and validates a DNS membership domain.
pub fn normalize_domain(domain: &str) -> Result<String, OriginParseError> {
    let lower = domain.trim_end_matches('.').to_ascii_lowercase();
    let ok = !lower.is_empty()
        && lower.len() <= 253
        && lower.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    if ok {
        Ok(lower)
    } else {
        Err(OriginParseError::Domain(domain.to_string()))
    }
}

impl FromStr for OriginId {
    type Err = OriginParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("key:") {
            let key =
                PublicKey::from_z32(rest).map_err(|e| OriginParseError::Key(e.to_string()))?;
            return Ok(OriginId::Key(key));
        }
        if let Some((id, domain)) = s.split_once('@') {
            return OriginId::named(id, domain);
        }
        // A bare z-base-32 key is also accepted for CLI convenience.
        if let Ok(key) = PublicKey::from_z32(s) {
            return Ok(OriginId::Key(key));
        }
        Err(OriginParseError::Shape(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

    #[test]
    fn key_origin_round_trip() {
        let key = SecretKey::generate().public();
        let o = OriginId::Key(key);
        let text = o.canonical();
        assert!(text.starts_with("key:"));
        assert_eq!(OriginId::from_str(&text).unwrap(), o);
    }

    #[test]
    fn named_origin_round_trip() {
        let o = OriginId::named("NAS", "Cluster.Example.COM.").unwrap();
        assert_eq!(o.canonical(), "nas@cluster.example.com");
        assert_eq!(OriginId::from_str("nas@cluster.example.com").unwrap(), o);
        assert_eq!(o.domain(), Some("cluster.example.com"));
    }

    #[test]
    fn bare_key_parses() {
        let key = SecretKey::generate().public();
        assert_eq!(
            OriginId::from_str(&key.to_z32()).unwrap(),
            OriginId::Key(key)
        );
    }

    #[test]
    fn rejects_bad_labels() {
        assert!(normalize_label("").is_err());
        assert!(normalize_label("has_underscore").is_err());
        assert!(normalize_label(&"x".repeat(64)).is_err());
        assert!(normalize_label("ok-1").is_ok());
    }

    #[test]
    fn rejects_bad_domains() {
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("a..b").is_err());
        assert!(normalize_domain("-lead.example").is_err());
        assert!(normalize_domain("ok.example.com").is_ok());
    }

    #[test]
    fn ordering_is_by_canonical_shape() {
        // Named origins sort together and stably; used for deterministic wire order.
        let a = OriginId::named("a", "x.example").unwrap();
        let b = OriginId::named("b", "x.example").unwrap();
        assert!(a < b);
    }
}
