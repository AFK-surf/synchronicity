//! [`OriginId`] — the stable identity that owns a trie (§3.1).

use std::{convert::Infallible, fmt, str::FromStr};

use synch_verified::origin::{self as verified, DomainError, OperationError};

use iroh_base::PublicKey;
use serde::{Deserialize, Serialize};

/// A device key: the ed25519 public key that is also the iroh endpoint id.
pub type NodeId = PublicKey;

/// The stable identity that owns a trie and keys all replicated state.
///
/// It never changes for the lifetime of a node, across any number of device-key
/// rotations (§3.1). Canonical rendering: `key:<z-base-32>` or `<id>@<domain>`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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
        let value = verified::named(id, domain).map_err(operation_error)?;
        Ok(OriginId::Named {
            domain: value.domain,
            id: value.id,
        })
    }

    /// The canonical text rendering, as stored in the `origin_id` SQL columns (§10).
    pub fn canonical(&self) -> String {
        let value = match self {
            OriginId::Key(key) => verified::Parsed::Key(key.as_bytes().to_vec()),
            OriginId::Named { domain, id } => verified::Parsed::Named(verified::Named {
                domain: domain.clone(),
                id: id.clone(),
            }),
        };
        verified::canonical(&value).expect("canonical origin serialization failed")
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

/// Decoding re-validates, because an `OriginId` arriving here is a peer's word.
///
/// Every other way to build one checks the label and domain; the value off a
/// wire or out of a stored record is the one place that would not. It keys
/// `blob_providers`, `bindings` and `entries` by its canonical rendering, so an
/// unvalidated one is an arbitrary row key — a 64 KB label, or a thousand
/// spellings of one member.
impl<'de> Deserialize<'de> for OriginId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// The same shape, decoded before it is judged.
        #[derive(Deserialize)]
        enum Wire {
            Key(NodeId),
            Named { domain: String, id: String },
        }
        match Wire::deserialize(deserializer)? {
            Wire::Key(key) => Ok(OriginId::Key(key)),
            Wire::Named { domain, id } => {
                OriginId::named(&id, &domain).map_err(serde::de::Error::custom)
            }
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
    /// The native operation failed; this is not rejection of an origin's syntax.
    #[error("origin validation operation failed: {0}")]
    Operation(#[source] OperationError<Infallible>),
}

impl From<DomainError> for OriginParseError {
    fn from(error: DomainError) -> Self {
        match error {
            DomainError::Label(text) => Self::Label(text),
            DomainError::Domain(text) => Self::Domain(text),
            DomainError::Shape(text) => Self::Shape(text),
            DomainError::KeyDecode => Self::Key("failed to decode base32 string".into()),
            DomainError::KeyData => Self::Key("data is not a valid public key".into()),
        }
    }
}

fn operation_error(error: verified::Error<Infallible>) -> OriginParseError {
    match error {
        verified::Error::Operation(error) => OriginParseError::Operation(error),
        verified::Error::Domain(error) => error.into(),
    }
}

/// Normalizes and validates a member label (`id=` in the TXT record, §3.2).
pub fn normalize_label(id: &str) -> Result<String, OriginParseError> {
    verified::normalize_label(id).map_err(operation_error)
}

/// Normalizes and validates a DNS membership domain.
pub fn normalize_domain(domain: &str) -> Result<String, OriginParseError> {
    verified::normalize_domain(domain).map_err(operation_error)
}

impl FromStr for OriginId {
    type Err = OriginParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut crypto = PointValidator(None);
        match verified::parse(&mut crypto, s).map_err(operation_error)? {
            verified::Parsed::Named(value) => Ok(Self::Named {
                domain: value.domain,
                id: value.id,
            }),
            verified::Parsed::Key(bytes) => crypto
                .0
                .filter(|key| key.as_bytes().as_slice() == bytes.as_slice())
                .map(Self::Key)
                .ok_or(OriginParseError::Operation(OperationError::Protocol)),
        }
    }
}

/// Cache the validated wire key so decoding the command result does not
/// repeat the cryptographic primitive. Syntax and diagnostic choice stay in Lean.
struct PointValidator(Option<NodeId>);

impl synch_verified::host::Crypto for PointValidator {
    synch_verified::host_unexpected!(verify_ed25519);
    type Error = Infallible;
    fn validate_ed25519(&mut self, bytes: &[u8]) -> Result<bool, Self::Error> {
        self.0 = <&[u8; 32]>::try_from(bytes)
            .ok()
            .and_then(|key| PublicKey::from_bytes(key).ok());
        Ok(self.0.is_some())
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

    #[test]
    fn canonical_key_uses_the_independent_rfc8032_wire_vector() {
        let bytes = [
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ];
        let key = NodeId::from_bytes(&bytes).unwrap();
        assert_eq!(
            OriginId::Key(key).canonical(),
            "key:47pjoycnsrfmxikm95jh13y88e8qnhzu5kungjpxyepgt7a8krpy"
        );
    }

    #[test]
    fn key_origin_round_trip() {
        let key = SecretKey::generate().public();
        let o = OriginId::Key(key);
        let text = o.canonical();
        assert!(text.starts_with("key:"));
        assert_eq!(OriginId::from_str(&text).unwrap(), o);
        // The bare z32 form parses to the same key origin.
        assert_eq!(OriginId::from_str(&key.to_z32()).unwrap(), o);
    }

    #[test]
    fn named_origin_round_trip() {
        let o = OriginId::named("NAS", "Cluster.Example.COM.").unwrap();
        assert_eq!(o.canonical(), "nas@cluster.example.com");
        assert_eq!(OriginId::from_str("nas@cluster.example.com").unwrap(), o);
        assert_eq!(o.domain(), Some("cluster.example.com"));
    }

    #[test]
    fn rejects_bad_labels() {
        assert!(normalize_label("").is_err());
        assert!(normalize_label("has_underscore").is_err());
        assert!(normalize_label(&"x".repeat(64)).is_err());
        assert!(normalize_label("ok-1").is_ok());
        // Domains validate label-by-label, with the same rules.
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("a..b").is_err());
        assert!(normalize_domain("-lead.example").is_err());
        assert!(normalize_domain("ok.example.com").is_ok());
    }

    /// An origin off the wire is checked the way a constructed one is: what
    /// decodes keys rows in three tables, so a label no constructor would
    /// produce must not become a row key here either.
    #[test]
    fn a_decoded_origin_is_validated_like_a_constructed_one() {
        let good = OriginId::named("nas", "cluster.example").unwrap();
        let bytes = postcard::to_stdvec(&good).unwrap();
        assert_eq!(
            postcard::from_bytes::<OriginId>(&bytes).unwrap(),
            good,
            "an honest origin round trips"
        );

        // The same shape, with a label and a domain nothing would accept.
        #[derive(serde::Serialize)]
        enum Forged {
            #[allow(dead_code)]
            Key(NodeId),
            Named {
                domain: String,
                id: String,
            },
        }
        for (id, domain) in [
            ("x".repeat(64), "cluster.example".to_string()),
            ("nas".to_string(), "not a domain".to_string()),
            (String::new(), "cluster.example".to_string()),
        ] {
            let forged = postcard::to_stdvec(&Forged::Named { domain, id }).unwrap();
            assert!(
                postcard::from_bytes::<OriginId>(&forged).is_err(),
                "a forged origin must not decode"
            );
        }

        // Case is normalized rather than being a second identity for one member.
        let shouty = postcard::to_stdvec(&Forged::Named {
            domain: "Cluster.Example".into(),
            id: "NAS".into(),
        })
        .unwrap();
        assert_eq!(postcard::from_bytes::<OriginId>(&shouty).unwrap(), good);
    }
}
