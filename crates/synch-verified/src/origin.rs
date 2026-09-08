//! Whole origin operations executed by Lean. Rust supplies only point validation.
use crate::{
    host::Crypto,
    operation::{self, terminal, Command, Decode},
};
use std::convert::Infallible;

pub use crate::generated::{
    NamedOrigin as Named, OriginError as DomainError, ParsedOrigin as Parsed,
};
pub use crate::operation::OperationError;

/// Syntax/point rejection remains distinct from failure of the host primitive.
pub type Error<E> = crate::CommandError<E, DomainError>;

fn finish<A: Decode, E>(result: Vec<u8>) -> Result<A, Error<E>> {
    Error::finish(Ok(result))
}

/// Parse syntax, normalize named components, and validate decoded key bytes.
pub fn parse<C: Crypto>(crypto: &mut C, text: &str) -> Result<Parsed, Error<C::Error>> {
    finish(
        operation::run_crypto(crypto, &Command::OriginParse(text.to_owned()))
            .map_err(Error::Operation)?,
    )
}

/// Validate both components together, preserving label-before-domain diagnostics.
pub fn named(id: &str, domain: &str) -> Result<Named, Error<Infallible>> {
    finish(
        operation::run_pure(&Command::OriginNamed {
            id: id.to_owned(),
            domain: domain.to_owned(),
        })
        .map_err(Error::Operation)?,
    )
}

/// Normalize one member label using the same operation used by named parsing.
pub fn normalize_label(text: &str) -> Result<String, Error<Infallible>> {
    finish(
        operation::run_pure(&Command::OriginNormalizeLabel(text.to_owned()))
            .map_err(Error::Operation)?,
    )
}

/// Normalize one membership domain using the same operation used by named parsing.
pub fn normalize_domain(text: &str) -> Result<String, Error<Infallible>> {
    finish(
        operation::run_pure(&Command::OriginNormalizeDomain(text.to_owned()))
            .map_err(Error::Operation)?,
    )
}

/// Serialize a typed origin in its canonical wire spelling.
pub fn canonical(origin: &Parsed) -> Result<String, OperationError<Infallible>> {
    let result = operation::run_pure(&Command::OriginCanonical(origin.clone()))?;
    terminal(&result).map_err(|()| OperationError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Point {
        result: Result<bool, &'static str>,
        keys: Vec<Vec<u8>>,
    }
    impl Crypto for Point {
        host_unexpected!(verify_ed25519);
        type Error = &'static str;
        fn validate_ed25519(&mut self, bytes: &[u8]) -> Result<bool, Self::Error> {
            self.keys.push(bytes.to_vec());
            self.result
        }
    }

    #[test]
    fn native_named_parse_does_not_request_crypto() {
        // Syntax and callback policy are proved in OriginProgramProofs;
        // keep one native command/host integration check.
        let mut point = Point {
            result: Err("must not call"),
            keys: Vec::new(),
        };
        assert_eq!(
            parse(&mut point, "NAS@Cluster.Example...").unwrap(),
            Parsed::Named(Named {
                id: "nas".into(),
                domain: "cluster.example".into()
            })
        );
        assert!(point.keys.is_empty());
    }

    #[test]
    fn point_rejection_and_host_failure_remain_distinct() {
        let bare = "y".repeat(52);
        let explicit = format!("key:{bare}");
        let mut point = Point {
            result: Ok(true),
            keys: Vec::new(),
        };
        assert_eq!(
            parse(&mut point, &explicit).unwrap(),
            Parsed::Key(vec![0; 32])
        );
        assert_eq!(point.keys, [vec![0; 32]]);
        point.result = Ok(false);
        assert!(matches!(
            parse(&mut point, &explicit),
            Err(Error::Domain(DomainError::KeyData))
        ));
        assert!(
            matches!(parse(&mut point, &bare), Err(Error::Domain(DomainError::Shape(text))) if text == bare)
        );
        point.result = Err("point service unavailable");
        for text in [&explicit, &bare] {
            assert!(matches!(
                parse(&mut point, text),
                Err(Error::Operation(OperationError::Host(
                    "point service unavailable"
                )))
            ));
        }
        let before = point.keys.len();
        assert!(matches!(
            parse(&mut point, &format!("key:{}b", "y".repeat(51))),
            Err(Error::Domain(DomainError::KeyDecode))
        ));
        assert!(matches!(
            parse(&mut point, "key:ca"),
            Err(Error::Domain(DomainError::KeyData))
        ));
        assert_eq!(point.keys.len(), before);
    }
}
