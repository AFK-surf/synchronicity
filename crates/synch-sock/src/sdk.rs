//! The C SDK header, compiled in so `synch socket sdk` cannot ship a stale one.

/// `sdk/synch.h`, verbatim.
///
/// Embedded rather than installed: a header on disk beside the binary is a
/// header that can be older than the binary, and the numbers in it are the
/// guest's only view of the ABI. A guest compiled against a stale header gets
/// wrong answers rather than errors — a `SY_POLL_*` bit that means something
/// else, an errno it reads as success — so the header travels with the build
/// that defines it.
pub const HEADER: &str = include_str!("../sdk/synch.h");

#[cfg(test)]
mod tests {
    use super::HEADER;
    use crate::abi::{self, errno, poll};

    /// Extracts a `#define NAME value` from the header.
    fn define(name: &str) -> Option<i64> {
        HEADER.lines().find_map(|line| {
            let rest = line.trim().strip_prefix("#define ")?;
            let (defined, value) = rest.split_once(char::is_whitespace)?;
            if defined != name {
                return None;
            }
            let value = value.split("/*").next()?.trim();
            match value.strip_prefix("0x") {
                Some(hex) => i64::from_str_radix(hex, 16).ok(),
                None => value.parse().ok(),
            }
        })
    }

    /// The header is the guest's only view of these numbers, and nothing at
    /// build time makes the guest and the host agree about them. This test is
    /// what does.
    #[test]
    fn the_header_and_the_abi_agree() {
        for (name, value) in [
            ("SY_EAGAIN", errno::EAGAIN),
            ("SY_EBADF", errno::EBADF),
            ("SY_EINVAL", errno::EINVAL),
            ("SY_EPERM", errno::EPERM),
            ("SY_ECONNRESET", errno::ECONNRESET),
            ("SY_ETIMEDOUT", errno::ETIMEDOUT),
            ("SY_ELIMIT", errno::ELIMIT),
            ("SY_ENOENT", errno::ENOENT),
            ("SY_EPIPE", errno::EPIPE),
            ("SY_POLL_IN", poll::IN as i64),
            ("SY_POLL_OUT", poll::OUT as i64),
            ("SY_POLL_HUP", poll::HUP as i64),
            ("SY_POLL_ERR", poll::ERR as i64),
            ("SY_POLL_RDHUP", poll::RDHUP as i64),
            ("SY_SELF", abi::SY_SELF),
            ("SY_PEER_MEMBER", abi::peer_kind::MEMBER as i64),
            ("SY_PEER_DELEGATE", abi::peer_kind::DELEGATE as i64),
            ("SY_BASE64_STANDARD", abi::base64_kind::STANDARD as i64),
            (
                "SY_BASE64_STANDARD_NO_PAD",
                abi::base64_kind::STANDARD_NO_PAD as i64,
            ),
            ("SY_BASE64_URL", abi::base64_kind::URL as i64),
            ("SY_BASE64_URL_NO_PAD", abi::base64_kind::URL_NO_PAD as i64),
        ] {
            assert_eq!(
                define(name),
                Some(value),
                "the header and the ABI disagree about {name}"
            );
        }
    }

    /// The entry macros name the sections the loader actually looks for. A
    /// typo here produces a program that loads and never runs.
    #[test]
    fn the_header_names_the_sections_the_loader_looks_for() {
        assert!(
            HEADER.contains(&format!("SY_SECTION(\"{}\")", abi::SECTION_STREAM)),
            "SY_ENTRY does not name {}",
            abi::SECTION_STREAM
        );
        assert!(
            HEADER.contains(&format!("SY_SECTION(\"{}\")", abi::SECTION_INIT)),
            "SY_INIT_ENTRY does not name {}",
            abi::SECTION_INIT
        );
    }

    /// Every helper the runtime registers must be declared in the header, and
    /// every helper the header declares must exist — a program that calls one
    /// the host does not register fails to *link*, at load, on the first
    /// connection, which is a long way from where the typo is.
    #[test]
    #[cfg(all(
        any(target_os = "linux", target_os = "macos", target_os = "openbsd"),
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn the_header_declares_exactly_the_helpers_the_runtime_registers() {
        let registered: std::collections::BTreeSet<&str> =
            crate::runtime::helper_names().into_iter().collect();
        let declared: std::collections::BTreeSet<&str> = HEADER
            .lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix("extern ")?;
                let open = rest.find('(')?;
                let name = rest[..open].rsplit(char::is_whitespace).next()?;
                Some(name.trim_start_matches('*'))
            })
            .collect();

        let missing: Vec<_> = registered.difference(&declared).collect();
        assert!(
            missing.is_empty(),
            "registered but not in the header: {missing:?}"
        );
        let extra: Vec<_> = declared.difference(&registered).collect();
        assert!(
            extra.is_empty(),
            "in the header but not registered: {extra:?}"
        );
    }
}
