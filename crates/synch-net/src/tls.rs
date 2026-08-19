//! Process-wide rustls provider selection.
//!
//! The workspace standardizes on [`ring`]: iroh is built with `tls-ring` and
//! hickory with `dnssec-ring`. reqwest therefore takes `rustls-no-provider`
//! rather than its `rustls` feature — that feature enables rustls's
//! aws-lc-rs provider, and with two providers enabled rustls refuses to
//! guess a process default and panics on the first TLS handshake.
//!
//! With no provider installed, reqwest panics as soon as a `Client` is
//! *built*, so the provider cannot wait for rustls's fallback (pick the one
//! provider the crate features name, at the first handshake). Every binary
//! installs it as the first thing its `main` does, via
//! [`install_ring_provider`]. Test binaries have no `main` of ours to
//! install from, so `sim` builds — the feature every test-carrying crate
//! dev-depends on — install it before `main` instead, with [`ctor`].

use rustls::crypto::ring;

/// Install `ring` as the process-wide rustls [`CryptoProvider`].
///
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
///
/// Idempotent and race-safe: a second call loses the race to install and the
/// error is dropped, because the outcome is the same provider either way.
pub fn install_ring_provider() {
    let _ = ring::default_provider().install_default();
}

/// The test-binary stand-in for the `main` every shipped binary opens with.
#[cfg(feature = "sim")]
#[ctor::ctor]
fn pre_main_install() {
    install_ring_provider();
}
