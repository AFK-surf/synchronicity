//! Process-wide rustls provider selection.
//!
//! The workspace standardizes on [`aws_lc_rs`]: iroh is built with
//! `tls-aws-lc-rs` and hickory with `dnssec-aws-lc-rs`. reqwest therefore
//! takes `rustls-no-provider` rather than its `rustls` feature — the
//! provider is named in one place, and a second one arriving through a
//! dependency's features would leave rustls unable to guess a process
//! default, panicking on the first TLS handshake.
//!
//! With no provider installed, reqwest panics as soon as a `Client` is
//! *built*, so the provider cannot wait for rustls's fallback (pick the one
//! provider the crate features name, at the first handshake). Every binary
//! installs it as the first thing its `main` does, via
//! [`install_crypto_provider`]. Test binaries have no `main` of ours to
//! install from, so `sim` builds — the feature every test-carrying crate
//! dev-depends on — install it before `main` instead, with [`ctor`].

use rustls::crypto::aws_lc_rs;

/// Install `aws-lc-rs` as the process-wide rustls [`CryptoProvider`].
///
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
///
/// Idempotent and race-safe: a second call loses the race to install and the
/// error is dropped, because the outcome is the same provider either way.
pub fn install_crypto_provider() {
    let _ = aws_lc_rs::default_provider().install_default();
}

/// The test-binary stand-in for the `main` every shipped binary opens with.
#[cfg(feature = "sim")]
#[ctor::ctor]
fn pre_main_install() {
    install_crypto_provider();
}
