use std::sync::OnceLock;

/// Ensures a rustls crypto provider is installed as the process default.
///
/// This is idempotent and safe to call multiple times. Installation is best-effort:
/// if the provider is already installed (by the application or another crate),
/// this does nothing.
pub(crate) fn ensure_crypto_provider_installed() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        // Best-effort: ignore error if already installed by the application.
        let _ = crypto_provider().install_default();
    });
}

#[cfg(feature = "ring")]
fn crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

#[cfg(feature = "aws-lc-rs")]
fn crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}
