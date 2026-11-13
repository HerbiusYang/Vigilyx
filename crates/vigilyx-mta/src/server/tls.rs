//! TLS acceptor

//! tokio-rustls (OpenSSL) TLS:
//! - 25/587: STARTTLS
//! - 465: TLS

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::config::TlsConfig;

/// TLS acceptor
pub fn build_tls_acceptor(tls_config: &TlsConfig) -> anyhow::Result<TlsAcceptor> {
    let cert_file = File::open(&tls_config.cert_path)?;
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                anyhow::anyhow!("Invalid certificate PEM in {:?}: {e}", tls_config.cert_path)
            })?;

    if certs.is_empty() {
        anyhow::bail!("No certificates found in {:?}", tls_config.cert_path);
    }

    let key_file = File::open(&tls_config.key_path)?;
    let key = match PrivateKeyDer::from_pem_reader(BufReader::new(key_file)) {
        Ok(key) => key,
        Err(rustls::pki_types::pem::Error::NoItemsFound) => {
            anyhow::bail!("No private key found in {:?}", tls_config.key_path)
        }
        Err(e) => anyhow::bail!("Invalid private key PEM in {:?}: {e}", tls_config.key_path),
    };

    // Select the provider explicitly. mail-auth verifies DKIM with ring while
    // rustls defaults to AWS-LC, so feature unification can make both visible;
    // the implicit builder intentionally panics in that situation.
    let server_config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;

    info!(
        cert = ?tls_config.cert_path,
        "TLS acceptor initialized"
    );

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}
