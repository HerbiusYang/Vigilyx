//! TLS acceptor

//! tokio-rustls (OpenSSL) TLS:
//! - 25/587: STARTTLS
//! - 465: TLS

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::config::TlsConfig;

/// TLS acceptor
pub fn build_tls_acceptor(tls_config: &TlsConfig) -> anyhow::Result<TlsAcceptor> {
    
    let cert_file = File::open(&tls_config.cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        anyhow::bail!(
            "No certificates found in {:?}",
            tls_config.cert_path
        );
    }

    
    let key_file = File::open(&tls_config.key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!(
            "No private key found in {:?}",
            tls_config.key_path
        ))?;

   // rustls ServerConfig
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    info!(
        cert = ?tls_config.cert_path,
        "TLS acceptor initialized"
    );

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}
