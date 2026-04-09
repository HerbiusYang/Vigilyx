//! Vigilyx MTA

//! SMTP, -> TLS -> -> / /.
//! SecurityEngine <8s inline.

pub mod config;
pub mod dlp;
pub(crate) mod envelope;
pub mod relay;
pub mod server;
