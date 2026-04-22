//! BPF handlerBuild

//! generatePerformance notesof BPF table,Used for leveldatapacket

use vigilyx_core::Config;

/// BuildPerformance notesof BPF handler
///
/// Performance notesstrategy:
/// 1. Use dst port prioritymatchclient of connection
/// 2. Add TCP flags,hops ACK packet (data)
/// 3. Use portrange BPF (if Portcontiguous)
pub(super) fn build_bpf_filter(config: &Config) -> String {
    // emailPort (SMTP/POP3/IMAP)
    let mut mail_ports: Vec<u16> = Vec::new();
    mail_ports.extend(&config.smtp_ports);
    mail_ports.extend(&config.pop3_ports);
    mail_ports.extend(&config.imap_ports);
    mail_ports.sort_unstable();
    mail_ports.dedup();

    let mail_filter: Vec<String> = mail_ports.iter().map(|p| format!("port {}", p)).collect();

    if config.webmail_servers.is_empty() {
        // emailProtocol
        return format!("tcp and ({})", mail_filter.join(" or "));
    }

    // HTTP Port + Target IP limit (only webmail Servicehandlerof HTTP Stream)
    let http_port_filter: Vec<String> = config
        .http_ports
        .iter()
        .map(|p| format!("port {}", p))
        .collect();
    let host_filter: Vec<String> = config
        .webmail_servers
        .iter()
        .map(|ip| format!("host {}", ip))
        .collect();

    // BPF: tcp and (emailPort or (HTTPPort and TargetIP))
    format!(
        "tcp and ({} or (({}) and ({})))",
        mail_filter.join(" or "),
        http_port_filter.join(" or "),
        host_filter.join(" or ")
    )
}
