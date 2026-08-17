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

    // Non-first IPv4 fragments do not contain TCP ports.  Keep every IPv4
    // fragment in the capture stream so the userspace bounded reassembler can
    // reconstruct the TCP segment instead of silently losing the entire flow.
    // The parser still admits only protocol=TCP and enforces its own limits.
    const IPV4_FRAGMENT_FILTER: &str =
        "ip and (((ip[6:2] & 0x1fff) != 0) or ((ip[6:2] & 0x2000) != 0))";

    if config.webmail_servers.is_empty() {
        // emailProtocol
        return format!(
            "(tcp and ({})) or ({})",
            mail_filter.join(" or "),
            IPV4_FRAGMENT_FILTER
        );
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

    // BPF: (tcp and (emailPort or (HTTPPort and TargetIP))) or IPv4 fragments.
    format!(
        "(tcp and ({} or (({}) and ({})))) or ({})",
        mail_filter.join(" or "),
        http_port_filter.join(" or "),
        host_filter.join(" or "),
        IPV4_FRAGMENT_FILTER
    )
}
