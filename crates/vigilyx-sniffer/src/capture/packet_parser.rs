//! Packet parsing utilities for the capture pipeline.
//!
//! Parses Ethernet/IPv4/IPv6/TCP frames, including VLAN tags.

use super::port_bitmap::PortBitmap;
use bytes::Bytes;
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::warn;
use vigilyx_core::{Direction, Protocol};

/// Maximum supported payload size.
pub(super) const MAX_PAYLOAD_SIZE: usize = 65535;

// Core packet structures.

/// Parsed packet metadata optimized for the hot path.
#[derive(Clone)]
#[repr(C)]
pub struct RawpacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub payload: Bytes,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    /// TCP sequence number used for stream reassembly.
    pub tcp_seq: u32,
    /// TCP acknowledgment number.
    pub tcp_ack: u32,
    /// TCP flags (SYN/FIN/RST/ACK/PSH).
    pub tcp_flags: u8,
}

/// IP Address
#[derive(Clone, Copy, Debug)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl std::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpAddr::V4(v4) => write!(f, "{}", v4),
            IpAddr::V6(v6) => write!(f, "{}", v6),
        }
    }
}

// ============================================
// Packet parsing helpers.
// ============================================

/// Parse a raw packet frame captured from pcap.
///
/// Uses shared `Bytes` storage and `Bytes::slice()` to avoid extra payload copies.
/// The capture loop performs a single `Bytes::copy_from_slice()`; the rest stays zero-copy.
#[inline]
pub(super) fn parse_raw_packet(frame: Bytes, port_bitmap: &PortBitmap) -> Option<RawpacketInfo> {
    if frame.len() < 54 {
        return None;
    }

    // Parse the Ethernet header.
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut ip_header_start = 14;

    // Walk VLAN tags, if present.
    let mut vlan_depth = 0;
    const MAX_VLAN_DEPTH: u8 = 2;

    while ethertype == 0x8100 || ethertype == 0x88A8 {
        vlan_depth += 1;
        if vlan_depth > MAX_VLAN_DEPTH {
            return None;
        }
        if frame.len() < ip_header_start + 4 {
            return None;
        }
        ip_header_start += 4;
        if frame.len() < ip_header_start + 2 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[ip_header_start - 2], frame[ip_header_start - 1]]);
    }

    if frame.len() < ip_header_start + 40 {
        return None;
    }

    let ip_version = match ethertype {
        0x0800 => 4,
        0x86DD => 6,
        _ => return None,
    };

    // slice() is O(1) - just Arc refcount bump, no memcpy
    let ip_data = frame.slice(ip_header_start..);

    if ip_version == 4 {
        parse_ipv4(ip_data, port_bitmap)
    } else {
        parse_ipv6(ip_data, port_bitmap)
    }
}

/// Fast-path packet parser with early branch pruning.
///
/// The capture loop already copied the frame into `Bytes`; this path only uses `slice()`.
#[inline]
pub(super) fn parse_packet(frame: Bytes, port_bitmap: &PortBitmap) -> Option<RawpacketInfo> {
    if frame.len() < 54 {
        // small: 14(Eth) + 20(IP) + 20(TCP)
        return None;
    }

    // HeaderParse (VLAN)
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut ip_header_start = 14;

    // Process 802.1Q VLAN (possibly)
    let mut vlan_depth = 0;
    const MAX_VLAN_DEPTH: u8 = 2; // prevent VLAN Attack

    while ethertype == 0x8100 || ethertype == 0x88A8 {
        // 802.1Q QinQ
        vlan_depth += 1;
        if vlan_depth > MAX_VLAN_DEPTH {
            return None; // VLAN Attack
        }
        if frame.len() < ip_header_start + 4 {
            return None;
        }
        ip_header_start += 4;
        if frame.len() < ip_header_start + 2 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[ip_header_start - 2], frame[ip_header_start - 1]]);
    }

    // Require enough bytes for the minimum IP and TCP headers.
    if frame.len() < ip_header_start + 40 {
        // Minimum sizes: 20-byte IP header + 20-byte TCP header.
        return None;
    }

    let ip_version = match ethertype {
        0x0800 => 4, // IPv4
        0x86DD => 6, // IPv6
        _ => return None,
    };

    // slice() is O(1) - just Arc refcount bump, no memcpy
    let ip_data = frame.slice(ip_header_start..);

    if ip_version == 4 {
        parse_ipv4(ip_data, port_bitmap)
    } else {
        parse_ipv6(ip_data, port_bitmap)
    }
}

/// Parse an IPv4 packet and extract the TCP payload for monitored ports.
#[inline]
fn parse_ipv4(data: Bytes, port_bitmap: &PortBitmap) -> Option<RawpacketInfo> {
    if data.len() < 20 {
        return None;
    }

    // IHL is measured in 32-bit words; valid values are 5..=15.
    let ihl_value = data[0] & 0x0F;
    if ihl_value < 5 {
        return None; // Invalid IHL.
    }
    let ihl = (ihl_value * 4) as usize;

    // Ensure the buffer actually contains the full IPv4 header.
    if data.len() < ihl {
        return None; // Truncated IPv4 header.
    }

    // Honor the IPv4 total-length field to avoid reading padding or garbage.
    let total_length = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_length < ihl {
        return None; // Total length smaller than header length.
    }
    if total_length > data.len() {
        return None; // Truncated packet.
    }

    // Drop fragmented IPv4 packets; TCP reassembly expects complete transport headers.
    let flags_offset = u16::from_be_bytes([data[6], data[7]]);
    let more_fragments = (flags_offset & 0x2000) != 0;
    let fragment_offset = (flags_offset & 0x1FFF) * 8;
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    if more_fragments || fragment_offset > 0 {
        // Only log fragments that belong to monitored ports to avoid noisy warnings.
        if fragment_offset == 0 && total_length >= ihl + 4 {
            let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
            let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
            if port_bitmap.contains(src_port) || port_bitmap.contains(dst_port) {
                warn!(
                    "Dropped fragmented IPv4 packet for monitored mail flow: {}:{} -> {}:{} fragment_offset={} more_fragments={}",
                    src_ip, src_port, dst_ip, dst_port, fragment_offset, more_fragments
                );
            }
        }
        return None;
    }

    let protocol = data[9];

    // Only TCP traffic is relevant to the mail and HTTP parsers.
    if protocol != 6 {
        return None;
    }

    // Slice only the valid transport payload described by the IP header.
    let tcp_data = data.slice(ihl..total_length);

    parse_tcp(
        tcp_data,
        IpAddr::V4(src_ip),
        IpAddr::V4(dst_ip),
        port_bitmap,
    )
}

/// Parse an IPv6 packet, walking extension headers until TCP is found.
#[inline]
fn parse_ipv6(data: Bytes, port_bitmap: &PortBitmap) -> Option<RawpacketInfo> {
    if data.len() < 40 {
        return None;
    }

    let src_ip = Ipv6Addr::from([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
        data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);
    let dst_ip = Ipv6Addr::from([
        data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31], data[32],
        data[33], data[34], data[35], data[36], data[37], data[38], data[39],
    ]);

    // Walk IPv6 extension headers until we reach TCP.
    let mut next_header = data[6];
    let mut offset = 40usize;
    let mut extension_count = 0;
    const MAX_EXTENSIONS: u8 = 10; // Prevent pathological extension-header chains.

    while next_header != 6 {
        // Stop if the chain is implausibly long.
        extension_count += 1;
        if extension_count > MAX_EXTENSIONS {
            return None;
        }

        // Every extension header starts with at least two bytes.
        if data.len() < offset + 2 {
            return None;
        }

        match next_header {
            // Fragment header.
            44 => {
                // Layout: next-header, reserved, offset/flags, identification.
                if data.len() < offset + 8 {
                    return None;
                }
                let frag_off_m = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                let fragment_offset = frag_off_m >> 3;
                let more_fragments = (frag_off_m & 0x01) != 0;
                if fragment_offset > 0 || more_fragments {
                    if fragment_offset == 0 && data.len() >= offset + 12 {
                        let tcp_offset = offset + 8;
                        let src_port = u16::from_be_bytes([data[tcp_offset], data[tcp_offset + 1]]);
                        let dst_port =
                            u16::from_be_bytes([data[tcp_offset + 2], data[tcp_offset + 3]]);
                        if port_bitmap.contains(src_port) || port_bitmap.contains(dst_port) {
                            warn!(
                                "Dropped fragmented IPv6 packet for monitored mail flow: [{}]:{} -> [{}]:{} fragment_offset={} more_fragments={}",
                                src_ip, src_port, dst_ip, dst_port, fragment_offset, more_fragments
                            );
                        }
                    }
                    // As with IPv4, fragments are ignored instead of being reassembled here.
                    return None;
                }
                next_header = data[offset];
                offset += 8;
            }
            0 | 43 | 60 => {
                // Hop-by-hop, routing, and destination options share the same length encoding.
                let ext_len = (data[offset + 1] as usize + 1) * 8;
                if data.len() < offset + ext_len {
                    return None;
                }
                next_header = data[offset];
                offset += ext_len;
            }
            51 => {
                // Authentication Header length is stored in 32-bit words minus 2.
                let ext_len = (data[offset + 1] as usize + 2) * 4;
                if data.len() < offset + ext_len {
                    return None;
                }
                next_header = data[offset];
                offset += ext_len;
            }
            59 => {
                // No next header means there is no TCP payload to parse.
                return None;
            }
            _ => {
                // Unknown or unsupported next-header value.
                return None;
            }
        }
    }

    // A minimal TCP header is 20 bytes.
    if data.len() < offset + 20 {
        return None;
    }

    // `Bytes::slice()` keeps this zero-copy.
    let tcp_data = data.slice(offset..);

    parse_tcp(
        tcp_data,
        IpAddr::V6(src_ip),
        IpAddr::V6(dst_ip),
        port_bitmap,
    )
}

/// Parse a TCP segment and keep only traffic for monitored ports.
///
/// The payload remains shared through `Bytes::slice()`, so no extra memcpy is needed.
#[inline(always)]
fn parse_tcp(
    data: Bytes,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    port_bitmap: &PortBitmap,
) -> Option<RawpacketInfo> {
    // Fast-fail before touching any header fields.
    if data.len() < 20 {
        return None;
    }

    // Read ports directly from the fixed TCP header positions.
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    // Preserve sequence and acknowledgment numbers for stream reassembly.
    let tcp_seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let tcp_ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    // Preserve TCP flags so the session layer can handle opens and closes.
    let tcp_flags = data[13];

    // Check both ports in a single bitmap lookup.
    let (dst_match, src_match) = port_bitmap.contains_either(dst_port, src_port);

    // Infer direction from the monitored endpoint.
    let (protocol, direction) = if dst_match {
        (Protocol::from_port(dst_port), Direction::Outbound)
    } else if src_match {
        (Protocol::from_port(src_port), Direction::Inbound)
    } else {
        return None;
    };

    // Data offset is encoded in 32-bit words.
    let data_offset_field = data[12] >> 4;
    if data_offset_field < 5 {
        return None;
    }
    let data_offset = (data_offset_field as usize) << 2; // * 4

    if data.len() <= data_offset {
        // Control packets may legitimately carry no payload.
        // Keep SYN/FIN/RST so the session layer can update connection state.
        const TCP_SYN: u8 = 0x02;
        const TCP_FIN: u8 = 0x01;
        const TCP_RST: u8 = 0x04;
        if (tcp_flags & (TCP_SYN | TCP_FIN | TCP_RST)) != 0 {
            return Some(RawpacketInfo {
                src_ip,
                dst_ip,
                payload: Bytes::new(),
                src_port,
                dst_port,
                protocol,
                direction,
                tcp_seq,
                tcp_ack,
                tcp_flags,
            });
        }
        return None;
    }

    let payload_len = data.len() - data_offset;
    if payload_len > MAX_PAYLOAD_SIZE {
        return None;
    }

    // Zero-copy payload slice backed by the original frame allocation.
    // The underlying memory stays shared with the frame `Bytes` from the capture loop.
    let payload = data.slice(data_offset..);

    Some(RawpacketInfo {
        src_ip,
        dst_ip,
        payload,
        src_port,
        dst_port,
        protocol,
        direction,
        tcp_seq,
        tcp_ack,
        tcp_flags,
    })
}
