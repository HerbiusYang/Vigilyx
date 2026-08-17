//! Packet parsing utilities for the capture pipeline.
//!
//! Parses Ethernet/IPv4/IPv6/TCP frames, including VLAN tags.

use super::port_bitmap::PortBitmap;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use tracing::{debug, warn};
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

/// A bounded IPv4 fragment reassembler used by the capture thread.
///
/// Fragmented IPv4 packets do not carry TCP ports in every fragment.  The old
/// parser therefore had to drop them, and the BPF filter could discard all
/// non-first fragments before userspace ever saw them.  Reassembly is kept
/// local to each capture loop so it does not add locking to the packet hot
/// path.  Every bound below is deliberate: an attacker must not be able to
/// turn IP fragmentation into an unbounded allocation or an indefinitely held
/// flow.
const IPV4_FRAGMENT_MAX_ENTRIES: usize = 1024;
const IPV4_FRAGMENT_MAX_BYTES: usize = 16 * 1024 * 1024;
const IPV4_FRAGMENT_MAX_DATAGRAM_BYTES: usize = 65_535;
const IPV4_FRAGMENT_TTL_SECS: u64 = 30;
const IPV4_FRAGMENT_SWEEP_SECS: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Ipv4FragmentKey {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    identification: u16,
}

#[derive(Debug)]
struct Ipv4FragmentPiece {
    offset: usize,
    data: Bytes,
}

#[derive(Debug, Default)]
struct Ipv4FragmentEntry {
    pieces: Vec<Ipv4FragmentPiece>,
    final_len: Option<usize>,
    buffered_bytes: usize,
    last_seen: Option<Instant>,
}

/// Stateful, bounded reassembly context.  One instance must be retained for
/// the lifetime of a capture loop; constructing one per packet would defeat
/// reassembly and silently reintroduce the old blind spot.
pub(super) struct Ipv4FragmentReassembler {
    entries: HashMap<Ipv4FragmentKey, Ipv4FragmentEntry>,
    buffered_bytes: usize,
    last_sweep: Instant,
}

impl Default for Ipv4FragmentReassembler {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            buffered_bytes: 0,
            last_sweep: Instant::now(),
        }
    }
}

impl Ipv4FragmentReassembler {
    fn evict_expired(&mut self, now: Instant) {
        if now.duration_since(self.last_sweep) < Duration::from_secs(IPV4_FRAGMENT_SWEEP_SECS) {
            return;
        }
        self.last_sweep = now;

        let ttl = Duration::from_secs(IPV4_FRAGMENT_TTL_SECS);
        let mut expired = Vec::new();
        for (key, entry) in &self.entries {
            if entry
                .last_seen
                .is_some_and(|last_seen| now.duration_since(last_seen) > ttl)
            {
                expired.push(*key);
            }
        }
        for key in expired {
            if let Some(entry) = self.entries.remove(&key) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(entry.buffered_bytes);
                debug!(
                    src = %key.src,
                    dst = %key.dst,
                    identification = key.identification,
                    buffered_bytes = entry.buffered_bytes,
                    "Expired incomplete IPv4 fragment datagram"
                );
            }
        }
    }

    fn evict_oldest_until_capacity(&mut self, additional_bytes: usize, protected: Ipv4FragmentKey) {
        while (self.entries.len() >= IPV4_FRAGMENT_MAX_ENTRIES
            || self.buffered_bytes.saturating_add(additional_bytes) > IPV4_FRAGMENT_MAX_BYTES)
            && self.entries.len() > 1
        {
            let oldest = self
                .entries
                .iter()
                .filter(|entry| entry.0 != &protected)
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(key, _)| *key);
            let Some(oldest) = oldest else {
                break;
            };
            if let Some(entry) = self.entries.remove(&oldest) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(entry.buffered_bytes);
                warn!(
                    src = %oldest.src,
                    dst = %oldest.dst,
                    identification = oldest.identification,
                    buffered_bytes = entry.buffered_bytes,
                    entries = self.entries.len(),
                    "Evicted incomplete IPv4 fragment datagram at reassembly capacity"
                );
            }
        }
    }

    fn remove_entry(&mut self, key: Ipv4FragmentKey) -> Option<Ipv4FragmentEntry> {
        let entry = self.entries.remove(&key)?;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(entry.buffered_bytes);
        Some(entry)
    }

    /// Return only byte ranges not already covered by an earlier fragment.
    /// This is first-seen-wins overlap handling: retransmitted/overlapping
    /// bytes cannot rewrite content that was already accepted.
    fn uncovered_ranges(
        entry: &Ipv4FragmentEntry,
        offset: usize,
        payload: &Bytes,
    ) -> Vec<(usize, Bytes)> {
        let end = offset + payload.len();
        let mut cursor = offset;
        let mut uncovered = Vec::new();

        for piece in &entry.pieces {
            let piece_end = piece.offset + piece.data.len();
            if piece_end <= cursor {
                continue;
            }
            if piece.offset >= end {
                break;
            }
            if piece.offset > cursor {
                let stop = piece.offset.min(end);
                uncovered.push((cursor, payload.slice(cursor - offset..stop - offset)));
            }
            cursor = cursor.max(piece_end.min(end));
            if cursor >= end {
                break;
            }
        }

        if cursor < end {
            uncovered.push((cursor, payload.slice(cursor - offset..end - offset)));
        }
        uncovered
    }

    fn is_complete(entry: &Ipv4FragmentEntry) -> bool {
        let Some(final_len) = entry.final_len else {
            return false;
        };
        let mut cursor = 0usize;
        for piece in &entry.pieces {
            if piece.offset != cursor {
                return false;
            }
            cursor += piece.data.len();
        }
        cursor == final_len
    }

    fn assemble(entry: Ipv4FragmentEntry) -> Option<Bytes> {
        let final_len = entry.final_len?;
        let mut output = BytesMut::with_capacity(final_len);
        for piece in entry.pieces {
            output.extend_from_slice(&piece.data);
        }
        Some(output.freeze())
    }

    /// Add one IPv4 payload fragment and return a complete TCP datagram when
    /// all byte ranges from offset zero to the terminal fragment are present.
    fn insert(
        &mut self,
        key: Ipv4FragmentKey,
        offset: usize,
        more_fragments: bool,
        payload: Bytes,
    ) -> Option<Bytes> {
        if payload.is_empty() || offset >= IPV4_FRAGMENT_MAX_DATAGRAM_BYTES {
            return None;
        }
        let end = offset.checked_add(payload.len())?;
        if end > IPV4_FRAGMENT_MAX_DATAGRAM_BYTES {
            let _ = self.remove_entry(key);
            return None;
        }

        self.evict_expired(Instant::now());

        // Remove/reinsert the entry to keep all capacity accounting in one
        // place and avoid holding a map borrow while evicting other entries.
        let mut entry = self.entries.remove(&key).unwrap_or_default();
        self.buffered_bytes = self.buffered_bytes.saturating_sub(entry.buffered_bytes);

        if let Some(final_len) = entry.final_len
            && (end > final_len || (!more_fragments && final_len != end))
        {
            warn!(
                src = %key.src,
                dst = %key.dst,
                identification = key.identification,
                existing_final_len = final_len,
                fragment_end = end,
                "Discarded inconsistent IPv4 fragment datagram"
            );
            return None;
        }
        if !more_fragments {
            if entry
                .pieces
                .iter()
                .any(|piece| piece.offset + piece.data.len() > end)
            {
                warn!(
                    src = %key.src,
                    dst = %key.dst,
                    identification = key.identification,
                    fragment_end = end,
                    "Discarded IPv4 fragment datagram whose terminal length conflicts with buffered bytes"
                );
                return None;
            }
            entry.final_len = Some(end);
        }

        let uncovered = Self::uncovered_ranges(&entry, offset, &payload);
        let additional_bytes: usize = uncovered.iter().map(|(_, bytes)| bytes.len()).sum();
        if additional_bytes > IPV4_FRAGMENT_MAX_BYTES {
            return None;
        }
        self.evict_oldest_until_capacity(additional_bytes, key);
        if self.entries.len() >= IPV4_FRAGMENT_MAX_ENTRIES
            || self.buffered_bytes.saturating_add(additional_bytes) > IPV4_FRAGMENT_MAX_BYTES
        {
            warn!(
                src = %key.src,
                dst = %key.dst,
                identification = key.identification,
                additional_bytes,
                entries = self.entries.len(),
                buffered_bytes = self.buffered_bytes,
                "Dropped IPv4 fragment because reassembly capacity is exhausted"
            );
            return None;
        }

        for (piece_offset, piece_data) in uncovered {
            entry.buffered_bytes += piece_data.len();
            entry.pieces.push(Ipv4FragmentPiece {
                offset: piece_offset,
                data: piece_data,
            });
        }
        entry.pieces.sort_unstable_by_key(|piece| piece.offset);
        entry.last_seen = Some(Instant::now());
        self.buffered_bytes += entry.buffered_bytes;

        if Self::is_complete(&entry) {
            let entry_bytes = entry.buffered_bytes;
            let assembled = Self::assemble(entry);
            self.buffered_bytes = self.buffered_bytes.saturating_sub(entry_bytes);
            return assembled;
        }

        self.entries.insert(key, entry);
        None
    }
}

impl IpAddr {
    /// True for `0.0.0.0` / `::` — never a legitimate packet destination.
    pub fn is_unspecified(&self) -> bool {
        match self {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        }
    }
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
#[allow(dead_code)]
#[inline]
pub(super) fn parse_raw_packet(frame: Bytes, port_bitmap: &PortBitmap) -> Option<RawpacketInfo> {
    let mut fragments = Ipv4FragmentReassembler::default();
    parse_raw_packet_with_reassembler(frame, port_bitmap, &mut fragments)
}

/// Parse a raw packet with a long-lived IPv4 fragment context.
#[inline]
pub(super) fn parse_raw_packet_with_reassembler(
    frame: Bytes,
    port_bitmap: &PortBitmap,
    fragments: &mut Ipv4FragmentReassembler,
) -> Option<RawpacketInfo> {
    parse_frame(frame, port_bitmap, fragments)
}

/// Fast-path packet parser with early branch pruning.
///
/// The capture loop already copied the frame into `Bytes`; this path only uses `slice()`.
#[allow(dead_code)]
#[inline]
pub(super) fn parse_packet(frame: Bytes, port_bitmap: &PortBitmap) -> Option<RawpacketInfo> {
    let mut fragments = Ipv4FragmentReassembler::default();
    parse_packet_with_reassembler(frame, port_bitmap, &mut fragments)
}

/// Fast-path parser with a long-lived IPv4 fragment context.
#[inline]
pub(super) fn parse_packet_with_reassembler(
    frame: Bytes,
    port_bitmap: &PortBitmap,
    fragments: &mut Ipv4FragmentReassembler,
) -> Option<RawpacketInfo> {
    parse_frame(frame, port_bitmap, fragments)
}

#[inline]
fn parse_frame(
    frame: Bytes,
    port_bitmap: &PortBitmap,
    fragments: &mut Ipv4FragmentReassembler,
) -> Option<RawpacketInfo> {
    if frame.len() < 34 {
        // Ethernet + minimum IPv4 header.  Non-first IPv4 fragments do not
        // contain a TCP header, so requiring 20 more bytes here would drop
        // valid fragments before the reassembler can see them.
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

    // Require enough bytes for the minimum IP header.  Non-first IPv4
    // fragments do not contain a TCP header, so the transport minimum is
    // checked by the protocol-specific parser after reassembly.
    if frame.len() < ip_header_start + 20 {
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
        parse_ipv4(ip_data, port_bitmap, fragments)
    } else {
        parse_ipv6(ip_data, port_bitmap)
    }
}

/// Parse an IPv4 packet and extract the TCP payload for monitored ports.
#[inline]
fn parse_ipv4(
    data: Bytes,
    port_bitmap: &PortBitmap,
    fragments: &mut Ipv4FragmentReassembler,
) -> Option<RawpacketInfo> {
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

    let protocol = data[9];

    // Only TCP traffic is relevant to the mail and HTTP parsers.  Filtering
    // before fragment bookkeeping also prevents arbitrary IP protocols from
    // consuming the bounded reassembly budget.
    if protocol != 6 {
        return None;
    }

    // Reassemble fragmented IPv4 payloads before looking for TCP ports.  A
    // non-first fragment has no TCP header of its own and cannot be classified
    // by the port bitmap.
    let flags_offset = u16::from_be_bytes([data[6], data[7]]);
    let more_fragments = (flags_offset & 0x2000) != 0;
    let fragment_offset = usize::from(flags_offset & 0x1FFF) * 8;
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    if more_fragments || fragment_offset > 0 {
        let key = Ipv4FragmentKey {
            src: src_ip,
            dst: dst_ip,
            protocol,
            identification: u16::from_be_bytes([data[4], data[5]]),
        };
        let tcp_data = fragments.insert(
            key,
            fragment_offset,
            more_fragments,
            data.slice(ihl..total_length),
        )?;
        return parse_tcp(
            tcp_data,
            IpAddr::V4(src_ip),
            IpAddr::V4(dst_ip),
            port_bitmap,
        );
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
    //
    // When BOTH ports are monitored (e.g. relay-to-relay SMTP between 25 and
    // 2525/587), preferring dst_match unconditionally splits one connection into
    // two one-way sessions: the reply packet (src=monitored port) is attributed
    // to a different flow. Resolve the ambiguity deterministically:
    // 1. A bare SYN (SYN without ACK) comes from the client.
    // 2. A SYN+ACK comes from the server.
    // 3. Otherwise the higher (ephemeral) port is the client side.
    // 4. Exact port tie without SYN: keep the historic dst_match preference.
    const TCP_SYN_FLAG: u8 = 0x02;
    const TCP_ACK_FLAG: u8 = 0x10;
    let (protocol, direction) = if dst_match && src_match {
        let syn = (tcp_flags & TCP_SYN_FLAG) != 0;
        let ack = (tcp_flags & TCP_ACK_FLAG) != 0;
        if syn && !ack {
            (Protocol::from_port(dst_port), Direction::Outbound)
        } else if syn && ack {
            (Protocol::from_port(src_port), Direction::Inbound)
        } else if src_port > dst_port {
            (Protocol::from_port(dst_port), Direction::Outbound)
        } else if dst_port > src_port {
            (Protocol::from_port(src_port), Direction::Inbound)
        } else {
            (Protocol::from_port(dst_port), Direction::Outbound)
        }
    } else if dst_match {
        (Protocol::from_port(dst_port), Direction::Outbound)
    } else if src_match {
        (Protocol::from_port(src_port), Direction::Inbound)
    } else {
        return None;
    };

    // A malformed or tunneled packet can carry an unspecified destination
    // address (IPv6 `::` / IPv4 `0.0.0.0`). A real server never sends replies
    // to such an address; if the packet were still classified Inbound from its
    // source port, every later packet of the flow would inherit the locked
    // wrong direction and the session attribution breaks. Demote to Outbound.
    let direction = if direction == Direction::Inbound && dst_ip.is_unspecified() {
        Direction::Outbound
    } else {
        direction
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TCP segment (20-byte header, no options) with payload.
    fn tcp_segment(src_port: u16, dst_port: u16, tcp_flags: u8, payload: &[u8]) -> Bytes {
        let mut buf = Vec::with_capacity(20 + payload.len());
        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf.extend_from_slice(&1000u32.to_be_bytes()); // seq
        buf.extend_from_slice(&0u32.to_be_bytes()); // ack
        buf.push(5 << 4); // data offset = 5 words
        buf.push(tcp_flags);
        buf.extend_from_slice(&8192u16.to_be_bytes()); // window
        buf.extend_from_slice(&0u16.to_be_bytes()); // checksum
        buf.extend_from_slice(&0u16.to_be_bytes()); // urgent
        buf.extend_from_slice(payload);
        Bytes::from(buf)
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn ethernet_ipv4_fragment(
        payload: &[u8],
        identification: u16,
        fragment_offset: usize,
        more_fragments: bool,
    ) -> Bytes {
        assert_eq!(fragment_offset % 8, 0);
        let mut frame = vec![0u8; 14 + 20 + payload.len()];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        let ip = &mut frame[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        ip[4..6].copy_from_slice(&identification.to_be_bytes());
        let mut flags_offset = (fragment_offset / 8) as u16;
        if more_fragments {
            flags_offset |= 0x2000;
        }
        ip[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        ip[8] = 64;
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        ip[20..].copy_from_slice(payload);
        Bytes::from(frame)
    }

    #[test]
    fn ipv4_fragments_are_reassembled_before_tcp_port_classification() {
        let bitmap = PortBitmap::from_ports(&[25]);
        let tcp = tcp_segment(51000, 25, 0x18, b"fragmented smtp payload");
        let split = 24; // 8-byte aligned; leaves an undersized non-first frame.
        let first = ethernet_ipv4_fragment(&tcp[..split], 0x4242, 0, true);
        let second = ethernet_ipv4_fragment(&tcp[split..], 0x4242, split, false);
        let mut reassembler = Ipv4FragmentReassembler::default();

        assert!(parse_packet_with_reassembler(first, &bitmap, &mut reassembler).is_none());
        let parsed = parse_packet_with_reassembler(second, &bitmap, &mut reassembler)
            .expect("complete IPv4 datagram should be parsed");
        assert_eq!(parsed.src_port, 51000);
        assert_eq!(parsed.dst_port, 25);
        assert_eq!(parsed.payload.as_ref(), b"fragmented smtp payload");
    }

    #[test]
    fn ipv4_fragments_can_arrive_out_of_order() {
        let bitmap = PortBitmap::from_ports(&[25]);
        let tcp = tcp_segment(51001, 25, 0x18, b"out of order");
        let split = 24;
        let first = ethernet_ipv4_fragment(&tcp[..split], 0x4343, 0, true);
        let second = ethernet_ipv4_fragment(&tcp[split..], 0x4343, split, false);
        let mut reassembler = Ipv4FragmentReassembler::default();

        assert!(parse_packet_with_reassembler(second, &bitmap, &mut reassembler).is_none());
        let parsed = parse_packet_with_reassembler(first, &bitmap, &mut reassembler)
            .expect("out-of-order fragments should be reassembled");
        assert_eq!(parsed.payload.as_ref(), b"out of order");
    }

    #[test]
    fn ipv4_fragment_overlap_is_first_seen_wins() {
        let bitmap = PortBitmap::from_ports(&[25]);
        let tcp = tcp_segment(51002, 25, 0x18, b"overlap-safe");
        let first = ethernet_ipv4_fragment(&tcp[..24], 0x4444, 0, true);
        let mut overlapping = tcp[16..].to_vec();
        overlapping[..8].fill(0xEE);
        let second = ethernet_ipv4_fragment(&overlapping, 0x4444, 16, false);
        let mut reassembler = Ipv4FragmentReassembler::default();

        assert!(parse_packet_with_reassembler(first, &bitmap, &mut reassembler).is_none());
        let parsed = parse_packet_with_reassembler(second, &bitmap, &mut reassembler)
            .expect("overlapping fragments should still produce one datagram");
        assert_eq!(parsed.payload.as_ref(), b"overlap-safe");
    }

    #[test]
    fn single_match_direction_unchanged() {
        let bitmap = PortBitmap::from_ports(&[25]);
        // Forward: ephemeral -> 25 is Outbound (client -> server).
        let fwd = parse_tcp(
            tcp_segment(51000, 25, 0x18, b"EHLO x\r\n"),
            v4(10, 0, 0, 1),
            v4(10, 0, 0, 2),
            &bitmap,
        )
        .expect("forward packet parsed");
        assert_eq!(fwd.direction, Direction::Outbound);
        assert_eq!(fwd.protocol, Protocol::Smtp);

        // Reply: 25 -> ephemeral is Inbound (server -> client).
        let back = parse_tcp(
            tcp_segment(25, 51000, 0x18, b"250 OK\r\n"),
            v4(10, 0, 0, 2),
            v4(10, 0, 0, 1),
            &bitmap,
        )
        .expect("reply packet parsed");
        assert_eq!(back.direction, Direction::Inbound);
    }

    #[test]
    fn both_ports_monitored_data_packets_keep_consistent_direction() {
        // Relay-to-relay: both 25 and 587 monitored. The ephemeral side (587
        // here stands in as the "higher" port) must be the client for BOTH
        // directions, otherwise the connection splits into two one-way sessions.
        let bitmap = PortBitmap::from_ports(&[25, 587]);

        let fwd = parse_tcp(
            tcp_segment(587, 25, 0x18, b"MAIL FROM:<a@b.c>\r\n"),
            v4(10, 0, 0, 1),
            v4(10, 0, 0, 2),
            &bitmap,
        )
        .expect("forward parsed");
        assert_eq!(fwd.direction, Direction::Outbound);
        assert_eq!(fwd.protocol, Protocol::Smtp);

        let back = parse_tcp(
            tcp_segment(25, 587, 0x18, b"250 OK\r\n"),
            v4(10, 0, 0, 2),
            v4(10, 0, 0, 1),
            &bitmap,
        )
        .expect("reply parsed");
        assert_eq!(
            back.direction,
            Direction::Inbound,
            "reply must map to the reverse direction of the same flow"
        );
        assert_eq!(back.protocol, Protocol::Smtp);
    }

    #[test]
    fn both_ports_monitored_syn_and_syn_ack_determine_direction() {
        // Equal monitored ports (25 <-> 25): port comparison ties, so the SYN
        // handshake must decide who is the client.
        let bitmap = PortBitmap::from_ports(&[25]);

        let syn = parse_tcp(
            tcp_segment(25, 25, 0x02, b""),
            v4(10, 0, 0, 1),
            v4(10, 0, 0, 2),
            &bitmap,
        );
        // Empty payload control packet is still returned for state tracking.
        let syn = syn.expect("SYN control packet kept");
        assert_eq!(syn.direction, Direction::Outbound);

        let syn_ack = parse_tcp(
            tcp_segment(25, 25, 0x12, b""),
            v4(10, 0, 0, 2),
            v4(10, 0, 0, 1),
            &bitmap,
        )
        .expect("SYN+ACK control packet kept");
        assert_eq!(syn_ack.direction, Direction::Inbound);
    }

    #[test]
    fn both_ports_monitored_syn_direction_wins_over_port_heuristic() {
        // A server listening on 2525 connecting OUT to port 25: SYN decides.
        let bitmap = PortBitmap::from_ports(&[25, 2525]);
        let syn = parse_tcp(
            tcp_segment(25, 2525, 0x02, b""),
            v4(10, 0, 0, 9),
            v4(10, 0, 0, 8),
            &bitmap,
        )
        .expect("SYN parsed");
        // src=25, dst=2525: port heuristic alone would pick dst>higher as client,
        // but the bare SYN proves src is the client.
        assert_eq!(syn.direction, Direction::Outbound);
        assert_eq!(syn.protocol, Protocol::Smtp);
    }

    #[test]
    fn unspecified_dst_address_not_locked_inbound() {
        // Packets with an unspecified destination (IPv6 `::` / IPv4 `0.0.0.0`)
        // cannot be genuine server replies; classifying them Inbound from the
        // source port would lock the whole flow to the wrong direction.
        let bitmap = PortBitmap::from_ports(&[25]);

        let v6 = parse_tcp(
            tcp_segment(25, 2525, 0x18, b"250 ok\r\n"),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            &bitmap,
        )
        .expect("v6 packet parsed");
        assert_eq!(v6.direction, Direction::Outbound);

        let v4_pkt = parse_tcp(
            tcp_segment(25, 2525, 0x18, b"250 ok\r\n"),
            v4(10, 0, 0, 20),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            &bitmap,
        )
        .expect("v4 packet parsed");
        assert_eq!(v4_pkt.direction, Direction::Outbound);

        // Sanity: a normal server reply with a real destination stays Inbound.
        let normal = parse_tcp(
            tcp_segment(25, 2525, 0x18, b"250 ok\r\n"),
            v4(10, 0, 0, 20),
            v4(10, 0, 0, 10),
            &bitmap,
        )
        .expect("normal reply parsed");
        assert_eq!(normal.direction, Direction::Inbound);
    }
}
