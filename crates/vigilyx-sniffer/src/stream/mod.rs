//! TCP StreamreassembleModule

//! Same1 TCP Connectionof datapacketreassemble CompletedataStream.
//! emailContent,due to emailContent TCP packet.

//! Performance optimizations:
//! - Use BTreeMap According toSequenceNumber (O(log n))
//! - AllocatebufferDistrict MemoryAllocate
//! - Set largeStreamsizePrevent memory exhaustion attacks


//! - Process TCP SequenceNumber (32bit Number 0xFFFFFFFF -> 0x00000000)
//! - Process,, datapacket

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use rustc_hash::FxHasher;
use std::collections::BTreeMap;
use std::hash::BuildHasherDefault;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, warn};


// TCP Sequence number comparison (Process)


/// TCP Sequence number comparison: a <b (Consider wrap-around)
///
/// TCP SequenceNumber 32 bit Number, From 0xFFFFFFFF 0x00000000.
/// Use Number value:if (a - b) of Numbervalue <0, a <b
#[inline(always)]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// TCP Sequence number comparison: a <= b (Consider wrap-around)
#[inline(always)]
fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

/// TCP Sequence number comparison: a> b (Consider wrap-around)
#[inline(always)]
fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}

/// TCP Sequence number comparison: a>= b (Consider wrap-around)
#[inline(always)]
fn seq_ge(a: u32, b: u32) -> bool {
    a == b || seq_gt(a, b)
}

/// Max single stream size (50MB - HTTP large file upload needs enough room for complete body)
const MAX_STREAM_SIZE: usize = 50 * 1024 * 1024;

/// SEC: Global memory budget for all TCP reassembly buffers (2 GB).
/// Prevents OOM when many large/slow streams accumulate simultaneously.
const GLOBAL_REASSEMBLY_BUDGET: u64 = 2 * 1024 * 1024 * 1024;

/// largepacketCount (Stream - 50MB / ~1400 bytes MTU 37500 packet)
const MAX_PACKETS_PER_STREAM: usize = 50_000;

/// Streamtimeout duration (15minute)
const STREAM_TIMEOUT_SECS: u64 = 900;

/// large StreamCount
const MAX_ACTIVE_STREAMS: usize = 50_000;

type FxDashMap<K, V> = DashMap<K, V, BuildHasherDefault<FxHasher>>;

/// TCP Stream (4Yuan)
#[derive(Clone, Copy, Hash, Eq, PartialEq, Debug)]
pub struct StreamId {
   /// source IP (store)
    pub src_ip: u128,
   /// Target IP
    pub dst_ip: u128,
   /// sourcePort
    pub src_port: u16,
   /// TargetPort
    pub dst_port: u16,
}

impl StreamId {
    pub fn new(src_ip: u128, dst_ip: u128, src_port: u16, dst_port: u16) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }

   /// Get Stream ID (Used for tracing)
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

/// TCP dataSegment
#[derive(Clone)]
pub struct TcpSegment {
   /// SequenceNumber
    pub seq: u32,
   /// data
    pub data: Bytes,
   /// whether FIN packet
    pub is_fin: bool,
   /// whether RST packet
    pub is_rst: bool,
   /// Receivetimestamp
    pub timestamp: Instant,
}

/// Single-direction TCP stream
pub struct TcpHalfStream {
   /// Segments ordered by sequence number
    segments: BTreeMap<u32, TcpSegment>,
   /// Earliest sequence number seen
    first_seq: Option<u32>,
   /// Next expected sequence number (end of reassembled data)
    next_seq: Option<u32>,
   /// Sequence number of the first byte in `reassembled`
    reassembled_start_seq: Option<u32>,
   /// Reassembled contiguous data
    reassembled: BytesMut,
   /// Total received bytes
    pub total_bytes: usize,
   /// Packet count
    packet_count: usize,
   /// Last activity timestamp
    last_activity: Instant,
   /// Whether stream is closed (FIN/RST received)
    is_closed: bool,
   /// Cumulative bytes prepended to reassembled buffer (for offset adjustment by caller)
    pub prepend_shift: usize,
   /// FIX #4: Number of bytes skipped due to gap tolerance (stream is not fully intact)
    pub gap_bytes_skipped: usize,
}

impl TcpHalfStream {
    pub fn new() -> Self {
        Self {
            segments: BTreeMap::new(),
            first_seq: None,
            next_seq: None,
            reassembled_start_seq: None,
            reassembled: BytesMut::with_capacity(4096),
            total_bytes: 0,
            packet_count: 0,
            last_activity: Instant::now(),
            is_closed: false,
            prepend_shift: 0,
            gap_bytes_skipped: 0,
        }
    }

   /// AdddataSegment
    pub fn add_segment(&mut self, segment: TcpSegment) -> Result<(), StreamError> {
       // SecurityCheck
        if self.total_bytes + segment.data.len() > MAX_STREAM_SIZE {
            warn!(
                "TCP Stream超出largesmalllimit: {} + {} > {}",
                self.total_bytes,
                segment.data.len(),
                MAX_STREAM_SIZE
            );
            return Err(StreamError::MaxSizeExceeded);
        }
        if self.packet_count >= MAX_PACKETS_PER_STREAM {
            warn!(
                "TCP Stream超出packet数limit: {} >= {}",
                self.packet_count, MAX_PACKETS_PER_STREAM
            );
            return Err(StreamError::MaxpacketsExceeded);
        }

        self.last_activity = segment.timestamp;
       // FIX #5: Don't increment packet_count yet - wait until after dedup checks
       // to avoid retransmits/ACKs exhausting MAX_PACKETS_PER_STREAM prematurely.

       // Process FIN/RST
        if segment.is_fin || segment.is_rst {
            debug!(
                "TCP StreamCloseSignal: FIN={} RST={} seq={}",
                segment.is_fin, segment.is_rst, segment.seq
            );
            self.is_closed = true;
        }

       // datapacket (if ACK) hops
        if segment.data.is_empty() {
            return Ok(());
        }

       // SegmentofEndSequenceNumber
        let seg_start = segment.seq;
        let seg_end = seg_start.wrapping_add(segment.data.len() as u32);

       // Update first_seq (GetReceivedof smallSequenceNumber)
        match self.first_seq {
            None => {
                debug!(
                    "TCP Streaminitialize: 首packet seq={}, len={}",
                    seg_start,
                    segment.data.len()
                );
                self.first_seq = Some(seg_start);
                self.next_seq = Some(seg_start);
            }
            Some(current_first) => {
                if seq_lt(seg_start, current_first) {
                    debug!(
                        "TCP StreamUpdate起始点: first_seq {} -> {} (Received更早ofpacket)",
                        current_first, seg_start
                    );
                    self.first_seq = Some(seg_start);
                   // if not Startreassemble, Update next_seq
                    if self.reassembled.is_empty() {
                        self.next_seq = Some(seg_start);
                    }
                }
            }
        }

       // SAFETY: first_seq is set in push_data() on the first SYN packet.
       // If we reach here without a SYN, skip the packet gracefully.
        let first_seq = match self.first_seq {
            Some(s) => s,
            None => return Ok(()),
        };
        let next_seq = self.next_seq.unwrap_or(first_seq);

       // Use ofSequence number comparison (Process)
       // only When Segment first_seq first hops (of data, StreamStartfirst)
        if seq_le(seg_end, first_seq) {
            debug!(
                "hops完全旧ofpacket: seg=[{}, {}), first_seq={}",
                seg_start, seg_end, first_seq
            );
            return Ok(());
        }

       // FIX #1: Out-of-order first packet handling.
       // Only skip as duplicate if the segment is fully within the reassembled range.
       // Segments arriving BEFORE reassembled_start_seq contain data that was missed
       // due to worker thread race (later packet won DashMap lock first).
        if !self.reassembled.is_empty() && seq_le(seg_end, next_seq) {
            if let Some(rstart) = self.reassembled_start_seq {
                if seq_ge(seg_start, rstart) {
                   // Truly within already-reassembled range -> duplicate
                    return Ok(());
                }
               // Segment predates reassembly start -> late-arriving early packet.
               // Prepend the non-overlapping portion to reassembled buffer.
                let prepend_end = if seq_lt(seg_end, rstart) {
                    seg_end
                } else {
                    rstart
                };
                let prepend_len = prepend_end.wrapping_sub(seg_start) as usize;
                if prepend_len > 0 && prepend_len <= segment.data.len() {
                    let prepend_data = &segment.data[..prepend_len];
                    let mut new_buf =
                        BytesMut::with_capacity(prepend_data.len() + self.reassembled.len());
                    new_buf.extend_from_slice(prepend_data);
                    new_buf.extend_from_slice(&self.reassembled);
                    self.reassembled = new_buf;
                    self.reassembled_start_seq = Some(seg_start);
                    self.prepend_shift += prepend_len;
                    self.total_bytes += prepend_len;
                    debug!(
                        "Prepended {} bytes (seq={}) before reassembly start",
                        prepend_len, seg_start
                    );
                }
                return Ok(());
            }
            return Ok(());
        }

       // if Segment alreadyProcessDistrict,onlykeepNewdata
        let effective_start;
        let effective_data;
        if !self.reassembled.is_empty() && seq_lt(seg_start, next_seq) {
           // SegmentofStart next_seq first,Need/Require (Whenalready reassembledata)
            let skip = next_seq.wrapping_sub(seg_start) as usize;
            if skip >= segment.data.len() {
               // Segmentall data
                debug!(
                    "hops完全重叠packet: seq={}, len={}, next_seq={}",
                    seg_start,
                    segment.data.len(),
                    next_seq
                );
                return Ok(());
            }
            effective_start = next_seq;
            effective_data = segment.data.slice(skip..);
            debug!(
                "部分重叠packet裁剪: 原始 seq={} len={}, 裁剪后 seq={} len={}",
                seg_start,
                segment.data.len(),
                effective_start,
                effective_data.len()
            );
        } else {
            effective_start = seg_start;
           // Bytes::slice(..) is O(1) - just increments refcount, no memcpy
            effective_data = segment.data.slice(..);
        }

        debug!(
            "TCP 添AddSegment: seq={} len={} total_bytes={} packet_count={} next_seq={}",
            effective_start,
            effective_data.len(),
            self.total_bytes,
            self.packet_count,
            next_seq
        );

       // FIX #5: Increment counters AFTER dedup - only count genuinely new data
        self.total_bytes += effective_data.len();
        self.packet_count += 1;

       // UseValiddataCreateNewSegment
        let effective_segment = TcpSegment {
            seq: effective_start,
            data: effective_data,
            is_fin: segment.is_fin,
            is_rst: segment.is_rst,
            timestamp: segment.timestamp,
        };

       // Checkwhetheralreadystored SameSequenceNumberofSegment (Process)
        if let Some(existing) = self.segments.get(&effective_start)
            && existing.data.len() >= effective_segment.data.len()
        {
           // already long waitofSegment,hops
            debug!("hops较shortof重传packet: seq={}", effective_start);
            return Ok(());
        }

       // path: Segment Connect Add reassembled,hops BTreeMap
       // Item: 1) Segment equalsPeriod of 1SequenceNumber 2) not WaitProcessof Segment
       // 3) already Start reassemble (reassembled)
       // packet BTreeMap path,due to whether ofSegment
        let seg_len = effective_segment.data.len();
        if effective_start == next_seq && self.segments.is_empty() && !self.reassembled.is_empty() {
            self.reassembled.extend_from_slice(&effective_segment.data);
            self.next_seq = Some(effective_start.wrapping_add(seg_len as u32));
            debug!(
                "TCP 快速RoadPath: seq={} len={} next_seq={:?}",
                effective_start, seg_len, self.next_seq
            );
            return Ok(());
        }

       // Slow path: out-of-order -> BTreeMap cache
        self.segments.insert(effective_start, effective_segment);

       // Eagerly try to reassemble after inserting - critical for SMTP where
       // server responses (354) must be reassembled promptly. Without this,
       // gaps in the BTreeMap stall reassembly until get_data(), which may
       // never be called for the server stream direction.
        self.try_reassemble(false);

        debug!(
            "TCP segment added (slow path): pending_segments={} first_seq={:?} next_seq={:?}",
            self.segments.len(),
            self.first_seq,
            self.next_seq
        );

        Ok(())
    }

   /// reassemblecontiguousofdataSegment
   ///
   /// 1. From expected_seq StartlookupcontiguousofSegment
   /// 2. Process ofpacket (BTreeMap)
   /// 3. Process TCP SequenceNumber
    fn try_reassemble(&mut self, allow_gap_skip: bool) {
       // if not Startreassemble,From first_seq Start
       // if already Start,From next_seq
        let start_seq = if self.reassembled.is_empty() {
            self.first_seq
        } else {
            self.next_seq
        };

        let Some(mut expected_seq) = start_seq else {
            return;
        };

       // Track start point for first reassembly
        if self.reassembled.is_empty() {
            self.next_seq = Some(expected_seq);
            self.reassembled_start_seq = Some(expected_seq);
        }

       // reassembleofSegment
        let mut to_remove = Vec::new();
        let mut iterations = 0;
        const MAX_ITERATIONS: usize = 10000; // preventinfiniteLoop

        loop {
            iterations += 1;
            if iterations > MAX_ITERATIONS {
                warn!("TCP reassembleIteratecount多，MediumBreak/Judge");
                break;
            }

           // Exact match: lookup seq == expected_seq
            if let Some(segment) = self.segments.get(&expected_seq).cloned() {
                self.reassembled.extend_from_slice(&segment.data);
                expected_seq = expected_seq.wrapping_add(segment.data.len() as u32);
                to_remove.push(segment.seq);
                continue;
            }

           // Lossy gap tolerance is reserved for explicit final-flush callers.
           // During normal reassembly we must not advance over a gap, otherwise
           // a late packet from worker/batch reordering becomes impossible to
           // recover and is permanently treated as missing.
            if allow_gap_skip {
                let found_next = self.segments.range(expected_seq..).next().or_else(|| {
                   // FIX #5: Handle TCP sequence number wraparound.
                   // If expected_seq is near u32::MAX and segments wrap to low values,
                   // range(expected_seq..) won't find them. Check from 0.
                    if expected_seq > 0xF0000000 {
                        self.segments.range(..0x10000000).next()
                    } else {
                        None
                    }
                });
                if let Some((&next_seg_seq, _)) = found_next {
                    let gap = next_seg_seq.wrapping_sub(expected_seq) as usize;
                    if gap > 0 && gap <= 1500 {
                        self.gap_bytes_skipped += gap;
                        expected_seq = next_seg_seq;
                        continue;
                    }
                }
            }

           // O(log n) lookup: BTreeMap range for key <= expected_seq
            let mut found_segment: Option<(u32, usize)> = None;

           // range(..=expected_seq) Get key <= expected_seq ofSegment,Getlast1
            if let Some((&seg_seq, seg)) = self.segments.range(..=expected_seq).next_back() {
                let seg_end = seg_seq.wrapping_add(seg.data.len() as u32);
                if seq_le(seg_seq, expected_seq) && seq_lt(expected_seq, seg_end) {
                    let offset = expected_seq.wrapping_sub(seg_seq) as usize;
                    if offset < seg.data.len() {
                        found_segment = Some((seg_seq, offset));
                    }
                }
            }

           // : Process of TCP SequenceNumber (expected_seq <0x10000)
            if found_segment.is_none() && expected_seq < 0x10000 {
               // CheckHighSequenceNumberSegmentwhether
                if let Some((&seg_seq, seg)) = self.segments.range(0xFF000000..).next_back() {
                    let seg_end = seg_seq.wrapping_add(seg.data.len() as u32);
                    if seq_le(seg_seq, expected_seq) && seq_lt(expected_seq, seg_end) {
                        let offset = expected_seq.wrapping_sub(seg_seq) as usize;
                        if offset < seg.data.len() {
                            found_segment = Some((seg_seq, offset));
                        }
                    }
                }
            }

            match found_segment {
                Some((seg_seq, offset)) => {
                    let Some(seg) = self.segments.get(&seg_seq) else {
                        break; // segment evicted between lookup and access
                    };
                   // onlyGet expected_seq ofValid
                    let partial = seg.data.slice(offset..);
                    self.reassembled.extend_from_slice(&partial);
                    expected_seq = expected_seq.wrapping_add(partial.len() as u32);
                    to_remove.push(seg_seq);
                }
                None => {
                   // not find reassembleofSegment,possibly,waitWait packet
                    break;
                }
            }
        }

       // alreadyreassembleofSegment
        for seq in to_remove {
            self.segments.remove(&seq);
        }

        self.next_seq = Some(expected_seq);
    }

   /// Get reassembled length without triggering reassembly
    pub fn reassembled_len(&self) -> usize {
        self.reassembled.len()
    }

   /// Number of pending (not yet reassembled) segments
    pub fn pending_segments(&self) -> usize {
        self.segments.len()
    }

   /// First sequence number
    pub fn first_seq(&self) -> Option<u32> {
        self.first_seq
    }

   /// Next expected sequence number
    pub fn next_seq(&self) -> Option<u32> {
        self.next_seq
    }

   /// Getalreadyreassembleofdata (reassemble)
    pub fn get_data(&mut self) -> &[u8] {
        self.try_reassemble(false);
        &self.reassembled
    }

   /// Get reassembled data together with total skipped gap bytes.
    pub fn get_data_and_gap_bytes(&mut self) -> (&[u8], usize) {
        self.try_reassemble(false);
        let gap_bytes = self.gap_bytes_skipped;
        (&self.reassembled, gap_bytes)
    }

   /// Get reassembled data while allowing a final lossy 1-MSS gap skip.
    pub fn get_data_lossy(&mut self) -> &[u8] {
        self.try_reassemble(true);
        &self.reassembled
    }

   /// Get reassembled data together with skipped gap bytes in lossy mode.
    pub fn get_data_and_gap_bytes_lossy(&mut self) -> (&[u8], usize) {
        self.try_reassemble(true);
        let gap_bytes = self.gap_bytes_skipped;
        (&self.reassembled, gap_bytes)
    }

   /// Get alreadyreassembleofdata ()
    pub fn take_data(&mut self) -> Bytes {
        self.reassembled.split().freeze()
    }

   /// whetheralreadyTimeout
    pub fn is_timeout(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

   /// whetheralreadycomplete
    pub fn is_complete(&self) -> bool {
        self.is_closed && self.segments.is_empty()
    }
}

/// TCP Stream
pub struct TcpStream {
   /// client -> Servicehandler
    pub client_to_server: TcpHalfStream,
   /// Servicehandler -> client
    pub server_to_client: TcpHalfStream,
   /// Createtimestamp
    pub created_at: Instant,
   /// Stream ID
    pub id: StreamId,
}

impl TcpStream {
    pub fn new(id: StreamId) -> Self {
        Self {
            client_to_server: TcpHalfStream::new(),
            server_to_client: TcpHalfStream::new(),
            created_at: Instant::now(),
            id,
        }
    }

   /// AdddataSegment
    pub fn add_segment(
        &mut self,
        segment: TcpSegment,
        is_client_to_server: bool,
    ) -> Result<(), StreamError> {
        if is_client_to_server {
            self.client_to_server.add_segment(segment)
        } else {
            self.server_to_client.add_segment(segment)
        }
    }

   /// whetheralreadyTimeout
    pub fn is_timeout(&self, timeout: Duration) -> bool {
        self.client_to_server.is_timeout(timeout) && self.server_to_client.is_timeout(timeout)
    }

   /// whetheralreadycomplete
    pub fn is_complete(&self) -> bool {
        self.client_to_server.is_complete() || self.server_to_client.is_complete()
    }

   /// GetclientSendofdata (reassemble)
    pub fn get_client_data(&mut self) -> &[u8] {
        self.client_to_server.get_data()
    }

   /// GetServicehandlerSendofdata (reassemble)
    pub fn get_server_data(&mut self) -> &[u8] {
        self.server_to_client.get_data()
    }

   /// Total bytes across both directions (for global memory budget tracking)
    pub fn total_bytes(&self) -> usize {
        self.client_to_server.total_bytes + self.server_to_client.total_bytes
    }
}

/// StreamreassembleError
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum StreamError {
   /// largeStreamsize
    MaxSizeExceeded,
   /// largepacketCount
    MaxpacketsExceeded,
   /// large StreamCount
    MaxStreamsExceeded,
}

/// TCP Streamreassemblehandler
pub struct TcpStreamReassembler {
   /// Stream
    streams: FxDashMap<StreamId, TcpStream>,
   /// timeout duration
    timeout: Duration,
   /// SEC: Global byte counter for all reassembly buffers (CWE-770)
    global_bytes: AtomicU64,
}

impl TcpStreamReassembler {
    pub fn new() -> Self {
        Self {
            streams: DashMap::with_hasher(BuildHasherDefault::default()),
            timeout: Duration::from_secs(STREAM_TIMEOUT_SECS),
            global_bytes: AtomicU64::new(0),
        }
    }

   /// Process TCP dataSegment
   ///
   /// Parameter:
   /// - `stream_id`: Stream
   /// - `seq`: TCP SequenceNumber
   /// - `data`: data
   /// - `tcp_flags`: TCP (FIN=0x01, RST=0x04)
   /// - `is_client_to_server`: whether client Servicehandler
    pub fn process_segment(
        &self,
        stream_id: StreamId,
        seq: u32,
        data: Bytes,
        tcp_flags: u8,
        is_client_to_server: bool,
    ) -> Result<(), StreamError> {
       // Check StreamCount
        if self.streams.len() >= MAX_ACTIVE_STREAMS {
           // CleanupTimeoutStream
            self.cleanup_timeout_streams();
            if self.streams.len() >= MAX_ACTIVE_STREAMS {
                warn!("活跃StreamCount超限: {}", self.streams.len());
                return Err(StreamError::MaxStreamsExceeded);
            }
        }

       // SEC: Global memory budget check - reject new segments when over budget (CWE-770)
        let seg_len = data.len() as u64;
        if self.global_bytes.load(Ordering::Relaxed) + seg_len > GLOBAL_REASSEMBLY_BUDGET {
            self.cleanup_timeout_streams();
            if self.global_bytes.load(Ordering::Relaxed) + seg_len > GLOBAL_REASSEMBLY_BUDGET {
                warn!(
                    "TCP reassembly global budget exceeded ({} bytes), dropping segment",
                    self.global_bytes.load(Ordering::Relaxed)
                );
                return Err(StreamError::MaxSizeExceeded);
            }
        }

        let segment = TcpSegment {
            seq,
            data,
            is_fin: (tcp_flags & 0x01) != 0,
            is_rst: (tcp_flags & 0x04) != 0,
            timestamp: Instant::now(),
        };

       // Get CreateStream
        let mut entry = self.streams.entry(stream_id).or_insert_with(|| {
            debug!("New建Stream: {:?}", stream_id);
            TcpStream::new(stream_id)
        });

        let result = entry.add_segment(segment, is_client_to_server);
        if result.is_ok() {
            self.global_bytes.fetch_add(seg_len, Ordering::Relaxed);
        }
        result
    }

   /// GetStreamofreassembledata (reassemble)
    pub fn get_stream_data(&self, stream_id: &StreamId) -> Option<(Bytes, Bytes)> {
        self.streams.get_mut(stream_id).map(|mut stream| {
            (
                Bytes::copy_from_slice(stream.get_client_data()),
                Bytes::copy_from_slice(stream.get_server_data()),
            )
        })
    }

   /// Remove and return stream, updating global byte budget
    pub fn remove_stream(&self, stream_id: &StreamId) -> Option<TcpStream> {
        self.streams.remove(stream_id).map(|(_, stream)| {
            let stream_bytes = stream.total_bytes() as u64;
            let _ = self
                .global_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(stream_bytes))
                });
            stream
        })
    }

   /// CleanupTimeoutStream
    pub fn cleanup_timeout_streams(&self) -> usize {
        let mut removed = 0;
        let mut freed_bytes = 0u64;
        self.streams.retain(|_, stream| {
            if stream.is_timeout(self.timeout) {
                freed_bytes += stream.total_bytes() as u64;
                removed += 1;
                false
            } else {
                true
            }
        });
        if removed > 0 {
            let _ = self
                .global_bytes
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(freed_bytes))
                });
            debug!(
                "Cleaned up {} timeout streams, freed {} bytes",
                removed, freed_bytes
            );
        }
        removed
    }

   /// Get StreamCount
    pub fn active_stream_count(&self) -> usize {
        self.streams.len()
    }

   /// GetalreadycompleteofStream ID List
    pub fn get_completed_streams(&self) -> Vec<StreamId> {
        self.streams
            .iter()
            .filter(|entry| entry.is_complete())
            .map(|entry| *entry.key())
            .collect()
    }
}

impl Default for TcpStreamReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    
   // Sequence number comparisonfunctionTest
    

    #[test]
    fn test_seq_comparison_normal() {
       // Normal
        assert!(seq_lt(100, 200));
        assert!(!seq_lt(200, 100));
        assert!(!seq_lt(100, 100));

        assert!(seq_le(100, 200));
        assert!(seq_le(100, 100));
        assert!(!seq_le(200, 100));
    }

    #[test]
    fn test_seq_comparison_wraparound() {
       // SequenceNumber Test
       // When a Connect max, b Connect 0, a <b
        let near_max = 0xFFFFFF00u32;
        let near_zero = 0x00000100u32;

       // near_max <near_zero (due to)
        assert!(seq_lt(near_max, near_zero));
        assert!(!seq_lt(near_zero, near_max));

        
        assert!(seq_lt(0xFFFFFFFF, 0x00000000));
        assert!(seq_lt(0xFFFFFFFF, 0x00000001));
        assert!(seq_lt(0xFFFFFFFE, 0x00000000));
    }

    #[test]
    fn test_seq_comparison_half_space() {
       // TCP SequenceNumber of1 2^31 = 0x80000000
       // value [-2^31, 2^31) Range Valid

       // value <2^31,Normal
        assert!(seq_lt(0, 0x7FFFFFFF));
        assert!(!seq_lt(0x7FFFFFFF, 0));

       // value 2^31,
       // 0 - 0x80000000 = 0x80000000, i32 i32::MIN (-2147483648)
       // i32::MIN <0 true, seq_lt(0, 0x80000000) Return true
       // Linux of TCP Sequence number comparisonline 1
        assert!(seq_lt(0, 0x80000000));
       // 0x80000000 - 0 = 0x80000000, i32 i32::MIN
       // i32::MIN <0 true, seq_lt(0x80000000, 0) Return true
       // of,But TCP Medium
        assert!(seq_lt(0x80000000, 0));
    }

    
   // reassembleTest
    

    #[test]
    fn test_stream_reassembly_in_order() {
        let mut stream = TcpHalfStream::new();

       // According to Add
        stream
            .add_segment(TcpSegment {
                seq: 1000,
                data: Bytes::from_static(b"EHLO "),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

        stream
            .add_segment(TcpSegment {
                seq: 1005,
                data: Bytes::from_static(b"example.com\r\n"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

        assert_eq!(stream.get_data(), b"EHLO example.com\r\n");
    }

    #[test]
    fn test_stream_reassembly_out_of_order() {
        let mut stream = TcpHalfStream::new();

       // Add (After2packet)
        stream
            .add_segment(TcpSegment {
                seq: 1006,
                data: Bytes::from_static(b"world"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

       // After1packet
        stream
            .add_segment(TcpSegment {
                seq: 1000,
                data: Bytes::from_static(b"hello "),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

        assert_eq!(stream.get_data(), b"hello world");
    }

    #[test]
    fn test_stream_reassembly_duplicate() {
        let mut stream = TcpHalfStream::new();

       // Add packet
        stream
            .add_segment(TcpSegment {
                seq: 1000,
                data: Bytes::from_static(b"hello"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

       // Add packet (hops)
        stream
            .add_segment(TcpSegment {
                seq: 1000,
                data: Bytes::from_static(b"hello"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

       // Add packet
        stream
            .add_segment(TcpSegment {
                seq: 1005,
                data: Bytes::from_static(b" world"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

        assert_eq!(stream.get_data(), b"hello world");
    }

    #[test]
    fn test_stream_reassembly_overlap() {
        let mut stream = TcpHalfStream::new();

       // AddAfter1packet
        stream
            .add_segment(TcpSegment {
                seq: 1000,
                data: Bytes::from_static(b"hello"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

       // Add ofpacket ()
        stream
            .add_segment(TcpSegment {
                seq: 1003, // "lo"
                data: Bytes::from_static(b"lo world"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

        assert_eq!(stream.get_data(), b"hello world");
    }

    #[test]
    fn test_stream_reassembly_with_gap() {
        let mut stream = TcpHalfStream::new();

       // AddAfter1packet
        stream
            .add_segment(TcpSegment {
                seq: 1000,
                data: Bytes::from_static(b"hello"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

       // AddAfter3packet (hopsAfter2packet)
        stream
            .add_segment(TcpSegment {
                seq: 1011, 
                data: Bytes::from_static(b"world"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

       // Strict reassembly must stop at the gap so a late segment can still repair it.
        assert_eq!(stream.get_data(), b"hello");
        assert_eq!(stream.gap_bytes_skipped, 0);

       // Addmissingofpacket
        stream
            .add_segment(TcpSegment {
                seq: 1005,
                data: Bytes::from_static(b" nice "),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

       // Once the missing bytes arrive, the stream becomes fully contiguous again.
        assert_eq!(stream.get_data(), b"hello nice world");
    }

    #[test]
    fn test_stream_reassembly_lossy_gap_skip() {
        let mut stream = TcpHalfStream::new();

        stream
            .add_segment(TcpSegment {
                seq: 2000,
                data: Bytes::from_static(b"hello"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();
        stream
            .add_segment(TcpSegment {
                seq: 2011,
                data: Bytes::from_static(b"world"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

       // Explicit lossy mode preserves the old "skip <= 1 MSS" escape hatch for
       // final flushes where no more packets are expected.
        assert_eq!(stream.get_data_lossy(), b"helloworld");
        assert_eq!(stream.gap_bytes_skipped, 6);
    }

    #[test]
    fn test_stream_reassembly_wraparound() {
        let mut stream = TcpHalfStream::new();

       // SequenceNumberConnect largevalue
        let start_seq = 0xFFFFFFF0u32;

        stream
            .add_segment(TcpSegment {
                seq: start_seq,
                data: Bytes::from_static(b"before"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

       // SequenceNumber ofpacket
       // start_seq + 6 = 0xFFFFFFF6, + 6 more = 0xFFFFFFFC, + 4 = 0x00000000
        let after_wrap_seq = start_seq.wrapping_add(6); // 0xFFFFFFF6

        stream
            .add_segment(TcpSegment {
                seq: after_wrap_seq,
                data: Bytes::from_static(b" after"),
                is_fin: false,
                is_rst: false,
                timestamp: Instant::now(),
            })
            .unwrap();

        assert_eq!(stream.get_data(), b"before after");
    }

    
   // Use TcpStreamReassembler ofTest
    

    #[test]
    fn test_reassembler_basic() {
        let reassembler = TcpStreamReassembler::new();
        let stream_id = StreamId::new(0, 0, 12345, 25);

        reassembler
            .process_segment(stream_id, 1000, Bytes::from_static(b"EHLO "), 0, true)
            .unwrap();
        reassembler
            .process_segment(
                stream_id,
                1005,
                Bytes::from_static(b"example.com\r\n"),
                0,
                true,
            )
            .unwrap();

        let (client_data, _) = reassembler.get_stream_data(&stream_id).unwrap();
        assert_eq!(&client_data[..], b"EHLO example.com\r\n");
    }

    #[test]
    fn test_reassembler_bidirectional() {
        let reassembler = TcpStreamReassembler::new();
        let stream_id = StreamId::new(0, 0, 12345, 25);

       // clientSend
        reassembler
            .process_segment(stream_id, 1000, Bytes::from_static(b"CLIENT"), 0, true)
            .unwrap();

       // ServicehandlerResponse
        reassembler
            .process_segment(stream_id, 2000, Bytes::from_static(b"SERVER"), 0, false)
            .unwrap();

        let (client_data, server_data) = reassembler.get_stream_data(&stream_id).unwrap();
        assert_eq!(&client_data[..], b"CLIENT");
        assert_eq!(&server_data[..], b"SERVER");
    }
}
