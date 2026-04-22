//! pcapng Add Parsehandler

//! Parse pcapng File SegmentMediumofdatapacket:
//! - Section Header Block (SHB): Byte
//! - Interface Description Block (IDB): GetlinkType
//! - Enhanced packet Block (EPB): Extract data

use tracing::{debug, warn};

/// pcapng TypeConstant
const SHB_TYPE: u32 = 0x0A0D0D0A; // Section Header Block
const IDB_TYPE: u32 = 0x00000001; // Interface Description Block
const EPB_TYPE: u32 = 0x00000006; // Enhanced packet Block

/// Byte
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ByteOrder {
    LittleEndian,
    BigEndian,
}

/// Parse ofdatapacketInfo
#[allow(dead_code)]
pub struct Pcapngpacket {
    /// timestamp Highbit ()
    pub timestamp_high: u32,
    /// timestamp Lowbit ()
    pub timestamp_low: u32,
    /// datapacket data
    pub data: Vec<u8>,
}

/// pcapng Add Parsehandler
pub struct PcapngParser {
    byte_order: ByteOrder,
    link_type: u16,
    initialized: bool,
}

impl PcapngParser {
    /// CreateNewofParsehandler (Defaultsmall)
    pub fn new() -> Self {
        Self {
            byte_order: ByteOrder::LittleEndian,
            link_type: 0,
            initialized: false,
        }
    }

    /// whetheralreadyinitialize (alreadyParse SHB)
    #[allow(dead_code)]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// GetlinkType
    #[allow(dead_code)]
    pub fn link_type(&self) -> u16 {
        self.link_type
    }

    /// FromByteArrayreadGet u32
    fn read_u32(&self, data: &[u8]) -> u32 {
        match self.byte_order {
            ByteOrder::LittleEndian => u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            ByteOrder::BigEndian => u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        }
    }

    /// FromByteArrayreadGet u16
    fn read_u16(&self, data: &[u8]) -> u16 {
        match self.byte_order {
            ByteOrder::LittleEndian => u16::from_le_bytes([data[0], data[1]]),
            ByteOrder::BigEndian => u16::from_be_bytes([data[0], data[1]]),
        }
    }

    /// Parse pcapng data,Extract
    pub fn parse_blocks(&mut self, data: &[u8]) -> Vec<Pcapngpacket> {
        let mut offset = 0;
        let mut packets = Vec::new();

        while offset + 12 <= data.len() {
            // TypeNeed/Require Process: SHB of magic Used for Byte
            let raw_type = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);

            if raw_type == SHB_TYPE {
                // SHB: Need/Require Parse Byte
                if let Some(new_offset) = self.parse_shb(&data[offset..]) {
                    offset += new_offset;
                    continue;
                } else {
                    break;
                }
            }

            // Usealready ofByte
            let block_type = self.read_u32(&data[offset..]);
            let block_total_len = self.read_u32(&data[offset + 4..]) as usize;

            // SecurityCheck
            if block_total_len < 12 || offset + block_total_len > data.len() {
                warn!(
                    "pcapng 块LengthInvalid: type=0x{:08x}, len={}, remaining={}",
                    block_type,
                    block_total_len,
                    data.len() - offset
                );
                break;
            }

            match block_type {
                IDB_TYPE => self.parse_idb(&data[offset..offset + block_total_len]),
                EPB_TYPE => {
                    if let Some(pkt) = self.parse_epb(&data[offset..offset + block_total_len]) {
                        packets.push(pkt);
                    }
                }
                _ => {
                    debug!("hopsUnknown pcapng 块: type=0x{:08x}", block_type);
                }
            }

            // LengthpacketContains 4 Bytealigned
            let aligned_len = (block_total_len + 3) & !3;
            offset += aligned_len;
        }

        packets
    }

    /// Parse Section Header Block (SHB) - Byte
    /// Return of Length
    fn parse_shb(&mut self, data: &[u8]) -> Option<usize> {
        // SHB smallLength: 4(type) + 4(len) + 4(magic) + 2(major) + 2(minor) + 8(section_len) + 4(trailing_len) = 28
        if data.len() < 28 {
            return None;
        }

        // Byte magic 8
        let magic = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        self.byte_order = if magic == 0x1A2B3C4D {
            ByteOrder::LittleEndian
        } else if magic == 0x4D3C2B1A {
            ByteOrder::BigEndian
        } else {
            warn!("Invalidof pcapng SHB magic: 0x{:08x}", magic);
            return None;
        };

        let block_total_len = self.read_u32(&data[4..]) as usize;
        self.initialized = true;

        debug!(
            "pcapng SHB: byte_order={:?}, block_len={}",
            self.byte_order, block_total_len
        );

        let aligned = (block_total_len + 3) & !3;
        Some(aligned)
    }

    /// Parse Interface Description Block (IDB) - GetlinkType
    fn parse_idb(&mut self, data: &[u8]) {
        // IDB: 4(type) + 4(len) + 2(link_type) + 2(reserved) + 4(snap_len) +...
        if data.len() < 16 {
            return;
        }

        self.link_type = self.read_u16(&data[8..]);
        debug!("pcapng IDB: link_type={} (1=Ethernet)", self.link_type);
    }

    /// Parse Enhanced packet Block (EPB) - Extractdatapacket
    fn parse_epb(&self, data: &[u8]) -> Option<Pcapngpacket> {
        // EPB: 4(type) + 4(len) + 4(interface_id) + 4(ts_high) + 4(ts_low) + 4(captured_len) + 4(original_len) + packet_data + 4(trailing_len)
        if data.len() < 32 {
            return None;
        }

        let ts_high = self.read_u32(&data[12..]);
        let ts_low = self.read_u32(&data[16..]);
        let captured_len = self.read_u32(&data[20..]) as usize;

        // dataFrom 28 Start
        let packet_start = 28;
        if data.len() < packet_start + captured_len {
            warn!(
                "pcapng EPB data不complete: captured_len={}, available={}",
                captured_len,
                data.len() - packet_start
            );
            return None;
        }

        Some(Pcapngpacket {
            timestamp_high: ts_high,
            timestamp_low: ts_low,
            data: data[packet_start..packet_start + captured_len].to_vec(),
        })
    }
}

impl Default for PcapngParser {
    fn default() -> Self {
        Self::new()
    }
}
