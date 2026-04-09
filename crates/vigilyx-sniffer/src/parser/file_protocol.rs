//! v3 FileProtocolParsehandler

//! Protocol:
//! Service -> client:
//! FILE <filename> <byte_count> <offset>\n<binary_pcapng_data>
//! HEARTBEAT\n

//! client -> Service:
//! SUBSCRIBE\n (FirstConnection)
//! RESUME <file> <offset>\n (Break/Judge)

use anyhow::{Result, anyhow};
use std::io::{BufRead, BufReader, Read};

/// Maximum line length for protocol commands (8 KB)
const MAX_LINE_LEN: usize = 8 * 1024;
/// Maximum file data frame size (50 MB)
const MAX_FILE_SIZE: usize = 50 * 1024 * 1024;

/// Protocol Type
#[allow(dead_code)]
pub enum Frame {
   /// Filedata
    Filedata {
        filename: String,
        data: Vec<u8>,
        offset: u64,
    },
   /// hops
    Heartbeat,
}

/// v3 FileProtocolreadGethandler
pub struct FileProtocolReader<R: Read> {
    reader: BufReader<R>,
   /// Whenfirst bit FileName (Used for RESUME)
    resume_file: Option<String>,
   /// Whenfirst bit (Used for RESUME)
    resume_offset: u64,
}

impl<R: Read> FileProtocolReader<R> {
   /// CreateNewofProtocolreadGethandler
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::with_capacity(1024 * 1024, reader), // 1MB bufferDistrict
            resume_file: None,
            resume_offset: 0,
        }
    }

   /// Parse 1
    pub fn next_frame(&mut self) -> Result<Frame> {
        let mut line = String::new();
        let bytes_read = self.reader.read_line(&mut line)?;
        if bytes_read == 0 {
            return Err(anyhow!("ConnectionalreadyClose"));
        }
        if line.len() > MAX_LINE_LEN {
            return Err(anyhow!(
                "ProtocolCommandlinelong: {} Byte (上限 {} Byte)",
                line.len(),
                MAX_LINE_LEN
            ));
        }

        let trimmed = line.trim();

        if trimmed.starts_with("FILE ") {
           // Parse: FILE <name> <size> <offset>
            let parts: Vec<&str> = trimmed.splitn(4, ' ').collect();
            if parts.len() != 4 {
                return Err(anyhow!("Invalidof FILE 帧格式: {}", trimmed));
            }

            let filename = parts[1].to_string();
            let size: usize = parts[2]
                .parse()
                .map_err(|_| anyhow!("Invalidof FILE 帧largesmall: {}", parts[2]))?;
            let offset: u64 = parts[3]
                .parse()
                .map_err(|_| anyhow!("Invalidof FILE 帧偏移: {}", parts[3]))?;

            if size > MAX_FILE_SIZE {
                return Err(anyhow!(
                    "FILE 帧largesmall超限: {} Byte (上限 {} Byte)",
                    size,
                    MAX_FILE_SIZE
                ));
            }

           // readGet size Byte2Base/Radixdata
            let mut data = vec![0u8; size];
            self.reader.read_exact(&mut data)?;

           // Update bit
            self.resume_file = Some(filename.clone());
            self.resume_offset = offset + size as u64;

            Ok(Frame::Filedata {
                filename,
                data,
                offset,
            })
        } else if trimmed.starts_with("HEARTBEAT") {
            Ok(Frame::Heartbeat)
        } else {
            Err(anyhow!("UnknownProtocol帧: {}", trimmed))
        }
    }

   /// GetWhenfirst bit (Used for RESUME)
    pub fn resume_position(&self) -> (Option<&str>, u64) {
        (self.resume_file.as_deref(), self.resume_offset)
    }
}
