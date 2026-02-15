//! HTTP/2 Frame Codec for WI-201 HTTP/2 support.
//!
//! This is a minimal, sans-I/O HTTP/2 frame parser designed for the WASM kernel.
//! It does NOT use the h2 crate (which requires tokio) but instead implements
//! the essential frame parsing needed for:
//! 1. Identifying stream IDs to map to flows
//! 2. Extracting HEADERS frames to parse HTTP requests/responses
//! 3. Accumulating DATA frames for request/response bodies
//! 4. Detecting end-of-stream markers
//!
//! Reference: RFC 7540 (HTTP/2)

use std::collections::HashMap;

/// HTTP/2 frame types (RFC 7540 Section 6)
#[allow(dead_code)]
pub mod frame_type {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const PRIORITY: u8 = 0x2;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;
}

/// HTTP/2 frame flags
#[allow(dead_code)]
pub mod flags {
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// HTTP/2 SETTINGS identifiers (RFC 7540 Section 6.5.2)
#[allow(dead_code)]
pub mod settings_id {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

/// HTTP/2 error codes (RFC 7540 Section 7)
#[allow(dead_code)]
pub mod error_code {
    pub const NO_ERROR: u32 = 0x0;
    pub const PROTOCOL_ERROR: u32 = 0x1;
    pub const INTERNAL_ERROR: u32 = 0x2;
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    pub const SETTINGS_TIMEOUT: u32 = 0x4;
    pub const STREAM_CLOSED: u32 = 0x5;
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    pub const REFUSED_STREAM: u32 = 0x7;
    pub const CANCEL: u32 = 0x8;
    pub const COMPRESSION_ERROR: u32 = 0x9;
    pub const CONNECT_ERROR: u32 = 0xa;
    pub const ENHANCE_YOUR_CALM: u32 = 0xb;
    pub const INADEQUATE_SECURITY: u32 = 0xc;
    pub const HTTP_1_1_REQUIRED: u32 = 0xd;
}

/// A parsed HTTP/2 frame header (9 bytes)
#[derive(Debug, Clone)]
pub struct H2FrameHeader {
    pub length: u32,      // 24 bits
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,   // 31 bits (high bit reserved)
}

impl H2FrameHeader {
    /// Parse a 9-byte frame header
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 9 {
            return None;
        }
        
        let length = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
        let frame_type = data[3];
        let flags = data[4];
        let stream_id = ((data[5] as u32) << 24) 
            | ((data[6] as u32) << 16) 
            | ((data[7] as u32) << 8) 
            | (data[8] as u32);
        let stream_id = stream_id & 0x7FFFFFFF; // Clear reserved bit
        
        Some(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    /// Total frame size including header
    pub fn total_size(&self) -> usize {
        9 + self.length as usize
    }

    /// Check if END_STREAM flag is set
    pub fn is_end_stream(&self) -> bool {
        self.flags & flags::END_STREAM != 0
    }

    /// Check if END_HEADERS flag is set
    pub fn is_end_headers(&self) -> bool {
        self.flags & flags::END_HEADERS != 0
    }
}

/// Events emitted by the H2 codec when parsing frames
#[derive(Debug)]
pub enum H2Event {
    /// New stream with HEADERS (request on client side, response on server side)
    Headers {
        stream_id: u32,
        header_block: Vec<u8>,  // HPACK-encoded headers
        end_stream: bool,
    },
    /// Data for a stream
    Data {
        stream_id: u32,
        data: Vec<u8>,
        end_stream: bool,
    },
    /// Stream was reset (RST_STREAM)
    StreamReset {
        stream_id: u32,
        error_code: u32,
    },
    /// Connection-level GOAWAY
    GoAway {
        last_stream_id: u32,
        error_code: u32,
    },
    /// Settings frame (connection-level)
    Settings {
        ack: bool,
        /// Parsed settings: (identifier, value) pairs. Empty for ACK frames.
        settings: Vec<(u16, u32)>,
    },
    /// Window update
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    /// Ping (connection-level)
    Ping {
        ack: bool,
        data: [u8; 8],
    },
}

/// State for a single HTTP/2 stream (lifecycle tracking only).
/// Note: Header block assembly uses pending_header_block fields on H2Codec.
/// Data payloads are returned directly via H2Event — not accumulated here.
#[derive(Debug, Default)]
pub struct StreamState {
    /// True if we've seen END_HEADERS
    pub headers_complete: bool,
    /// True if we've seen END_STREAM
    pub stream_ended: bool,
}

/// HTTP/2 frame parser for the WASM kernel.
/// 
/// This is a simple, synchronous parser that extracts events from raw bytes.
/// It does NOT implement flow control, HPACK compression, or other complex features.
/// Those are handled by the browser/upstream server.
#[derive(Debug, Default)]
pub struct H2Codec {
    /// Buffer for incomplete frames
    buffer: Vec<u8>,
    /// State per stream
    streams: HashMap<u32, StreamState>,
    /// Connection preface received (for servers)
    preface_received: bool,
    /// Stream ID with pending header block (waiting for CONTINUATION + END_HEADERS)
    pending_headers_stream: Option<u32>,
    /// END_STREAM flag from the HEADERS frame that started the pending header block
    pending_headers_end_stream: bool,
    /// Accumulated header block data across HEADERS + CONTINUATION frames
    pending_header_block: Vec<u8>,
}

/// Maximum accumulated header block size (256 KB).
/// Prevents unbounded memory growth from malicious/buggy CONTINUATION floods.
pub const MAX_HEADER_BLOCK_SIZE: usize = 256 * 1024;

/// The HTTP/2 connection preface (24 bytes)
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Check if data starts with HTTP/2 connection preface (h2c detection)
pub fn is_h2c_preface(data: &[u8]) -> bool {
    data.len() >= CONNECTION_PREFACE.len() && &data[..CONNECTION_PREFACE.len()] == CONNECTION_PREFACE
}


impl H2Codec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process incoming data and return parsed events.
    /// 
    /// This is the main entry point - feed raw bytes and get back events.
    pub fn process(&mut self, data: &[u8]) -> Result<Vec<H2Event>, String> {
        self.buffer.extend_from_slice(data);
        let mut events = Vec::new();

        // Check for connection preface (client sends this first)
        if !self.preface_received && self.buffer.len() >= CONNECTION_PREFACE.len() {
            if &self.buffer[..CONNECTION_PREFACE.len()] == CONNECTION_PREFACE {
                self.buffer.drain(..CONNECTION_PREFACE.len());
                self.preface_received = true;
            }
        }

        // Parse frames
        loop {
            // Need at least 9 bytes for frame header
            if self.buffer.len() < 9 {
                break;
            }

            let header = match H2FrameHeader::parse(&self.buffer) {
                Some(h) => h,
                None => break,
            };

            // Check if we have the complete frame
            let total_size = header.total_size();
            if self.buffer.len() < total_size {
                break;
            }

            // Extract frame payload: split buffer to avoid double copy
            // After split_off(total_size), self.buffer has [0..total_size] and remainder has [total_size..]
            let remainder = self.buffer.split_off(total_size);
            let mut frame_data = std::mem::replace(&mut self.buffer, remainder);
            // frame_data is the full frame (header + payload), self.buffer is now the remaining data
            let payload = if frame_data.len() > 9 {
                frame_data.drain(..9);
                frame_data
            } else {
                Vec::new()
            };

            // Parse the frame
            if let Some(event) = self.parse_frame(&header, payload)? {
                events.push(event);
            }
        }

        Ok(events)
    }

    /// Parse a single frame and return an event if applicable
    fn parse_frame(&mut self, header: &H2FrameHeader, payload: Vec<u8>) -> Result<Option<H2Event>, String> {
        match header.frame_type {
            frame_type::DATA => {
                let data = self.extract_data_payload(header, payload)?;
                let stream = self.streams.entry(header.stream_id).or_default();
                if header.is_end_stream() {
                    stream.stream_ended = true;
                }
                Ok(Some(H2Event::Data {
                    stream_id: header.stream_id,
                    data,
                    end_stream: header.is_end_stream(),
                }))
            }
            frame_type::HEADERS => {
                let header_block = self.extract_headers_payload(header, payload)?;
                let stream = self.streams.entry(header.stream_id).or_default();
                if header.is_end_stream() {
                    stream.stream_ended = true;
                }
                if header.is_end_headers() {
                    // Complete header block in a single frame
                    stream.headers_complete = true;
                    Ok(Some(H2Event::Headers {
                        stream_id: header.stream_id,
                        header_block,
                        end_stream: header.is_end_stream(),
                    }))
                } else {
                    // Headers span multiple frames - accumulate and wait for CONTINUATION
                    if header_block.len() > MAX_HEADER_BLOCK_SIZE {
                        return Err(format!(
                            "Header block too large ({} bytes, max {})",
                            header_block.len(), MAX_HEADER_BLOCK_SIZE
                        ));
                    }
                    self.pending_headers_stream = Some(header.stream_id);
                    self.pending_headers_end_stream = header.is_end_stream();
                    self.pending_header_block = header_block;
                    Ok(None)
                }
            }
            frame_type::CONTINUATION => {
                if let Some(pending_stream) = self.pending_headers_stream {
                    if pending_stream != header.stream_id {
                        return Err(format!("CONTINUATION for stream {} but pending headers on stream {}",
                            header.stream_id, pending_stream));
                    }
                    // Guard against unbounded header block accumulation
                    let new_size = self.pending_header_block.len() + payload.len();
                    if new_size > MAX_HEADER_BLOCK_SIZE {
                        self.pending_headers_stream = None;
                        self.pending_header_block.clear();
                        return Err(format!(
                            "Header block too large ({} bytes, max {})",
                            new_size, MAX_HEADER_BLOCK_SIZE
                        ));
                    }
                    self.pending_header_block.extend_from_slice(&payload);
                    if header.is_end_headers() {
                        let stream = self.streams.entry(header.stream_id).or_default();
                        stream.headers_complete = true;
                        let full_block = std::mem::take(&mut self.pending_header_block);
                        let end_stream = self.pending_headers_end_stream;
                        self.pending_headers_stream = None;
                        self.pending_headers_end_stream = false;
                        Ok(Some(H2Event::Headers {
                            stream_id: header.stream_id,
                            header_block: full_block,
                            end_stream,
                        }))
                    } else {
                        Ok(None)
                    }
                } else {
                    Err(format!("Unexpected CONTINUATION frame for stream {}", header.stream_id))
                }
            }
            frame_type::RST_STREAM => {
                if payload.len() < 4 {
                    return Err("RST_STREAM frame too short".to_string());
                }
                let error_code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                self.streams.remove(&header.stream_id);
                Ok(Some(H2Event::StreamReset {
                    stream_id: header.stream_id,
                    error_code,
                }))
            }
            frame_type::SETTINGS => {
                let ack = header.flags & 0x1 != 0;
                let mut settings = Vec::new();
                if !ack && payload.len() >= 6 {
                    // Parse setting entries: each is 6 bytes (u16 id + u32 value)
                    let mut pos = 0;
                    while pos + 6 <= payload.len() {
                        let id = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
                        let value = u32::from_be_bytes([
                            payload[pos + 2], payload[pos + 3],
                            payload[pos + 4], payload[pos + 5],
                        ]);
                        settings.push((id, value));
                        pos += 6;
                    }
                }
                Ok(Some(H2Event::Settings { ack, settings }))
            }
            frame_type::GOAWAY => {
                if payload.len() < 8 {
                    return Err("GOAWAY frame too short".to_string());
                }
                let last_stream_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7FFFFFFF;
                let error_code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                Ok(Some(H2Event::GoAway {
                    last_stream_id,
                    error_code,
                }))
            }
            frame_type::WINDOW_UPDATE => {
                if payload.len() < 4 {
                    return Err("WINDOW_UPDATE frame too short".to_string());
                }
                let increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7FFFFFFF;
                Ok(Some(H2Event::WindowUpdate {
                    stream_id: header.stream_id,
                    increment,
                }))
            }
            frame_type::PING => {
                if payload.len() < 8 {
                    return Err("PING frame too short".to_string());
                }
                let ack = header.flags & 0x1 != 0;
                let mut data = [0u8; 8];
                data.copy_from_slice(&payload[..8]);
                Ok(Some(H2Event::Ping { ack, data }))
            }
            frame_type::PRIORITY => {
                // Ignore PRIORITY frames
                Ok(None)
            }
            frame_type::PUSH_PROMISE => {
                // We don't support server push in the proxy
                Ok(None)
            }
            _ => {
                // Unknown frame type - ignore
                Ok(None)
            }
        }
    }

    /// Extract DATA payload, handling PADDED flag.
    /// Takes ownership of the payload Vec to avoid re-copying.
    fn extract_data_payload(&self, header: &H2FrameHeader, mut payload: Vec<u8>) -> Result<Vec<u8>, String> {
        if header.flags & flags::PADDED != 0 {
            if payload.is_empty() {
                return Err("PADDED DATA frame with no payload".to_string());
            }
            let pad_length = payload[0] as usize;
            if pad_length >= payload.len() {
                return Err("Invalid padding length in DATA frame".to_string());
            }
            // Remove padding from end, then remove pad_length byte from start
            payload.truncate(payload.len() - pad_length);
            payload.remove(0);
            Ok(payload)
        } else {
            Ok(payload)
        }
    }

    /// Extract HEADERS payload, handling PADDED and PRIORITY flags.
    /// Takes ownership of the payload Vec to avoid re-copying.
    fn extract_headers_payload(&self, header: &H2FrameHeader, mut payload: Vec<u8>) -> Result<Vec<u8>, String> {
        let mut offset = 0;
        let mut end = payload.len();

        // Handle PADDED flag
        if header.flags & flags::PADDED != 0 {
            if payload.is_empty() {
                return Err("PADDED HEADERS frame with no payload".to_string());
            }
            let pad_length = payload[0] as usize;
            offset = 1;
            if pad_length >= payload.len() - offset {
                return Err("Invalid padding length in HEADERS frame".to_string());
            }
            end = payload.len() - pad_length;
        }

        // Handle PRIORITY flag
        if header.flags & flags::PRIORITY != 0 {
            if payload.len() - offset < 5 {
                return Err("PRIORITY HEADERS frame with insufficient data".to_string());
            }
            offset += 5; // Skip stream dependency (4 bytes) + weight (1 byte)
        }

        // If no stripping needed, return as-is
        if offset == 0 && end == payload.len() {
            return Ok(payload);
        }

        // Need subrange: truncate end first, then drain start
        payload.truncate(end);
        if offset > 0 {
            payload.drain(..offset);
        }
        Ok(payload)
    }

    /// Remove a stream (e.g., after completing a flow)
    pub fn remove_stream(&mut self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

    /// Reset codec state (e.g., after upstream reconnect)
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.streams.clear();
        self.preface_received = false;
        self.pending_headers_stream = None;
        self.pending_headers_end_stream = false;
        self.pending_header_block.clear();
    }

    /// Create a RST_STREAM frame with HTTP_1_1_REQUIRED error
    pub fn create_rst_stream(stream_id: u32, error_code: u32) -> Vec<u8> {
        let mut frame = Vec::with_capacity(13);
        // Length: 4 bytes
        frame.push(0);
        frame.push(0);
        frame.push(4);
        // Type: RST_STREAM
        frame.push(frame_type::RST_STREAM);
        // Flags: none
        frame.push(0);
        // Stream ID
        frame.extend_from_slice(&stream_id.to_be_bytes());
        // Error code
        frame.extend_from_slice(&error_code.to_be_bytes());
        frame
    }

    /// Create a GOAWAY frame
    #[allow(dead_code)]
    pub fn create_goaway(last_stream_id: u32, error_code: u32) -> Vec<u8> {
        let mut frame = Vec::with_capacity(17);
        // Length: 8 bytes
        frame.push(0);
        frame.push(0);
        frame.push(8);
        // Type: GOAWAY
        frame.push(frame_type::GOAWAY);
        // Flags: none
        frame.push(0);
        // Stream ID: 0 (connection-level)
        frame.extend_from_slice(&0u32.to_be_bytes());
        // Last stream ID
        frame.extend_from_slice(&last_stream_id.to_be_bytes());
        // Error code
        frame.extend_from_slice(&error_code.to_be_bytes());
        frame
    }

    /// Create a SETTINGS ACK frame
    #[allow(dead_code)]
    pub fn create_settings_ack() -> Vec<u8> {
        vec![
            0, 0, 0,  // Length: 0
            frame_type::SETTINGS,
            0x1,      // Flags: ACK
            0, 0, 0, 0,  // Stream ID: 0
        ]
    }

    /// Create an empty SETTINGS frame (use default settings)
    /// This is sent by the server to the client at connection start
    #[allow(dead_code)]
    pub fn create_settings() -> Vec<u8> {
        vec![
            0, 0, 0,  // Length: 0 (no settings, use defaults)
            frame_type::SETTINGS,
            0x0,      // Flags: 0 (not ACK)
            0, 0, 0, 0,  // Stream ID: 0
        ]
    }

    /// Create a SETTINGS frame with larger initial window size
    /// This allows upstream to send more data before waiting for WINDOW_UPDATE
    /// Critical for multiplexing - default 65535 bytes is too small for concurrent streams
    #[allow(dead_code)]
    pub fn create_settings_with_window(initial_window_size: u32) -> Vec<u8> {
        // SETTINGS frame with SETTINGS_INITIAL_WINDOW_SIZE (0x4)
        // Each setting is 6 bytes: 2 byte ID + 4 byte value
        let mut frame = vec![
            0, 0, 6,  // Length: 6 bytes (one setting)
            frame_type::SETTINGS,
            0x0,      // Flags: 0 (not ACK)
            0, 0, 0, 0,  // Stream ID: 0
        ];
        // SETTINGS_INITIAL_WINDOW_SIZE = 0x4
        frame.push(0);
        frame.push(4);
        // Window size value (4 bytes, big-endian)
        frame.push((initial_window_size >> 24) as u8);
        frame.push((initial_window_size >> 16) as u8);
        frame.push((initial_window_size >> 8) as u8);
        frame.push(initial_window_size as u8);
        frame
    }

    /// Create a PING ACK frame
    #[allow(dead_code)]
    pub fn create_ping_ack(data: [u8; 8]) -> Vec<u8> {
        let mut frame = vec![
            0, 0, 8,  // Length: 8
            frame_type::PING,
            0x1,      // Flags: ACK
            0, 0, 0, 0,  // Stream ID: 0
        ];
        frame.extend_from_slice(&data);
        frame
    }

    /// Create a WINDOW_UPDATE frame to replenish flow control window
    /// stream_id=0 updates connection-level window, otherwise stream-level
    pub fn create_window_update(stream_id: u32, increment: u32) -> Vec<u8> {
        let increment = increment & 0x7FFFFFFF; // Clear reserved bit
        vec![
            0, 0, 4,  // Length: 4 bytes
            frame_type::WINDOW_UPDATE,
            0x0,      // Flags: none
            (stream_id >> 24) as u8,
            (stream_id >> 16) as u8,
            (stream_id >> 8) as u8,
            stream_id as u8,
            (increment >> 24) as u8,
            (increment >> 16) as u8,
            (increment >> 8) as u8,
            increment as u8,
        ]
    }

    /// Create a CONTINUATION frame to continue a header block
    /// end_headers: true if this is the final frame in the header block sequence
    pub fn create_continuation_frame(stream_id: u32, payload: &[u8], end_headers: bool) -> Vec<u8> {
        let length = payload.len() as u32;
        let mut flags_byte = 0x0;
        if end_headers {
            flags_byte |= flags::END_HEADERS;
        }

        let mut frame = vec![
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
            frame_type::CONTINUATION,
            flags_byte,
            // Stream ID (31 bits, bit 31 is reserved)
            (stream_id >> 24) as u8,
            (stream_id >> 16) as u8,
            (stream_id >> 8) as u8,
            stream_id as u8,
        ];
        frame.extend_from_slice(payload);
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header_parse() {
        // DATA frame, length 5, stream 1, END_STREAM
        let header_bytes = [0, 0, 5, 0, 1, 0, 0, 0, 1];
        let header = H2FrameHeader::parse(&header_bytes).unwrap();
        
        assert_eq!(header.length, 5);
        assert_eq!(header.frame_type, frame_type::DATA);
        assert_eq!(header.stream_id, 1);
        assert!(header.is_end_stream());
        assert!(!header.is_end_headers());
    }

    #[test]
    fn test_frame_header_headers() {
        // HEADERS frame, length 10, stream 3, END_HEADERS
        let header_bytes = [0, 0, 10, 1, 4, 0, 0, 0, 3];
        let header = H2FrameHeader::parse(&header_bytes).unwrap();
        
        assert_eq!(header.length, 10);
        assert_eq!(header.frame_type, frame_type::HEADERS);
        assert_eq!(header.stream_id, 3);
        assert!(!header.is_end_stream());
        assert!(header.is_end_headers());
    }

    #[test]
    fn test_codec_parse_data() {
        let mut codec = H2Codec::new();
        codec.preface_received = true; // Skip preface check
        
        // DATA frame: length 5, type 0, flags 1 (END_STREAM), stream 1
        let mut frame = vec![0, 0, 5, 0, 1, 0, 0, 0, 1];
        frame.extend_from_slice(b"hello");
        
        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);
        
        match &events[0] {
            H2Event::Data { stream_id, data, end_stream } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(data, b"hello");
                assert!(*end_stream);
            }
            _ => panic!("Expected Data event"),
        }
    }

    #[test]
    fn test_codec_parse_headers() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;
        
        // HEADERS frame: length 4, type 1, flags 5 (END_STREAM | END_HEADERS), stream 1
        let mut frame = vec![0, 0, 4, 1, 5, 0, 0, 0, 1];
        frame.extend_from_slice(&[0x82, 0x86, 0x84, 0x41]); // Some HPACK bytes
        
        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);
        
        match &events[0] {
            H2Event::Headers { stream_id, header_block, end_stream } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(header_block, &[0x82, 0x86, 0x84, 0x41]);
                assert!(*end_stream);
            }
            _ => panic!("Expected Headers event"),
        }
    }

    #[test]
    fn test_codec_parse_rst_stream() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;
        
        // RST_STREAM frame: length 4, type 3, flags 0, stream 1, error HTTP_1_1_REQUIRED
        let frame = [0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 0xd];
        
        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);
        
        match &events[0] {
            H2Event::StreamReset { stream_id, error_code } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(*error_code, error_code::HTTP_1_1_REQUIRED);
            }
            _ => panic!("Expected StreamReset event"),
        }
    }

    #[test]
    fn test_codec_parse_goaway() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;
        
        // GOAWAY frame: length 8, type 7, flags 0, stream 0
        // last_stream_id = 5, error = HTTP_1_1_REQUIRED
        let frame = [0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0xd];
        
        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);
        
        match &events[0] {
            H2Event::GoAway { last_stream_id, error_code } => {
                assert_eq!(*last_stream_id, 5);
                assert_eq!(*error_code, error_code::HTTP_1_1_REQUIRED);
            }
            _ => panic!("Expected GoAway event"),
        }
    }

    #[test]
    fn test_codec_fragmented_frames() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;
        
        // Build a complete frame
        let mut frame = vec![0, 0, 5, 0, 1, 0, 0, 0, 1]; // Header
        frame.extend_from_slice(b"hello");
        
        // Feed it in fragments
        let events1 = codec.process(&frame[..5]).unwrap();
        assert!(events1.is_empty()); // Not enough data
        
        let events2 = codec.process(&frame[5..10]).unwrap();
        assert!(events2.is_empty()); // Still not enough
        
        let events3 = codec.process(&frame[10..]).unwrap();
        assert_eq!(events3.len(), 1); // Now complete
    }

    #[test]
    fn test_create_rst_stream() {
        let frame = H2Codec::create_rst_stream(1, error_code::HTTP_1_1_REQUIRED);
        
        assert_eq!(frame.len(), 13);
        assert_eq!(&frame[0..3], &[0, 0, 4]); // Length
        assert_eq!(frame[3], frame_type::RST_STREAM);
        assert_eq!(frame[4], 0); // Flags
        assert_eq!(&frame[5..9], &[0, 0, 0, 1]); // Stream ID
        assert_eq!(&frame[9..13], &[0, 0, 0, 0xd]); // Error code
    }

    #[test]
    fn test_connection_preface_handling() {
        let mut codec = H2Codec::new();
        
        // Send connection preface followed by SETTINGS
        let mut data = CONNECTION_PREFACE.to_vec();
        data.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]); // Empty SETTINGS
        
        let events = codec.process(&data).unwrap();
        assert!(codec.preface_received);
        assert_eq!(events.len(), 1);
        
        match &events[0] {
            H2Event::Settings { ack, .. } => assert!(!ack),
            _ => panic!("Expected Settings event"),
        }
    }

    #[test]
    fn test_padded_data_frame() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // DATA frame with PADDED flag: length 10, pad_length 4, data "hello"
        let mut frame = vec![0, 0, 10, 0, 0x9, 0, 0, 0, 1]; // 0x9 = END_STREAM | PADDED
        frame.push(4); // Pad length
        frame.extend_from_slice(b"hello");
        frame.extend_from_slice(&[0, 0, 0, 0]); // Padding

        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::Data { data, .. } => {
                assert_eq!(data, b"hello");
            }
            _ => panic!("Expected Data event"),
        }
    }

    // =========================================================================
    // CONTINUATION Frame Tests (Bug 13 fix)
    // =========================================================================

    #[test]
    fn test_continuation_single_frame() {
        // HEADERS without END_HEADERS, followed by CONTINUATION with END_HEADERS
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // HEADERS: length 3, type 1, flags 0 (no END_HEADERS, no END_STREAM), stream 1
        let mut data = vec![0, 0, 3, 1, 0, 0, 0, 0, 1];
        data.extend_from_slice(&[0x82, 0x86, 0x84]); // First part of HPACK

        // CONTINUATION: length 2, type 9, flags 4 (END_HEADERS), stream 1
        data.extend_from_slice(&[0, 0, 2, 9, 4, 0, 0, 0, 1]);
        data.extend_from_slice(&[0x41, 0x8a]); // Rest of HPACK

        let events = codec.process(&data).unwrap();
        // HEADERS without END_HEADERS → no event
        // CONTINUATION with END_HEADERS → Headers event with assembled block
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::Headers { stream_id, header_block, end_stream } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(header_block, &[0x82, 0x86, 0x84, 0x41, 0x8a]);
                assert!(!*end_stream);
            }
            _ => panic!("Expected Headers event"),
        }
    }

    #[test]
    fn test_continuation_multiple_frames() {
        // HEADERS + 2 CONTINUATIONs before END_HEADERS
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // HEADERS: length 2, flags 0, stream 3
        let mut data = vec![0, 0, 2, 1, 0, 0, 0, 0, 3];
        data.extend_from_slice(&[0x82, 0x86]);

        // CONTINUATION 1: length 2, flags 0 (no END_HEADERS), stream 3
        data.extend_from_slice(&[0, 0, 2, 9, 0, 0, 0, 0, 3]);
        data.extend_from_slice(&[0x84, 0x41]);

        // CONTINUATION 2: length 1, flags 4 (END_HEADERS), stream 3
        data.extend_from_slice(&[0, 0, 1, 9, 4, 0, 0, 0, 3]);
        data.extend_from_slice(&[0x8a]);

        let events = codec.process(&data).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::Headers { stream_id, header_block, end_stream } => {
                assert_eq!(*stream_id, 3);
                assert_eq!(header_block, &[0x82, 0x86, 0x84, 0x41, 0x8a]);
                assert!(!*end_stream);
            }
            _ => panic!("Expected Headers event"),
        }
    }

    #[test]
    fn test_continuation_preserves_end_stream() {
        // HEADERS with END_STREAM but no END_HEADERS, then CONTINUATION with END_HEADERS
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // HEADERS: length 2, flags 1 (END_STREAM only, no END_HEADERS), stream 1
        let mut data = vec![0, 0, 2, 1, 0x1, 0, 0, 0, 1];
        data.extend_from_slice(&[0x82, 0x86]);

        // CONTINUATION: length 1, flags 4 (END_HEADERS), stream 1
        data.extend_from_slice(&[0, 0, 1, 9, 4, 0, 0, 0, 1]);
        data.extend_from_slice(&[0x84]);

        let events = codec.process(&data).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::Headers { stream_id, header_block, end_stream } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(header_block, &[0x82, 0x86, 0x84]);
                assert!(*end_stream, "END_STREAM from HEADERS should be preserved");
            }
            _ => panic!("Expected Headers event"),
        }
    }

    #[test]
    fn test_continuation_wrong_stream_returns_error() {
        // HEADERS on stream 1, CONTINUATION on stream 3 → protocol error
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // HEADERS: stream 1, no END_HEADERS
        let mut data = vec![0, 0, 2, 1, 0, 0, 0, 0, 1];
        data.extend_from_slice(&[0x82, 0x86]);

        // CONTINUATION: stream 3 (wrong!)
        data.extend_from_slice(&[0, 0, 1, 9, 4, 0, 0, 0, 3]);
        data.extend_from_slice(&[0x84]);

        let result = codec.process(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("CONTINUATION for stream 3"), "Error: {}", err);
        assert!(err.contains("pending headers on stream 1"), "Error: {}", err);
    }

    #[test]
    fn test_unexpected_continuation_returns_error() {
        // CONTINUATION without preceding HEADERS → protocol error
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // CONTINUATION: stream 1, END_HEADERS
        let mut data = vec![0, 0, 2, 9, 4, 0, 0, 0, 1];
        data.extend_from_slice(&[0x82, 0x86]);

        let result = codec.process(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Unexpected CONTINUATION"), "Error: {}", err);
    }

    #[test]
    fn test_continuation_incremental_delivery() {
        // Feed HEADERS and CONTINUATION in separate process() calls
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // First call: HEADERS without END_HEADERS
        let mut headers_frame = vec![0, 0, 3, 1, 0, 0, 0, 0, 1];
        headers_frame.extend_from_slice(&[0x82, 0x86, 0x84]);
        let events1 = codec.process(&headers_frame).unwrap();
        assert!(events1.is_empty(), "No event until END_HEADERS");

        // Second call: CONTINUATION with END_HEADERS
        let mut cont_frame = vec![0, 0, 2, 9, 4, 0, 0, 0, 1];
        cont_frame.extend_from_slice(&[0x41, 0x8a]);
        let events2 = codec.process(&cont_frame).unwrap();
        assert_eq!(events2.len(), 1);

        match &events2[0] {
            H2Event::Headers { stream_id, header_block, .. } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(header_block, &[0x82, 0x86, 0x84, 0x41, 0x8a]);
            }
            _ => panic!("Expected Headers event"),
        }
    }

    // =========================================================================
    // Protocol Frame Tests (PING, WINDOW_UPDATE, SETTINGS)
    // =========================================================================

    #[test]
    fn test_ping_frame_parsing() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // PING: length 8, type 6, flags 0, stream 0
        let mut frame = vec![0, 0, 8, 6, 0, 0, 0, 0, 0];
        frame.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // opaque data

        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::Ping { ack, data } => {
                assert!(!*ack);
                assert_eq!(*data, [1, 2, 3, 4, 5, 6, 7, 8]);
            }
            _ => panic!("Expected Ping event"),
        }
    }

    #[test]
    fn test_ping_ack_frame_parsing() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // PING ACK: length 8, type 6, flags 1 (ACK), stream 0
        let mut frame = vec![0, 0, 8, 6, 1, 0, 0, 0, 0];
        frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);

        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::Ping { ack, data } => {
                assert!(*ack);
                assert_eq!(*data, [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
            }
            _ => panic!("Expected Ping ACK event"),
        }
    }

    #[test]
    fn test_window_update_parsing() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // WINDOW_UPDATE: length 4, type 8, flags 0, stream 5, increment 65536
        let mut frame = vec![0, 0, 4, 8, 0, 0, 0, 0, 5];
        frame.extend_from_slice(&0x00010000u32.to_be_bytes()); // 65536

        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::WindowUpdate { stream_id, increment } => {
                assert_eq!(*stream_id, 5);
                assert_eq!(*increment, 65536);
            }
            _ => panic!("Expected WindowUpdate event"),
        }
    }

    #[test]
    fn test_window_update_connection_level() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // Connection-level WINDOW_UPDATE: stream 0
        let mut frame = vec![0, 0, 4, 8, 0, 0, 0, 0, 0];
        frame.extend_from_slice(&0x00100000u32.to_be_bytes()); // 1MB

        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::WindowUpdate { stream_id, increment } => {
                assert_eq!(*stream_id, 0);
                assert_eq!(*increment, 0x100000);
            }
            _ => panic!("Expected WindowUpdate event"),
        }
    }

    #[test]
    fn test_settings_ack_parsing() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // SETTINGS ACK: length 0, type 4, flags 1 (ACK), stream 0
        let frame = vec![0, 0, 0, 4, 1, 0, 0, 0, 0];

        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::Settings { ack, .. } => assert!(*ack),
            _ => panic!("Expected Settings ACK event"),
        }
    }

    // =========================================================================
    // Frame Builder Tests
    // =========================================================================

    #[test]
    fn test_create_settings_ack() {
        let frame = H2Codec::create_settings_ack();
        assert_eq!(frame.len(), 9);
        assert_eq!(&frame[0..3], &[0, 0, 0]); // Length: 0
        assert_eq!(frame[3], frame_type::SETTINGS);
        assert_eq!(frame[4], 0x1); // ACK flag
        assert_eq!(&frame[5..9], &[0, 0, 0, 0]); // Stream 0
    }

    #[test]
    fn test_create_settings_empty() {
        let frame = H2Codec::create_settings();
        assert_eq!(frame.len(), 9);
        assert_eq!(&frame[0..3], &[0, 0, 0]); // Length: 0
        assert_eq!(frame[3], frame_type::SETTINGS);
        assert_eq!(frame[4], 0x0); // No flags
    }

    #[test]
    fn test_create_settings_with_window() {
        let frame = H2Codec::create_settings_with_window(1_048_576); // 1MB
        assert_eq!(frame.len(), 15); // 9 header + 6 setting
        assert_eq!(&frame[0..3], &[0, 0, 6]); // Length: 6
        assert_eq!(frame[3], frame_type::SETTINGS);
        // Setting ID = 0x4 (INITIAL_WINDOW_SIZE)
        assert_eq!(&frame[9..11], &[0, 4]);
        // Value = 1048576 (0x00100000)
        assert_eq!(&frame[11..15], &[0x00, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn test_create_ping_ack() {
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let frame = H2Codec::create_ping_ack(data);
        assert_eq!(frame.len(), 17); // 9 header + 8 data
        assert_eq!(&frame[0..3], &[0, 0, 8]); // Length: 8
        assert_eq!(frame[3], frame_type::PING);
        assert_eq!(frame[4], 0x1); // ACK flag
        assert_eq!(&frame[5..9], &[0, 0, 0, 0]); // Stream 0
        assert_eq!(&frame[9..17], &data);
    }

    #[test]
    fn test_create_window_update() {
        let frame = H2Codec::create_window_update(7, 32768);
        assert_eq!(frame.len(), 13); // 9 header + 4 increment
        assert_eq!(&frame[0..3], &[0, 0, 4]); // Length: 4
        assert_eq!(frame[3], frame_type::WINDOW_UPDATE);
        assert_eq!(frame[4], 0); // No flags
        // Stream ID = 7
        assert_eq!(&frame[5..9], &[0, 0, 0, 7]);
        // Increment = 32768
        assert_eq!(&frame[9..13], &[0, 0, 0x80, 0]);
    }

    #[test]
    fn test_create_goaway() {
        let frame = H2Codec::create_goaway(5, error_code::NO_ERROR);
        assert_eq!(frame.len(), 17); // 9 header + 8 payload
        assert_eq!(&frame[0..3], &[0, 0, 8]); // Length: 8
        assert_eq!(frame[3], frame_type::GOAWAY);
        assert_eq!(&frame[5..9], &[0, 0, 0, 0]); // Stream 0
        assert_eq!(&frame[9..13], &[0, 0, 0, 5]); // Last stream ID
        assert_eq!(&frame[13..17], &[0, 0, 0, 0]); // NO_ERROR
    }

    // =========================================================================
    // Multiple Frames & Edge Cases
    // =========================================================================

    #[test]
    fn test_multiple_frames_in_single_process() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        let mut data = Vec::new();

        // Frame 1: HEADERS on stream 1 (END_HEADERS | END_STREAM)
        data.extend_from_slice(&[0, 0, 2, 1, 5, 0, 0, 0, 1]);
        data.extend_from_slice(&[0x82, 0x86]);

        // Frame 2: HEADERS on stream 3 (END_HEADERS only)
        data.extend_from_slice(&[0, 0, 1, 1, 4, 0, 0, 0, 3]);
        data.extend_from_slice(&[0x84]);

        // Frame 3: DATA on stream 3 (END_STREAM)
        data.extend_from_slice(&[0, 0, 5, 0, 1, 0, 0, 0, 3]);
        data.extend_from_slice(b"hello");

        let events = codec.process(&data).unwrap();
        assert_eq!(events.len(), 3);

        // Verify order preserved
        assert!(matches!(&events[0], H2Event::Headers { stream_id: 1, .. }));
        assert!(matches!(&events[1], H2Event::Headers { stream_id: 3, .. }));
        assert!(matches!(&events[2], H2Event::Data { stream_id: 3, .. }));
    }

    #[test]
    fn test_headers_with_priority_flag() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // HEADERS with PRIORITY flag: length 7, flags 0x24 (END_HEADERS | PRIORITY), stream 1
        let mut frame = vec![0, 0, 7, 1, 0x24, 0, 0, 0, 1];
        // Priority: stream dependency (4 bytes) + weight (1 byte)
        frame.extend_from_slice(&[0, 0, 0, 0]); // Dependency on stream 0
        frame.push(255); // Weight
        // Header block (2 bytes)
        frame.extend_from_slice(&[0x82, 0x86]);

        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::Headers { stream_id, header_block, .. } => {
                assert_eq!(*stream_id, 1);
                // Should extract only the header block, skipping priority bytes
                assert_eq!(header_block, &[0x82, 0x86]);
            }
            _ => panic!("Expected Headers event"),
        }
    }

    #[test]
    fn test_rst_stream_removes_stream_state() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // First send HEADERS to create stream state
        let mut data = vec![0, 0, 2, 1, 4, 0, 0, 0, 1]; // END_HEADERS
        data.extend_from_slice(&[0x82, 0x86]);
        codec.process(&data).unwrap();

        // Stream 1 should exist
        assert!(codec.streams.get(&1).is_some());

        // RST_STREAM on stream 1
        let rst = [0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8]; // CANCEL
        codec.process(&rst).unwrap();

        // Stream 1 should be removed
        assert!(codec.streams.get(&1).is_none());
    }

    #[test]
    fn test_priority_frame_ignored() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // PRIORITY frame: length 5, type 2, flags 0, stream 1
        let mut frame = vec![0, 0, 5, 2, 0, 0, 0, 0, 1];
        frame.extend_from_slice(&[0, 0, 0, 0, 16]); // dependency + weight

        let events = codec.process(&frame).unwrap();
        assert!(events.is_empty(), "PRIORITY frames should be silently ignored");
    }

    #[test]
    fn test_unknown_frame_type_ignored() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // Unknown frame type 0xFF: length 3, stream 1
        let mut frame = vec![0, 0, 3, 0xFF, 0, 0, 0, 0, 1];
        frame.extend_from_slice(&[1, 2, 3]);

        let events = codec.process(&frame).unwrap();
        assert!(events.is_empty(), "Unknown frame types should be silently ignored");
    }

    #[test]
    fn test_window_update_too_short_returns_error() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // WINDOW_UPDATE with only 2 bytes payload (needs 4)
        let frame = vec![0, 0, 2, 8, 0, 0, 0, 0, 1, 0, 0];

        let result = codec.process(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("WINDOW_UPDATE"));
    }

    #[test]
    fn test_ping_too_short_returns_error() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // PING with only 4 bytes payload (needs 8)
        let frame = vec![0, 0, 4, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4];

        let result = codec.process(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PING"));
    }

    #[test]
    fn test_goaway_too_short_returns_error() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // GOAWAY with only 4 bytes payload (needs 8)
        let frame = vec![0, 0, 4, 7, 0, 0, 0, 0, 0, 0, 0, 0, 5];

        let result = codec.process(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("GOAWAY"));
    }

    #[test]
    fn test_rst_stream_too_short_returns_error() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // RST_STREAM with only 2 bytes payload (needs 4)
        let frame = vec![0, 0, 2, 3, 0, 0, 0, 0, 1, 0, 0];

        let result = codec.process(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("RST_STREAM"));
    }

    #[test]
    fn test_window_update_clears_reserved_bit() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // WINDOW_UPDATE with reserved bit set (0x80010000 → should be 65536)
        let frame = vec![0, 0, 4, 8, 0, 0, 0, 0, 0, 0x80, 0x01, 0x00, 0x00];

        let events = codec.process(&frame).unwrap();
        match &events[0] {
            H2Event::WindowUpdate { increment, .. } => {
                assert_eq!(*increment, 65536, "Reserved bit should be cleared");
            }
            _ => panic!("Expected WindowUpdate"),
        }
    }

    #[test]
    fn test_stream_id_clears_reserved_bit() {
        // Frame header with reserved bit set on stream ID
        let header_bytes = [0, 0, 0, 4, 0, 0x80, 0x00, 0x00, 0x05]; // stream = 0x80000005
        let header = H2FrameHeader::parse(&header_bytes).unwrap();
        assert_eq!(header.stream_id, 5, "Reserved bit should be cleared from stream ID");
    }

    #[test]
    fn test_empty_data_frame() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // Empty DATA frame with END_STREAM (used for completing request with no body)
        let frame = vec![0, 0, 0, 0, 1, 0, 0, 0, 1]; // length 0, END_STREAM

        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::Data { stream_id, data, end_stream } => {
                assert_eq!(*stream_id, 1);
                assert!(data.is_empty());
                assert!(*end_stream);
            }
            _ => panic!("Expected Data event"),
        }
    }

    // =========================================================================
    // SETTINGS Parsing Tests (Bug 17 fix)
    // =========================================================================

    #[test]
    fn test_settings_parsing_initial_window_size() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // SETTINGS with INITIAL_WINDOW_SIZE=1048576 (1MB)
        let mut frame = vec![0, 0, 6, 4, 0, 0, 0, 0, 0]; // length=6, SETTINGS, no flags
        frame.extend_from_slice(&[0, 4]); // INITIAL_WINDOW_SIZE id
        frame.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // 1048576

        let events = codec.process(&frame).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::Settings { ack, settings } => {
                assert!(!*ack);
                assert_eq!(settings.len(), 1);
                assert_eq!(settings[0], (settings_id::INITIAL_WINDOW_SIZE, 1048576));
            }
            _ => panic!("Expected Settings event"),
        }
    }

    #[test]
    fn test_settings_parsing_max_frame_size() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // SETTINGS with MAX_FRAME_SIZE=32768
        let mut frame = vec![0, 0, 6, 4, 0, 0, 0, 0, 0];
        frame.extend_from_slice(&[0, 5]); // MAX_FRAME_SIZE id
        frame.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]); // 32768

        let events = codec.process(&frame).unwrap();
        match &events[0] {
            H2Event::Settings { settings, .. } => {
                assert_eq!(settings[0], (settings_id::MAX_FRAME_SIZE, 32768));
            }
            _ => panic!("Expected Settings event"),
        }
    }

    #[test]
    fn test_settings_parsing_multiple_settings() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // SETTINGS with INITIAL_WINDOW_SIZE + MAX_FRAME_SIZE + HEADER_TABLE_SIZE
        let mut frame = vec![0, 0, 18, 4, 0, 0, 0, 0, 0]; // length=18 (3 settings * 6)
        // HEADER_TABLE_SIZE = 8192
        frame.extend_from_slice(&[0, 1]); // id 0x1
        frame.extend_from_slice(&[0x00, 0x00, 0x20, 0x00]);
        // INITIAL_WINDOW_SIZE = 65535
        frame.extend_from_slice(&[0, 4]); // id 0x4
        frame.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
        // MAX_FRAME_SIZE = 16384
        frame.extend_from_slice(&[0, 5]); // id 0x5
        frame.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]);

        let events = codec.process(&frame).unwrap();
        match &events[0] {
            H2Event::Settings { ack, settings } => {
                assert!(!*ack);
                assert_eq!(settings.len(), 3);
                assert_eq!(settings[0], (settings_id::HEADER_TABLE_SIZE, 8192));
                assert_eq!(settings[1], (settings_id::INITIAL_WINDOW_SIZE, 65535));
                assert_eq!(settings[2], (settings_id::MAX_FRAME_SIZE, 16384));
            }
            _ => panic!("Expected Settings event"),
        }
    }

    #[test]
    fn test_settings_ack_has_empty_settings() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // SETTINGS ACK: length 0, flags ACK
        let frame = vec![0, 0, 0, 4, 1, 0, 0, 0, 0];

        let events = codec.process(&frame).unwrap();
        match &events[0] {
            H2Event::Settings { ack, settings } => {
                assert!(*ack);
                assert!(settings.is_empty());
            }
            _ => panic!("Expected Settings ACK event"),
        }
    }

    #[test]
    fn test_settings_parsing_unknown_setting_ignored() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // SETTINGS with unknown id 0xFF + known INITIAL_WINDOW_SIZE
        let mut frame = vec![0, 0, 12, 4, 0, 0, 0, 0, 0]; // length=12
        // Unknown setting 0xFF = 42
        frame.extend_from_slice(&[0, 0xFF]);
        frame.extend_from_slice(&[0, 0, 0, 42]);
        // INITIAL_WINDOW_SIZE = 65535
        frame.extend_from_slice(&[0, 4]);
        frame.extend_from_slice(&[0, 0, 0xFF, 0xFF]);

        let events = codec.process(&frame).unwrap();
        match &events[0] {
            H2Event::Settings { settings, .. } => {
                // Both settings should be present (unknown ones are passed through)
                assert_eq!(settings.len(), 2);
                assert_eq!(settings[0], (0xFF, 42));
                assert_eq!(settings[1], (settings_id::INITIAL_WINDOW_SIZE, 65535));
            }
            _ => panic!("Expected Settings event"),
        }
    }

    // =========================================================================
    // Stream Cleanup Tests (Bug 22 fix)
    // =========================================================================

    #[test]
    fn test_remove_stream_on_completion() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // Send HEADERS to create stream 1
        let mut data = vec![0, 0, 2, 1, 4, 0, 0, 0, 1]; // END_HEADERS
        data.extend_from_slice(&[0x82, 0x86]);
        codec.process(&data).unwrap();
        assert!(codec.streams.get(&1).is_some());

        // Remove stream 1
        codec.remove_stream(1);
        assert!(codec.streams.get(&1).is_none());
        assert!(!codec.streams.get(&1).map_or(false, |s| s.stream_ended));
    }

    #[test]
    fn test_remove_stream_nonexistent_is_noop() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;
        // Should not panic
        codec.remove_stream(999);
    }

    // =========================================================================
    // Codec Reset Tests (Bug 27 fix)
    // =========================================================================

    #[test]
    fn test_codec_reset_clears_all_state() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // Create some stream state
        let mut data = vec![0, 0, 2, 1, 4, 0, 0, 0, 1]; // HEADERS, END_HEADERS, stream 1
        data.extend_from_slice(&[0x82, 0x86]);
        codec.process(&data).unwrap();
        assert!(codec.streams.get(&1).is_some());

        // Reset
        codec.reset();
        assert!(!codec.preface_received);
        assert!(codec.streams.get(&1).is_none());
    }

    #[test]
    fn test_codec_reset_clears_pending_continuation() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // Send HEADERS without END_HEADERS (starts CONTINUATION accumulation)
        let mut headers_frame = vec![0, 0, 3, 1, 0, 0, 0, 0, 1]; // no END_HEADERS
        headers_frame.extend_from_slice(&[0x82, 0x86, 0x84]);
        let events = codec.process(&headers_frame).unwrap();
        assert!(events.is_empty()); // Waiting for CONTINUATION

        // Reset should clear pending state
        codec.reset();

        // After reset, a CONTINUATION should be an error (no pending headers)
        let mut cont_frame = vec![0, 0, 2, 9, 4, 0, 0, 0, 1]; // CONTINUATION, END_HEADERS
        cont_frame.extend_from_slice(&[0x41, 0x8a]);
        let result = codec.process(&cont_frame);
        assert!(result.is_err(), "CONTINUATION after reset should be unexpected");
    }

    #[test]
    fn test_codec_reset_allows_new_preface() {
        let mut codec = H2Codec::new();

        // First session: send preface + settings
        let mut data = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        data.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]); // Empty SETTINGS
        let events = codec.process(&data).unwrap();
        assert_eq!(events.len(), 1);
        assert!(codec.preface_received);

        // Reset for new session
        codec.reset();
        assert!(!codec.preface_received);

        // Second session: send new preface
        let mut data2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        data2.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        let events2 = codec.process(&data2).unwrap();
        assert_eq!(events2.len(), 1);
        assert!(codec.preface_received);
    }

    // ============= CONTINUATION frame tests =============

    #[test]
    fn test_create_continuation_frame() {
        let payload = b"test-header-block";
        let frame = H2Codec::create_continuation_frame(1, payload, false);

        // Frame header (9 bytes) + payload
        assert_eq!(frame.len(), 9 + payload.len());

        // Length field (3 bytes, big-endian)
        assert_eq!(frame[0], 0);
        assert_eq!(frame[1], 0);
        assert_eq!(frame[2], payload.len() as u8);

        // Type = CONTINUATION (0x9)
        assert_eq!(frame[3], 0x9);

        // Stream ID = 1
        assert_eq!(u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]), 1);

        // Payload
        assert_eq!(&frame[9..], payload);
    }

    #[test]
    fn test_continuation_end_headers_flag() {
        let payload = b"header-data";
        let frame_with_flag = H2Codec::create_continuation_frame(1, payload, true);
        let frame_without_flag = H2Codec::create_continuation_frame(1, payload, false);

        // END_HEADERS flag (0x4) should be set in first frame
        assert_eq!(frame_with_flag[4], 0x4);

        // No flags should be set in second frame
        assert_eq!(frame_without_flag[4], 0x0);
    }

    #[test]
    fn test_continuation_frame_empty_payload() {
        let frame = H2Codec::create_continuation_frame(1, &[], true);
        assert_eq!(frame.len(), 9); // Header only, no payload
        assert_eq!(frame[2], 0); // Length = 0
    }

    // =========================================================================
    // Phase 7: CONTINUATION Size Bound Tests
    // =========================================================================

    #[test]
    fn test_continuation_size_bound_rejects_oversized_block() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // HEADERS without END_HEADERS, large initial block (200KB)
        let initial_block = vec![0x82; 200 * 1024];
        let initial_len = initial_block.len() as u32;
        let mut data = vec![
            (initial_len >> 16) as u8,
            (initial_len >> 8) as u8,
            initial_len as u8,
            frame_type::HEADERS,
            0, // no END_HEADERS, no END_STREAM
            0, 0, 0, 1, // stream 1
        ];
        data.extend_from_slice(&initial_block);
        codec.process(&data).unwrap(); // 200KB is under 256KB limit, should succeed

        // CONTINUATION that pushes total over 256KB
        let cont_block = vec![0x86; 100 * 1024]; // 100KB more → 300KB total
        let cont_len = cont_block.len() as u32;
        let mut cont_data = vec![
            (cont_len >> 16) as u8,
            (cont_len >> 8) as u8,
            cont_len as u8,
            frame_type::CONTINUATION,
            flags::END_HEADERS,
            0, 0, 0, 1, // stream 1
        ];
        cont_data.extend_from_slice(&cont_block);

        let result = codec.process(&cont_data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Header block too large"), "Error: {}", err);
        assert!(err.contains("max 262144"), "Error should mention max size: {}", err);
    }

    #[test]
    fn test_continuation_size_bound_allows_normal_headers() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // HEADERS without END_HEADERS, small block (100 bytes)
        let mut data = vec![0, 0, 100, frame_type::HEADERS, 0, 0, 0, 0, 1];
        data.extend_from_slice(&vec![0x82; 100]);
        codec.process(&data).unwrap();

        // CONTINUATION that stays under limit (200 bytes total)
        let mut cont = vec![0, 0, 100, frame_type::CONTINUATION, flags::END_HEADERS, 0, 0, 0, 1];
        cont.extend_from_slice(&vec![0x86; 100]);
        let events = codec.process(&cont).unwrap();

        assert_eq!(events.len(), 1);
        match &events[0] {
            H2Event::Headers { header_block, .. } => {
                assert_eq!(header_block.len(), 200);
            }
            _ => panic!("Expected Headers event"),
        }
    }

    #[test]
    fn test_headers_initial_block_exceeds_limit() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // HEADERS without END_HEADERS, initial block exceeds 256KB
        let big_block = vec![0x82; 300 * 1024];
        let len = big_block.len() as u32;
        let mut data = vec![
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            frame_type::HEADERS,
            0, // no END_HEADERS
            0, 0, 0, 1,
        ];
        data.extend_from_slice(&big_block);

        let result = codec.process(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Header block too large"));
    }

    // =========================================================================
    // Phase 7: Buffer Optimization Tests
    // =========================================================================

    #[test]
    fn test_buffer_optimization_preserves_remaining_data() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // Two DATA frames concatenated
        let mut data = Vec::new();
        // Frame 1: 5 bytes "hello"
        data.extend_from_slice(&[0, 0, 5, 0, 1, 0, 0, 0, 1]); // END_STREAM
        data.extend_from_slice(b"hello");
        // Frame 2: 5 bytes "world"
        data.extend_from_slice(&[0, 0, 5, 0, 1, 0, 0, 0, 3]); // END_STREAM, stream 3
        data.extend_from_slice(b"world");

        let events = codec.process(&data).unwrap();
        assert_eq!(events.len(), 2);

        match &events[0] {
            H2Event::Data { stream_id, data, end_stream } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(data, b"hello");
                assert!(*end_stream);
            }
            _ => panic!("Expected first Data event"),
        }
        match &events[1] {
            H2Event::Data { stream_id, data, end_stream } => {
                assert_eq!(*stream_id, 3);
                assert_eq!(data, b"world");
                assert!(*end_stream);
            }
            _ => panic!("Expected second Data event"),
        }
    }

    #[test]
    fn test_buffer_optimization_large_frame() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // Large DATA frame (16KB) — typical max H2 frame size
        let payload = vec![0xAB; 16384];
        let len = payload.len() as u32;
        let mut data = vec![
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            frame_type::DATA,
            flags::END_STREAM,
            0, 0, 0, 1,
        ];
        data.extend_from_slice(&payload);

        let events = codec.process(&data).unwrap();
        assert_eq!(events.len(), 1);

        match &events[0] {
            H2Event::Data { data, .. } => {
                assert_eq!(data.len(), 16384);
                assert_eq!(data[0], 0xAB);
                assert_eq!(data[16383], 0xAB);
            }
            _ => panic!("Expected Data event"),
        }
    }

    #[test]
    fn test_buffer_empty_after_complete_consumption() {
        let mut codec = H2Codec::new();
        codec.preface_received = true;

        // Single frame, no remaining data
        let mut data = vec![0, 0, 3, 0, 1, 0, 0, 0, 1]; // DATA, END_STREAM
        data.extend_from_slice(b"abc");

        codec.process(&data).unwrap();
        assert!(codec.buffer.is_empty(), "Buffer should be empty after consuming single frame");
    }
}
