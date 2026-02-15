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
