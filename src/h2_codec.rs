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
    pub const ENABLE_CONNECT_PROTOCOL: u16 = 0x8;
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

/// Maximum length value encodable in the 24-bit frame length field.
pub const MAX_FRAME_PAYLOAD_LENGTH: u32 = 0xFFFFFF; // 16,777,215

/// A parsed HTTP/2 frame header (9 bytes)
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, PartialEq)]
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

/// Maximum buffer size (1 MB).
/// Prevents unbounded memory growth from slow/partial frame delivery.
pub const MAX_BUFFER_SIZE: usize = 1024 * 1024;

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
        // Guard against unbounded buffer growth BEFORE copying data in.
        // Check prospective size to avoid transient memory spike.
        let prospective_size = self.buffer.len() + data.len();
        if prospective_size > MAX_BUFFER_SIZE {
            return Err(format!(
                "Buffer size {} would exceed maximum {}",
                prospective_size, MAX_BUFFER_SIZE
            ));
        }
        self.buffer.extend_from_slice(data);

        let mut events = Vec::new();

        // Check for connection preface (client sends this first)
        if !self.preface_received && self.buffer.len() >= CONNECTION_PREFACE.len()
            && &self.buffer[..CONNECTION_PREFACE.len()] == CONNECTION_PREFACE
        {
                self.buffer.drain(..CONNECTION_PREFACE.len());
                self.preface_received = true;
        }

        // Parse frames using offset tracking to avoid per-frame allocation.
        // On error, we drain consumed bytes first so already-parsed frames
        // are not re-processed on the next call (prevents duplicate events).
        let mut offset = 0;
        loop {
            let remaining = &self.buffer[offset..];

            // Need at least 9 bytes for frame header
            if remaining.len() < 9 {
                break;
            }

            let header = match H2FrameHeader::parse(remaining) {
                Some(h) => h,
                None => break,
            };

            // Check if we have the complete frame
            let total_size = header.total_size();
            if remaining.len() < total_size {
                break;
            }

            // Extract payload as a slice, then copy only what we need
            let payload = remaining[9..total_size].to_vec();
            offset += total_size;

            // Parse the frame. On error, drain consumed bytes first to avoid
            // re-processing already-parsed frames on the next process() call.
            match self.parse_frame(&header, payload) {
                Ok(Some(event)) => events.push(event),
                Ok(None) => {}
                Err(e) => {
                    if offset > 0 {
                        self.buffer.drain(..offset);
                    }
                    return Err(e);
                }
            }
        }

        // Drain consumed bytes once
        if offset > 0 {
            self.buffer.drain(..offset);
        }

        Ok(events)
    }

    /// Parse a single frame and return an event if applicable
    fn parse_frame(&mut self, header: &H2FrameHeader, payload: Vec<u8>) -> Result<Option<H2Event>, String> {
        // RFC 7540 Section 6.10: While a header block is pending (between HEADERS
        // without END_HEADERS and the final CONTINUATION with END_HEADERS), no other
        // frame type may be received on ANY stream except CONTINUATION on the same stream.
        if let Some(pending_stream) = self.pending_headers_stream {
            if header.frame_type != frame_type::CONTINUATION {
                return Err(format!(
                    "Received frame type {} while CONTINUATION expected for stream {}",
                    header.frame_type, pending_stream
                ));
            }
        }

        match header.frame_type {
            frame_type::DATA => {
                // RFC 7540 Section 6.1: DATA frames MUST be associated with a stream.
                if header.stream_id == 0 {
                    return Err("DATA frame on stream 0".to_string());
                }
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
                // RFC 7540 Section 6.2: HEADERS frames MUST be associated with a stream.
                if header.stream_id == 0 {
                    return Err("HEADERS frame on stream 0".to_string());
                }
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
                // RFC 7540 Section 6.4: RST_STREAM MUST NOT be sent for stream 0.
                if header.stream_id == 0 {
                    return Err("RST_STREAM frame on stream 0".to_string());
                }
                // RFC 7540 Section 6.4: RST_STREAM must have exactly 4 bytes.
                if payload.len() != 4 {
                    return Err(format!(
                        "RST_STREAM frame size error: expected 4 bytes, got {}",
                        payload.len()
                    ));
                }
                let error_code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                self.streams.remove(&header.stream_id);
                Ok(Some(H2Event::StreamReset {
                    stream_id: header.stream_id,
                    error_code,
                }))
            }
            frame_type::SETTINGS => {
                // RFC 7540 Section 6.5: SETTINGS frames always apply to a connection,
                // never a single stream. Stream ID MUST be 0.
                if header.stream_id != 0 {
                    return Err("SETTINGS frame on non-zero stream".to_string());
                }
                let ack = header.flags & 0x1 != 0;
                if ack {
                    // RFC 7540 Section 6.5: SETTINGS ACK must have payload length 0.
                    if header.length != 0 {
                        return Err(format!(
                            "SETTINGS ACK with non-zero length: {}",
                            header.length
                        ));
                    }
                    return Ok(Some(H2Event::Settings { ack: true, settings: Vec::new() }));
                }
                // RFC 7540 Section 6.5: Payload must be a multiple of 6 bytes.
                if !payload.len().is_multiple_of(6) {
                    return Err(format!(
                        "SETTINGS frame size error: payload length {} is not a multiple of 6",
                        payload.len()
                    ));
                }
                let mut settings = Vec::new();
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
                Ok(Some(H2Event::Settings { ack, settings }))
            }
            frame_type::GOAWAY => {
                // RFC 7540 Section 6.8: GOAWAY must be on stream 0.
                if header.stream_id != 0 {
                    return Err("GOAWAY frame on non-zero stream".to_string());
                }
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
                // RFC 7540 Section 6.9: WINDOW_UPDATE must have exactly 4 bytes.
                if payload.len() != 4 {
                    return Err(format!(
                        "WINDOW_UPDATE frame size error: expected 4 bytes, got {}",
                        payload.len()
                    ));
                }
                let increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7FFFFFFF;
                // RFC 7540 Section 6.9.1: increment of 0 MUST be treated as
                // PROTOCOL_ERROR for streams, FLOW_CONTROL_ERROR for connection.
                if increment == 0 {
                    return Err(format!(
                        "WINDOW_UPDATE with zero increment on stream {}",
                        header.stream_id
                    ));
                }
                Ok(Some(H2Event::WindowUpdate {
                    stream_id: header.stream_id,
                    increment,
                }))
            }
            frame_type::PING => {
                // RFC 7540 Section 6.7: PING must be on stream 0.
                if header.stream_id != 0 {
                    return Err("PING frame on non-zero stream".to_string());
                }
                // RFC 7540 Section 6.7: PING must have exactly 8 bytes.
                if payload.len() != 8 {
                    return Err(format!(
                        "PING frame size error: expected 8 bytes, got {}",
                        payload.len()
                    ));
                }
                let ack = header.flags & 0x1 != 0;
                let mut data = [0u8; 8];
                data.copy_from_slice(&payload[..8]);
                Ok(Some(H2Event::Ping { ack, data }))
            }
            frame_type::PRIORITY => {
                // RFC 7540 Section 6.3: PRIORITY on stream 0 is PROTOCOL_ERROR.
                if header.stream_id == 0 {
                    return Err("PRIORITY frame on stream 0".to_string());
                }
                // RFC 7540 Section 6.3: PRIORITY must have exactly 5 bytes.
                if payload.len() != 5 {
                    return Err(format!(
                        "PRIORITY frame size error: expected 5 bytes, got {}",
                        payload.len()
                    ));
                }
                // Ignore PRIORITY frames (no event emitted)
                Ok(None)
            }
            frame_type::PUSH_PROMISE => {
                // We don't support server push in the proxy
                Ok(None)
            }
            _ => {
                // Unknown frame type - ignore per RFC 7540 Section 4.1
                Ok(None)
            }
        }
    }

    /// Extract DATA payload, handling PADDED flag.
    fn extract_data_payload(&self, header: &H2FrameHeader, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        if header.flags & flags::PADDED != 0 {
            if payload.is_empty() {
                return Err("PADDED DATA frame with no payload".to_string());
            }
            let pad_length = payload[0] as usize;
            // RFC 7540 Section 6.1: padding length must be less than the
            // frame payload length (pad_length byte + data + padding must fit).
            if 1 + pad_length > payload.len() {
                return Err("Invalid padding length in DATA frame".to_string());
            }
            let data_end = payload.len() - pad_length;
            Ok(payload[1..data_end].to_vec())
        } else {
            Ok(payload)
        }
    }

    /// Extract HEADERS payload, handling PADDED and PRIORITY flags.
    fn extract_headers_payload(&self, header: &H2FrameHeader, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        let mut offset = 0;
        let mut end = payload.len();

        // Handle PADDED flag
        if header.flags & flags::PADDED != 0 {
            if payload.is_empty() {
                return Err("PADDED HEADERS frame with no payload".to_string());
            }
            let pad_length = payload[0] as usize;
            offset = 1;
            if pad_length > payload.len() - offset {
                return Err("Invalid padding length in HEADERS frame".to_string());
            }
            end = payload.len() - pad_length;
        }

        // Handle PRIORITY flag
        if header.flags & flags::PRIORITY != 0 {
            if end - offset < 5 {
                return Err("PRIORITY HEADERS frame with insufficient data".to_string());
            }
            offset += 5; // Skip stream dependency (4 bytes) + weight (1 byte)
        }

        // Avoid unnecessary copy when no stripping is needed
        if offset == 0 && end == payload.len() {
            return Ok(payload);
        }

        Ok(payload[offset..end].to_vec())
    }

    /// Remove a stream (e.g., after completing a flow)
    pub fn remove_stream(&mut self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

    /// Return the number of tracked streams.
    ///
    /// This is useful for monitoring memory usage: the codec stores a small
    /// `StreamState` entry per active stream ID. Callers are responsible for
    /// calling `remove_stream()` once a stream is fully done; otherwise the
    /// map grows without bound over the life of a connection.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
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

    /// Set preface_received flag (for testing)
    /// This is useful in tests to simulate a connection where the preface has already been received.
    pub fn set_preface_received(&mut self, value: bool) {
        self.preface_received = value;
    }

    /// Get preface_received flag (for testing)
    pub fn preface_received(&self) -> bool {
        self.preface_received
    }

    /// Create a RST_STREAM frame
    pub fn create_rst_stream(stream_id: u32, error_code: u32) -> Vec<u8> {
        let stream_id = stream_id & 0x7FFFFFFF; // Clear reserved bit
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
        let last_stream_id = last_stream_id & 0x7FFFFFFF; // Clear reserved bit
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

    /// Create a SETTINGS frame with larger initial window size and RFC 8441 extended CONNECT.
    /// - INITIAL_WINDOW_SIZE: allows peer to send more data before WINDOW_UPDATE
    /// - ENABLE_CONNECT_PROTOCOL: lets browsers use H2 WebSocket (extended CONNECT with :protocol)
    #[allow(dead_code)]
    pub fn create_settings_with_window(initial_window_size: u32) -> Vec<u8> {
        // SETTINGS frame with two settings (6 bytes each = 12 bytes total)
        let mut frame = vec![
            0, 0, 12, // Length: 12 bytes (two settings)
            frame_type::SETTINGS,
            0x0,      // Flags: 0 (not ACK)
            0, 0, 0, 0,  // Stream ID: 0
        ];
        // SETTINGS_INITIAL_WINDOW_SIZE = 0x4
        frame.push(0);
        frame.push(4);
        frame.push((initial_window_size >> 24) as u8);
        frame.push((initial_window_size >> 16) as u8);
        frame.push((initial_window_size >> 8) as u8);
        frame.push(initial_window_size as u8);
        // SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x8, value = 1 (RFC 8441)
        frame.push(0);
        frame.push(8);
        frame.push(0);
        frame.push(0);
        frame.push(0);
        frame.push(1);
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

    /// Create a WINDOW_UPDATE frame to replenish flow control window.
    /// stream_id=0 updates connection-level window, otherwise stream-level.
    ///
    /// # Panics
    /// Panics if `increment` is 0 (after masking the reserved bit), because
    /// RFC 7540 §6.9 requires a non-zero window size increment.
    pub fn create_window_update(stream_id: u32, increment: u32) -> Vec<u8> {
        let stream_id = stream_id & 0x7FFFFFFF; // Clear reserved bit
        let increment = increment & 0x7FFFFFFF; // Clear reserved bit
        assert!(increment != 0, "WINDOW_UPDATE increment must be non-zero (RFC 7540 §6.9)");
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

    /// Create a CONTINUATION frame to continue a header block.
    /// end_headers: true if this is the final frame in the header block sequence.
    ///
    /// # Panics
    /// Panics if `payload` length exceeds the maximum 24-bit frame length (16,777,215).
    pub fn create_continuation_frame(stream_id: u32, payload: &[u8], end_headers: bool) -> Vec<u8> {
        assert!(
            payload.len() <= MAX_FRAME_PAYLOAD_LENGTH as usize,
            "Payload length {} exceeds maximum frame payload length {}",
            payload.len(), MAX_FRAME_PAYLOAD_LENGTH
        );
        let stream_id = stream_id & 0x7FFFFFFF; // Clear reserved bit
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

    /// Create a single HEADERS frame from a pre-encoded HPACK header block.
    ///
    /// Sets END_HEADERS. Does NOT handle splitting across CONTINUATION frames —
    /// use `create_headers_frames` for that.
    ///
    /// # Panics
    /// Panics if `header_block` length exceeds the maximum 24-bit frame length (16,777,215).
    pub fn create_headers_frame(stream_id: u32, header_block: &[u8], end_stream: bool) -> Vec<u8> {
        assert!(
            header_block.len() <= MAX_FRAME_PAYLOAD_LENGTH as usize,
            "Header block length {} exceeds maximum frame payload length {}",
            header_block.len(), MAX_FRAME_PAYLOAD_LENGTH
        );
        let stream_id = stream_id & 0x7FFFFFFF; // Clear reserved bit
        let length = header_block.len();
        let mut flags_byte = flags::END_HEADERS;
        if end_stream {
            flags_byte |= flags::END_STREAM;
        }

        let mut frame = Vec::with_capacity(9 + length);
        frame.push((length >> 16) as u8);
        frame.push((length >> 8) as u8);
        frame.push(length as u8);
        frame.push(frame_type::HEADERS);
        frame.push(flags_byte);
        frame.extend_from_slice(&stream_id.to_be_bytes());
        frame.extend_from_slice(header_block);
        frame
    }

    /// Create HEADERS frame(s) from a pre-encoded HPACK header block,
    /// splitting into HEADERS + CONTINUATION frames if the block exceeds `max_frame_size`.
    ///
    /// # Panics
    /// Panics if `max_frame_size` exceeds the maximum 24-bit frame length (16,777,215).
    pub fn create_headers_frames(stream_id: u32, header_block: &[u8], end_stream: bool, max_frame_size: u32) -> Vec<Vec<u8>> {
        assert!(
            max_frame_size <= MAX_FRAME_PAYLOAD_LENGTH,
            "max_frame_size {} exceeds maximum frame payload length {}",
            max_frame_size, MAX_FRAME_PAYLOAD_LENGTH
        );
        let stream_id = stream_id & 0x7FFFFFFF; // Clear reserved bit
        if header_block.len() <= max_frame_size as usize {
            return vec![Self::create_headers_frame(stream_id, header_block, end_stream)];
        }

        let mut frames = Vec::new();
        let mut remaining = header_block;
        let mut is_first = true;

        while !remaining.is_empty() {
            let chunk_size = remaining.len().min(max_frame_size as usize);
            let chunk = &remaining[..chunk_size];
            remaining = &remaining[chunk_size..];

            if is_first {
                // HEADERS without END_HEADERS
                let mut flags_byte = 0x0;
                if end_stream {
                    flags_byte |= flags::END_STREAM;
                }

                let mut frame = Vec::with_capacity(9 + chunk.len());
                frame.push((chunk_size >> 16) as u8);
                frame.push((chunk_size >> 8) as u8);
                frame.push(chunk_size as u8);
                frame.push(frame_type::HEADERS);
                frame.push(flags_byte);
                frame.extend_from_slice(&stream_id.to_be_bytes());
                frame.extend_from_slice(chunk);
                frames.push(frame);
                is_first = false;
            } else {
                let is_last = remaining.is_empty();
                frames.push(Self::create_continuation_frame(stream_id, chunk, is_last));
            }
        }

        frames
    }

    /// Create DATA frame(s), splitting into multiple frames if `data` exceeds `max_frame_size`.
    /// END_STREAM is set only on the last frame (when `end_stream` is true).
    ///
    /// # Panics
    /// Panics if `max_frame_size` exceeds the maximum 24-bit frame length (16,777,215).
    pub fn create_data_frames(stream_id: u32, data: &[u8], end_stream: bool, max_frame_size: u32) -> Vec<Vec<u8>> {
        assert!(
            max_frame_size <= MAX_FRAME_PAYLOAD_LENGTH,
            "max_frame_size {} exceeds maximum frame payload length {}",
            max_frame_size, MAX_FRAME_PAYLOAD_LENGTH
        );
        let stream_id = stream_id & 0x7FFFFFFF; // Clear reserved bit
        if data.len() <= max_frame_size as usize {
            let length = data.len() as u32;
            let flags_byte = if end_stream { flags::END_STREAM } else { 0 };

            let mut frame = Vec::with_capacity(9 + data.len());
            frame.push((length >> 16) as u8);
            frame.push((length >> 8) as u8);
            frame.push(length as u8);
            frame.push(frame_type::DATA);
            frame.push(flags_byte);
            frame.extend_from_slice(&stream_id.to_be_bytes());
            frame.extend_from_slice(data);
            return vec![frame];
        }

        let mut frames = Vec::new();
        let mut remaining = data;

        while !remaining.is_empty() {
            let chunk_size = remaining.len().min(max_frame_size as usize);
            let chunk = &remaining[..chunk_size];
            remaining = &remaining[chunk_size..];

            let is_last = remaining.is_empty();
            let flags_byte = if is_last && end_stream { flags::END_STREAM } else { 0 };

            let mut frame = Vec::with_capacity(9 + chunk.len());
            frame.push((chunk_size >> 16) as u8);
            frame.push((chunk_size >> 8) as u8);
            frame.push(chunk_size as u8);
            frame.push(frame_type::DATA);
            frame.push(flags_byte);
            frame.extend_from_slice(&stream_id.to_be_bytes());
            frame.extend_from_slice(chunk);
            frames.push(frame);
        }

        frames
    }
}
