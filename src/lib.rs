//! h2-sans-io: A minimal, sans-I/O HTTP/2 frame codec
//!
//! This crate provides a synchronous HTTP/2 frame parser and encoder designed for
//! environments that cannot use async runtimes (e.g., WebAssembly, embedded systems).
//!
//! # Features
//!
//! - **Sans-I/O Design**: No async runtime dependencies (no tokio)
//! - **Pure Rust**: No C bindings, compiles to WASM
//! - **RFC 7540 Compliant**: Handles DATA, HEADERS, CONTINUATION, SETTINGS,
//!   RST_STREAM, GOAWAY, PING, WINDOW_UPDATE frames
//! - **HPACK Support**: Header compression via fluke-hpack
//! - **Flow Control**: WINDOW_UPDATE handling and generation
//! - **CONTINUATION Assembly**: Automatic header block reassembly
//!
//! # Quick Start
//!
//! ```rust
//! use h2_sans_io::{H2Codec, H2Event};
//!
//! // Create codec for parsing incoming frames
//! let mut codec = H2Codec::new();
//!
//! // Feed raw bytes and get parsed events
//! let frame_bytes = [0, 0, 5, 0, 1, 0, 0, 0, 1, b'h', b'e', b'l', b'l', b'o'];
//! let events = codec.process(&frame_bytes).unwrap();
//!
//! for event in events {
//!     match event {
//!         H2Event::Headers { stream_id, header_block, end_stream } => {
//!             println!("Headers on stream {}: {:?} bytes", stream_id, header_block.len());
//!         }
//!         H2Event::Data { stream_id, data, end_stream } => {
//!             println!("Data on stream {}: {} bytes", stream_id, data.len());
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!
//! # Architecture
//!
//! This crate is intentionally minimal. It provides:
//! - Frame parsing (bytes → events)
//! - Frame encoding (events → bytes)
//! - HPACK wrapper (header compression)
//!
//! It does NOT provide:
//! - TCP/UDP transport (you provide the bytes)
//! - TLS (use rustls or similar)
//! - Connection management (your responsibility)
//!
//! # Use Cases
//!
//! - **Browser-based proxies**: WASM kernels that intercept HTTP/2 traffic
//! - **Embedded HTTP/2 servers**: Resource-constrained environments
//! - **Testing utilities**: Protocol testing without async complexity

pub mod h2_codec;
pub mod hpack;

pub use h2_codec::{
    H2Codec, H2Event, H2FrameHeader, StreamState,
    CONNECTION_PREFACE, MAX_HEADER_BLOCK_SIZE,
    error_code, flags, frame_type, settings_id,
    is_h2c_preface,
};

pub use hpack::{H2Header, HpackDecoder, HpackEncoder};
