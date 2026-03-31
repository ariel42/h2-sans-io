# h2-sans-io

A minimal, sans-I/O HTTP/2 frame codec for WASM and async-free environments.

## Why?

The Rust ecosystem has excellent HTTP/2 libraries ([hyperium/h2](https://github.com/hyperium/h2)), but they all require async runtimes like tokio. This makes them unsuitable for:

- **WebAssembly**: Browsers don't have tokio
- **Embedded systems**: No room for async runtimes
- **Simple use cases**: Don't need full async infrastructure

`h2-sans-io` gives you a synchronous, zero-dependency frame codec that compiles anywhere Rust does — including `wasm32-unknown-unknown`.

## Features

- **Sans-I/O Design**: You provide raw bytes, you get parsed events. No sockets, no async, no runtime.
- **Pure Rust**: Compiles to WASM with no C bindings. Optimized for size (`opt-level = "z"`, LTO enabled).
- **RFC 7540 Compliant**: Strict validation of all frame types per the HTTP/2 specification:
  - **DATA** — Stream payload with optional padding
  - **HEADERS** — Header block with optional padding and priority
  - **CONTINUATION** — Automatic multi-frame header block assembly
  - **SETTINGS** — Connection parameter negotiation with ACK handling
  - **RST_STREAM** — Stream termination with error codes
  - **GOAWAY** — Graceful connection shutdown
  - **PING** — Connection liveness and RTT measurement
  - **WINDOW_UPDATE** — Flow control window management
  - **PRIORITY** — Stream priority (parsed and validated, not acted on)
- **RFC 8441 Support**: `SETTINGS_ENABLE_CONNECT_PROTOCOL` for HTTP/2 WebSocket (extended CONNECT with `:protocol`).
- **HPACK**: Header compression via [fluke-hpack](https://crates.io/crates/fluke-hpack) with binary-safe headers (no lossy UTF-8 conversion — gRPC binary metadata preserved faithfully).
- **Flow Control**: WINDOW_UPDATE parsing and frame generation for both connection-level and stream-level windows.
- **CONTINUATION Assembly**: Automatic header block reassembly across HEADERS + CONTINUATION frames, with a configurable size limit (256 KB) and CONTINUATION interlock enforcement per RFC 7540 §6.10.
- **Connection Preface**: Automatic h2c (cleartext HTTP/2) preface detection.
- **Buffer Protection**: Bounded internal buffer (1 MB) prevents memory exhaustion from slow or malicious senders. Size checks run before copying data.
- **236 Unit Tests**: Comprehensive test suite covering RFC compliance, edge cases, error recovery, binary HPACK headers, dynamic table state, and frame builder roundtrips.

## Quick Start

```rust
use h2_sans_io::{H2Codec, H2Event};

let mut codec = H2Codec::new();
let events = codec.process(&frame_bytes).unwrap();

for event in events {
    match event {
        H2Event::Headers { stream_id, header_block, end_stream } => {
            println!("Headers on stream {}", stream_id);
        }
        H2Event::Data { stream_id, data, end_stream } => {
            println!("Data on stream {}: {} bytes", stream_id, data.len());
        }
        H2Event::Settings { ack, settings } => {
            for (id, value) in &settings {
                println!("Setting 0x{:x} = {}", id, value);
            }
        }
        H2Event::WindowUpdate { stream_id, increment } => {
            println!("Window update: stream {} += {}", stream_id, increment);
        }
        H2Event::Ping { ack, data } => {
            if !ack {
                // Echo back with ACK
                let pong = H2Codec::create_ping_ack(data);
            }
        }
        H2Event::GoAway { last_stream_id, error_code } => {
            println!("GoAway: last_stream={}, error=0x{:x}", last_stream_id, error_code);
        }
        H2Event::StreamReset { stream_id, error_code } => {
            println!("Stream {} reset with error 0x{:x}", stream_id, error_code);
        }
    }
}
```

## Encoding Frames

```rust
use h2_sans_io::H2Codec;

// RST_STREAM (cancel a stream)
let rst = H2Codec::create_rst_stream(stream_id, 0x8); // CANCEL

// WINDOW_UPDATE (connection-level flow control)
let window_update = H2Codec::create_window_update(0, 65535);

// SETTINGS ACK
let settings_ack = H2Codec::create_settings_ack();

// SETTINGS with custom initial window size + extended CONNECT (RFC 8441)
let settings = H2Codec::create_settings_with_window(1 << 20); // 1 MB window

// PING ACK (echo opaque data back)
let pong = H2Codec::create_ping_ack([1, 2, 3, 4, 5, 6, 7, 8]);

// GOAWAY (graceful shutdown)
let goaway = H2Codec::create_goaway(last_stream_id, 0x0); // NO_ERROR

// CONTINUATION (split large header blocks)
let cont = H2Codec::create_continuation_frame(stream_id, &header_block_fragment, true);

// HEADERS frame (single frame, sets END_HEADERS)
let headers = H2Codec::create_headers_frame(stream_id, &hpack_block, end_stream);

// HEADERS + CONTINUATION frames (auto-splits if block > max_frame_size)
let frames = H2Codec::create_headers_frames(stream_id, &hpack_block, end_stream, 16384);

// DATA frames (auto-splits if data > max_frame_size, END_STREAM on last)
let frames = H2Codec::create_data_frames(stream_id, &body, true, 16384);
```

## HPACK (Header Compression)

Header names and values are `Vec<u8>` to preserve binary content faithfully (e.g. gRPC `-bin` metadata suffixed headers). Use `name_str()` / `value_str()` for UTF-8 access.

```rust
use h2_sans_io::{HpackDecoder, HpackEncoder, H2Header};

// Encode headers
let mut encoder = HpackEncoder::new();
let headers = vec![
    H2Header::new(":method", "GET"),
    H2Header::new(":path", "/api/data"),
    H2Header::new("x-custom-bin", vec![0x00, 0xFF, 0x80]), // binary value
];
let encoded = encoder.encode(&headers);

// Decode headers
let mut decoder = HpackDecoder::new();
let decoded = decoder.decode(&encoded).unwrap();
assert_eq!(decoded[0].name_str().unwrap(), ":method");
assert_eq!(decoded[0].value_str().unwrap(), "GET");
// Binary values are preserved without lossy conversion
assert_eq!(decoded[2].value, vec![0x00, 0xFF, 0x80]);
```

## Error Codes

The `error_code` module provides all RFC 7540 §7 error codes as constants:

```rust
use h2_sans_io::error_code;

let rst = H2Codec::create_rst_stream(1, error_code::CANCEL);
let goaway = H2Codec::create_goaway(0, error_code::NO_ERROR);
```

Available codes: `NO_ERROR`, `PROTOCOL_ERROR`, `INTERNAL_ERROR`, `FLOW_CONTROL_ERROR`, `SETTINGS_TIMEOUT`, `STREAM_CLOSED`, `FRAME_SIZE_ERROR`, `REFUSED_STREAM`, `CANCEL`, `COMPRESSION_ERROR`, `CONNECT_ERROR`, `ENHANCE_YOUR_CALM`, `INADEQUATE_SECURITY`, `HTTP_1_1_REQUIRED`.

## Architecture

This crate is intentionally minimal. It provides:

- **Frame parsing** — raw bytes in, typed `H2Event` variants out
- **Frame encoding** — static builders for all control frame types
- **HPACK wrapper** — stateful header compression/decompression
- **Incremental parsing** — handles partial frames across multiple `process()` calls

It does **not** provide:

- TCP/TLS transport (you provide the bytes)
- Connection/stream lifecycle management
- Priority scheduling or dependency trees
- Server push (PUSH_PROMISE frames are silently ignored)

## Use Cases

- **Browser-based MITM proxies**: WASM kernels intercepting HTTP/2 traffic
- **WASM HTTP/2 clients**: Client-side HTTP/2 without server infrastructure
- **Embedded HTTP/2 servers**: Resource-constrained environments
- **Protocol testing**: Test HTTP/2 implementations without async complexity
- **Educational**: Learn how HTTP/2 framing works at the wire level

## Comparison

| Crate | Async | WASM | Scope |
|-------|-------|------|-------|
| [hyperium/h2](https://github.com/hyperium/h2) | tokio | No | Full client/server |
| **h2-sans-io** | None | Yes | Frame codec + HPACK |

## Requirements

- Rust 2021 edition (1.56+)
- Single dependency: [fluke-hpack](https://crates.io/crates/fluke-hpack) 0.3

## License

MIT
