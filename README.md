# h2-sans-io

A minimal, sans-I/O HTTP/2 frame codec for WASM and async-free environments.

## Why?

The Rust ecosystem has excellent HTTP/2 libraries ([hyperium/h2](https://github.com/hyperium/h2)), but they all require async runtimes like tokio. This makes them unsuitable for:

- **WebAssembly**: Browsers don't have tokio
- **Embedded systems**: No room for async runtimes
- **Simple use cases**: Don't need full async infrastructure

## Features

- **Sans-I/O Design**: No async dependencies
- **Pure Rust**: Compiles to WASM, no C bindings
- **RFC 7540 Compliant**:
  - DATA, HEADERS, CONTINUATION, SETTINGS frames
  - RST_STREAM, GOAWAY, PING, WINDOW_UPDATE
- **HPACK**: Header compression via [fluke-hpack](https://crates.io/crates/fluke-hpack)
- **Flow Control**: WINDOW_UPDATE handling and generation
- **CONTINUATION Assembly**: Automatic header block reassembly
- **Connection Preface**: h2c (cleartext) detection

## Quick Start

```rust
use h2_sans_io::{H2Codec, H2Event};

// Parse HTTP/2 frames
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
            println!("SETTINGS ACK: {}", ack);
        }
        _ => {}
    }
}
```

## Encode Frames

```rust
use h2_sans_io::H2Codec;

// Create frames to send
let rst = H2Codec::create_rst_stream(stream_id, 0x8); // CANCEL
let window_update = H2Codec::create_window_update(0, 65535); // Connection-level
let settings_ack = H2Codec::create_settings_ack();
```

## HPACK (Header Compression)

```rust
use h2_sans_io::{HpackDecoder, HpackEncoder, H2Header};

// Encode headers
let mut encoder = HpackEncoder::new();
let headers = vec![
    H2Header::new(":method", "GET"),
    H2Header::new(":path", "/"),
];
let encoded = encoder.encode(&headers);

// Decode headers
let mut decoder = HpackDecoder::new();
let decoded = decoder.decode(&encoded).unwrap();
```

## Use Cases

- **Browser-based MITM proxies**: Intercept HTTP/2 traffic in the browser
- **WASM HTTP/2 clients**: Client-side HTTP/2 without servers
- **Embedded servers**: Resource-constrained environments
- **Testing**: Protocol testing without async complexity

## Comparison

| Crate | Async | WASM | Scope |
|-------|-------|------|-------|
| hyperium/h2 | tokio | No | Full client/server |
| this crate | None | Yes | Frame codec only |

## Requirements

- Rust 1.56+
- No external dependencies (just fluke-hpack)

## License

MIT
