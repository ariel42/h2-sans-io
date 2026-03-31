# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.1] - 2026-03-31

### Added

- `H2Codec::create_headers_frame()` for building a single HEADERS frame from a pre-encoded
  HPACK header block. Sets END_HEADERS automatically.
- `H2Codec::create_headers_frames()` for building HEADERS + CONTINUATION frames with
  automatic splitting when the header block exceeds `max_frame_size`.
- `H2Codec::create_data_frames()` for building DATA frames with automatic splitting when
  data exceeds `max_frame_size`. END_STREAM is set only on the last frame.
- 30 new tests for the frame building functions covering flags, length encoding, stream ID
  encoding, reserved bit masking, payload integrity across splits, exact boundary cases,
  empty payloads, and codec roundtrips.

### Fixed

- **Reserved bit not masked in new frame builders.** `create_headers_frame`,
  `create_headers_frames`, and `create_data_frames` now mask the reserved bit on
  `stream_id` (`& 0x7FFFFFFF`), consistent with all other frame builders in the crate.

## [0.9.0] - 2026-03-31

### Added

- `MAX_BUFFER_SIZE` constant (1 MB) to prevent unbounded buffer growth from partial frames.
- `MAX_FRAME_PAYLOAD_LENGTH` constant (0xFFFFFF) for the 24-bit frame length limit.
- `H2Header::name_str()` and `H2Header::value_str()` convenience methods for UTF-8 access.
- `PartialEq` derive on `H2Event` and `H2FrameHeader` for easier testing and comparison.
- `create_window_update` now panics on zero increment (RFC 7540 Section 6.9).
- `create_continuation_frame` now panics if payload exceeds the 24-bit max frame length.
- 131 new unit tests (207 total) across 6 new test files:
  - `rfc_compliance.rs` - RFC 7540 validation rules and create-then-parse roundtrips.
  - `edge_cases.rs` - Buffer management, padding, preface, byte-at-a-time delivery.
  - `error_recovery.rs` - Drain-on-error, buffer overflow, interleaved streams.
  - `binary_and_state.rs` - Binary HPACK headers, dynamic table state across blocks.

### Fixed

- **Critical: Duplicate events on error.** When `parse_frame` errored on the Nth frame in a
  buffer, frames 0..N-1 were not drained and would be re-processed on the next `process()` call,
  producing duplicate events. The error path now drains all consumed bytes before returning.
- **Critical: Memory spike on buffer overflow.** `process()` copied input into the internal buffer
  via `extend_from_slice` *before* checking `MAX_BUFFER_SIZE`, allowing a single oversized call
  to transiently allocate unbounded memory. The size check now runs before the copy.
- **HPACK binary data corruption.** `H2Header` used `String` fields with `from_utf8_lossy`,
  silently replacing non-UTF-8 bytes (e.g. gRPC binary metadata) with U+FFFD. Fields are now
  `Vec<u8>` to preserve all bytes faithfully.
- **22 RFC 7540 compliance violations:**
  - DATA frames on stream 0 now rejected (Section 6.1).
  - HEADERS frames on stream 0 now rejected (Section 6.2).
  - PRIORITY frames on stream 0 now rejected; payload must be exactly 5 bytes (Section 6.3).
  - RST_STREAM on stream 0 now rejected; payload must be exactly 4 bytes (Section 6.4).
  - SETTINGS on non-zero stream now rejected; ACK with non-zero payload rejected; payload
    must be a multiple of 6 bytes (Section 6.5).
  - PING on non-zero stream now rejected; payload must be exactly 8 bytes (Section 6.7).
  - GOAWAY on non-zero stream now rejected (Section 6.8).
  - WINDOW_UPDATE payload must be exactly 4 bytes; zero increment rejected (Section 6.9).
  - Non-CONTINUATION frames during header block assembly now rejected (Section 6.10).
  - Reserved bit now masked in `create_rst_stream`, `create_goaway`,
    `create_window_update`, and `create_continuation_frame`.
- **Performance: per-frame allocation in `process()`.** Replaced `split_off` + `mem::replace`
  (which allocated a new `Vec` per frame) with offset tracking and a single `drain` at the end.
- **Performance: O(n) `remove(0)` in `extract_data_payload`.** Replaced with slice indexing.
- **Performance: unnecessary copy in `extract_headers_payload`.** When no padding or priority
  stripping is needed, the owned `Vec` is now returned directly instead of copied.

### Changed

- **Breaking:** `H2Header.name` and `H2Header.value` changed from `String` to `Vec<u8>`.
  Use `name_str()` / `value_str()` for UTF-8 access.
- **Breaking:** `H2Header::new()` now accepts `impl Into<Vec<u8>>` instead of `impl Into<String>`.
  All existing `&str` call sites continue to compile without changes.

## [0.1.1] - 2026-03-30

### Added

- SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441) support for H2 WebSocket.
- `create_settings_with_window()` builder includes ENABLE_CONNECT_PROTOCOL setting.
- Comprehensive test suite for HTTP/2 codec and HPACK (76 tests).

## [0.1.0] - 2026-02-15

### Added

- Initial release: minimal sans-I/O HTTP/2 frame codec.
- Frame parsing (DATA, HEADERS, CONTINUATION, SETTINGS, RST_STREAM, GOAWAY, PING, WINDOW_UPDATE).
- Frame encoding (builders for RST_STREAM, GOAWAY, SETTINGS, PING, WINDOW_UPDATE, CONTINUATION).
- HPACK header compression via fluke-hpack wrapper.
- CONTINUATION frame assembly with MAX_HEADER_BLOCK_SIZE limit.
- Connection preface detection.
