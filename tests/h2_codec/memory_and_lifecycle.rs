//! Tests for stream memory lifecycle and the stream_count() accessor.
//!
//! Verifies that the internal `streams` HashMap grows and shrinks
//! correctly, and that callers can monitor it via `stream_count()`.

use h2_sans_io::{H2Codec, flags, frame_type};

fn build_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() as u32;
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.push((length >> 16) as u8);
    frame.push((length >> 8) as u8);
    frame.push(length as u8);
    frame.push(frame_type);
    frame.push(flags);
    let sid = stream_id & 0x7FFFFFFF;
    frame.push((sid >> 24) as u8);
    frame.push((sid >> 16) as u8);
    frame.push((sid >> 8) as u8);
    frame.push(sid as u8);
    frame.extend_from_slice(payload);
    frame
}

fn codec() -> H2Codec {
    let mut c = H2Codec::new();
    c.set_preface_received(true);
    c
}

// ═══════════════════════════════════════════════════════════════════════════
// stream_count() basic behavior
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_stream_count_initially_zero() {
    assert_eq!(codec().stream_count(), 0);
}

#[test]
fn test_stream_count_grows_with_data_frames() {
    let mut c = codec();
    let f1 = build_frame(frame_type::DATA, 0, 1, b"a");
    let f2 = build_frame(frame_type::DATA, 0, 3, b"b");
    let f3 = build_frame(frame_type::DATA, 0, 5, b"c");

    c.process(&f1).unwrap();
    assert_eq!(c.stream_count(), 1);

    c.process(&f2).unwrap();
    assert_eq!(c.stream_count(), 2);

    c.process(&f3).unwrap();
    assert_eq!(c.stream_count(), 3);
}

#[test]
fn test_stream_count_grows_with_headers_frames() {
    let mut c = codec();
    let h1 = build_frame(frame_type::HEADERS, flags::END_HEADERS, 1, &[0x82]);
    let h2 = build_frame(frame_type::HEADERS, flags::END_HEADERS, 3, &[0x82]);

    c.process(&h1).unwrap();
    assert_eq!(c.stream_count(), 1);

    c.process(&h2).unwrap();
    assert_eq!(c.stream_count(), 2);
}

#[test]
fn test_stream_count_no_double_counting() {
    let mut c = codec();
    // Two DATA frames on the same stream should not create two entries
    let f1 = build_frame(frame_type::DATA, 0, 1, b"chunk1");
    let f2 = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"chunk2");
    let mut combined = f1;
    combined.extend_from_slice(&f2);
    c.process(&combined).unwrap();
    assert_eq!(c.stream_count(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// stream_count() decreases on removal
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_stream_count_decreases_with_remove_stream() {
    let mut c = codec();
    let f1 = build_frame(frame_type::DATA, 0, 1, b"a");
    let f2 = build_frame(frame_type::DATA, 0, 3, b"b");
    let mut combined = f1;
    combined.extend_from_slice(&f2);
    c.process(&combined).unwrap();
    assert_eq!(c.stream_count(), 2);

    c.remove_stream(1);
    assert_eq!(c.stream_count(), 1);

    c.remove_stream(3);
    assert_eq!(c.stream_count(), 0);
}

#[test]
fn test_stream_count_decreases_on_rst_stream() {
    let mut c = codec();
    // Create two streams
    let h1 = build_frame(frame_type::HEADERS, flags::END_HEADERS, 1, &[0x82]);
    let h2 = build_frame(frame_type::HEADERS, flags::END_HEADERS, 3, &[0x82]);
    let mut combined = h1;
    combined.extend_from_slice(&h2);
    c.process(&combined).unwrap();
    assert_eq!(c.stream_count(), 2);

    // RST_STREAM removes the stream entry
    let rst = build_frame(frame_type::RST_STREAM, 0, 1, &0x8u32.to_be_bytes());
    c.process(&rst).unwrap();
    assert_eq!(c.stream_count(), 1);
}

#[test]
fn test_stream_count_remove_nonexistent_is_noop() {
    let mut c = codec();
    let f1 = build_frame(frame_type::DATA, 0, 1, b"a");
    c.process(&f1).unwrap();
    assert_eq!(c.stream_count(), 1);

    c.remove_stream(999); // doesn't exist
    assert_eq!(c.stream_count(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// stream_count() on reset
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_stream_count_resets_to_zero() {
    let mut c = codec();
    let f1 = build_frame(frame_type::DATA, 0, 1, b"a");
    let f2 = build_frame(frame_type::DATA, 0, 3, b"b");
    let f3 = build_frame(frame_type::DATA, 0, 5, b"c");
    let mut combined = f1;
    combined.extend_from_slice(&f2);
    combined.extend_from_slice(&f3);
    c.process(&combined).unwrap();
    assert_eq!(c.stream_count(), 3);

    c.reset();
    assert_eq!(c.stream_count(), 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Many streams stress test
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_many_streams_tracked_and_cleaned() {
    let mut c = codec();
    // Open 50 streams (odd IDs, as per HTTP/2 client-initiated)
    for i in 0..50 {
        let stream_id = i * 2 + 1;
        let f = build_frame(frame_type::HEADERS, flags::END_HEADERS, stream_id, &[0x82]);
        c.process(&f).unwrap();
    }
    assert_eq!(c.stream_count(), 50);

    // Remove them all
    for i in 0..50 {
        c.remove_stream(i * 2 + 1);
    }
    assert_eq!(c.stream_count(), 0);
}

#[test]
fn test_stream_count_after_headers_then_data() {
    let mut c = codec();
    // HEADERS on stream 1
    let h = build_frame(frame_type::HEADERS, flags::END_HEADERS, 1, &[0x82]);
    c.process(&h).unwrap();
    assert_eq!(c.stream_count(), 1);

    // DATA on same stream — should NOT increase count
    let d = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"body");
    c.process(&d).unwrap();
    assert_eq!(c.stream_count(), 1);
}
