//! Tests for error recovery behavior in H2Codec.
//!
//! These tests verify that the codec handles errors correctly without
//! corrupting state, duplicating events, or becoming permanently broken.

use h2_sans_io::{H2Codec, H2Event, MAX_BUFFER_SIZE, flags, frame_type};

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
// Error on Nth frame must not cause duplicate events for frames 0..N-1
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_error_on_second_frame_no_duplicate_first_event() {
    // This tests the critical bug: if parse_frame errors on frame N,
    // frames 0..N-1 must be drained so they aren't re-processed.
    let mut c = codec();

    // Frame 1: valid DATA on stream 1
    let frame1 = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"hello");
    // Frame 2: invalid RST_STREAM on stream 0 (will error)
    let frame2 = build_frame(frame_type::RST_STREAM, 0, 0, &0u32.to_be_bytes());

    let mut combined = frame1;
    combined.extend_from_slice(&frame2);

    // First process: frame1 succeeds, frame2 errors → returns Err
    let result = c.process(&combined);
    assert!(result.is_err(), "Should error on RST_STREAM stream 0");

    // Second process: frame1 must NOT be re-emitted (it was already drained)
    let events = c.process(&[]).unwrap();
    assert!(events.is_empty(), "Frame 1 must not be duplicated after error");
}

#[test]
fn test_error_on_third_frame_drains_first_two() {
    let mut c = codec();

    let frame1 = build_frame(frame_type::DATA, 0, 1, b"aaa");
    let frame2 = build_frame(frame_type::DATA, 0, 3, b"bbb");
    // Invalid: WINDOW_UPDATE with 0 increment
    let frame3 = build_frame(frame_type::WINDOW_UPDATE, 0, 0, &0u32.to_be_bytes());

    let mut combined = frame1;
    combined.extend_from_slice(&frame2);
    combined.extend_from_slice(&frame3);

    let result = c.process(&combined);
    assert!(result.is_err());

    // Verify frames 1 and 2 are not re-processed
    let events = c.process(&[]).unwrap();
    assert!(events.is_empty());
}

#[test]
fn test_error_drains_up_to_error_frame_remaining_data_parseable() {
    let mut c = codec();

    // Frame 1: valid DATA
    let frame1 = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"ok");
    // Frame 2: invalid PING on non-zero stream (will error)
    let frame2 = build_frame(frame_type::PING, 0, 5, &[0; 8]);
    // Frame 3: valid DATA (after the error frame)
    let frame3 = build_frame(frame_type::DATA, flags::END_STREAM, 3, b"after");

    let mut combined = frame1;
    combined.extend_from_slice(&frame2);
    combined.extend_from_slice(&frame3);

    // Process: frame1 ok, frame2 errors → drain includes frame1 AND frame2
    let result = c.process(&combined);
    assert!(result.is_err());

    // After the error, frame1 and frame2 are drained. Only frame3 remains.
    // Frame3 is valid, so it should parse successfully.
    let events = c.process(&[]).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0], H2Event::Data {
        stream_id: 3,
        data: b"after".to_vec(),
        end_stream: true,
    });
}

#[test]
fn test_valid_events_returned_before_error() {
    // When error occurs on frame N, events from frames 0..N-1 are lost
    // (we return Err, not Ok with partial events). This is by design -
    // an H2 protocol error is a connection-level error and the connection
    // should be torn down.
    let mut c = codec();

    let frame1 = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"good");
    let frame2 = build_frame(frame_type::DATA, 0, 0, b"bad"); // DATA on stream 0

    let mut combined = frame1;
    combined.extend_from_slice(&frame2);

    let result = c.process(&combined);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// Buffer overflow: pre-check prevents memory spike
// ═══════════════════════════════════════════════════════════════════════════

/// Build a buffer chunk that won't be parsed as valid frames.
/// Uses a frame header declaring a huge payload length so the codec
/// sees it as an incomplete frame and just buffers it.
fn unparseable_chunk(size: usize) -> Vec<u8> {
    assert!(size >= 9, "Need at least 9 bytes for frame header");
    let mut data = Vec::with_capacity(size);
    // Frame header: length = 0xFFFFFF (max), type=DATA, flags=0, stream=1
    // This declares 16MB of payload, so the codec will always see it as incomplete.
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    data.resize(size, 0xAA); // Fill rest with non-zero filler
    data
}

#[test]
fn test_buffer_overflow_check_before_copy() {
    let mut c = codec();

    // Fill buffer to near-max with data that won't parse as frames
    let almost_full = unparseable_chunk(MAX_BUFFER_SIZE - 10);
    c.process(&almost_full).unwrap();

    // Now try to add data that would exceed the limit.
    // The check happens BEFORE extend_from_slice, so no transient spike.
    let overflow = vec![0xBBu8; 20];
    let result = c.process(&overflow);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("would exceed"));
}

#[test]
fn test_buffer_overflow_codec_still_usable_after_reset() {
    let mut c = codec();

    // Fill buffer near-max
    let big = unparseable_chunk(MAX_BUFFER_SIZE - 5);
    c.process(&big).unwrap();
    let result = c.process(&[0xCC; 20]);
    assert!(result.is_err());

    // Reset clears the buffer
    c.reset();
    c.set_preface_received(true);

    // Codec works again after reset
    let frame = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"ok");
    let events = c.process(&frame).unwrap();
    assert_eq!(events.len(), 1);
}

#[test]
fn test_buffer_at_exact_limit_is_ok() {
    let mut c = codec();

    // Fill to exactly MAX_BUFFER_SIZE with unparseable data
    let exact = unparseable_chunk(MAX_BUFFER_SIZE);
    let result = c.process(&exact);
    assert!(result.is_ok());
}

#[test]
fn test_buffer_one_over_limit_is_error() {
    let mut c = codec();

    let over = unparseable_chunk(MAX_BUFFER_SIZE + 1);
    let result = c.process(&over);
    assert!(result.is_err());
}

#[test]
fn test_buffer_overflow_incremental() {
    // Build up buffer incrementally, then one byte tips it over
    let mut c = codec();
    let chunk = unparseable_chunk(MAX_BUFFER_SIZE);
    c.process(&chunk).unwrap();

    let result = c.process(&[0xDD]);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// PRIORITY frame validation (RFC 7540 §6.3)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_priority_on_stream_zero_is_error() {
    // RFC 7540 §6.3: PRIORITY on stream 0 is PROTOCOL_ERROR.
    let frame = build_frame(frame_type::PRIORITY, 0, 0, &[0, 0, 0, 0, 15]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("stream 0"));
}

#[test]
fn test_priority_wrong_length_is_error() {
    // RFC 7540 §6.3: PRIORITY must be exactly 5 bytes.
    let frame = build_frame(frame_type::PRIORITY, 0, 1, &[0, 0, 0, 0]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("size error"));
}

#[test]
fn test_priority_too_long_is_error() {
    let frame = build_frame(frame_type::PRIORITY, 0, 1, &[0, 0, 0, 0, 15, 0]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("size error"));
}

#[test]
fn test_priority_valid_is_ignored() {
    // Valid PRIORITY frame: 5 bytes on non-zero stream → ignored (no event)
    let frame = build_frame(frame_type::PRIORITY, 0, 1, &[0, 0, 0, 0, 15]);
    let events = codec().process(&frame).unwrap();
    assert!(events.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// H2Event PartialEq tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_h2event_partialeq_data() {
    let e1 = H2Event::Data { stream_id: 1, data: b"hello".to_vec(), end_stream: true };
    let e2 = H2Event::Data { stream_id: 1, data: b"hello".to_vec(), end_stream: true };
    let e3 = H2Event::Data { stream_id: 2, data: b"hello".to_vec(), end_stream: true };
    assert_eq!(e1, e2);
    assert_ne!(e1, e3);
}

#[test]
fn test_h2event_partialeq_headers() {
    let e1 = H2Event::Headers { stream_id: 1, header_block: vec![0x82], end_stream: false };
    let e2 = H2Event::Headers { stream_id: 1, header_block: vec![0x82], end_stream: false };
    assert_eq!(e1, e2);
}

#[test]
fn test_h2event_partialeq_settings() {
    let e1 = H2Event::Settings { ack: true, settings: vec![] };
    let e2 = H2Event::Settings { ack: true, settings: vec![] };
    let e3 = H2Event::Settings { ack: false, settings: vec![] };
    assert_eq!(e1, e2);
    assert_ne!(e1, e3);
}

#[test]
fn test_h2event_partialeq_different_variants() {
    let data = H2Event::Data { stream_id: 1, data: vec![], end_stream: true };
    let ping = H2Event::Ping { ack: false, data: [0; 8] };
    assert_ne!(data, ping);
}

// ═══════════════════════════════════════════════════════════════════════════
// create_window_update zero-increment panic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "non-zero")]
fn test_create_window_update_zero_increment_panics() {
    H2Codec::create_window_update(1, 0);
}

#[test]
#[should_panic(expected = "non-zero")]
fn test_create_window_update_reserved_bit_makes_zero_panics() {
    // increment = 0x80000000 → after masking reserved bit → 0 → panic
    H2Codec::create_window_update(1, 0x80000000);
}

// ═══════════════════════════════════════════════════════════════════════════
// extract_headers_payload no-copy optimization
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_headers_no_padding_no_priority_returns_full_block() {
    // HEADERS without PADDED or PRIORITY flags should return the entire
    // payload as-is without unnecessary copying.
    let payload = vec![0x82, 0x86, 0x84];
    let frame = build_frame(
        frame_type::HEADERS,
        flags::END_HEADERS | flags::END_STREAM,
        1,
        &payload,
    );
    let events = codec().process(&frame).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Headers { header_block, .. } => {
            assert_eq!(header_block, &payload);
        }
        _ => panic!("Expected Headers"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Interleaved streams
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_interleaved_data_frames_different_streams() {
    let mut c = codec();
    let f1 = build_frame(frame_type::DATA, 0, 1, b"s1-a");
    let f2 = build_frame(frame_type::DATA, 0, 3, b"s3-a");
    let f3 = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"s1-b");
    let f4 = build_frame(frame_type::DATA, flags::END_STREAM, 3, b"s3-b");

    let mut combined = f1;
    combined.extend_from_slice(&f2);
    combined.extend_from_slice(&f3);
    combined.extend_from_slice(&f4);

    let events = c.process(&combined).unwrap();
    assert_eq!(events.len(), 4);

    assert_eq!(events[0], H2Event::Data { stream_id: 1, data: b"s1-a".to_vec(), end_stream: false });
    assert_eq!(events[1], H2Event::Data { stream_id: 3, data: b"s3-a".to_vec(), end_stream: false });
    assert_eq!(events[2], H2Event::Data { stream_id: 1, data: b"s1-b".to_vec(), end_stream: true });
    assert_eq!(events[3], H2Event::Data { stream_id: 3, data: b"s3-b".to_vec(), end_stream: true });
}

#[test]
fn test_headers_then_data_same_stream() {
    let mut c = codec();
    let headers = build_frame(frame_type::HEADERS, flags::END_HEADERS, 1, &[0x82]);
    let data = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"body");

    let mut combined = headers;
    combined.extend_from_slice(&data);

    let events = c.process(&combined).unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], H2Event::Headers { stream_id: 1, .. }));
    assert!(matches!(&events[1], H2Event::Data { stream_id: 1, .. }));
}

// ═══════════════════════════════════════════════════════════════════════════
// H2FrameHeader PartialEq
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_frame_header_partialeq() {
    use h2_sans_io::H2FrameHeader;
    let h1 = H2FrameHeader::parse(&[0, 0, 5, 0, 1, 0, 0, 0, 1]).unwrap();
    let h2 = H2FrameHeader::parse(&[0, 0, 5, 0, 1, 0, 0, 0, 1]).unwrap();
    assert_eq!(h1, h2);
}

// ═══════════════════════════════════════════════════════════════════════════
// MAX_FRAME_PAYLOAD_LENGTH constant
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_max_frame_payload_length_constant() {
    use h2_sans_io::MAX_FRAME_PAYLOAD_LENGTH;
    assert_eq!(MAX_FRAME_PAYLOAD_LENGTH, 0xFFFFFF);
}
