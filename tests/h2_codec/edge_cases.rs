//! Edge-case and security tests for H2Codec.
//!
//! Tests for buffer management, resource limits, boundary conditions,
//! and adversarial inputs.

use h2_sans_io::{H2Codec, H2Event, MAX_HEADER_BLOCK_SIZE, MAX_BUFFER_SIZE, flags, frame_type, is_h2c_preface, CONNECTION_PREFACE};

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
// Buffer management
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_process_empty_input() {
    let events = codec().process(&[]).unwrap();
    assert!(events.is_empty());
}

#[test]
fn test_process_partial_header_buffered() {
    let mut c = codec();
    // Send only 5 bytes of a 9-byte frame header
    let events = c.process(&[0, 0, 5, 0, 1]).unwrap();
    assert!(events.is_empty());

    // Complete the header + payload
    let events = c.process(&[0, 0, 0, 1, b'h', b'e', b'l', b'l', b'o']).unwrap();
    assert_eq!(events.len(), 1);
}

#[test]
fn test_process_partial_payload_buffered() {
    let mut c = codec();
    // Frame header says length=10 but we only provide 5 payload bytes
    let mut data = vec![0, 0, 10, frame_type::DATA, flags::END_STREAM, 0, 0, 0, 1];
    data.extend_from_slice(b"hello"); // 5 of 10 bytes
    let events = c.process(&data).unwrap();
    assert!(events.is_empty());

    // Provide remaining 5 bytes
    let events = c.process(b"world").unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Data { data, .. } => assert_eq!(data, b"helloworld"),
        _ => panic!("Expected Data"),
    }
}

#[test]
fn test_multiple_frames_single_call() {
    let mut c = codec();
    let frame1 = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"aaa");
    let frame2 = build_frame(frame_type::DATA, flags::END_STREAM, 3, b"bbb");
    let mut combined = frame1;
    combined.extend_from_slice(&frame2);
    let events = c.process(&combined).unwrap();
    assert_eq!(events.len(), 2);
}

#[test]
fn test_buffer_limit_exceeded() {
    let mut c = codec();
    // Feed data exceeding MAX_BUFFER_SIZE without completing a frame
    let big_chunk = vec![0xAAu8; MAX_BUFFER_SIZE + 1];
    let result = c.process(&big_chunk);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("would exceed"));
}

#[test]
fn test_buffer_consumed_after_processing() {
    let mut c = codec();
    let frame = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"hello");
    c.process(&frame).unwrap();
    // Process empty data — should return nothing and not re-emit
    let events = c.process(&[]).unwrap();
    assert!(events.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Connection preface handling
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_preface_consumed_before_frames() {
    let mut c = H2Codec::new(); // preface NOT received
    let mut data = CONNECTION_PREFACE.to_vec();
    // Append a SETTINGS frame (typical after preface)
    data.extend_from_slice(&build_frame(frame_type::SETTINGS, 0, 0, &[]));
    let events = c.process(&data).unwrap();
    assert!(c.preface_received());
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], H2Event::Settings { .. }));
}

#[test]
fn test_preface_not_consumed_when_already_received() {
    let mut c = codec(); // preface already received
    // Feed raw preface bytes — they should be treated as frame data, not stripped
    let result = c.process(CONNECTION_PREFACE);
    // The preface bytes don't form a valid frame header, so nothing emitted
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_preface_partial_then_complete() {
    let mut c = H2Codec::new();
    // Send first half of preface
    let half = CONNECTION_PREFACE.len() / 2;
    let events = c.process(&CONNECTION_PREFACE[..half]).unwrap();
    assert!(events.is_empty());
    assert!(!c.preface_received());

    // Send rest of preface
    let events = c.process(&CONNECTION_PREFACE[half..]).unwrap();
    assert!(events.is_empty());
    assert!(c.preface_received());
}

#[test]
fn test_is_h2c_preface_valid() {
    assert!(is_h2c_preface(CONNECTION_PREFACE));
}

#[test]
fn test_is_h2c_preface_with_extra_data() {
    let mut data = CONNECTION_PREFACE.to_vec();
    data.extend_from_slice(b"extra");
    assert!(is_h2c_preface(&data));
}

#[test]
fn test_is_h2c_preface_too_short() {
    assert!(!is_h2c_preface(&CONNECTION_PREFACE[..10]));
}

#[test]
fn test_is_h2c_preface_wrong_data() {
    assert!(!is_h2c_preface(b"GET / HTTP/1.1\r\n\r\n12345678"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Codec reset
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_reset_clears_buffer() {
    let mut c = codec();
    // Feed partial frame
    c.process(&[0, 0, 100, 0, 0, 0, 0, 0, 1]).unwrap();
    c.reset();
    // After reset, buffer should be empty — no leftover processing
    let events = c.process(&[]).unwrap();
    assert!(events.is_empty());
    assert!(!c.preface_received());
}

#[test]
fn test_reset_during_continuation() {
    let mut c = codec();
    // Start header block
    let headers = build_frame(frame_type::HEADERS, 0, 1, &[0x82]);
    c.process(&headers).unwrap();

    c.reset();
    c.set_preface_received(true);

    // After reset, CONTINUATION should fail (no pending headers)
    let cont = build_frame(frame_type::CONTINUATION, flags::END_HEADERS, 1, &[0x83]);
    let result = c.process(&cont);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Unexpected CONTINUATION"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Stream state
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_end_stream_flag_tracked() {
    let mut c = codec();
    // DATA with END_STREAM
    let frame = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"fin");
    let events = c.process(&frame).unwrap();
    match &events[0] {
        H2Event::Data { end_stream, .. } => assert!(*end_stream),
        _ => panic!("Expected Data"),
    }
}

#[test]
fn test_data_without_end_stream() {
    let frame = build_frame(frame_type::DATA, 0, 1, b"partial");
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Data { end_stream, .. } => assert!(!*end_stream),
        _ => panic!("Expected Data"),
    }
}

#[test]
fn test_multiple_data_frames_same_stream() {
    let mut c = codec();
    let f1 = build_frame(frame_type::DATA, 0, 1, b"chunk1");
    let f2 = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"chunk2");
    let mut combined = f1;
    combined.extend_from_slice(&f2);
    let events = c.process(&combined).unwrap();
    assert_eq!(events.len(), 2);
    match &events[0] {
        H2Event::Data { end_stream, data, .. } => {
            assert!(!*end_stream);
            assert_eq!(data, b"chunk1");
        }
        _ => panic!("Expected Data"),
    }
    match &events[1] {
        H2Event::Data { end_stream, data, .. } => {
            assert!(*end_stream);
            assert_eq!(data, b"chunk2");
        }
        _ => panic!("Expected Data"),
    }
}

#[test]
fn test_remove_stream() {
    let mut c = codec();
    let frame = build_frame(frame_type::DATA, flags::END_STREAM, 7, b"x");
    c.process(&frame).unwrap();
    c.remove_stream(7);
    // Removing again is a no-op
    c.remove_stream(7);
}

// ═══════════════════════════════════════════════════════════════════════════
// Empty and zero-length frames
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_empty_data_frame() {
    let frame = build_frame(frame_type::DATA, flags::END_STREAM, 1, &[]);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Data { data, .. } => assert!(data.is_empty()),
        _ => panic!("Expected Data"),
    }
}

#[test]
fn test_empty_headers_frame() {
    let frame = build_frame(frame_type::HEADERS, flags::END_HEADERS | flags::END_STREAM, 1, &[]);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Headers { header_block, .. } => assert!(header_block.is_empty()),
        _ => panic!("Expected Headers"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Unknown and ignored frames
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_unknown_frame_type_ignored() {
    let frame = build_frame(0xFF, 0, 1, b"unknown data");
    let events = codec().process(&frame).unwrap();
    assert!(events.is_empty());
}

#[test]
fn test_priority_frame_ignored() {
    // PRIORITY: 5 bytes (4 byte stream dep + 1 byte weight)
    let frame = build_frame(frame_type::PRIORITY, 0, 1, &[0, 0, 0, 0, 15]);
    let events = codec().process(&frame).unwrap();
    assert!(events.is_empty());
}

#[test]
fn test_push_promise_ignored() {
    let frame = build_frame(frame_type::PUSH_PROMISE, 0, 1, &[0, 0, 0, 2, 0x82]);
    let events = codec().process(&frame).unwrap();
    assert!(events.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Frame header parsing edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_frame_header_parse_too_few_bytes() {
    use h2_sans_io::H2FrameHeader;
    assert!(H2FrameHeader::parse(&[0; 8]).is_none());
    assert!(H2FrameHeader::parse(&[]).is_none());
}

#[test]
fn test_frame_header_max_length() {
    use h2_sans_io::H2FrameHeader;
    // Max 24-bit length: 0xFFFFFF = 16,777,215
    let data = [0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0];
    let h = H2FrameHeader::parse(&data).unwrap();
    assert_eq!(h.length, 0xFFFFFF);
    assert_eq!(h.total_size(), 9 + 0xFFFFFF);
}

#[test]
fn test_frame_header_stream_id_reserved_bit() {
    use h2_sans_io::H2FrameHeader;
    // Stream ID with reserved bit set: 0x80000001
    let data = [0, 0, 0, 0, 0, 0x80, 0x00, 0x00, 0x01];
    let h = H2FrameHeader::parse(&data).unwrap();
    assert_eq!(h.stream_id, 1, "Reserved bit should be masked off");
}

// ═══════════════════════════════════════════════════════════════════════════
// Padded HEADERS edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_headers_padded_exact_padding() {
    // pad_length=3, header_block=[0x82], padding=[0,0,0]
    let payload = vec![3, 0x82, 0, 0, 0];
    let frame = build_frame(frame_type::HEADERS, flags::END_HEADERS | flags::PADDED, 1, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Headers { header_block, .. } => assert_eq!(header_block, &[0x82]),
        _ => panic!("Expected Headers"),
    }
}

#[test]
fn test_headers_padded_zero_padding() {
    // pad_length=0, just header data
    let payload = vec![0, 0x82, 0x86];
    let frame = build_frame(frame_type::HEADERS, flags::END_HEADERS | flags::PADDED, 1, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Headers { header_block, .. } => assert_eq!(header_block, &[0x82, 0x86]),
        _ => panic!("Expected Headers"),
    }
}

#[test]
fn test_headers_padded_exceeds_remaining() {
    // pad_length=100, but only 2 bytes remain after pad_length
    let payload = vec![100, 0x82, 0x86];
    let frame = build_frame(frame_type::HEADERS, flags::END_HEADERS | flags::PADDED, 1, &payload);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("padding"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Padded DATA edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_data_padded_zero_data_bytes() {
    // pad_length=3, no data, padding=[0,0,0]
    let payload = vec![3, 0, 0, 0];
    let frame = build_frame(frame_type::DATA, flags::PADDED | flags::END_STREAM, 1, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Data { data, .. } => assert!(data.is_empty()),
        _ => panic!("Expected Data"),
    }
}

#[test]
fn test_data_padded_zero_padding() {
    // pad_length=0
    let payload = vec![0, b'h', b'i'];
    let frame = build_frame(frame_type::DATA, flags::PADDED | flags::END_STREAM, 1, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Data { data, .. } => assert_eq!(data, b"hi"),
        _ => panic!("Expected Data"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// GOAWAY reserved bit masking
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_goaway_last_stream_id_reserved_bit_masked() {
    // last_stream_id with reserved bit set
    let mut payload = Vec::new();
    payload.extend_from_slice(&0x80000005u32.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    let frame = build_frame(frame_type::GOAWAY, 0, 0, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::GoAway { last_stream_id, .. } => {
            assert_eq!(*last_stream_id, 5);
        }
        _ => panic!("Expected GoAway"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Byte-at-a-time delivery (stress test for buffering)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_byte_at_a_time_delivery() {
    let mut c = codec();
    let frame = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"hello");

    // Feed one byte at a time
    for (i, &byte) in frame.iter().enumerate() {
        let events = c.process(&[byte]).unwrap();
        if i < frame.len() - 1 {
            assert!(events.is_empty(), "Should not emit events until frame complete");
        } else {
            assert_eq!(events.len(), 1);
            match &events[0] {
                H2Event::Data { data, .. } => assert_eq!(data, b"hello"),
                _ => panic!("Expected Data"),
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAX_HEADER_BLOCK_SIZE and MAX_BUFFER_SIZE constants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_max_header_block_size_constant() {
    assert_eq!(MAX_HEADER_BLOCK_SIZE, 256 * 1024);
}

#[test]
fn test_max_buffer_size_constant() {
    assert_eq!(MAX_BUFFER_SIZE, 1024 * 1024);
}
