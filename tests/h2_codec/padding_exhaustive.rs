//! Exhaustive padding tests for DATA and HEADERS frames.
//!
//! Covers boundary conditions in padding validation per RFC 7540 §6.1 and §6.2.

use h2_sans_io::{H2Codec, H2Event, flags, frame_type};

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
// DATA frame padding edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_data_padded_fills_entire_frame() {
    // pad_length=5, padding=[0;5], 0 data bytes — valid per RFC 7540 §6.1
    let mut payload = vec![5]; // pad_length
    payload.extend_from_slice(&[0; 5]); // padding only, no data
    let frame = build_frame(frame_type::DATA, flags::PADDED | flags::END_STREAM, 1, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Data { data, end_stream, .. } => {
            assert!(data.is_empty(), "Data should be empty when padding fills frame");
            assert!(*end_stream);
        }
        _ => panic!("Expected Data"),
    }
}

#[test]
fn test_data_padded_boundary_pad_length_equals_remaining() {
    // pad_length byte = 4, then exactly 4 bytes of padding → 0 data bytes
    // This is: payload = [pad_len=4, pad, pad, pad, pad]
    // data_end = payload.len() - pad_length = 5 - 4 = 1, so data = payload[1..1] = empty
    let payload = vec![4, 0, 0, 0, 0];
    let frame = build_frame(frame_type::DATA, flags::PADDED | flags::END_STREAM, 1, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Data { data, .. } => assert!(data.is_empty()),
        _ => panic!("Expected Data"),
    }
}

#[test]
fn test_data_padded_one_byte_data() {
    // pad_length=2, data=0x42, padding=[0,0]
    let payload = vec![2, 0x42, 0, 0];
    let frame = build_frame(frame_type::DATA, flags::PADDED | flags::END_STREAM, 1, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Data { data, .. } => assert_eq!(data, &[0x42]),
        _ => panic!("Expected Data"),
    }
}

#[test]
fn test_data_padded_pad_length_exceeds_frame() {
    // pad_length=10, but only 2 bytes after pad_length → error
    let payload = vec![10, 0x42, 0x43];
    let frame = build_frame(frame_type::DATA, flags::PADDED, 1, &payload);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("padding"));
}

#[test]
fn test_data_padded_max_pad_length() {
    // pad_length=255 (maximum), need 256 total bytes (1 pad_len + 255 padding)
    let mut payload = vec![255]; // pad_length
    payload.extend_from_slice(&vec![0; 255]); // 255 bytes of padding
    let frame = build_frame(frame_type::DATA, flags::PADDED | flags::END_STREAM, 1, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Data { data, .. } => assert!(data.is_empty()),
        _ => panic!("Expected Data"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HEADERS frame padding edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_headers_padded_empty_payload_is_error() {
    let frame = build_frame(
        frame_type::HEADERS,
        flags::END_HEADERS | flags::PADDED,
        1,
        &[], // empty payload with PADDED flag
    );
    let result = codec().process(&frame);
    assert!(result.is_err());
}

#[test]
fn test_headers_priority_only_exactly_5_bytes() {
    // PRIORITY flag set, exactly 5 bytes for priority fields, no header block
    let payload = vec![0, 0, 0, 0, 15]; // stream_dep=0, weight=15
    let frame = build_frame(
        frame_type::HEADERS,
        flags::END_HEADERS | flags::PRIORITY,
        1,
        &payload,
    );
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Headers { header_block, .. } => {
            assert!(header_block.is_empty(), "Header block should be empty");
        }
        _ => panic!("Expected Headers"),
    }
}

#[test]
fn test_headers_priority_less_than_5_bytes_is_error() {
    // PRIORITY flag set but only 4 bytes
    let payload = vec![0, 0, 0, 0];
    let frame = build_frame(
        frame_type::HEADERS,
        flags::END_HEADERS | flags::PRIORITY,
        1,
        &payload,
    );
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("insufficient"));
}

#[test]
fn test_headers_padded_priority_combined() {
    // PADDED + PRIORITY: pad_length=2, stream_dep=0, weight=10, header_block=0x82, padding=[0,0]
    let payload = vec![2, 0, 0, 0, 0, 10, 0x82, 0, 0];
    let frame = build_frame(
        frame_type::HEADERS,
        flags::END_HEADERS | flags::PADDED | flags::PRIORITY,
        1,
        &payload,
    );
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Headers { header_block, .. } => {
            assert_eq!(header_block, &[0x82]);
        }
        _ => panic!("Expected Headers"),
    }
}

#[test]
fn test_headers_padded_priority_padding_fills_everything() {
    // PADDED + PRIORITY: pad_length=0, stream_dep, weight, then no header block
    let payload = vec![0, 0, 0, 0, 0, 15]; // pad_length=0 + 5 priority bytes, no header block
    let frame = build_frame(
        frame_type::HEADERS,
        flags::END_HEADERS | flags::PADDED | flags::PRIORITY,
        1,
        &payload,
    );
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Headers { header_block, .. } => {
            assert!(header_block.is_empty());
        }
        _ => panic!("Expected Headers"),
    }
}

#[test]
fn test_headers_padded_padding_exceeds_remaining_is_error() {
    // pad_length=100, but only 3 bytes remain → error
    let payload = vec![100, 0x82, 0x86, 0x84];
    let frame = build_frame(
        frame_type::HEADERS,
        flags::END_HEADERS | flags::PADDED,
        1,
        &payload,
    );
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("padding"));
}
