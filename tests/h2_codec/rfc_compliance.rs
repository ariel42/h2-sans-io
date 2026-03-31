//! RFC 7540 compliance tests for H2Codec.
//!
//! These tests verify that the codec correctly enforces constraints
//! from RFC 7540 (HTTP/2) that protect against protocol violations.

use h2_sans_io::{H2Codec, H2Event, flags, frame_type, settings_id};

// ─── Helper: build a raw H2 frame from parts ───────────────────────────────

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
// Section 6.1 — DATA frames
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_data_on_stream_zero_is_error() {
    // RFC 7540 §6.1: DATA frames MUST be associated with a stream.
    let frame = build_frame(frame_type::DATA, flags::END_STREAM, 0, b"hello");
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("stream 0"));
}

#[test]
fn test_data_on_valid_stream() {
    let frame = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"hello");
    let events = codec().process(&frame).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Data { stream_id, data, end_stream } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(data, b"hello");
            assert!(*end_stream);
        }
        _ => panic!("Expected Data event"),
    }
}

#[test]
fn test_padded_data_valid() {
    // pad_length=2, data="hi", padding=0x00 0x00
    let payload = vec![2, b'h', b'i', 0, 0];
    let frame = build_frame(frame_type::DATA, flags::PADDED, 1, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Data { data, .. } => assert_eq!(data, b"hi"),
        _ => panic!("Expected Data event"),
    }
}

#[test]
fn test_padded_data_pad_length_exceeds_payload() {
    // pad_length=10 but only 3 bytes total after pad_length byte
    let payload = vec![10, b'h', b'i'];
    let frame = build_frame(frame_type::DATA, flags::PADDED, 1, &payload);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("padding"));
}

#[test]
fn test_padded_data_empty_payload_is_error() {
    let frame = build_frame(frame_type::DATA, flags::PADDED, 1, &[]);
    let result = codec().process(&frame);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6.2 — HEADERS frames
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_headers_on_stream_zero_is_error() {
    // RFC 7540 §6.2: HEADERS frames MUST be associated with a stream.
    let frame = build_frame(frame_type::HEADERS, flags::END_HEADERS | flags::END_STREAM, 0, b"\x82");
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("stream 0"));
}

#[test]
fn test_headers_with_padding_and_priority() {
    // Combine PADDED + PRIORITY flags
    // pad_length=1, stream_dep=0x00000000, weight=15, header_block=0x82, padding=0x00
    let payload = vec![1, 0, 0, 0, 0, 15, 0x82, 0];
    let frame = build_frame(
        frame_type::HEADERS,
        flags::END_HEADERS | flags::PADDED | flags::PRIORITY,
        1,
        &payload,
    );
    let events = codec().process(&frame).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Headers { header_block, .. } => {
            assert_eq!(header_block, &[0x82]);
        }
        _ => panic!("Expected Headers event"),
    }
}

#[test]
fn test_headers_padded_insufficient_for_priority() {
    // PADDED + PRIORITY but not enough bytes for priority fields after pad_length
    let payload = vec![0, 0, 0]; // pad_length=0, only 2 bytes left (need 5 for priority)
    let frame = build_frame(
        frame_type::HEADERS,
        flags::END_HEADERS | flags::PADDED | flags::PRIORITY,
        1,
        &payload,
    );
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("insufficient"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6.4 — RST_STREAM frames
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_rst_stream_on_stream_zero_is_error() {
    // RFC 7540 §6.4: RST_STREAM MUST NOT be sent for connection (stream 0).
    let frame = build_frame(frame_type::RST_STREAM, 0, 0, &0u32.to_be_bytes());
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("stream 0"));
}

#[test]
fn test_rst_stream_wrong_length_too_short() {
    // RFC 7540 §6.4: RST_STREAM must be exactly 4 bytes.
    let frame = build_frame(frame_type::RST_STREAM, 0, 1, &[0, 0, 0]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("size error"));
}

#[test]
fn test_rst_stream_wrong_length_too_long() {
    // RFC 7540 §6.4: RST_STREAM must be exactly 4 bytes, not more.
    let frame = build_frame(frame_type::RST_STREAM, 0, 1, &[0, 0, 0, 0, 0]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("size error"));
}

#[test]
fn test_rst_stream_valid() {
    let frame = build_frame(frame_type::RST_STREAM, 0, 3, &8u32.to_be_bytes());
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::StreamReset { stream_id, error_code } => {
            assert_eq!(*stream_id, 3);
            assert_eq!(*error_code, 8); // CANCEL
        }
        _ => panic!("Expected StreamReset"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6.5 — SETTINGS frames
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_settings_on_non_zero_stream_is_error() {
    // RFC 7540 §6.5: SETTINGS must be on stream 0.
    let frame = build_frame(frame_type::SETTINGS, 0, 1, &[]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("non-zero stream"));
}

#[test]
fn test_settings_ack_with_payload_is_error() {
    // RFC 7540 §6.5: SETTINGS ACK MUST have payload length of 0.
    let frame = build_frame(frame_type::SETTINGS, 0x1, 0, &[0; 6]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("non-zero length"));
}

#[test]
fn test_settings_ack_empty_is_valid() {
    let frame = build_frame(frame_type::SETTINGS, 0x1, 0, &[]);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { ack, settings } => {
            assert!(*ack);
            assert!(settings.is_empty());
        }
        _ => panic!("Expected Settings"),
    }
}

#[test]
fn test_settings_payload_not_multiple_of_6_is_error() {
    // RFC 7540 §6.5: Payload must be a multiple of 6 bytes.
    let frame = build_frame(frame_type::SETTINGS, 0, 0, &[0; 7]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not a multiple of 6"));
}

#[test]
fn test_settings_empty_payload_is_valid() {
    // Empty SETTINGS (0 settings entries) is valid per RFC.
    let frame = build_frame(frame_type::SETTINGS, 0, 0, &[]);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { ack, settings } => {
            assert!(!*ack);
            assert!(settings.is_empty());
        }
        _ => panic!("Expected Settings"),
    }
}

#[test]
fn test_settings_two_entries() {
    let mut payload = Vec::new();
    // INITIAL_WINDOW_SIZE = 65535
    payload.extend_from_slice(&settings_id::INITIAL_WINDOW_SIZE.to_be_bytes());
    payload.extend_from_slice(&65535u32.to_be_bytes());
    // MAX_FRAME_SIZE = 32768
    payload.extend_from_slice(&settings_id::MAX_FRAME_SIZE.to_be_bytes());
    payload.extend_from_slice(&32768u32.to_be_bytes());

    let frame = build_frame(frame_type::SETTINGS, 0, 0, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { settings, .. } => {
            assert_eq!(settings.len(), 2);
            assert_eq!(settings[0], (settings_id::INITIAL_WINDOW_SIZE, 65535));
            assert_eq!(settings[1], (settings_id::MAX_FRAME_SIZE, 32768));
        }
        _ => panic!("Expected Settings"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6.7 — PING frames
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_ping_on_non_zero_stream_is_error() {
    // RFC 7540 §6.7: PING must be on stream 0.
    let frame = build_frame(frame_type::PING, 0, 1, &[1, 2, 3, 4, 5, 6, 7, 8]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("non-zero stream"));
}

#[test]
fn test_ping_wrong_length_too_short() {
    let frame = build_frame(frame_type::PING, 0, 0, &[1, 2, 3]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("size error"));
}

#[test]
fn test_ping_wrong_length_too_long() {
    // RFC 7540 §6.7: PING must be exactly 8 bytes.
    let frame = build_frame(frame_type::PING, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("size error"));
}

#[test]
fn test_ping_valid() {
    let ping_data = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let frame = build_frame(frame_type::PING, 0, 0, &ping_data);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Ping { ack, data } => {
            assert!(!*ack);
            assert_eq!(*data, ping_data);
        }
        _ => panic!("Expected Ping"),
    }
}

#[test]
fn test_ping_ack_valid() {
    let ping_data = [1, 2, 3, 4, 5, 6, 7, 8];
    let frame = build_frame(frame_type::PING, 0x1, 0, &ping_data);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Ping { ack, data } => {
            assert!(*ack);
            assert_eq!(*data, ping_data);
        }
        _ => panic!("Expected Ping ACK"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6.8 — GOAWAY frames
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_goaway_on_non_zero_stream_is_error() {
    // RFC 7540 §6.8: GOAWAY must be on stream 0.
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u32.to_be_bytes()); // last_stream_id
    payload.extend_from_slice(&0u32.to_be_bytes()); // error_code
    let frame = build_frame(frame_type::GOAWAY, 0, 1, &payload);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("non-zero stream"));
}

#[test]
fn test_goaway_too_short() {
    let frame = build_frame(frame_type::GOAWAY, 0, 0, &[0; 7]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("too short"));
}

#[test]
fn test_goaway_with_debug_data() {
    // GOAWAY can have optional debug data after the 8 required bytes.
    let mut payload = Vec::new();
    payload.extend_from_slice(&100u32.to_be_bytes()); // last_stream_id
    payload.extend_from_slice(&0u32.to_be_bytes());   // NO_ERROR
    payload.extend_from_slice(b"debug info here");
    let frame = build_frame(frame_type::GOAWAY, 0, 0, &payload);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::GoAway { last_stream_id, error_code } => {
            assert_eq!(*last_stream_id, 100);
            assert_eq!(*error_code, 0);
        }
        _ => panic!("Expected GoAway"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6.9 — WINDOW_UPDATE frames
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_window_update_zero_increment_is_error() {
    // RFC 7540 §6.9.1: increment of 0 is a protocol error.
    let frame = build_frame(frame_type::WINDOW_UPDATE, 0, 1, &0u32.to_be_bytes());
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("zero increment"));
}

#[test]
fn test_window_update_zero_increment_on_connection_is_error() {
    let frame = build_frame(frame_type::WINDOW_UPDATE, 0, 0, &0u32.to_be_bytes());
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("zero increment"));
}

#[test]
fn test_window_update_wrong_length_too_short() {
    let frame = build_frame(frame_type::WINDOW_UPDATE, 0, 0, &[0, 0, 1]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("size error"));
}

#[test]
fn test_window_update_wrong_length_too_long() {
    // RFC 7540 §6.9: WINDOW_UPDATE must be exactly 4 bytes.
    let frame = build_frame(frame_type::WINDOW_UPDATE, 0, 0, &[0, 0, 0, 1, 0]);
    let result = codec().process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("size error"));
}

#[test]
fn test_window_update_max_increment() {
    // Maximum valid increment: 2^31 - 1 (reserved bit cleared)
    let frame = build_frame(frame_type::WINDOW_UPDATE, 0, 0, &0x7FFFFFFFu32.to_be_bytes());
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::WindowUpdate { increment, .. } => {
            assert_eq!(*increment, 0x7FFFFFFF);
        }
        _ => panic!("Expected WindowUpdate"),
    }
}

#[test]
fn test_window_update_reserved_bit_cleared() {
    // High bit set in the wire value should be masked off
    let frame = build_frame(frame_type::WINDOW_UPDATE, 0, 0, &0xFFFFFFFFu32.to_be_bytes());
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::WindowUpdate { increment, .. } => {
            assert_eq!(*increment, 0x7FFFFFFF);
        }
        _ => panic!("Expected WindowUpdate"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Section 6.10 — CONTINUATION frame interlock
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_non_continuation_during_header_block_is_error() {
    // RFC 7540 §6.10: Between HEADERS without END_HEADERS and the final
    // CONTINUATION with END_HEADERS, no other frame type may appear.
    let mut c = codec();

    // HEADERS without END_HEADERS (starts header block assembly)
    let headers_frame = build_frame(frame_type::HEADERS, 0, 1, &[0x82]);
    c.process(&headers_frame).unwrap();

    // DATA frame while CONTINUATION is expected → error
    let data_frame = build_frame(frame_type::DATA, flags::END_STREAM, 1, b"data");
    let result = c.process(&data_frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("CONTINUATION expected"));
}

#[test]
fn test_settings_during_header_block_is_error() {
    let mut c = codec();
    let headers_frame = build_frame(frame_type::HEADERS, 0, 1, &[0x82]);
    c.process(&headers_frame).unwrap();

    let settings_frame = build_frame(frame_type::SETTINGS, 0, 0, &[]);
    let result = c.process(&settings_frame);
    assert!(result.is_err());
}

#[test]
fn test_ping_during_header_block_is_error() {
    let mut c = codec();
    let headers_frame = build_frame(frame_type::HEADERS, 0, 1, &[0x82]);
    c.process(&headers_frame).unwrap();

    let ping_frame = build_frame(frame_type::PING, 0, 0, &[0; 8]);
    let result = c.process(&ping_frame);
    assert!(result.is_err());
}

#[test]
fn test_continuation_on_different_stream_during_header_block_is_error() {
    let mut c = codec();
    let headers_frame = build_frame(frame_type::HEADERS, 0, 1, &[0x82]);
    c.process(&headers_frame).unwrap();

    // CONTINUATION on stream 3 while pending on stream 1
    let cont_frame = build_frame(frame_type::CONTINUATION, flags::END_HEADERS, 3, &[0x83]);
    let result = c.process(&cont_frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("pending headers on stream 1"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Frame building — reserved bit masking
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_create_rst_stream_masks_reserved_bit() {
    let frame = H2Codec::create_rst_stream(0x80000001, 0);
    // stream_id bytes at offset 5..9
    let sid = u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]);
    assert_eq!(sid, 1, "reserved bit should be cleared");
}

#[test]
fn test_create_goaway_masks_reserved_bit() {
    let frame = H2Codec::create_goaway(0x80000005, 0);
    // last_stream_id is in the payload at offset 9..13
    let lsid = u32::from_be_bytes([frame[9], frame[10], frame[11], frame[12]]);
    assert_eq!(lsid, 5, "reserved bit should be cleared");
}

#[test]
fn test_create_window_update_masks_stream_reserved_bit() {
    let frame = H2Codec::create_window_update(0x80000001, 100);
    let sid = u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]);
    assert_eq!(sid, 1);
}

#[test]
fn test_create_continuation_masks_reserved_bit() {
    let frame = H2Codec::create_continuation_frame(0x80000001, &[0x82], true);
    let sid = u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]);
    assert_eq!(sid, 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// Roundtrip: create → parse
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_roundtrip_rst_stream() {
    let frame = H2Codec::create_rst_stream(5, 8); // stream 5, CANCEL
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::StreamReset { stream_id, error_code } => {
            assert_eq!(*stream_id, 5);
            assert_eq!(*error_code, 8);
        }
        _ => panic!("Expected StreamReset"),
    }
}

#[test]
fn test_roundtrip_goaway() {
    let frame = H2Codec::create_goaway(99, 0);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::GoAway { last_stream_id, error_code } => {
            assert_eq!(*last_stream_id, 99);
            assert_eq!(*error_code, 0);
        }
        _ => panic!("Expected GoAway"),
    }
}

#[test]
fn test_roundtrip_settings_ack() {
    let frame = H2Codec::create_settings_ack();
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { ack, settings } => {
            assert!(*ack);
            assert!(settings.is_empty());
        }
        _ => panic!("Expected Settings ACK"),
    }
}

#[test]
fn test_roundtrip_settings_empty() {
    let frame = H2Codec::create_settings();
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { ack, settings } => {
            assert!(!*ack);
            assert!(settings.is_empty());
        }
        _ => panic!("Expected Settings"),
    }
}

#[test]
fn test_roundtrip_settings_with_window() {
    let frame = H2Codec::create_settings_with_window(1_000_000);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { ack, settings } => {
            assert!(!*ack);
            assert_eq!(settings.len(), 2);
            assert_eq!(settings[0], (settings_id::INITIAL_WINDOW_SIZE, 1_000_000));
            assert_eq!(settings[1], (settings_id::ENABLE_CONNECT_PROTOCOL, 1));
        }
        _ => panic!("Expected Settings"),
    }
}

#[test]
fn test_roundtrip_ping_ack() {
    let data = [1, 2, 3, 4, 5, 6, 7, 8];
    let frame = H2Codec::create_ping_ack(data);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::Ping { ack, data: d } => {
            assert!(*ack);
            assert_eq!(*d, data);
        }
        _ => panic!("Expected Ping ACK"),
    }
}

#[test]
fn test_roundtrip_window_update() {
    let frame = H2Codec::create_window_update(3, 65535);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::WindowUpdate { stream_id, increment } => {
            assert_eq!(*stream_id, 3);
            assert_eq!(*increment, 65535);
        }
        _ => panic!("Expected WindowUpdate"),
    }
}

#[test]
fn test_roundtrip_window_update_connection_level() {
    let frame = H2Codec::create_window_update(0, 32768);
    let events = codec().process(&frame).unwrap();
    match &events[0] {
        H2Event::WindowUpdate { stream_id, increment } => {
            assert_eq!(*stream_id, 0);
            assert_eq!(*increment, 32768);
        }
        _ => panic!("Expected WindowUpdate"),
    }
}

#[test]
fn test_roundtrip_continuation() {
    let mut c = codec();
    // First: HEADERS without END_HEADERS
    let headers = build_frame(frame_type::HEADERS, 0, 1, &[0x82]);
    c.process(&headers).unwrap();

    // Then: CONTINUATION with END_HEADERS
    let cont = H2Codec::create_continuation_frame(1, &[0x86], true);
    let events = c.process(&cont).unwrap();
    match &events[0] {
        H2Event::Headers { stream_id, header_block, .. } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(header_block, &[0x82, 0x86]);
        }
        _ => panic!("Expected Headers"),
    }
}
