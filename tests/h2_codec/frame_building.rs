//! Tests for HTTP/2 frame building

use h2_sans_io::{H2Codec, frame_type, error_code};

#[test]
fn test_create_rst_stream() {
    let frame = H2Codec::create_rst_stream(1, error_code::HTTP_1_1_REQUIRED);
    assert_eq!(frame.len(), 13);
    assert_eq!(&frame[0..3], &[0, 0, 4]);
    assert_eq!(frame[3], frame_type::RST_STREAM);
}

#[test]
fn test_create_settings_ack() {
    let frame = H2Codec::create_settings_ack();
    assert_eq!(frame.len(), 9);
    assert_eq!(&frame[0..3], &[0, 0, 0]);
    assert_eq!(frame[3], frame_type::SETTINGS);
    assert_eq!(frame[4], 0x1);
}

#[test]
fn test_create_settings_empty() {
    let frame = H2Codec::create_settings();
    assert_eq!(frame.len(), 9);
    assert_eq!(frame[3], frame_type::SETTINGS);
}

#[test]
fn test_create_settings_with_window() {
    let frame = H2Codec::create_settings_with_window(1_048_576);
    // 9-byte header + 12-byte body (2 settings: INITIAL_WINDOW_SIZE + ENABLE_CONNECT_PROTOCOL)
    assert_eq!(frame.len(), 21);
    assert_eq!(&frame[0..3], &[0, 0, 12]); // length = 12
    assert_eq!(&frame[9..11], &[0, 4]); // INITIAL_WINDOW_SIZE
    assert_eq!(&frame[15..17], &[0, 8]); // ENABLE_CONNECT_PROTOCOL
    assert_eq!(&frame[17..21], &[0, 0, 0, 1]); // value = 1
}

#[test]
fn test_create_ping_ack() {
    let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let frame = H2Codec::create_ping_ack(data);
    assert_eq!(frame.len(), 17);
    assert_eq!(frame[3], frame_type::PING);
    assert_eq!(frame[4], 0x1);
}

#[test]
fn test_create_window_update() {
    let frame = H2Codec::create_window_update(7, 32768);
    assert_eq!(frame.len(), 13);
    assert_eq!(frame[3], frame_type::WINDOW_UPDATE);
}

#[test]
fn test_create_goaway() {
    let frame = H2Codec::create_goaway(5, error_code::NO_ERROR);
    assert_eq!(frame.len(), 17);
    assert_eq!(frame[3], frame_type::GOAWAY);
}

#[test]
fn test_create_continuation_frame() {
    let payload = b"test-header-block";
    let frame = H2Codec::create_continuation_frame(1, payload, false);
    assert_eq!(frame.len(), 9 + payload.len());
    assert_eq!(frame[3], 0x9);
}

#[test]
fn test_continuation_end_headers_flag() {
    let payload = b"header-data";
    let frame_with_flag = H2Codec::create_continuation_frame(1, payload, true);
    let frame_without_flag = H2Codec::create_continuation_frame(1, payload, false);
    assert_eq!(frame_with_flag[4], 0x4);
    assert_eq!(frame_without_flag[4], 0x0);
}

#[test]
fn test_continuation_frame_empty_payload() {
    let frame = H2Codec::create_continuation_frame(1, &[], true);
    assert_eq!(frame.len(), 9);
    assert_eq!(frame[2], 0);
}

// ─── Helper ────────────────────────────────────────────────────────

/// Extract the 24-bit length field from a 9-byte frame header.
fn frame_length(frame: &[u8]) -> usize {
    ((frame[0] as usize) << 16) | ((frame[1] as usize) << 8) | (frame[2] as usize)
}

/// Extract the 31-bit stream ID (reserved bit masked) from a 9-byte frame header.
fn frame_stream_id(frame: &[u8]) -> u32 {
    u32::from_be_bytes([frame[5] & 0x7F, frame[6], frame[7], frame[8]])
}

/// Concatenate all payloads (bytes after the 9-byte header) across frames.
fn concat_payloads(frames: &[Vec<u8>]) -> Vec<u8> {
    frames.iter().flat_map(|f| f[9..].to_vec()).collect()
}

// ─── create_headers_frame ──────────────────────────────────────────

#[test]
fn test_create_headers_frame_basic() {
    let block = b"hpack-encoded-headers";
    let frame = H2Codec::create_headers_frame(1, block, false);
    // Total length
    assert_eq!(frame.len(), 9 + block.len());
    // 24-bit length field
    assert_eq!(frame_length(&frame), block.len());
    // Frame type
    assert_eq!(frame[3], frame_type::HEADERS);
    // Flags: END_HEADERS only
    assert_eq!(frame[4], 0x04);
    // Stream ID
    assert_eq!(frame_stream_id(&frame), 1);
    // Payload preserved
    assert_eq!(&frame[9..], block.as_slice());
}

#[test]
fn test_create_headers_frame_end_stream() {
    let frame = H2Codec::create_headers_frame(3, b"h", true);
    // END_HEADERS | END_STREAM
    assert_eq!(frame[4], 0x05);
}

#[test]
fn test_create_headers_frame_stream_id_encoding() {
    let frame = H2Codec::create_headers_frame(257, b"x", false);
    assert_eq!(frame_stream_id(&frame), 257);
}

#[test]
fn test_create_headers_frame_reserved_bit_cleared() {
    // Stream ID with bit 31 set — must be masked off
    let frame = H2Codec::create_headers_frame(0x80000001, b"x", false);
    assert_eq!(frame_stream_id(&frame), 1);
    // Verify the raw byte has bit 7 clear
    assert_eq!(frame[5] & 0x80, 0);
}

#[test]
fn test_create_headers_frame_empty_block() {
    let frame = H2Codec::create_headers_frame(1, &[], false);
    assert_eq!(frame.len(), 9);
    assert_eq!(frame_length(&frame), 0);
    assert_eq!(frame[3], frame_type::HEADERS);
    assert_eq!(frame[4], 0x04); // END_HEADERS
}

#[test]
fn test_create_headers_frame_length_encoding_large() {
    // 300 bytes → verify 24-bit encoding is correct
    let block = vec![0xAA; 300];
    let frame = H2Codec::create_headers_frame(1, &block, false);
    assert_eq!(frame_length(&frame), 300);
    assert_eq!(frame[0], 0); // 300 >> 16
    assert_eq!(frame[1], 1); // (300 >> 8) & 0xFF
    assert_eq!(frame[2], 44); // 300 & 0xFF
}

// ─── create_headers_frames ─────────────────────────────────────────

#[test]
fn test_create_headers_frames_single_frame() {
    let block = vec![0xAB; 100];
    let frames = H2Codec::create_headers_frames(1, &block, false, 16384);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0][3], frame_type::HEADERS);
    assert_eq!(frames[0][4], 0x04); // END_HEADERS
    assert_eq!(&frames[0][9..], block.as_slice());
}

#[test]
fn test_create_headers_frames_exact_boundary() {
    // block.len() == max_frame_size → single frame (<=)
    let block = vec![0xBB; 100];
    let frames = H2Codec::create_headers_frames(1, &block, true, 100);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0][4], 0x05); // END_HEADERS | END_STREAM
}

#[test]
fn test_create_headers_frames_one_byte_over_boundary() {
    // 101 bytes with max 100 → split into 2
    let block = vec![0xCC; 101];
    let frames = H2Codec::create_headers_frames(1, &block, false, 100);
    assert_eq!(frames.len(), 2);
    assert_eq!(frame_length(&frames[0]), 100);
    assert_eq!(frame_length(&frames[1]), 1);
}

#[test]
fn test_create_headers_frames_two_way_split_with_end_stream() {
    let block = vec![0xCD; 200];
    let frames = H2Codec::create_headers_frames(5, &block, true, 100);
    assert_eq!(frames.len(), 2);
    // First: HEADERS with END_STREAM, without END_HEADERS
    assert_eq!(frames[0][3], frame_type::HEADERS);
    assert_eq!(frames[0][4], 0x01); // END_STREAM only
    // Second: CONTINUATION with END_HEADERS
    assert_eq!(frames[1][3], frame_type::CONTINUATION);
    assert_eq!(frames[1][4], 0x04); // END_HEADERS
}

#[test]
fn test_create_headers_frames_two_way_split_no_end_stream() {
    let block = vec![0xDD; 200];
    let frames = H2Codec::create_headers_frames(5, &block, false, 100);
    assert_eq!(frames.len(), 2);
    // First: HEADERS with no flags
    assert_eq!(frames[0][4], 0x00);
    // Second: CONTINUATION with END_HEADERS
    assert_eq!(frames[1][4], 0x04);
}

#[test]
fn test_create_headers_frames_three_way_split() {
    let block = vec![0xEF; 300];
    let frames = H2Codec::create_headers_frames(7, &block, false, 100);
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0][3], frame_type::HEADERS);
    assert_eq!(frames[0][4], 0x00); // No flags
    assert_eq!(frames[1][3], frame_type::CONTINUATION);
    assert_eq!(frames[1][4], 0x00); // Not last
    assert_eq!(frames[2][3], frame_type::CONTINUATION);
    assert_eq!(frames[2][4], 0x04); // END_HEADERS on last
}

#[test]
fn test_create_headers_frames_payload_integrity() {
    // Verify concatenated payloads == original block
    let block: Vec<u8> = (0..250).map(|i| (i % 256) as u8).collect();
    let frames = H2Codec::create_headers_frames(1, &block, true, 80);
    assert_eq!(concat_payloads(&frames), block);
}

#[test]
fn test_create_headers_frames_consistent_stream_ids() {
    let block = vec![0xFF; 300];
    let frames = H2Codec::create_headers_frames(99, &block, false, 100);
    for frame in &frames {
        assert_eq!(frame_stream_id(frame), 99);
    }
}

#[test]
fn test_create_headers_frames_reserved_bit_cleared() {
    let block = vec![0x11; 200];
    let frames = H2Codec::create_headers_frames(0x80000005, &block, false, 100);
    for frame in &frames {
        assert_eq!(frame_stream_id(frame), 5);
    }
}

#[test]
fn test_create_headers_frames_empty_block() {
    let frames = H2Codec::create_headers_frames(1, &[], false, 100);
    assert_eq!(frames.len(), 1);
    assert_eq!(frame_length(&frames[0]), 0);
    assert_eq!(frames[0][3], frame_type::HEADERS);
    assert_eq!(frames[0][4], 0x04); // END_HEADERS
}

#[test]
fn test_create_headers_frames_roundtrip() {
    // Build frames, then parse them back through codec
    let block = vec![0x42; 250];
    let frames = H2Codec::create_headers_frames(1, &block, true, 100);
    let mut codec = H2Codec::new();
    let _ = codec.process(h2_sans_io::CONNECTION_PREFACE);
    let _ = codec.process(&H2Codec::create_settings());
    let mut all_bytes = Vec::new();
    for f in &frames {
        all_bytes.extend_from_slice(f);
    }
    let events = codec.process(&all_bytes).unwrap();
    let headers_events: Vec<_> = events.iter()
        .filter(|e| matches!(e, h2_sans_io::H2Event::Headers { .. }))
        .collect();
    assert_eq!(headers_events.len(), 1);
    if let h2_sans_io::H2Event::Headers { stream_id, header_block, end_stream } = &headers_events[0] {
        assert_eq!(*stream_id, 1);
        assert_eq!(header_block, &block);
        assert!(*end_stream);
    }
}

// ─── create_data_frames ────────────────────────────────────────────

#[test]
fn test_create_data_frames_single_with_end_stream() {
    let data = vec![0x01; 50];
    let frames = H2Codec::create_data_frames(1, &data, true, 16384);
    assert_eq!(frames.len(), 1);
    assert_eq!(frame_length(&frames[0]), 50);
    assert_eq!(frames[0][3], frame_type::DATA);
    assert_eq!(frames[0][4], 0x01); // END_STREAM
    assert_eq!(frame_stream_id(&frames[0]), 1);
    assert_eq!(&frames[0][9..], data.as_slice());
}

#[test]
fn test_create_data_frames_single_no_end_stream() {
    let data = vec![0x03; 50];
    let frames = H2Codec::create_data_frames(1, &data, false, 100);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0][4], 0x00);
}

#[test]
fn test_create_data_frames_exact_boundary() {
    let data = vec![0x04; 100];
    let frames = H2Codec::create_data_frames(1, &data, true, 100);
    assert_eq!(frames.len(), 1); // Fits exactly
    assert_eq!(frames[0][4], 0x01); // END_STREAM
}

#[test]
fn test_create_data_frames_split_end_stream() {
    let data = vec![0x02; 250];
    let frames = H2Codec::create_data_frames(3, &data, true, 100);
    assert_eq!(frames.len(), 3);
    // Only last frame has END_STREAM
    assert_eq!(frames[0][4], 0x00);
    assert_eq!(frames[1][4], 0x00);
    assert_eq!(frames[2][4], 0x01);
    for f in &frames {
        assert_eq!(f[3], frame_type::DATA);
    }
}

#[test]
fn test_create_data_frames_split_no_end_stream() {
    let data = vec![0x05; 250];
    let frames = H2Codec::create_data_frames(1, &data, false, 100);
    assert_eq!(frames.len(), 3);
    // No frame has END_STREAM
    for f in &frames {
        assert_eq!(f[4], 0x00);
    }
}

#[test]
fn test_create_data_frames_empty() {
    let frames = H2Codec::create_data_frames(1, &[], true, 16384);
    assert_eq!(frames.len(), 1);
    assert_eq!(frame_length(&frames[0]), 0);
    assert_eq!(frames[0].len(), 9);
    assert_eq!(frames[0][4], 0x01); // END_STREAM
}

#[test]
fn test_create_data_frames_empty_no_end_stream() {
    let frames = H2Codec::create_data_frames(1, &[], false, 16384);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0][4], 0x00);
}

#[test]
fn test_create_data_frames_payload_integrity() {
    let data: Vec<u8> = (0..333).map(|i| (i % 256) as u8).collect();
    let frames = H2Codec::create_data_frames(1, &data, true, 100);
    assert_eq!(concat_payloads(&frames), data);
}

#[test]
fn test_create_data_frames_consistent_stream_ids() {
    let data = vec![0xFF; 300];
    let frames = H2Codec::create_data_frames(77, &data, true, 100);
    for frame in &frames {
        assert_eq!(frame_stream_id(frame), 77);
    }
}

#[test]
fn test_create_data_frames_reserved_bit_cleared() {
    let data = vec![0x22; 50];
    let frames = H2Codec::create_data_frames(0x80000003, &data, true, 100);
    assert_eq!(frame_stream_id(&frames[0]), 3);
    assert_eq!(frames[0][5] & 0x80, 0);
}

#[test]
fn test_create_data_frames_length_encoding() {
    let data = vec![0x33; 300];
    let frames = H2Codec::create_data_frames(1, &data, true, 16384);
    assert_eq!(frames.len(), 1);
    assert_eq!(frame_length(&frames[0]), 300);
}

#[test]
fn test_create_data_frames_roundtrip() {
    let data = vec![0x99; 250];
    let frames = H2Codec::create_data_frames(1, &data, true, 100);
    let mut codec = H2Codec::new();
    let _ = codec.process(h2_sans_io::CONNECTION_PREFACE);
    let _ = codec.process(&H2Codec::create_settings());
    // Need a HEADERS first to open the stream
    let headers_frame = H2Codec::create_headers_frame(1, &[], false);
    let _ = codec.process(&headers_frame);
    // Feed DATA frames
    let mut all_bytes = Vec::new();
    for f in &frames {
        all_bytes.extend_from_slice(f);
    }
    let events = codec.process(&all_bytes).unwrap();
    let data_events: Vec<_> = events.iter()
        .filter(|e| matches!(e, h2_sans_io::H2Event::Data { .. }))
        .collect();
    // Concatenate all data payloads
    let mut received = Vec::new();
    let mut saw_end_stream = false;
    for event in &data_events {
        if let h2_sans_io::H2Event::Data { data: d, end_stream, .. } = event {
            received.extend_from_slice(d);
            if *end_stream { saw_end_stream = true; }
        }
    }
    assert_eq!(received, data);
    assert!(saw_end_stream);
}
