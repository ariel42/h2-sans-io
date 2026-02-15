//! Tests for H2Codec processing (bytes -> events)

use h2_sans_io::{H2Codec, H2Event, CONNECTION_PREFACE, error_code, frame_type, flags};

fn with_preface(codec: &mut H2Codec) {
    codec.set_preface_received(true);
}

#[test]
fn test_codec_fragmented_frames() {
    let mut codec = H2Codec::new();
    codec.set_preface_received(true);

    // Build a complete frame
    let mut frame = vec![0, 0, 5, 0, 1, 0, 0, 0, 1]; // Header
    frame.extend_from_slice(b"hello");

    // Feed it in fragments
    let events1 = codec.process(&frame[..5]).unwrap();
    assert!(events1.is_empty()); // Not enough data

    let events2 = codec.process(&frame[5..10]).unwrap();
    assert!(events2.is_empty()); // Still not enough

    let events3 = codec.process(&frame[10..]).unwrap();
    assert_eq!(events3.len(), 1); // Now complete
}

#[test]
fn test_connection_preface_handling() {
    let mut codec = H2Codec::new();

    // Send connection preface followed by SETTINGS
    let mut data = CONNECTION_PREFACE.to_vec();
    data.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]); // Empty SETTINGS

    let events = codec.process(&data).unwrap();
    assert!(codec.preface_received());
    assert_eq!(events.len(), 1);

    match &events[0] {
        H2Event::Settings { ack, .. } => assert!(!ack),
        _ => panic!("Expected Settings event"),
    }
}

#[test]
fn test_padded_data_frame() {
    let mut codec = H2Codec::new();
    codec.set_preface_received(true);

    // DATA frame with PADDED flag: length 10, pad_length 4, data "hello"
    let mut frame = vec![0, 0, 10, 0, 0x9, 0, 0, 0, 1]; // 0x9 = END_STREAM | PADDED
    frame.push(4); // Pad length
    frame.extend_from_slice(b"hello");
    frame.extend_from_slice(&[0, 0, 0, 0]); // Padding

    let events = codec.process(&frame).unwrap();
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
fn test_codec_parse_data() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut frame = vec![0, 0, 5, 0, 1, 0, 0, 0, 1];
    frame.extend_from_slice(b"hello");
    let events = codec.process(&frame).unwrap();
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
fn test_codec_parse_headers() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut frame = vec![0, 0, 4, 1, 5, 0, 0, 0, 1];
    frame.extend_from_slice(&[0x82, 0x86, 0x84, 0x41]);
    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Headers { stream_id, header_block, end_stream } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(header_block, &[0x82, 0x86, 0x84, 0x41]);
            assert!(*end_stream);
        }
        _ => panic!("Expected Headers event"),
    }
}

#[test]
fn test_codec_parse_rst_stream() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let frame = [0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 0xd];
    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::StreamReset { stream_id, error_code } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(*error_code, error_code::HTTP_1_1_REQUIRED);
        }
        _ => panic!("Expected StreamReset event"),
    }
}

#[test]
fn test_codec_parse_goaway() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let frame = [0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0xd];
    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::GoAway { last_stream_id, error_code } => {
            assert_eq!(*last_stream_id, 5);
            assert_eq!(*error_code, error_code::HTTP_1_1_REQUIRED);
        }
        _ => panic!("Expected GoAway event"),
    }
}

#[test]
fn test_multiple_frames_in_single_process() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 2, 1, 5, 0, 0, 0, 1]);
    data.extend_from_slice(&[0x82, 0x86]);
    data.extend_from_slice(&[0, 0, 1, 1, 4, 0, 0, 0, 3]);
    data.extend_from_slice(&[0x84]);
    data.extend_from_slice(&[0, 0, 5, 0, 1, 0, 0, 0, 3]);
    data.extend_from_slice(b"hello");
    let events = codec.process(&data).unwrap();
    assert_eq!(events.len(), 3);
}

#[test]
fn test_empty_data_frame() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let frame = vec![0, 0, 0, 0, 1, 0, 0, 0, 1];
    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Data { stream_id, data, end_stream } => {
            assert_eq!(*stream_id, 1);
            assert!(data.is_empty());
            assert!(*end_stream);
        }
        _ => panic!("Expected Data event"),
    }
}

#[test]
fn test_buffer_optimization_preserves_remaining_data() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 5, 0, 1, 0, 0, 0, 1]);
    data.extend_from_slice(b"hello");
    data.extend_from_slice(&[0, 0, 5, 0, 1, 0, 0, 0, 3]);
    data.extend_from_slice(b"world");
    let events = codec.process(&data).unwrap();
    assert_eq!(events.len(), 2);
}

#[test]
fn test_buffer_optimization_large_frame() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let payload = vec![0xAB; 16384];
    let len = payload.len() as u32;
    let mut data = vec![
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        frame_type::DATA,
        flags::END_STREAM,
        0, 0, 0, 1,
    ];
    data.extend_from_slice(&payload);
    let events = codec.process(&data).unwrap();
    assert_eq!(events.len(), 1);
}

#[test]
fn test_headers_with_priority_flag() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut frame = vec![0, 0, 7, 1, 0x24, 0, 0, 0, 1];
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.push(255);
    frame.extend_from_slice(&[0x82, 0x86]);
    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);
}

#[test]
fn test_headers_initial_block_exceeds_limit() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);

    // HEADERS without END_HEADERS, initial block exceeds 256KB
    let big_block = vec![0x82; 300 * 1024];
    let len = big_block.len() as u32;
    let mut data = vec![
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        frame_type::HEADERS,
        0, // no END_HEADERS
        0, 0, 0, 1,
    ];
    data.extend_from_slice(&big_block);

    let result = codec.process(&data);
    assert!(result.is_err());
}

#[test]
fn test_buffer_empty_after_complete_consumption() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut data = vec![0, 0, 5, 0, 1, 0, 0, 0, 1];
    data.extend_from_slice(b"hello");
    codec.process(&data).unwrap();

    // After complete consumption, buffer should be empty
    // Process empty slice
    let events = codec.process(&[]).unwrap();
    assert!(events.is_empty());
}
