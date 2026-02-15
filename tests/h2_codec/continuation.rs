//! Tests for HTTP/2 CONTINUATION frame handling

use h2_sans_io::{H2Codec, H2Event, frame_type, flags};

fn with_preface(codec: &mut H2Codec) {
    codec.set_preface_received(true);
}

#[test]
fn test_continuation_single_frame() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut data = vec![0, 0, 3, 1, 0, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86, 0x84]);
    data.extend_from_slice(&[0, 0, 2, 9, 4, 0, 0, 0, 1]);
    data.extend_from_slice(&[0x41, 0x8a]);
    let events = codec.process(&data).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Headers { stream_id, header_block, .. } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(header_block, &[0x82, 0x86, 0x84, 0x41, 0x8a]);
        }
        _ => panic!("Expected Headers event"),
    }
}

#[test]
fn test_continuation_multiple_frames() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut data = vec![0, 0, 2, 1, 0, 0, 0, 0, 3];
    data.extend_from_slice(&[0x82, 0x86]);
    data.extend_from_slice(&[0, 0, 2, 9, 0, 0, 0, 0, 3]);
    data.extend_from_slice(&[0x84, 0x41]);
    data.extend_from_slice(&[0, 0, 1, 9, 4, 0, 0, 0, 3]);
    data.extend_from_slice(&[0x8a]);
    let events = codec.process(&data).unwrap();
    assert_eq!(events.len(), 1);
}

#[test]
fn test_continuation_preserves_end_stream() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut data = vec![0, 0, 2, 1, 0x1, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);
    data.extend_from_slice(&[0, 0, 1, 9, 4, 0, 0, 0, 1]);
    data.extend_from_slice(&[0x84]);
    let events = codec.process(&data).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Headers { end_stream, .. } => {
            assert!(*end_stream);
        }
        _ => panic!("Expected Headers event"),
    }
}

#[test]
fn test_continuation_incremental_delivery() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut headers_frame = vec![0, 0, 3, 1, 0, 0, 0, 0, 1];
    headers_frame.extend_from_slice(&[0x82, 0x86, 0x84]);
    let events1 = codec.process(&headers_frame).unwrap();
    assert!(events1.is_empty());
    let mut cont_frame = vec![0, 0, 2, 9, 4, 0, 0, 0, 1];
    cont_frame.extend_from_slice(&[0x41, 0x8a]);
    let events2 = codec.process(&cont_frame).unwrap();
    assert_eq!(events2.len(), 1);
}

#[test]
fn test_continuation_size_bound_allows_normal_headers() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut data = vec![0, 0, 100, frame_type::HEADERS, 0, 0, 0, 0, 1];
    data.extend_from_slice(&vec![0x82; 100]);
    codec.process(&data).unwrap();
    let mut cont = vec![0, 0, 100, frame_type::CONTINUATION, flags::END_HEADERS, 0, 0, 0, 1];
    cont.extend_from_slice(&vec![0x86; 100]);
    let events = codec.process(&cont).unwrap();
    assert_eq!(events.len(), 1);
}

#[test]
fn test_continuation_wrong_stream_returns_error() {
    // HEADERS on stream 1, CONTINUATION on stream 3 → protocol error
    let mut codec = H2Codec::new();
    codec.set_preface_received(true);

    // HEADERS: stream 1, no END_HEADERS
    let mut data = vec![0, 0, 2, 1, 0, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);

    // CONTINUATION: stream 3 (wrong!)
    data.extend_from_slice(&[0, 0, 1, 9, 4, 0, 0, 0, 3]);
    data.extend_from_slice(&[0x84]);

    let result = codec.process(&data);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("CONTINUATION for stream 3"), "Error: {}", err);
    assert!(err.contains("pending headers on stream 1"), "Error: {}", err);
}

#[test]
fn test_unexpected_continuation_returns_error() {
    // CONTINUATION without preceding HEADERS → protocol error
    let mut codec = H2Codec::new();
    codec.set_preface_received(true);

    let mut data = vec![0, 0, 1, 9, 4, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);

    let result = codec.process(&data);
    assert!(result.is_err());
}

#[test]
fn test_continuation_size_bound_rejects_oversized_block() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);

    // HEADERS without END_HEADERS, large initial block (200KB)
    let initial_block = vec![0x82; 200 * 1024];
    let initial_len = initial_block.len() as u32;
    let mut data = vec![
        (initial_len >> 16) as u8,
        (initial_len >> 8) as u8,
        initial_len as u8,
        frame_type::HEADERS,
        0, // no END_HEADERS, no END_STREAM
        0, 0, 0, 1, // stream 1
    ];
    data.extend_from_slice(&initial_block);
    codec.process(&data).unwrap(); // 200KB is under 256KB limit, should succeed

    // CONTINUATION that pushes total over 256KB
    let cont_block = vec![0x86; 100 * 1024]; // 100KB more → 300KB total
    let cont_len = cont_block.len() as u32;
    let mut cont_data = vec![
        (cont_len >> 16) as u8,
        (cont_len >> 8) as u8,
        cont_len as u8,
        frame_type::CONTINUATION,
        flags::END_HEADERS,
        0, 0, 0, 1, // stream 1
    ];
    cont_data.extend_from_slice(&cont_block);

    let result = codec.process(&cont_data);
    assert!(result.is_err());
}
