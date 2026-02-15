//! Tests for HTTP/2 CONTINUATION frame handling

use h2_sans_io::{H2Codec, H2Event, frame_type, flags};

#[test]
fn test_continuation_single_frame() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // HEADERS without END_HEADERS
    let mut data = vec![0, 0, 3, 1, 0, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86, 0x84]);

    // CONTINUATION with END_HEADERS
    data.extend_from_slice(&[0, 0, 2, 9, 4, 0, 0, 0, 1]);
    data.extend_from_slice(&[0x41, 0x8a]);

    let events = codec.process(&data).unwrap();
    assert_eq!(events.len(), 1);

    match &events[0] {
        H2Event::Headers { stream_id, header_block, end_stream } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(header_block, &[0x82, 0x86, 0x84, 0x41, 0x8a]);
            assert!(!*end_stream);
        }
        _ => panic!("Expected Headers event"),
    }
}

#[test]
fn test_continuation_multiple_frames() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // HEADERS
    let mut data = vec![0, 0, 2, 1, 0, 0, 0, 0, 3];
    data.extend_from_slice(&[0x82, 0x86]);

    // CONTINUATION 1
    data.extend_from_slice(&[0, 0, 2, 9, 0, 0, 0, 0, 3]);
    data.extend_from_slice(&[0x84, 0x41]);

    // CONTINUATION 2 (END_HEADERS)
    data.extend_from_slice(&[0, 0, 1, 9, 4, 0, 0, 0, 3]);
    data.extend_from_slice(&[0x8a]);

    let events = codec.process(&data).unwrap();
    assert_eq!(events.len(), 1);

    match &events[0] {
        H2Event::Headers { stream_id, header_block, .. } => {
            assert_eq!(*stream_id, 3);
            assert_eq!(header_block, &[0x82, 0x86, 0x84, 0x41, 0x8a]);
        }
        _ => panic!("Expected Headers event"),
    }
}

#[test]
fn test_continuation_preserves_end_stream() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // HEADERS with END_STREAM but no END_HEADERS
    let mut data = vec![0, 0, 2, 1, 0x1, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);

    // CONTINUATION with END_HEADERS
    data.extend_from_slice(&[0, 0, 1, 9, 4, 0, 0, 0, 1]);
    data.extend_from_slice(&[0x84]);

    let events = codec.process(&data).unwrap();
    assert_eq!(events.len(), 1);

    match &events[0] {
        H2Event::Headers { end_stream, .. } => {
            assert!(*end_stream, "END_STREAM from HEADERS should be preserved");
        }
        _ => panic!("Expected Headers event"),
    }
}

#[test]
fn test_continuation_wrong_stream_returns_error() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // HEADERS on stream 1
    let mut data = vec![0, 0, 2, 1, 0, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);

    // CONTINUATION on stream 3 (wrong!)
    data.extend_from_slice(&[0, 0, 1, 9, 4, 0, 0, 0, 3]);
    data.extend_from_slice(&[0x84]);

    let result = codec.process(&data);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("CONTINUATION for stream 3"));
}

#[test]
fn test_unexpected_continuation_returns_error() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // CONTINUATION without preceding HEADERS
    let mut data = vec![0, 0, 2, 9, 4, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);

    let result = codec.process(&data);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Unexpected CONTINUATION"));
}

#[test]
fn test_continuation_incremental_delivery() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // First call: HEADERS without END_HEADERS
    let mut headers_frame = vec![0, 0, 3, 1, 0, 0, 0, 0, 1];
    headers_frame.extend_from_slice(&[0x82, 0x86, 0x84]);
    let events1 = codec.process(&headers_frame).unwrap();
    assert!(events1.is_empty());

    // Second call: CONTINUATION with END_HEADERS
    let mut cont_frame = vec![0, 0, 2, 9, 4, 0, 0, 0, 1];
    cont_frame.extend_from_slice(&[0x41, 0x8a]);
    let events2 = codec.process(&cont_frame).unwrap();
    assert_eq!(events2.len(), 1);
}

#[test]
fn test_continuation_size_bound_rejects_oversized_block() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // HEADERS without END_HEADERS, 200KB
    let initial_block = vec![0x82; 200 * 1024];
    let initial_len = initial_block.len() as u32;
    let mut data = vec![
        (initial_len >> 16) as u8,
        (initial_len >> 8) as u8,
        initial_len as u8,
        frame_type::HEADERS,
        0,
        0, 0, 0, 1,
    ];
    data.extend_from_slice(&initial_block);
    codec.process(&data).unwrap();

    // CONTINUATION pushes over 256KB limit
    let cont_block = vec![0x86; 100 * 1024];
    let cont_len = cont_block.len() as u32;
    let mut cont_data = vec![
        (cont_len >> 16) as u8,
        (cont_len >> 8) as u8,
        cont_len as u8,
        frame_type::CONTINUATION,
        flags::END_HEADERS,
        0, 0, 0, 1,
    ];
    cont_data.extend_from_slice(&cont_block);

    let result = codec.process(&cont_data);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Header block too large"));
}
