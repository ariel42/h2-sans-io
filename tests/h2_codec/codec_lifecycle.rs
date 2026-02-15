//! Tests for H2Codec lifecycle (reset, stream cleanup)

use h2_sans_io::{H2Codec, H2Event, CONNECTION_PREFACE};

#[test]
fn test_connection_preface_handling() {
    let mut codec = H2Codec::new();

    let mut data = CONNECTION_PREFACE.to_vec();
    data.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);

    let events = codec.process(&data).unwrap();
    assert!(codec.preface_received);
    assert_eq!(events.len(), 1);

    match &events[0] {
        H2Event::Settings { ack, .. } => assert!(!ack),
        _ => panic!("Expected Settings event"),
    }
}

#[test]
fn test_rst_stream_removes_stream_state() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // Send HEADERS to create stream state
    let mut data = vec![0, 0, 2, 1, 4, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);
    codec.process(&data).unwrap();

    assert!(codec.streams.get(&1).is_some());

    // RST_STREAM on stream 1
    let rst = [0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8];
    codec.process(&rst).unwrap();

    assert!(codec.streams.get(&1).is_none());
}

#[test]
fn test_remove_stream_on_completion() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let mut data = vec![0, 0, 2, 1, 4, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);
    codec.process(&data).unwrap();
    assert!(codec.streams.get(&1).is_some());

    codec.remove_stream(1);
    assert!(codec.streams.get(&1).is_none());
}

#[test]
fn test_remove_stream_nonexistent_is_noop() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;
    codec.remove_stream(999); // Should not panic
}

#[test]
fn test_codec_reset_clears_all_state() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let mut data = vec![0, 0, 2, 1, 4, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);
    codec.process(&data).unwrap();
    assert!(codec.streams.get(&1).is_some());

    codec.reset();
    assert!(!codec.preface_received);
    assert!(codec.streams.get(&1).is_none());
}

#[test]
fn test_codec_reset_clears_pending_continuation() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // Send HEADERS without END_HEADERS
    let mut headers_frame = vec![0, 0, 3, 1, 0, 0, 0, 0, 1];
    headers_frame.extend_from_slice(&[0x82, 0x86, 0x84]);
    let events = codec.process(&headers_frame).unwrap();
    assert!(events.is_empty());

    codec.reset();

    // After reset, CONTINUATION should be unexpected
    let mut cont_frame = vec![0, 0, 2, 9, 4, 0, 0, 0, 1];
    cont_frame.extend_from_slice(&[0x41, 0x8a]);
    let result = codec.process(&cont_frame);
    assert!(result.is_err());
}

#[test]
fn test_codec_reset_allows_new_preface() {
    let mut codec = H2Codec::new();

    // First session
    let mut data = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    data.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    let events = codec.process(&data).unwrap();
    assert!(codec.preface_received);

    // Reset
    codec.reset();
    assert!(!codec.preface_received);

    // Second session
    let mut data2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    data2.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    let events2 = codec.process(&data2).unwrap();
    assert!(codec.preface_received);
}

#[test]
fn test_priority_frame_ignored() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let mut frame = vec![0, 0, 5, 2, 0, 0, 0, 0, 1];
    frame.extend_from_slice(&[0, 0, 0, 0, 16]);

    let events = codec.process(&frame).unwrap();
    assert!(events.is_empty(), "PRIORITY frames should be silently ignored");
}

#[test]
fn test_unknown_frame_type_ignored() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let mut frame = vec![0, 0, 3, 0xFF, 0, 0, 0, 0, 1];
    frame.extend_from_slice(&[1, 2, 3]);

    let events = codec.process(&frame).unwrap();
    assert!(events.is_empty(), "Unknown frame types should be silently ignored");
}
