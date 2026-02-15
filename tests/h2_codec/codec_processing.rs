//! Tests for H2Codec processing (bytes -> events)

use h2_sans_io::{H2Codec, H2Event, frame_type, error_code};

#[test]
fn test_codec_parse_data() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

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
    codec.preface_received = true;

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
    codec.preface_received = true;

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
    codec.preface_received = true;

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
fn test_codec_fragmented_frames() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let mut frame = vec![0, 0, 5, 0, 1, 0, 0, 0, 1];
    frame.extend_from_slice(b"hello");

    let events1 = codec.process(&frame[..5]).unwrap();
    assert!(events1.is_empty());

    let events2 = codec.process(&frame[5..10]).unwrap();
    assert!(events2.is_empty());

    let events3 = codec.process(&frame[10..]).unwrap();
    assert_eq!(events3.len(), 1);
}

#[test]
fn test_padded_data_frame() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let mut frame = vec![0, 0, 10, 0, 0x9, 0, 0, 0, 1];
    frame.push(4); // Pad length
    frame.extend_from_slice(b"hello");
    frame.extend_from_slice(&[0, 0, 0, 0]); // Padding

    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);

    match &events[0] {
        H2Event::Data { data, .. } => {
            assert_eq!(data, b"hello");
        }
        _ => panic!("Expected Data event"),
    }
}

#[test]
fn test_multiple_frames_in_single_process() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let mut data = Vec::new();
    data.extend_from_slice(&[0, 0, 2, 1, 5, 0, 0, 0, 1]); // HEADERS stream 1
    data.extend_from_slice(&[0x82, 0x86]);
    data.extend_from_slice(&[0, 0, 1, 1, 4, 0, 0, 0, 3]); // HEADERS stream 3
    data.extend_from_slice(&[0x84]);
    data.extend_from_slice(&[0, 0, 5, 0, 1, 0, 0, 0, 3]); // DATA stream 3
    data.extend_from_slice(b"hello");

    let events = codec.process(&data).unwrap();
    assert_eq!(events.len(), 3);
}

#[test]
fn test_empty_data_frame() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let frame = vec![0, 0, 0, 0, 1, 0, 0, 0, 1]; // length 0, END_STREAM

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
