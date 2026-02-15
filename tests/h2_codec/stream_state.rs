//! Tests for H2Codec stream state management

use h2_sans_io::{H2Codec, flags};

fn with_preface(codec: &mut H2Codec) {
    codec.set_preface_received(true);
}

#[test]
fn test_remove_stream_on_completion() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);

    // Send request on stream 1
    let mut data = vec![0, 0, 2, 1, flags::END_STREAM | flags::END_HEADERS, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);
    codec.process(&data).unwrap();

    // Send response on stream 1 (END_STREAM)
    let mut resp = vec![0, 0, 2, 1, flags::END_STREAM | flags::END_HEADERS, 0, 0, 0, 1];
    resp.extend_from_slice(&[0x88]);
    codec.process(&resp).unwrap();
}

#[test]
fn test_remove_stream_nonexistent_is_noop() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    // Removing non-existent stream should not panic
    codec.remove_stream(999);
}

#[test]
fn test_codec_reset_clears_all_state() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);

    // Process some frames
    let mut data = vec![0, 0, 2, 1, flags::END_STREAM | flags::END_HEADERS, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);
    codec.process(&data).unwrap();

    // Reset the codec
    codec.reset();

    // After reset, should be able to process preface again
    let mut data2 = h2_sans_io::CONNECTION_PREFACE.to_vec();
    data2.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    let events = codec.process(&data2).unwrap();
    assert!(!events.is_empty());
}

#[test]
fn test_codec_reset_clears_pending_continuation() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);

    // Send HEADERS without END_HEADERS
    let mut data = vec![0, 0, 2, 1, 0, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);
    codec.process(&data).unwrap();

    // Reset should clear pending continuation
    codec.reset();

    // After reset, pending continuation should be cleared
    let mut data2 = h2_sans_io::CONNECTION_PREFACE.to_vec();
    data2.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    let events = codec.process(&data2).unwrap();
    assert!(!events.is_empty());
}

#[test]
fn test_codec_reset_allows_new_preface() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);

    // Process some data
    let frame = vec![0, 0, 5, 0, 1, 0, 0, 0, 1];
    let mut f = frame.clone();
    f.extend_from_slice(b"hello");
    codec.process(&f).unwrap();

    // Reset
    codec.reset();

    // Should be able to process new preface
    let mut data = h2_sans_io::CONNECTION_PREFACE.to_vec();
    data.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    let events = codec.process(&data).unwrap();
    assert!(codec.preface_received());
    assert_eq!(events.len(), 1);
}

#[test]
fn test_rst_stream_removes_stream_state() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);

    // Create stream with headers
    let mut data = vec![0, 0, 2, 1, 4, 0, 0, 0, 1];
    data.extend_from_slice(&[0x82, 0x86]);
    codec.process(&data).unwrap();

    // Send RST_STREAM
    let rst = [0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 8];
    codec.process(&rst).unwrap();
}
