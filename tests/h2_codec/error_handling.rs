//! Tests for H2Codec error handling

use h2_sans_io::H2Codec;

#[test]
fn test_window_update_too_short_returns_error() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let frame = vec![0, 0, 2, 8, 0, 0, 0, 0, 1, 0, 0];

    let result = codec.process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("WINDOW_UPDATE"));
}

#[test]
fn test_ping_too_short_returns_error() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let frame = vec![0, 0, 4, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4];

    let result = codec.process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("PING"));
}

#[test]
fn test_goaway_too_short_returns_error() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let frame = vec![0, 0, 4, 7, 0, 0, 0, 0, 0, 0, 0, 0, 5];

    let result = codec.process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("GOAWAY"));
}

#[test]
fn test_rst_stream_too_short_returns_error() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let frame = vec![0, 0, 2, 3, 0, 0, 0, 0, 1, 0, 0];

    let result = codec.process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("RST_STREAM"));
}

#[test]
fn test_padded_data_frame_invalid_padding() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // PADDED DATA frame with padding exceeding payload
    let frame = vec![0, 0, 6, 0, 0x8, 0, 0, 0, 1]; // length 6
    frame.push(10); // Pad length 10 > payload (only 5 bytes after pad length)
    frame.extend_from_slice(b"hello");

    let result = codec.process(&frame);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Invalid padding"));
}

#[test]
fn test_headers_with_priority_flag() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // HEADERS with PRIORITY flag
    let mut frame = vec![0, 0, 7, 1, 0x24, 0, 0, 0, 1];
    frame.extend_from_slice(&[0, 0, 0, 0]); // Dependency
    frame.push(255); // Weight
    frame.extend_from_slice(&[0x82, 0x86]); // Header block

    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);

    match &events[0] {
        H2Event::Headers { header_block, .. } => {
            // Should extract only the header block, skipping priority bytes
            assert_eq!(header_block, &[0x82, 0x86]);
        }
        _ => panic!("Expected Headers event"),
    }
}

#[test]
fn test_headers_initial_block_exceeds_limit() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    // HEADERS without END_HEADERS, initial block exceeds 256KB
    let big_block = vec![0x82; 300 * 1024];
    let len = big_block.len() as u32;
    let mut data = vec![
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        1, // HEADERS
        0,
        0, 0, 0, 1,
    ];
    data.extend_from_slice(&big_block);

    let result = codec.process(&data);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Header block too large"));
}
