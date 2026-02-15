//! Tests for HTTP/2 frame building

use h2_sans_io::{H2Codec, frame_type, error_code};

#[test]
fn test_create_rst_stream() {
    let frame = H2Codec::create_rst_stream(1, error_code::HTTP_1_1_REQUIRED);

    assert_eq!(frame.len(), 13);
    assert_eq!(&frame[0..3], &[0, 0, 4]); // Length
    assert_eq!(frame[3], frame_type::RST_STREAM);
    assert_eq!(frame[4], 0); // Flags
    assert_eq!(&frame[5..9], &[0, 0, 0, 1]); // Stream ID
    assert_eq!(&frame[9..13], &[0, 0, 0, 0xd]); // Error code
}

#[test]
fn test_create_settings_ack() {
    let frame = H2Codec::create_settings_ack();
    assert_eq!(frame.len(), 9);
    assert_eq!(&frame[0..3], &[0, 0, 0]); // Length: 0
    assert_eq!(frame[3], frame_type::SETTINGS);
    assert_eq!(frame[4], 0x1); // ACK flag
    assert_eq!(&frame[5..9], &[0, 0, 0, 0]); // Stream 0
}

#[test]
fn test_create_settings_empty() {
    let frame = H2Codec::create_settings();
    assert_eq!(frame.len(), 9);
    assert_eq!(&frame[0..3], &[0, 0, 0]);
    assert_eq!(frame[3], frame_type::SETTINGS);
    assert_eq!(frame[4], 0x0); // No flags
}

#[test]
fn test_create_settings_with_window() {
    let frame = H2Codec::create_settings_with_window(1_048_576); // 1MB
    assert_eq!(frame.len(), 15);
    assert_eq!(&frame[0..3], &[0, 0, 6]); // Length: 6
    assert_eq!(frame[3], frame_type::SETTINGS);
    // Setting ID = 0x4 (INITIAL_WINDOW_SIZE)
    assert_eq!(&frame[9..11], &[0, 4]);
    // Value = 1048576
    assert_eq!(&frame[11..15], &[0x00, 0x10, 0x00, 0x00]);
}

#[test]
fn test_create_ping_ack() {
    let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let frame = H2Codec::create_ping_ack(data);
    assert_eq!(frame.len(), 17);
    assert_eq!(&frame[0..3], &[0, 0, 8]);
    assert_eq!(frame[3], frame_type::PING);
    assert_eq!(frame[4], 0x1); // ACK flag
    assert_eq!(&frame[9..17], &data);
}

#[test]
fn test_create_window_update() {
    let frame = H2Codec::create_window_update(7, 32768);
    assert_eq!(frame.len(), 13);
    assert_eq!(&frame[0..3], &[0, 0, 4]);
    assert_eq!(frame[3], frame_type::WINDOW_UPDATE);
    assert_eq!(&frame[5..9], &[0, 0, 0, 7]);
    assert_eq!(&frame[9..13], &[0, 0, 0x80, 0]);
}

#[test]
fn test_create_goaway() {
    let frame = H2Codec::create_goaway(5, error_code::NO_ERROR);
    assert_eq!(frame.len(), 17);
    assert_eq!(&frame[0..3], &[0, 0, 8]);
    assert_eq!(frame[3], frame_type::GOAWAY);
    assert_eq!(&frame[9..13], &[0, 0, 0, 5]); // Last stream ID
    assert_eq!(&frame[13..17], &[0, 0, 0, 0]); // NO_ERROR
}

#[test]
fn test_create_continuation_frame() {
    let payload = b"test-header-block";
    let frame = H2Codec::create_continuation_frame(1, payload, false);

    assert_eq!(frame.len(), 9 + payload.len());
    assert_eq!(frame[3], 0x9); // CONTINUATION
    assert_eq!(frame[4], 0x0); // No END_HEADERS
    assert_eq!(&frame[9..], payload);
}

#[test]
fn test_continuation_end_headers_flag() {
    let payload = b"header-data";
    let frame_with_flag = H2Codec::create_continuation_frame(1, payload, true);
    let frame_without_flag = H2Codec::create_continuation_frame(1, payload, false);

    assert_eq!(frame_with_flag[4], 0x4); // END_HEADERS flag
    assert_eq!(frame_without_flag[4], 0x0);
}
