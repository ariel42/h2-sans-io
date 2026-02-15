//! Tests for HTTP/2 protocol frames (PING, WINDOW_UPDATE, SETTINGS)

use h2_sans_io::{H2Codec, H2Event, settings_id};

fn with_preface(codec: &mut H2Codec) {
    codec.set_preface_received(true);
}

#[test]
fn test_ping_frame_parsing() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut frame = vec![0, 0, 8, 6, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Ping { ack, data } => {
            assert!(!*ack);
            assert_eq!(*data, [1, 2, 3, 4, 5, 6, 7, 8]);
        }
        _ => panic!("Expected Ping event"),
    }
}

#[test]
fn test_ping_ack_frame_parsing() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut frame = vec![0, 0, 8, 6, 1, 0, 0, 0, 0];
    frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
    let events = codec.process(&frame).unwrap();
    match &events[0] {
        H2Event::Ping { ack, data } => {
            assert!(*ack);
            assert_eq!(*data, [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
        }
        _ => panic!("Expected Ping ACK event"),
    }
}

#[test]
fn test_window_update_parsing() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut frame = vec![0, 0, 4, 8, 0, 0, 0, 0, 5];
    frame.extend_from_slice(&0x00010000u32.to_be_bytes());
    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::WindowUpdate { stream_id, increment } => {
            assert_eq!(*stream_id, 5);
            assert_eq!(*increment, 65536);
        }
        _ => panic!("Expected WindowUpdate event"),
    }
}

#[test]
fn test_window_update_connection_level() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut frame = vec![0, 0, 4, 8, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&0x00100000u32.to_be_bytes());
    let events = codec.process(&frame).unwrap();
    match &events[0] {
        H2Event::WindowUpdate { stream_id, increment } => {
            assert_eq!(*stream_id, 0);
            assert_eq!(*increment, 0x100000);
        }
        _ => panic!("Expected WindowUpdate event"),
    }
}

#[test]
fn test_settings_ack_parsing() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let frame = vec![0, 0, 0, 4, 1, 0, 0, 0, 0];
    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Settings { ack, .. } => assert!(*ack),
        _ => panic!("Expected Settings ACK event"),
    }
}

#[test]
fn test_settings_parsing_initial_window_size() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut frame = vec![0, 0, 6, 4, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&[0, 4]);
    frame.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);
    let events = codec.process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { ack, settings } => {
            assert!(!*ack);
            assert_eq!(settings.len(), 1);
            assert_eq!(settings[0], (settings_id::INITIAL_WINDOW_SIZE, 1048576));
        }
        _ => panic!("Expected Settings event"),
    }
}

#[test]
fn test_settings_parsing_max_frame_size() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut frame = vec![0, 0, 6, 4, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&[0, 5]);
    frame.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]);
    let events = codec.process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { settings, .. } => {
            assert_eq!(settings[0], (settings_id::MAX_FRAME_SIZE, 32768));
        }
        _ => panic!("Expected Settings event"),
    }
}

#[test]
fn test_settings_parsing_multiple_settings() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut frame = vec![0, 0, 18, 4, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&[0, 1, 0x00, 0x00, 0x20, 0x00]);
    frame.extend_from_slice(&[0, 4, 0x00, 0x00, 0xFF, 0xFF]);
    frame.extend_from_slice(&[0, 5, 0x00, 0x00, 0x40, 0x00]);
    let events = codec.process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { settings, .. } => {
            assert_eq!(settings.len(), 3);
        }
        _ => panic!("Expected Settings event"),
    }
}

#[test]
fn test_settings_ack_has_empty_settings() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let frame = vec![0, 0, 0, 4, 1, 0, 0, 0, 0];
    let events = codec.process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { ack, settings } => {
            assert!(*ack);
            assert!(settings.is_empty());
        }
        _ => panic!("Expected Settings ACK event"),
    }
}

#[test]
fn test_settings_parsing_unknown_setting_ignored() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let mut frame = vec![0, 0, 12, 4, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&[0, 0xFF, 0, 0, 0, 42]);
    frame.extend_from_slice(&[0, 4, 0, 0, 0xFF, 0xFF]);
    let events = codec.process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { settings, .. } => {
            assert_eq!(settings.len(), 2);
        }
        _ => panic!("Expected Settings event"),
    }
}

#[test]
fn test_priority_frame_ignored() {
    // PRIORITY frames (type 0x2) should be ignored
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let frame = vec![0, 0, 5, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 128];
    let events = codec.process(&frame).unwrap();
    // PRIORITY should be silently ignored (no event)
    assert!(events.is_empty());
}

#[test]
fn test_unknown_frame_type_ignored() {
    // Unknown frame types should be ignored
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    let frame = vec![0, 0, 4, 0xFF, 0, 0, 0, 0, 1, 1, 2, 3, 4];
    let events = codec.process(&frame).unwrap();
    // Unknown frame type should be silently ignored
    assert!(events.is_empty());
}

#[test]
fn test_window_update_too_short_returns_error() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    // WINDOW_UPDATE needs 4 bytes for increment, here only 2
    let frame = vec![0, 0, 2, 8, 0, 0, 0, 0, 1, 0, 1];
    let result = codec.process(&frame);
    assert!(result.is_err());
}

#[test]
fn test_ping_too_short_returns_error() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    // PING needs 8 bytes of data, here only 4
    let frame = vec![0, 0, 4, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4];
    let result = codec.process(&frame);
    assert!(result.is_err());
}

#[test]
fn test_goaway_too_short_returns_error() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    // GOAWAY needs at least 8 bytes (last_stream_id + error_code), here only 4
    let frame = vec![0, 0, 4, 7, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let result = codec.process(&frame);
    assert!(result.is_err());
}

#[test]
fn test_rst_stream_too_short_returns_error() {
    let mut codec = H2Codec::new();
    with_preface(&mut codec);
    // RST_STREAM needs 4 bytes for error code, here only 2
    let frame = vec![0, 0, 2, 3, 0, 0, 0, 0, 1, 0, 1];
    let result = codec.process(&frame);
    assert!(result.is_err());
}
