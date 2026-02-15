//! Tests for HTTP/2 protocol frames (PING, WINDOW_UPDATE, SETTINGS)

use h2_sans_io::{H2Codec, H2Event, settings_id};

#[test]
fn test_ping_frame_parsing() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

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
    codec.preface_received = true;

    let mut frame = vec![0, 0, 8, 6, 1, 0, 0, 0, 0];
    frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);

    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);

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
    codec.preface_received = true;

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
    codec.preface_received = true;

    let mut frame = vec![0, 0, 4, 8, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&0x00100000u32.to_be_bytes());

    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);

    match &events[0] {
        H2Event::WindowUpdate { stream_id, increment } => {
            assert_eq!(*stream_id, 0);
            assert_eq!(*increment, 0x100000);
        }
        _ => panic!("Expected WindowUpdate event"),
    }
}

#[test]
fn test_window_update_clears_reserved_bit() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

    let frame = vec![0, 0, 4, 8, 0, 0, 0, 0, 0, 0x80, 0x01, 0x00, 0x00];

    let events = codec.process(&frame).unwrap();
    match &events[0] {
        H2Event::WindowUpdate { increment, .. } => {
            assert_eq!(*increment, 65536);
        }
        _ => panic!("Expected WindowUpdate"),
    }
}

#[test]
fn test_settings_ack_parsing() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

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
    codec.preface_received = true;

    let mut frame = vec![0, 0, 6, 4, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&[0, 4]); // INITIAL_WINDOW_SIZE id
    frame.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // 1048576

    let events = codec.process(&frame).unwrap();
    assert_eq!(events.len(), 1);

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
    codec.preface_received = true;

    let mut frame = vec![0, 0, 6, 4, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&[0, 5]); // MAX_FRAME_SIZE id
    frame.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]); // 32768

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
    codec.preface_received = true;

    let mut frame = vec![0, 0, 18, 4, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&[0, 1, 0x00, 0x00, 0x20, 0x00]); // HEADER_TABLE_SIZE
    frame.extend_from_slice(&[0, 4, 0x00, 0x00, 0xFF, 0xFF]); // INITIAL_WINDOW_SIZE
    frame.extend_from_slice(&[0, 5, 0x00, 0x00, 0x40, 0x00]); // MAX_FRAME_SIZE

    let events = codec.process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { settings, .. } => {
            assert_eq!(settings.len(), 3);
            assert_eq!(settings[0], (settings_id::HEADER_TABLE_SIZE, 8192));
            assert_eq!(settings[1], (settings_id::INITIAL_WINDOW_SIZE, 65535));
            assert_eq!(settings[2], (settings_id::MAX_FRAME_SIZE, 16384));
        }
        _ => panic!("Expected Settings event"),
    }
}

#[test]
fn test_settings_ack_has_empty_settings() {
    let mut codec = H2Codec::new();
    codec.preface_received = true;

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
    codec.preface_received = true;

    let mut frame = vec![0, 0, 12, 4, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&[0, 0xFF, 0, 0, 0, 42]); // Unknown setting
    frame.extend_from_slice(&[0, 4, 0, 0, 0xFF, 0xFF]); // INITIAL_WINDOW_SIZE

    let events = codec.process(&frame).unwrap();
    match &events[0] {
        H2Event::Settings { settings, .. } => {
            assert_eq!(settings.len(), 2);
            assert_eq!(settings[0], (0xFF, 42));
            assert_eq!(settings[1], (settings_id::INITIAL_WINDOW_SIZE, 65535));
        }
        _ => panic!("Expected Settings event"),
    }
}
