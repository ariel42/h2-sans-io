//! Comprehensive roundtrip tests simulating real HTTP/2 conversations.
//!
//! These tests exercise multi-frame sequences that mimic actual usage:
//! connection setup, request/response lifecycle, mid-stream control frames.

use h2_sans_io::{H2Codec, H2Event, CONNECTION_PREFACE, frame_type, error_code, settings_id};

fn build_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() as u32;
    let mut frame = Vec::with_capacity(9 + payload.len());
    frame.push((length >> 16) as u8);
    frame.push((length >> 8) as u8);
    frame.push(length as u8);
    frame.push(frame_type);
    frame.push(flags);
    let sid = stream_id & 0x7FFFFFFF;
    frame.push((sid >> 24) as u8);
    frame.push((sid >> 16) as u8);
    frame.push((sid >> 8) as u8);
    frame.push(sid as u8);
    frame.extend_from_slice(payload);
    frame
}

// ═══════════════════════════════════════════════════════════════════════════
// Full connection lifecycle
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_full_lifecycle_preface_settings_headers_data_rst() {
    let mut c = H2Codec::new();

    // 1. Connection preface
    c.process(CONNECTION_PREFACE).unwrap();
    assert!(c.preface_received());

    // 2. SETTINGS
    let settings = H2Codec::create_settings_with_window(1 << 20);
    let events = c.process(&settings).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Settings { ack, settings } => {
            assert!(!*ack);
            assert_eq!(settings.len(), 2);
        }
        _ => panic!("Expected Settings"),
    }

    // 3. SETTINGS ACK
    let ack = H2Codec::create_settings_ack();
    let events = c.process(&ack).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Settings { ack, .. } => assert!(*ack),
        _ => panic!("Expected Settings ACK"),
    }

    // 4. HEADERS on stream 1
    let headers = H2Codec::create_headers_frame(1, &[0x82, 0x86, 0x84], false);
    let events = c.process(&headers).unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], H2Event::Headers { stream_id: 1, end_stream: false, .. }));

    // 5. DATA on stream 1
    let data_frames = H2Codec::create_data_frames(1, b"request body", true, 16384);
    let events = c.process(&data_frames[0]).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Data { stream_id, data, end_stream } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(data, b"request body");
            assert!(*end_stream);
        }
        _ => panic!("Expected Data"),
    }

    // 6. RST_STREAM on stream 1
    let rst = H2Codec::create_rst_stream(1, error_code::CANCEL);
    let events = c.process(&rst).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::StreamReset { stream_id, error_code: ec } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(*ec, error_code::CANCEL);
        }
        _ => panic!("Expected StreamReset"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Multiple concurrent streams
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_concurrent_streams_interleaved() {
    let mut c = H2Codec::new();
    c.set_preface_received(true);

    // Open stream 1 and stream 3 with HEADERS
    let h1 = H2Codec::create_headers_frame(1, &[0x82], false);
    let h3 = H2Codec::create_headers_frame(3, &[0x84], false);
    let mut data = h1;
    data.extend_from_slice(&h3);
    let events = c.process(&data).unwrap();
    assert_eq!(events.len(), 2);

    // Interleave DATA on both streams
    let d1 = H2Codec::create_data_frames(1, b"stream-1-body", true, 16384);
    let d3 = H2Codec::create_data_frames(3, b"stream-3-body", true, 16384);
    let mut data = d1[0].clone();
    data.extend_from_slice(&d3[0]);
    let events = c.process(&data).unwrap();
    assert_eq!(events.len(), 2);

    // Verify stream IDs
    match &events[0] {
        H2Event::Data { stream_id, .. } => assert_eq!(*stream_id, 1),
        _ => panic!("Expected Data"),
    }
    match &events[1] {
        H2Event::Data { stream_id, .. } => assert_eq!(*stream_id, 3),
        _ => panic!("Expected Data"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// GOAWAY mid-stream
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_goaway_mid_stream() {
    let mut c = H2Codec::new();
    c.set_preface_received(true);

    // Open stream 1
    let h1 = H2Codec::create_headers_frame(1, &[0x82], false);
    c.process(&h1).unwrap();

    // Send some data
    let d1 = H2Codec::create_data_frames(1, b"partial", false, 16384);
    c.process(&d1[0]).unwrap();

    // GOAWAY
    let goaway = H2Codec::create_goaway(1, error_code::NO_ERROR);
    let events = c.process(&goaway).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::GoAway { last_stream_id, error_code: ec } => {
            assert_eq!(*last_stream_id, 1);
            assert_eq!(*ec, error_code::NO_ERROR);
        }
        _ => panic!("Expected GoAway"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Ping/Pong mid-stream
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_ping_pong_mid_stream() {
    let mut c = H2Codec::new();
    c.set_preface_received(true);

    // Open stream 1
    let h1 = H2Codec::create_headers_frame(1, &[0x82], false);
    c.process(&h1).unwrap();

    // PING request
    let ping_data = [1, 2, 3, 4, 5, 6, 7, 8];
    let ping = build_frame(frame_type::PING, 0, 0, &ping_data);
    let events = c.process(&ping).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Ping { ack, data } => {
            assert!(!*ack);
            assert_eq!(*data, ping_data);
        }
        _ => panic!("Expected Ping"),
    }

    // Create and parse PING ACK
    let pong = H2Codec::create_ping_ack(ping_data);
    let events = c.process(&pong).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Ping { ack, data } => {
            assert!(*ack);
            assert_eq!(*data, ping_data);
        }
        _ => panic!("Expected Ping ACK"),
    }

    // Can still process data on stream 1 after ping/pong
    let d1 = H2Codec::create_data_frames(1, b"after-ping", true, 16384);
    let events = c.process(&d1[0]).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Data { stream_id, data, .. } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(data, b"after-ping");
        }
        _ => panic!("Expected Data"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Headers split via CONTINUATION then DATA
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_continuation_then_data() {
    let mut c = H2Codec::new();
    c.set_preface_received(true);

    // HEADERS without END_HEADERS
    let block = vec![0x82; 200];
    let frames = H2Codec::create_headers_frames(1, &block, false, 100);
    assert!(frames.len() > 1);

    // Feed all HEADERS + CONTINUATION frames
    let mut all_bytes = Vec::new();
    for f in &frames {
        all_bytes.extend_from_slice(f);
    }
    let events = c.process(&all_bytes).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Headers { stream_id, header_block, end_stream } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(header_block, &block);
            assert!(!*end_stream);
        }
        _ => panic!("Expected Headers"),
    }

    // Now send DATA on the same stream
    let data_frames = H2Codec::create_data_frames(1, b"body-after-continuation", true, 16384);
    let events = c.process(&data_frames[0]).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Data { stream_id, data, end_stream } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(data, b"body-after-continuation");
            assert!(*end_stream);
        }
        _ => panic!("Expected Data"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Window update flow
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_settings_then_window_update_flow() {
    let mut c = H2Codec::new();
    c.set_preface_received(true);

    // SETTINGS with window
    let settings = H2Codec::create_settings_with_window(65535);
    let events = c.process(&settings).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Settings { settings, .. } => {
            assert!(settings.iter().any(|(id, _)| *id == settings_id::INITIAL_WINDOW_SIZE));
        }
        _ => panic!("Expected Settings"),
    }

    // Connection-level WINDOW_UPDATE
    let wu_conn = H2Codec::create_window_update(0, 65535);
    let events = c.process(&wu_conn).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::WindowUpdate { stream_id, increment } => {
            assert_eq!(*stream_id, 0);
            assert_eq!(*increment, 65535);
        }
        _ => panic!("Expected WindowUpdate"),
    }

    // Stream-level WINDOW_UPDATE
    let wu_stream = H2Codec::create_window_update(1, 32768);
    let events = c.process(&wu_stream).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::WindowUpdate { stream_id, increment } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(*increment, 32768);
        }
        _ => panic!("Expected WindowUpdate"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Large multi-frame DATA roundtrip
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_large_data_split_roundtrip() {
    let mut c = H2Codec::new();
    c.set_preface_received(true);

    // 50KB of data split into 16KB frames
    let body: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
    let frames = H2Codec::create_data_frames(1, &body, true, 16384);
    assert!(frames.len() > 1);

    let mut all_bytes = Vec::new();
    for f in &frames {
        all_bytes.extend_from_slice(f);
    }

    let events = c.process(&all_bytes).unwrap();
    // Should have multiple DATA events
    let mut reassembled = Vec::new();
    let mut saw_end_stream = false;
    for event in &events {
        match event {
            H2Event::Data { data, end_stream, .. } => {
                reassembled.extend_from_slice(data);
                if *end_stream {
                    saw_end_stream = true;
                }
            }
            _ => panic!("Expected only Data events"),
        }
    }
    assert_eq!(reassembled, body);
    assert!(saw_end_stream);
}
