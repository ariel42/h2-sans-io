//! Edge-case tests for connection preface handling.
//!
//! Tests for multi-fragment preface delivery, non-preface data,
//! and interactions with set_preface_received.

use h2_sans_io::{H2Codec, H2Event, CONNECTION_PREFACE, frame_type};

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
// Preface split across many process() calls
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_preface_split_across_three_calls() {
    let mut c = H2Codec::new();
    let preface = CONNECTION_PREFACE;
    let third = preface.len() / 3;

    let events = c.process(&preface[..third]).unwrap();
    assert!(events.is_empty());
    assert!(!c.preface_received());

    let events = c.process(&preface[third..third * 2]).unwrap();
    assert!(events.is_empty());
    assert!(!c.preface_received());

    let events = c.process(&preface[third * 2..]).unwrap();
    assert!(events.is_empty());
    assert!(c.preface_received());
}

#[test]
fn test_preface_one_byte_at_a_time() {
    let mut c = H2Codec::new();
    for (i, &byte) in CONNECTION_PREFACE.iter().enumerate() {
        let events = c.process(&[byte]).unwrap();
        assert!(events.is_empty());
        if i < CONNECTION_PREFACE.len() - 1 {
            assert!(!c.preface_received());
        } else {
            assert!(c.preface_received());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Non-preface data on fresh codec
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_non_preface_data_buffered_without_crash() {
    let mut c = H2Codec::new();
    // Feed raw bytes that don't look like a preface
    let garbage = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let events = c.process(garbage).unwrap();
    // No preface match, no valid frame headers → just buffered
    assert!(events.is_empty());
    assert!(!c.preface_received());
}

#[test]
fn test_partial_preface_prefix_then_wrong_data() {
    let mut c = H2Codec::new();
    // Send first 10 bytes of preface correctly
    c.process(&CONNECTION_PREFACE[..10]).unwrap();
    assert!(!c.preface_received());

    // Send wrong data for the rest — preface will be detected only when
    // buffer has >= 24 bytes and the full preface is checked
    let wrong = b"XXXXXXXXXXXXXX"; // 14 bytes → total=24
    let events = c.process(wrong).unwrap();
    assert!(events.is_empty());
    // The buffer now has 24 bytes but they don't match the preface
    assert!(!c.preface_received());
}

// ═══════════════════════════════════════════════════════════════════════════
// Frames embedded immediately after preface
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_preface_plus_settings_plus_headers_in_one_call() {
    let mut c = H2Codec::new();
    let mut data = CONNECTION_PREFACE.to_vec();
    // SETTINGS frame
    data.extend_from_slice(&build_frame(frame_type::SETTINGS, 0, 0, &[]));
    // HEADERS frame on stream 1
    data.extend_from_slice(&build_frame(
        frame_type::HEADERS,
        0x05, // END_HEADERS | END_STREAM
        1,
        &[0x82],
    ));

    let events = c.process(&data).unwrap();
    assert!(c.preface_received());
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], H2Event::Settings { .. }));
    assert!(matches!(&events[1], H2Event::Headers { .. }));
}

// ═══════════════════════════════════════════════════════════════════════════
// set_preface_received interactions
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_set_preface_false_after_true() {
    let mut c = H2Codec::new();
    c.set_preface_received(true);
    assert!(c.preface_received());

    c.set_preface_received(false);
    assert!(!c.preface_received());

    // Now send the preface bytes — they should be consumed again
    let mut data = CONNECTION_PREFACE.to_vec();
    data.extend_from_slice(&build_frame(frame_type::SETTINGS, 0, 0, &[]));
    let events = c.process(&data).unwrap();
    assert!(c.preface_received());
    assert_eq!(events.len(), 1);
}

#[test]
fn test_preface_already_received_raw_bytes_treated_as_data() {
    let mut c = H2Codec::new();
    c.set_preface_received(true);

    // Feed raw preface bytes — since preface is already received,
    // these are treated as frame data (and will just be buffered since
    // they don't form valid frame headers)
    let events = c.process(CONNECTION_PREFACE).unwrap();
    assert!(events.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Reset and re-preface
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_reset_then_preface_again() {
    let mut c = H2Codec::new();
    c.set_preface_received(true);

    // Process a frame
    let frame = build_frame(frame_type::SETTINGS, 0, 0, &[]);
    c.process(&frame).unwrap();

    // Reset
    c.reset();
    assert!(!c.preface_received());

    // Re-send preface + settings
    let mut data = CONNECTION_PREFACE.to_vec();
    data.extend_from_slice(&build_frame(frame_type::SETTINGS, 0, 0, &[]));
    let events = c.process(&data).unwrap();
    assert!(c.preface_received());
    assert_eq!(events.len(), 1);
}
