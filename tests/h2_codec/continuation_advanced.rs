//! Advanced CONTINUATION frame tests.
//!
//! Tests for edge cases in CONTINUATION handling beyond the basics
//! already covered in continuation.rs.

use h2_sans_io::{H2Codec, H2Event, flags, frame_type};

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

fn codec() -> H2Codec {
    let mut c = H2Codec::new();
    c.set_preface_received(true);
    c
}

// ═══════════════════════════════════════════════════════════════════════════
// Many CONTINUATION frames
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_many_continuation_frames() {
    let mut c = codec();
    let num_continuations = 10;

    // HEADERS without END_HEADERS
    let headers = build_frame(frame_type::HEADERS, 0, 1, &[0x82]);
    c.process(&headers).unwrap();

    // 9 CONTINUATION frames without END_HEADERS
    for _ in 0..num_continuations - 1 {
        let cont = build_frame(frame_type::CONTINUATION, 0, 1, &[0x86]);
        c.process(&cont).unwrap();
    }

    // Final CONTINUATION with END_HEADERS
    let final_cont = build_frame(frame_type::CONTINUATION, flags::END_HEADERS, 1, &[0x84]);
    let events = c.process(&final_cont).unwrap();

    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Headers { stream_id, header_block, .. } => {
            assert_eq!(*stream_id, 1);
            // 1 byte from HEADERS + 9 bytes from middle CONTINUATIONs + 1 byte from final
            assert_eq!(header_block.len(), 1 + (num_continuations - 1) + 1);
        }
        _ => panic!("Expected Headers"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONTINUATION with empty payload
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_continuation_empty_payload() {
    let mut c = codec();

    // HEADERS without END_HEADERS
    let headers = build_frame(frame_type::HEADERS, 0, 1, &[0x82, 0x86]);
    c.process(&headers).unwrap();

    // CONTINUATION with 0 bytes payload + END_HEADERS
    let cont = build_frame(frame_type::CONTINUATION, flags::END_HEADERS, 1, &[]);
    let events = c.process(&cont).unwrap();

    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Headers { header_block, .. } => {
            assert_eq!(header_block, &[0x82, 0x86]);
        }
        _ => panic!("Expected Headers"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Error cleanup during CONTINUATION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_continuation_size_overflow_clears_pending_state() {
    let mut c = codec();

    // HEADERS with large initial block (200KB) — under 256KB limit
    let initial = vec![0x82; 200 * 1024];
    let initial_len = initial.len() as u32;
    let mut data = vec![
        (initial_len >> 16) as u8,
        (initial_len >> 8) as u8,
        initial_len as u8,
        frame_type::HEADERS,
        0, // no END_HEADERS
        0, 0, 0, 1,
    ];
    data.extend_from_slice(&initial);
    c.process(&data).unwrap();

    // CONTINUATION that pushes over 256KB — error
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
    let result = c.process(&cont_data);
    assert!(result.is_err());

    // After the error, the pending header state should be cleared.
    // A new HEADERS frame should work (no stale CONTINUATION interlock).
    let new_headers = build_frame(frame_type::HEADERS, flags::END_HEADERS, 3, &[0x82]);
    let events = c.process(&new_headers).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Headers { stream_id, .. } => assert_eq!(*stream_id, 3),
        _ => panic!("Expected Headers"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Sequential header blocks on different streams
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_sequential_header_blocks_different_streams() {
    let mut c = codec();

    // First: HEADERS on stream 1 with CONTINUATION
    let h1 = build_frame(frame_type::HEADERS, 0, 1, &[0x82]);
    c.process(&h1).unwrap();
    let c1 = build_frame(frame_type::CONTINUATION, flags::END_HEADERS, 1, &[0x86]);
    let events = c.process(&c1).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Headers { stream_id, header_block, .. } => {
            assert_eq!(*stream_id, 1);
            assert_eq!(header_block, &[0x82, 0x86]);
        }
        _ => panic!("Expected Headers"),
    }

    // Second: HEADERS on stream 3 with CONTINUATION
    let h3 = build_frame(frame_type::HEADERS, 0, 3, &[0x84]);
    c.process(&h3).unwrap();
    let c3 = build_frame(frame_type::CONTINUATION, flags::END_HEADERS, 3, &[0x88]);
    let events = c.process(&c3).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        H2Event::Headers { stream_id, header_block, .. } => {
            assert_eq!(*stream_id, 3);
            assert_eq!(header_block, &[0x84, 0x88]);
        }
        _ => panic!("Expected Headers"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONTINUATION end_stream propagation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_continuation_no_end_stream_on_headers() {
    let mut c = codec();

    // HEADERS without END_STREAM and without END_HEADERS
    let h = build_frame(frame_type::HEADERS, 0, 1, &[0x82]);
    c.process(&h).unwrap();

    // CONTINUATION with END_HEADERS
    let cont = build_frame(frame_type::CONTINUATION, flags::END_HEADERS, 1, &[0x86]);
    let events = c.process(&cont).unwrap();
    match &events[0] {
        H2Event::Headers { end_stream, .. } => {
            assert!(!*end_stream, "END_STREAM should be false");
        }
        _ => panic!("Expected Headers"),
    }
}

#[test]
fn test_continuation_end_stream_on_headers() {
    let mut c = codec();

    // HEADERS with END_STREAM but without END_HEADERS
    let h = build_frame(frame_type::HEADERS, flags::END_STREAM, 1, &[0x82]);
    c.process(&h).unwrap();

    // CONTINUATION with END_HEADERS (no END_STREAM — that's only on HEADERS)
    let cont = build_frame(frame_type::CONTINUATION, flags::END_HEADERS, 1, &[0x86]);
    let events = c.process(&cont).unwrap();
    match &events[0] {
        H2Event::Headers { end_stream, .. } => {
            assert!(*end_stream, "END_STREAM should propagate from HEADERS");
        }
        _ => panic!("Expected Headers"),
    }
}
