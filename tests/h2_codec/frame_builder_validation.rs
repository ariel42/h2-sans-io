//! Tests for frame builder input validation.
//!
//! These tests verify the assert guards added to prevent silent 24-bit
//! length truncation in frame builder functions.

use h2_sans_io::{H2Codec, MAX_FRAME_PAYLOAD_LENGTH};

// ═══════════════════════════════════════════════════════════════════════════
// create_headers_frame — payload length validation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "exceeds maximum frame payload length")]
fn test_create_headers_frame_oversized_payload_panics() {
    // Header block larger than 2^24-1 must panic, not silently truncate.
    let oversized = vec![0xAA; MAX_FRAME_PAYLOAD_LENGTH as usize + 1];
    H2Codec::create_headers_frame(1, &oversized, false);
}

#[test]
fn test_create_headers_frame_at_max_payload_length_ok() {
    // Exactly at the limit should succeed.
    let max_block = vec![0xBB; MAX_FRAME_PAYLOAD_LENGTH as usize];
    let frame = H2Codec::create_headers_frame(1, &max_block, false);
    // Verify the 24-bit length field encodes correctly
    let encoded_len = ((frame[0] as u32) << 16) | ((frame[1] as u32) << 8) | (frame[2] as u32);
    assert_eq!(encoded_len, MAX_FRAME_PAYLOAD_LENGTH);
}

#[test]
fn test_create_headers_frame_small_payload_ok() {
    let block = vec![0x82; 100];
    let frame = H2Codec::create_headers_frame(1, &block, true);
    assert_eq!(frame.len(), 9 + 100);
}

// ═══════════════════════════════════════════════════════════════════════════
// create_headers_frames — max_frame_size validation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "exceeds maximum frame payload length")]
fn test_create_headers_frames_oversized_max_frame_size_panics() {
    let block = vec![0xCC; 100];
    H2Codec::create_headers_frames(1, &block, false, MAX_FRAME_PAYLOAD_LENGTH + 1);
}

#[test]
fn test_create_headers_frames_at_max_frame_size_ok() {
    let block = vec![0xDD; 100];
    let frames = H2Codec::create_headers_frames(1, &block, false, MAX_FRAME_PAYLOAD_LENGTH);
    assert_eq!(frames.len(), 1);
}

#[test]
fn test_create_headers_frames_normal_max_frame_size_ok() {
    let block = vec![0xEE; 200];
    let frames = H2Codec::create_headers_frames(1, &block, true, 16384);
    assert_eq!(frames.len(), 1);
}

#[test]
#[should_panic(expected = "exceeds maximum frame payload length")]
fn test_create_headers_frames_u32_max_panics() {
    let block = vec![0xFF; 10];
    H2Codec::create_headers_frames(1, &block, false, u32::MAX);
}

// ═══════════════════════════════════════════════════════════════════════════
// create_data_frames — max_frame_size validation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "exceeds maximum frame payload length")]
fn test_create_data_frames_oversized_max_frame_size_panics() {
    let data = vec![0x11; 100];
    H2Codec::create_data_frames(1, &data, true, MAX_FRAME_PAYLOAD_LENGTH + 1);
}

#[test]
fn test_create_data_frames_at_max_frame_size_ok() {
    let data = vec![0x22; 100];
    let frames = H2Codec::create_data_frames(1, &data, true, MAX_FRAME_PAYLOAD_LENGTH);
    assert_eq!(frames.len(), 1);
}

#[test]
fn test_create_data_frames_normal_max_frame_size_ok() {
    let data = vec![0x33; 200];
    let frames = H2Codec::create_data_frames(1, &data, true, 16384);
    assert_eq!(frames.len(), 1);
}

#[test]
#[should_panic(expected = "exceeds maximum frame payload length")]
fn test_create_data_frames_u32_max_panics() {
    let data = vec![0x44; 10];
    H2Codec::create_data_frames(1, &data, true, u32::MAX);
}

// ═══════════════════════════════════════════════════════════════════════════
// create_continuation_frame — existing assert (regression test)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[should_panic(expected = "exceeds maximum frame payload length")]
fn test_create_continuation_frame_oversized_panics() {
    let oversized = vec![0x55; MAX_FRAME_PAYLOAD_LENGTH as usize + 1];
    H2Codec::create_continuation_frame(1, &oversized, true);
}

#[test]
fn test_create_continuation_frame_at_max_ok() {
    let max_block = vec![0x66; MAX_FRAME_PAYLOAD_LENGTH as usize];
    let frame = H2Codec::create_continuation_frame(1, &max_block, true);
    let encoded_len = ((frame[0] as u32) << 16) | ((frame[1] as u32) << 8) | (frame[2] as u32);
    assert_eq!(encoded_len, MAX_FRAME_PAYLOAD_LENGTH);
}
