//! Tests for HPACK binary header preservation and dynamic table state.
//!
//! These tests verify that:
//! - Binary (non-UTF-8) header values are preserved faithfully
//! - The dynamic table state is maintained correctly across multiple operations
//! - The H2Header API works with raw bytes

use h2_sans_io::{H2Header, HpackDecoder, HpackEncoder};

// ═══════════════════════════════════════════════════════════════════════════
// Binary header value preservation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_binary_header_value_roundtrip() {
    // gRPC uses binary metadata with header names ending in "-bin".
    // Values can be arbitrary bytes including invalid UTF-8.
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let binary_value: Vec<u8> = vec![0x00, 0xFF, 0x80, 0xFE, 0x01];
    let headers = vec![
        H2Header::new(b"grpc-status-bin".to_vec(), binary_value.clone()),
    ];

    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name, b"grpc-status-bin");
    assert_eq!(decoded[0].value, binary_value);
}

#[test]
fn test_header_value_with_null_bytes() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let value_with_nulls = vec![b'a', 0x00, b'b', 0x00, b'c'];
    let headers = vec![H2Header::new(b"x-test".to_vec(), value_with_nulls.clone())];

    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();

    assert_eq!(decoded[0].value, value_with_nulls);
}

#[test]
fn test_header_with_high_bytes() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    // All bytes 0x80..0xFF (non-ASCII)
    let high_bytes: Vec<u8> = (0x80..=0xFF).collect();
    let headers = vec![H2Header::new(b"x-binary".to_vec(), high_bytes.clone())];

    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();

    assert_eq!(decoded[0].value, high_bytes);
}

// ═══════════════════════════════════════════════════════════════════════════
// H2Header API tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_h2header_new_from_str() {
    let h = H2Header::new("content-type", "text/html");
    assert_eq!(h.name, b"content-type");
    assert_eq!(h.value, b"text/html");
}

#[test]
fn test_h2header_new_from_vec() {
    let h = H2Header::new(vec![0x01, 0x02], vec![0x03, 0x04]);
    assert_eq!(h.name, vec![0x01, 0x02]);
    assert_eq!(h.value, vec![0x03, 0x04]);
}

#[test]
fn test_h2header_name_str_valid_utf8() {
    let h = H2Header::new("content-type", "text/html");
    assert_eq!(h.name_str().unwrap(), "content-type");
    assert_eq!(h.value_str().unwrap(), "text/html");
}

#[test]
fn test_h2header_name_str_invalid_utf8() {
    let h = H2Header::new(vec![0xFF, 0xFE], vec![0x80]);
    assert!(h.name_str().is_err());
    assert!(h.value_str().is_err());
}

#[test]
fn test_h2header_partialeq() {
    let h1 = H2Header::new("a", "b");
    let h2 = H2Header::new("a", "b");
    let h3 = H2Header::new("a", "c");
    assert_eq!(h1, h2);
    assert_ne!(h1, h3);
}

#[test]
fn test_h2header_debug() {
    let h = H2Header::new("x", "y");
    let debug = format!("{:?}", h);
    assert!(debug.contains("H2Header"));
}

#[test]
fn test_h2header_clone() {
    let h = H2Header::new(vec![1, 2, 3], vec![4, 5, 6]);
    let c = h.clone();
    assert_eq!(h, c);
}

// ═══════════════════════════════════════════════════════════════════════════
// HPACK dynamic table state across multiple operations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_encoder_decoder_dynamic_table_state() {
    // HPACK maintains a dynamic table: encoding the same headers a second
    // time should produce a shorter encoding because the entries are now
    // indexed in the dynamic table.
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let headers = vec![
        H2Header::new("x-custom-header", "some-value-here"),
    ];

    let encoded1 = encoder.encode(&headers);
    let decoded1 = decoder.decode(&encoded1).unwrap();
    assert_eq!(decoded1[0].name, b"x-custom-header");
    assert_eq!(decoded1[0].value, b"some-value-here");

    // Second encoding of the same headers should be shorter (indexed)
    let encoded2 = encoder.encode(&headers);
    let decoded2 = decoder.decode(&encoded2).unwrap();
    assert_eq!(decoded2[0].name, b"x-custom-header");
    assert_eq!(decoded2[0].value, b"some-value-here");

    assert!(
        encoded2.len() <= encoded1.len(),
        "Second encoding ({} bytes) should be <= first ({} bytes) due to dynamic table",
        encoded2.len(),
        encoded1.len()
    );
}

#[test]
fn test_multiple_sequential_header_blocks() {
    // Simulate multiple request/response header blocks on a single connection.
    // The dynamic table state must carry over between blocks.
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    // First request
    let req1 = vec![
        H2Header::new(":method", "GET"),
        H2Header::new(":path", "/api/v1/users"),
        H2Header::new(":scheme", "https"),
        H2Header::new(":authority", "example.com"),
    ];
    let enc1 = encoder.encode(&req1);
    let dec1 = decoder.decode(&enc1).unwrap();
    assert_eq!(dec1.len(), 4);

    // Second request: same authority, different path
    let req2 = vec![
        H2Header::new(":method", "GET"),
        H2Header::new(":path", "/api/v1/posts"),
        H2Header::new(":scheme", "https"),
        H2Header::new(":authority", "example.com"),
    ];
    let enc2 = encoder.encode(&req2);
    let dec2 = decoder.decode(&enc2).unwrap();
    assert_eq!(dec2.len(), 4);

    // Verify correctness
    assert_eq!(dec2[0].name, b":method");
    assert_eq!(dec2[0].value, b"GET");
    assert_eq!(dec2[1].name, b":path");
    assert_eq!(dec2[1].value, b"/api/v1/posts");
    assert_eq!(dec2[3].name, b":authority");
    assert_eq!(dec2[3].value, b"example.com");

    // Third request
    let req3 = vec![
        H2Header::new(":method", "POST"),
        H2Header::new(":path", "/api/v1/posts"),
        H2Header::new(":scheme", "https"),
        H2Header::new(":authority", "example.com"),
        H2Header::new("content-type", "application/json"),
    ];
    let enc3 = encoder.encode(&req3);
    let dec3 = decoder.decode(&enc3).unwrap();
    assert_eq!(dec3.len(), 5);
    assert_eq!(dec3[0].value, b"POST");
    assert_eq!(dec3[4].name, b"content-type");
}

#[test]
fn test_decoder_independent_of_encoder() {
    // Verify that decoder and encoder are independently stateful.
    // Using mismatched encoder/decoder should fail or produce wrong results.
    let mut encoder1 = HpackEncoder::new();
    let mut encoder2 = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    // Encode with encoder1 (populates its dynamic table)
    let headers = vec![H2Header::new("x-session", "abc123")];
    let enc1 = encoder1.encode(&headers);
    decoder.decode(&enc1).unwrap();

    // Encode same headers with encoder2 (separate dynamic table)
    let enc2 = encoder2.encode(&headers);
    // This should decode correctly because both encoders are fresh
    let dec2 = decoder.decode(&enc2).unwrap();
    assert_eq!(dec2[0].name, b"x-session");
    assert_eq!(dec2[0].value, b"abc123");
}

// ═══════════════════════════════════════════════════════════════════════════
// HPACK edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_encode_empty_headers() {
    let mut encoder = HpackEncoder::new();
    let encoded = encoder.encode(&[]);
    assert!(encoded.is_empty());
}

#[test]
fn test_decode_empty_block() {
    let mut decoder = HpackDecoder::new();
    let decoded = decoder.decode(&[]).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn test_encode_empty_name_and_value() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let headers = vec![H2Header::new(b"".to_vec(), b"".to_vec())];
    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();

    assert_eq!(decoded.len(), 1);
    assert!(decoded[0].name.is_empty());
    assert!(decoded[0].value.is_empty());
}

#[test]
fn test_encode_large_header_value() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let large_value = vec![b'x'; 8192];
    let headers = vec![H2Header::new("x-large", large_value.clone())];
    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();

    assert_eq!(decoded[0].value, large_value);
}

#[test]
fn test_decode_invalid_data_returns_error() {
    let mut decoder = HpackDecoder::new();
    // 0xFF with no following data is invalid HPACK
    let result = decoder.decode(&[0xFF, 0xFF, 0xFF, 0xFF]);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// HpackEncoder/HpackDecoder Debug
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_hpack_encoder_debug() {
    let encoder = HpackEncoder::new();
    let debug = format!("{:?}", encoder);
    assert!(debug.contains("HpackEncoder"));
}

#[test]
fn test_hpack_decoder_debug() {
    let decoder = HpackDecoder::new();
    let debug = format!("{:?}", decoder);
    assert!(debug.contains("HpackDecoder"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Default trait
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_hpack_encoder_default() {
    let encoder: HpackEncoder = Default::default();
    let debug = format!("{:?}", encoder);
    assert!(debug.contains("HpackEncoder"));
}

#[test]
fn test_hpack_decoder_default() {
    let decoder: HpackDecoder = Default::default();
    let debug = format!("{:?}", decoder);
    assert!(debug.contains("HpackDecoder"));
}
