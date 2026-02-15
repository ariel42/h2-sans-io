//! Tests for HPACK encoding

use h2_sans_io::{H2Header, HpackDecoder, HpackEncoder};

#[test]
fn test_encode_decode_roundtrip() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();
    let headers = vec![
        H2Header::new(":status", "200"),
        H2Header::new("content-type", "application/json"),
    ];
    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();
    assert_eq!(decoded.len(), 2);
}

#[test]
fn test_encode_literal_header() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();
    let headers = vec![H2Header::new("x-custom", "value")];
    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();
    assert_eq!(decoded[0].name, "x-custom");
}

#[test]
fn test_encode_indexed_header() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();
    let headers = vec![H2Header::new(":method", "GET")];
    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();
    assert_eq!(decoded[0].value, "GET");
}

#[test]
fn test_encode_multiple_headers() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();
    let headers = vec![
        H2Header::new(":method", "GET"),
        H2Header::new(":path", "/"),
        H2Header::new(":scheme", "https"),
    ];
    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();
    assert_eq!(decoded.len(), 3);
}

#[test]
fn test_encoder_new() {
    let encoder = HpackEncoder::new();
    assert!(std::mem::size_of_val(&encoder) > 0);
}

#[test]
fn test_decoder_new() {
    let decoder = HpackDecoder::new();
    assert!(std::mem::size_of_val(&decoder) > 0);
}

#[test]
fn test_h2header_new() {
    let header = H2Header::new("content-type", "text/html");
    assert_eq!(header.name, "content-type");
    assert_eq!(header.value, "text/html");
}

#[test]
fn test_h2header_clone() {
    let header = H2Header::new("host", "example.com");
    let cloned = header.clone();
    assert_eq!(cloned.name, header.name);
    assert_eq!(cloned.value, header.value);
}

#[test]
fn test_encode_decode_comprehensive_roundtrip() {
    // Comprehensive roundtrip with mixed pseudo + regular headers
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let headers = vec![
        H2Header::new(":status", "200"),
        H2Header::new("content-type", "application/json"),
        H2Header::new("x-request-id", "abc-123-def"),
        H2Header::new("set-cookie", "session=xyz"),
        H2Header::new("set-cookie", "theme=dark"),
    ];

    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();

    assert_eq!(decoded.len(), headers.len());
    for (orig, dec) in headers.iter().zip(decoded.iter()) {
        assert_eq!(orig.name, dec.name);
        assert_eq!(orig.value, dec.value);
    }
}
