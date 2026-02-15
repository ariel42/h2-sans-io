//! Tests for HPACK encoding

use h2_sans_io::{HpackDecoder, HpackEncoder, H2Header};

#[test]
fn test_encode_indexed_header() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let headers = vec![H2Header::new(":method", "GET")];
    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name, ":method");
    assert_eq!(decoded[0].value, "GET");
}

#[test]
fn test_encode_literal_header() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let headers = vec![H2Header::new("x-custom", "value")];
    let encoded = encoder.encode(&headers);
    let decoded = decoder.decode(&encoded).unwrap();

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name, "x-custom");
    assert_eq!(decoded[0].value, "value");
}

#[test]
fn test_encode_decode_roundtrip() {
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
