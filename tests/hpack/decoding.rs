//! Tests for HPACK decoding

use h2_sans_io::{HpackDecoder, H2Header};

#[test]
fn test_decode_indexed_header() {
    let mut decoder = HpackDecoder::new();

    // 0x82 = indexed header, index 2 = :method: GET
    let data = [0x82];
    let headers = decoder.decode(&data).unwrap();

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, ":method");
    assert_eq!(headers[0].value, "GET");
}

#[test]
fn test_decode_multiple_indexed_headers() {
    let mut decoder = HpackDecoder::new();

    // 0x82 = :method: GET, 0x86 = :scheme: http, 0x84 = :path: /
    let data = [0x82, 0x86, 0x84];
    let headers = decoder.decode(&data).unwrap();

    assert_eq!(headers.len(), 3);
    assert_eq!(headers[0].name, ":method");
    assert_eq!(headers[0].value, "GET");
    assert_eq!(headers[1].name, ":scheme");
    assert_eq!(headers[1].value, "http");
    assert_eq!(headers[2].name, ":path");
    assert_eq!(headers[2].value, "/");
}

#[test]
fn test_decode_literal_with_indexing() {
    let mut decoder = HpackDecoder::new();

    // 0x40 = literal with indexing, new name
    let data = [
        0x40, // Literal with indexing, new name
        0x06, // Name length: 6
        b'c', b'u', b's', b't', b'o', b'm',
        0x05, // Value length: 5
        b'v', b'a', b'l', b'u', b'e',
    ];

    let headers = decoder.decode(&data).unwrap();

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, "custom");
    assert_eq!(headers[0].value, "value");
}

#[test]
fn test_decode_literal_indexed_name() {
    let mut decoder = HpackDecoder::new();

    // 0x41 = literal with indexing, indexed name (index 1 = :authority)
    let data = [
        0x41, // Literal with indexing, name index 1
        0x0B, // Value length: 11
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
    ];

    let headers = decoder.decode(&data).unwrap();

    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, ":authority");
    assert_eq!(headers[0].value, "example.com");
}
