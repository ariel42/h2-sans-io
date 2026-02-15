//! Tests for HPACK decoding

use h2_sans_io::HpackDecoder;

#[test]
fn test_decode_indexed_header() {
    let mut decoder = HpackDecoder::new();
    let data = [0x82];
    let headers = decoder.decode(&data).unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, ":method");
}

#[test]
fn test_decode_multiple_indexed_headers() {
    let mut decoder = HpackDecoder::new();
    let data = [0x82, 0x86, 0x84];
    let headers = decoder.decode(&data).unwrap();
    assert_eq!(headers.len(), 3);
}

#[test]
fn test_decode_literal_with_indexing() {
    let mut decoder = HpackDecoder::new();
    let data = [0x40, 0x06, b'c', b'u', b's', b't', b'o', b'm', 0x05, b'v', b'a', b'l', b'u', b'e'];
    let headers = decoder.decode(&data).unwrap();
    assert_eq!(headers[0].name, "custom");
}

#[test]
fn test_decode_literal_indexed_name() {
    let mut decoder = HpackDecoder::new();
    let data = [0x41, 0x0B, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm'];
    let headers = decoder.decode(&data).unwrap();
    assert_eq!(headers[0].name, ":authority");
}

#[test]
fn test_decode_status_200() {
    let mut decoder = HpackDecoder::new();
    let data = [0x88];
    let headers = decoder.decode(&data).unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, ":status");
    assert_eq!(headers[0].value, "200");
}
