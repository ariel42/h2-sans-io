//! Tests for HTTP/2 frame header parsing

use h2_sans_io::{H2FrameHeader, frame_type};

#[test]
fn test_frame_header_parse() {
    let header_bytes = [0, 0, 5, 0, 1, 0, 0, 0, 1];
    let header = H2FrameHeader::parse(&header_bytes).unwrap();
    assert_eq!(header.length, 5);
    assert_eq!(header.frame_type, frame_type::DATA);
    assert_eq!(header.stream_id, 1);
    assert!(header.is_end_stream());
    assert!(!header.is_end_headers());
}

#[test]
fn test_frame_header_headers() {
    let header_bytes = [0, 0, 10, 1, 4, 0, 0, 0, 3];
    let header = H2FrameHeader::parse(&header_bytes).unwrap();
    assert_eq!(header.length, 10);
    assert_eq!(header.frame_type, frame_type::HEADERS);
    assert_eq!(header.stream_id, 3);
    assert!(!header.is_end_stream());
    assert!(header.is_end_headers());
}

#[test]
fn test_stream_id_clears_reserved_bit() {
    let header_bytes = [0, 0, 0, 4, 0, 0x80, 0x00, 0x00, 0x05];
    let header = H2FrameHeader::parse(&header_bytes).unwrap();
    assert_eq!(header.stream_id, 5);
}

#[test]
fn test_total_size() {
    let header = H2FrameHeader {
        length: 100,
        frame_type: 0,
        flags: 0,
        stream_id: 1,
    };
    assert_eq!(header.total_size(), 109);
}
