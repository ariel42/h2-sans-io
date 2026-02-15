//! Tests for HTTP/2 frame header parsing

use h2_sans_io::{H2Codec, H2Event, H2FrameHeader, frame_type, flags};

#[test]
fn test_frame_header_parse() {
    // DATA frame, length 5, stream 1, END_STREAM
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
    // HEADERS frame, length 10, stream 3, END_HEADERS
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
    // Frame header with reserved bit set on stream ID
    let header_bytes = [0, 0, 0, 4, 0, 0x80, 0x00, 0x00, 0x05];
    let header = H2FrameHeader::parse(&header_bytes).unwrap();
    assert_eq!(header.stream_id, 5, "Reserved bit should be cleared from stream ID");
}

#[test]
fn test_total_size() {
    let header = H2FrameHeader {
        length: 100,
        frame_type: 0,
        flags: 0,
        stream_id: 1,
    };
    assert_eq!(header.total_size(), 109); // 9 + 100
}
