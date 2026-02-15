//! HPACK: Header Compression for HTTP/2 (RFC 7541)
//!
//! Thin wrapper around `fluke-hpack` providing the H2Header type
//! and decoder/encoder interfaces used throughout the kernel.

/// A decoded HTTP/2 header
#[derive(Debug, Clone, PartialEq)]
pub struct H2Header {
    pub name: String,
    pub value: String,
}

impl H2Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// HPACK decoder for HTTP/2 header blocks.
/// Wraps `fluke_hpack::Decoder` which maintains dynamic table state per-connection.
pub struct HpackDecoder {
    inner: fluke_hpack::Decoder<'static>,
}

impl std::fmt::Debug for HpackDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpackDecoder").finish()
    }
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackDecoder {
    pub fn new() -> Self {
        Self {
            inner: fluke_hpack::Decoder::new(),
        }
    }

    /// Decode an HPACK-encoded header block into H2Headers.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<H2Header>, String> {
        let pairs = self.inner.decode(data).map_err(|e| format!("HPACK decode error: {:?}", e))?;
        Ok(pairs
            .into_iter()
            .map(|(name, value)| {
                H2Header::new(
                    String::from_utf8_lossy(&name).into_owned(),
                    String::from_utf8_lossy(&value).into_owned(),
                )
            })
            .collect())
    }
}

/// HPACK encoder for HTTP/2 header blocks.
/// Wraps `fluke_hpack::Encoder` which maintains dynamic table state per-connection.
pub struct HpackEncoder {
    inner: fluke_hpack::Encoder<'static>,
}

impl std::fmt::Debug for HpackEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpackEncoder").finish()
    }
}

impl Default for HpackEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackEncoder {
    pub fn new() -> Self {
        Self {
            inner: fluke_hpack::Encoder::new(),
        }
    }

    /// Encode headers into an HPACK header block.
    pub fn encode(&mut self, headers: &[H2Header]) -> Vec<u8> {
        let pairs: Vec<(&[u8], &[u8])> = headers
            .iter()
            .map(|h| (h.name.as_bytes(), h.value.as_bytes()))
            .collect();
        self.inner.encode(pairs)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        // Name: "custom" (length 6)
        // Value: "value" (length 5)
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
        // Value: "example.com" (length 11)
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

    #[test]
    fn test_encode_indexed_header() {
        // Roundtrip: encode then decode, verify headers match
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
        // Roundtrip: encode then decode, verify headers match
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
}
