//! HPACK: Header Compression for HTTP/2 (RFC 7541)
//!
//! Thin wrapper around `fluke-hpack` providing the H2Header type
//! and decoder/encoder interfaces used throughout the kernel.

/// A decoded HTTP/2 header.
///
/// Both `name` and `value` are raw byte vectors to avoid data loss with
/// non-UTF-8 values (e.g. gRPC binary metadata). Use the convenience
/// methods `name_str()` / `value_str()` when you know the content is UTF-8.
#[derive(Debug, Clone, PartialEq)]
pub struct H2Header {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl H2Header {
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Return the header name as a UTF-8 string, or an error if not valid UTF-8.
    pub fn name_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.name)
    }

    /// Return the header value as a UTF-8 string, or an error if not valid UTF-8.
    pub fn value_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.value)
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
    ///
    /// Header names and values are returned as raw bytes to preserve
    /// binary content faithfully (no lossy UTF-8 conversion).
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<H2Header>, String> {
        let pairs = self.inner.decode(data).map_err(|e| format!("HPACK decode error: {:?}", e))?;
        Ok(pairs
            .into_iter()
            .map(|(name, value)| H2Header::new(name, value))
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
            .map(|h| (h.name.as_slice(), h.value.as_slice()))
            .collect();
        self.inner.encode(pairs)
    }
}
