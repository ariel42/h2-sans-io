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
