//! JSON-LD transport and HTML embedding support.
//!
//! JsonLd contains valid JSON encoded so it is safe both as an
//! application/ld+json response body and inside an HTML
//! script type="application/ld+json" data block. It deliberately does not
//! implement JSON-LD expansion, compaction, context loading, or vocabulary
//! validation.
//!
//! The HTML serializer escapes every literal less-than sign as \u003c. HTML
//! parses a script element's raw text before considering its type, so an
//! otherwise inert JSON-LD string containing a script end tag could terminate
//! the element. The JSON escape preserves the string value while removing that
//! HTML parser boundary.

use rama_core::bytes::{ByteStr, Bytes};
use serde::{Serialize, de::DeserializeOwned};
use std::io::{self, Write};

use crate::headers::ContentType;
use crate::service::web::response::{Headers, IntoResponse};
use crate::{Body, Response};

const INITIAL_CAPACITY: usize = 128;
const LESS_THAN_ESCAPE: &[u8] = br"\u003c";

/// A valid, script-data-safe JSON-LD document.
///
/// This type guarantees JSON syntax and safe HTML embedding. It does not
/// process JSON-LD semantics such as @context, expansion, or compaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JsonLd(ByteStr);

impl JsonLd {
    /// Serialize value directly into script-data-safe JSON.
    ///
    /// Every literal less-than sign emitted by the serializer is encoded as a
    /// JSON Unicode escape so strings containing a script end tag cannot
    /// terminate an enclosing HTML script element.
    pub fn serialize<T>(value: &T) -> Result<Self, serde_json::Error>
    where
        T: Serialize + ?Sized,
    {
        let mut writer = ScriptSafeJsonWriter::with_capacity(INITIAL_CAPACITY);
        serde_json::to_writer(&mut writer, value)?;
        Ok(Self(ByteStr::from(writer.into_string())))
    }

    /// Serialize an existing serde_json::Value.
    ///
    /// Unlike arbitrary Serialize implementations, a Value cannot reject
    /// serialization, and the in-memory writer used here cannot fail.
    #[must_use]
    pub fn from_value(value: &serde_json::Value) -> Self {
        #[expect(
            clippy::expect_used,
            reason = "serde_json::Value serialized to an infallible in-memory writer cannot fail"
        )]
        Self::serialize(value).expect("serde_json::Value serialization to memory to succeed")
    }

    /// Validate and prepare existing JSON bytes.
    ///
    /// The original allocation is retained when the input contains no literal
    /// less-than sign. Otherwise only those bytes are rewritten into JSON
    /// Unicode escapes.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, serde_json::Error> {
        serde_json::from_slice::<serde::de::IgnoredAny>(&bytes)?;

        if !bytes.contains(&b'<') {
            // SAFETY: serde_json accepted the complete input, which includes
            // validating that all strings and therefore the document are
            // valid UTF-8.
            return Ok(Self(unsafe { ByteStr::from_utf8_unchecked(bytes) }));
        }

        let mut writer = ScriptSafeJsonWriter::with_capacity(bytes.len());
        #[expect(
            clippy::expect_used,
            reason = "the in-memory JSON-LD writer cannot fail"
        )]
        writer
            .write_all(&bytes)
            .expect("the in-memory JSON-LD writer cannot fail");
        Ok(Self(ByteStr::from(writer.into_string())))
    }

    /// Deserialize the document into T.
    pub fn deserialize<T>(&self) -> Result<T, serde_json::Error>
    where
        T: DeserializeOwned,
    {
        serde_json::from_str(&self.0)
    }

    /// Return the encoded JSON bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Return the encoded JSON text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the document into its cheaply-shareable encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.0.into()
    }

    /// Render this document as an HTML JSON-LD data block.
    #[cfg(feature = "html")]
    #[cfg_attr(docsrs, doc(cfg(feature = "html")))]
    #[must_use]
    pub fn script(&self) -> JsonLdScript {
        JsonLdScript {
            document: self.clone(),
            id: None,
        }
    }
}

impl AsRef<[u8]> for JsonLd {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<Bytes> for JsonLd {
    type Error = serde_json::Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl TryFrom<Vec<u8>> for JsonLd {
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(Bytes::from(value))
    }
}

impl TryFrom<String> for JsonLd {
    type Error = serde_json::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_bytes(Bytes::from(value))
    }
}

impl From<JsonLd> for Body {
    fn from(value: JsonLd) -> Self {
        value.into_bytes().into()
    }
}

impl IntoResponse for JsonLd {
    fn into_response(self) -> Response {
        (Headers::single(ContentType::json_ld()), self.into_bytes()).into_response()
    }
}

/// An HTML script type="application/ld+json" data block.
#[cfg(feature = "html")]
#[cfg_attr(docsrs, doc(cfg(feature = "html")))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonLdScript {
    document: JsonLd,
    id: Option<Box<str>>,
}

#[cfg(feature = "html")]
impl JsonLdScript {
    /// Set the script element's id attribute.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<Box<str>>) -> Self {
        self.id = Some(id.into());
        self
    }
}

#[cfg(feature = "html")]
impl crate::protocols::html::IntoHtml for JsonLdScript {
    fn into_html(self) -> impl crate::protocols::html::IntoHtml {
        self
    }

    fn escape_and_write(self, output: &mut String) {
        use crate::protocols::html::escape_into;

        output.push_str(r#"<script type="application/ld+json""#);
        if let Some(id) = self.id {
            output.push_str(r#" id=""#);
            escape_into(output, &id);
            output.push('"');
        }
        output.push('>');
        output.push_str(self.document.as_str());
        output.push_str("</script>");
    }

    fn size_hint(&self) -> usize {
        const ELEMENT_OVERHEAD: usize = r#"<script type="application/ld+json"></script>"#.len();
        let id_overhead = self
            .id
            .as_deref()
            .map_or(0, |id| r#" id="""#.len() + id.len() + 1);
        ELEMENT_OVERHEAD + id_overhead + self.document.as_str().len()
    }
}

/// In-memory writer that makes serialized JSON safe for HTML script data.
struct ScriptSafeJsonWriter {
    bytes: Vec<u8>,
}

impl ScriptSafeJsonWriter {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn into_string(self) -> String {
        // SAFETY: callers only feed this writer either serde_json output or a
        // complete document already validated by serde_json. Replacing ASCII
        // less-than with an ASCII JSON escape preserves UTF-8.
        unsafe { String::from_utf8_unchecked(self.bytes) }
    }
}

impl Write for ScriptSafeJsonWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut start = 0;
        for (index, byte) in buf.iter().copied().enumerate() {
            if byte == b'<' {
                self.bytes.extend_from_slice(&buf[start..index]);
                self.bytes.extend_from_slice(LESS_THAN_ESCAPE);
                start = index + 1;
            }
        }
        self.bytes.extend_from_slice(&buf[start..]);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "html")]
mod extract;

#[cfg(feature = "html")]
#[doc(inline)]
pub use extract::{EmbeddedJsonLd, ExtractJsonLd, ExtractJsonLdError, extract_from_html};

#[cfg(test)]
mod tests;
