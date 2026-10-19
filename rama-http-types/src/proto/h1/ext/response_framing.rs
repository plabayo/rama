use rama_core::extensions::Extension;

use crate::{HeaderMap, HeaderName, header};

/// Prefer close-delimited framing when encoding an HTTP/1 response.
///
/// Insert this extension on the response or its inherited context.
/// The encoder emits neither
/// `Content-Length` nor `Transfer-Encoding`, adds `Connection: close`, streams
/// the body unchanged, and closes the connection when the body ends. An exact
/// body size hint does not override this choice. Like other context extensions,
/// the preference remains effective when middleware derives a response from it.
///
/// Explicit `Content-Length`, `Transfer-Encoding`, or `Trailer` headers take
/// precedence, using the encoder's normal framing and validation rules. Without
/// these headers, the body must not produce trailers. This extension has no effect
/// on responses that cannot carry a body (including HEAD and successful CONNECT)
/// or on HTTP/2 connections.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Extension)]
#[extension(tags(http))]
pub struct CloseDelimitedResponse;

/// Original HTTP/1 response framing, recorded by the client decoder before
/// middleware can remove or change the framing headers.
///
/// Each parsed response receives its own value, overriding inherited metadata.
/// This is informational; inserting it does not select outgoing framing. When
/// HTTP/1 independently selects chunked framing, the original transfer-encoding
/// name supplies its spelling. Explicit outgoing headers take precedence.
#[derive(Clone, Debug, Eq, PartialEq, Extension)]
#[extension(tags(http))]
#[non_exhaustive]
pub enum OriginalResponseBodyFraming {
    /// No HTTP message body, for example a HEAD response or protocol upgrade.
    Empty,
    /// The response body has an explicit Content-Length.
    ContentLength,
    /// Transfer-Encoding was present, whether or not its final coding is chunked.
    TransferEncoded(TransferEncodingHeaderName),
    /// A body delimited by EOF, with neither Content-Length nor Transfer-Encoding.
    CloseDelimited,
}

/// A transfer-encoding header name with its original spelling.
///
/// The field identity is validated on construction; using this name cannot
/// change a framing field into a different HTTP header.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TransferEncodingHeaderName(HeaderName);

impl TransferEncodingHeaderName {
    /// Capture the spelling of the first transfer-encoding field, if present.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        if !headers.contains_key(header::TRANSFER_ENCODING) {
            return None;
        }
        headers
            .keys()
            .find(|name| *name == header::TRANSFER_ENCODING)
            .cloned()
            .map(Self)
    }

    #[must_use]
    pub fn name(&self) -> &HeaderName {
        &self.0
    }
}

impl TryFrom<HeaderName> for TransferEncodingHeaderName {
    type Error = HeaderName;

    /// Accept a transfer-encoding name, returning any other name unchanged.
    fn try_from(name: HeaderName) -> Result<Self, Self::Error> {
        if name == header::TRANSFER_ENCODING {
            Ok(Self(name))
        } else {
            Err(name)
        }
    }
}

#[cfg(test)]
mod tests {
    use rama_core::extensions::ExtensionsRef as _;

    use super::*;
    use crate::{
        Response, Version,
        header::hop_by_hop::{
            HopByHopHeaderContext, HopByHopResponseDisposition,
            sanitize_hop_by_hop_response_headers,
        },
    };

    #[test]
    fn framing_name_retains_spelling_without_retaining_an_http1_header_on_other_protocols() {
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let mut response = Response::builder()
                .version(version)
                .header("tRaNsFeR-EnCoDiNg", "chunked")
                .body(())
                .unwrap();
            let name = TransferEncodingHeaderName::from_headers(response.headers()).unwrap();
            assert_eq!(name.name().as_original_str(), "tRaNsFeR-EnCoDiNg");
            response
                .extensions()
                .insert(OriginalResponseBodyFraming::TransferEncoded(name));
            assert_eq!(
                sanitize_hop_by_hop_response_headers(
                    &mut response,
                    &HopByHopHeaderContext::default()
                ),
                HopByHopResponseDisposition::Forward
            );
            assert!(!response.headers().contains_key(header::TRANSFER_ENCODING));
        }
    }
}
