use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::Extension,
};

/// Requested trust anchor identifiers for the `trust_anchors` ClientHello extension.
///
/// This controls what is advertised to the peer, not certificate verification.
/// An empty identifier list still requests the extension, while
/// [`Self::omitted`] leaves it out regardless of any inherited setting.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringRequestedTrustAnchors(Option<Box<[u8]>>);

impl BoringRequestedTrustAnchors {
    /// Encode identifiers, each between 1 and 255 bytes, in the provided order.
    ///
    /// The complete extension body must fit in the TLS 16-bit length field.
    /// An empty iterator requests an empty list.
    pub fn try_from_ids<I, B>(ids: I) -> Result<Self, BoxError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut body = vec![0, 0];
        for id in ids {
            let id = id.as_ref();
            let length = u8::try_from(id.len())
                .ok()
                .filter(|length| *length != 0)
                .ok_or_else(|| {
                    BoxError::from_static_str("trust anchor identifier must contain 1..=255 bytes")
                })?;
            if body.len() + 1 + id.len() > usize::from(u16::MAX) {
                return Err(BoxError::from_static_str(
                    "trust anchor extension body is too large",
                ));
            }
            body.push(length);
            body.extend_from_slice(id);
        }
        let length = u16::try_from(body.len() - 2).map_err(|_overflow| {
            BoxError::from_static_str("trust anchor identifier list is too large")
        })?;
        body[..2].copy_from_slice(&length.to_be_bytes());
        Ok(Self(Some(body.into_boxed_slice())))
    }

    /// Retain a captured extension body, including its outer 16-bit length prefix.
    ///
    /// This is deliberately unchecked so infallible ClientHello conversion does
    /// not discard malformed data. Connector construction validates it and fails
    /// rather than silently omitting the requested extension.
    pub fn from_raw_extension_body(body: impl Into<Box<[u8]>>) -> Self {
        Self(Some(body.into()))
    }

    /// Leave the extension out, overriding any inherited request.
    #[must_use]
    pub const fn omitted() -> Self {
        Self(None)
    }

    /// The extension body including its outer length prefix, or `None` when omitted.
    #[must_use]
    pub fn extension_body(&self) -> Option<&[u8]> {
        self.0.as_deref()
    }

    /// Validate the body and return the identifier sequence without its outer length.
    ///
    /// BoringSSL accepts this sequence as non-empty, 8-bit length-prefixed IDs.
    /// Returns `None` when the extension is omitted.
    pub fn identifier_list(&self) -> Result<Option<&[u8]>, BoxError> {
        let Some(body) = self.0.as_deref() else {
            return Ok(None);
        };
        let Some((length, ids)) = body
            .split_first_chunk::<2>()
            .filter(|_| body.len() <= usize::from(u16::MAX))
        else {
            return Err(BoxError::from_static_str(
                "invalid trust anchor extension body size",
            ));
        };
        if usize::from(u16::from_be_bytes(*length)) != ids.len() {
            return Err(BoxError::from_static_str(
                "trust anchor list length does not match body",
            ));
        }
        let mut rest = ids;
        while let Some((&length, tail)) = rest.split_first() {
            let length = usize::from(length);
            if length == 0 || tail.len() < length {
                return Err(BoxError::from_static_str(
                    "empty or truncated trust anchor identifier",
                ));
            }
            rest = &tail[length..];
        }
        Ok(Some(ids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{BoringClientConfigExt, TlsConnectorData};
    use rama_tls::{
        CompressionAlgorithm, ExtensionId, ProtocolVersion,
        client::{ClientHello, ClientHelloExtension, TlsClientConfig},
    };

    #[test]
    fn logical_identifiers_and_wire_body_describe_the_same_list() {
        let logical =
            BoringRequestedTrustAnchors::try_from_ids([&[42][..], &[17, 34][..]]).unwrap();
        let captured =
            BoringRequestedTrustAnchors::from_raw_extension_body(vec![0, 5, 1, 42, 2, 17, 34]);
        assert_eq!(
            logical.identifier_list().unwrap(),
            Some(&[1, 42, 2, 17, 34][..])
        );
        assert_eq!(
            captured.identifier_list().unwrap(),
            Some(&[1, 42, 2, 17, 34][..])
        );
        assert_eq!(logical.extension_body(), captured.extension_body());
        let config = TlsClientConfig::new().with_requested_trust_anchors(logical);
        TlsConnectorData::try_from(&config).unwrap();
    }

    #[test]
    fn an_empty_identifier_list_differs_from_an_omitted_extension() {
        let anchors =
            BoringRequestedTrustAnchors::try_from_ids(std::iter::empty::<&[u8]>()).unwrap();
        assert_eq!(anchors.identifier_list().unwrap(), Some(&[][..]));
        assert_eq!(anchors.extension_body(), Some(&[0, 0][..]));
        let omitted = BoringRequestedTrustAnchors::omitted();
        assert_eq!(omitted.identifier_list().unwrap(), None);
        assert_eq!(omitted.extension_body(), None);
        for anchors in [anchors, omitted] {
            let config = TlsClientConfig::new().with_requested_trust_anchors(anchors);
            TlsConnectorData::try_from(&config).unwrap();
        }
    }

    #[test]
    fn logical_identifiers_must_fit_their_wire_lengths() {
        for id in [vec![], vec![42; 256]] {
            BoringRequestedTrustAnchors::try_from_ids([id]).unwrap_err();
        }
        BoringRequestedTrustAnchors::try_from_ids([vec![42; 255]]).unwrap();
        BoringRequestedTrustAnchors::try_from_ids(vec![vec![42; 255]; 256]).unwrap_err();
    }

    #[test]
    fn extension_body_length_includes_the_outer_length_prefix() {
        let mut ids = vec![vec![42]; 32_765];
        ids.push(vec![17, 34]);
        let anchors = BoringRequestedTrustAnchors::try_from_ids(&ids).unwrap();
        let list = anchors.identifier_list().unwrap().unwrap();
        assert_eq!(list.len(), 65_533);

        let mut too_large = vec![255, 255];
        too_large.extend_from_slice(list);
        too_large.extend_from_slice(&[1, 42]);
        BoringRequestedTrustAnchors::from_raw_extension_body(too_large)
            .identifier_list()
            .unwrap_err();
        ids.push(vec![42]);
        BoringRequestedTrustAnchors::try_from_ids(ids).unwrap_err();
    }

    #[test]
    fn malformed_captured_bodies_fail_connector_construction() {
        for body in [
            vec![0, 0],
            vec![],
            vec![0],
            vec![0, 1],
            vec![0, 1, 0],
            vec![0, 2, 2, 42],
        ] {
            let valid = body == [0, 0];
            let hello = ClientHello::new(
                ProtocolVersion::TLSv1_2,
                vec![],
                vec![CompressionAlgorithm::Null],
                vec![ClientHelloExtension::Opaque {
                    id: ExtensionId::TRUST_ANCHORS,
                    data: body,
                }],
            );
            let config = TlsClientConfig::new_from_client_hello(&hello);
            let result = TlsConnectorData::try_from(&config);
            if valid {
                result.unwrap();
            } else {
                assert!(result.unwrap_err().to_string().contains("trust anchor"));
            }
        }
    }
}
