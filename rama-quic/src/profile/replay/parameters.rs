//! Bounded parameter expectations for a prepared native QUIC handshake.

use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_quic_proto::capture::{CaptureLimits, transport_parameters_from_hello};
use rama_tls::client::ClientHello;
use rama_ua::profile::capture::order::{
    OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture, ProtocolValue,
};

/// A validated QUIC parameter projection from one selected connection tuple.
///
/// Literals must be emitted unchanged. Redacted connection bindings require
/// fresh values of the retained length. Providers validate the actual generated
/// ClientHello before exposing handshake output; this is not a capability flag.
#[derive(Debug)]
pub struct ParameterExpectation(OrderedProtocolCapture);

impl TryFrom<OrderedProtocolCapture> for ParameterExpectation {
    type Error = BoxError;

    fn try_from(capture: OrderedProtocolCapture) -> Result<Self, Self::Error> {
        capture.canonical(OrderCaptureLimits::default())?;
        if !matches!(capture.namespace, OrderNamespace::QuicParameter) {
            return Err(BoxError::from_static_str(
                "captured QUIC parameters have the wrong namespace",
            ));
        }
        Ok(Self(capture))
    }
}

impl ParameterExpectation {
    /// Validated source fields, in their retained wire order.
    #[must_use]
    pub fn capture(&self) -> &OrderedProtocolCapture {
        &self.0
    }

    /// Check the native parameter body using the same bounded parser as capture.
    pub fn validate(&self, hello: &ClientHello) -> Result<(), BoxError> {
        let actual = transport_parameters_from_hello(hello, &CaptureLimits::default())?;
        if actual.len() != self.0.fields.len()
            || !actual
                .iter()
                .zip(self.0.fields.iter())
                .all(|(actual, expected)| {
                    actual.id.0 == expected.id
                        && match &expected.value {
                            ProtocolValue::Literal(value) => {
                                actual.value.as_slice() == value.as_ref()
                            }
                            ProtocolValue::ConnectionLength(length) => {
                                actual.value.len() == *length
                            }
                        }
                })
        {
            return Err(BoxError::from_static_str(
                "native QUIC parameters differ from the captured tuple",
            ));
        }
        Ok(())
    }
}
