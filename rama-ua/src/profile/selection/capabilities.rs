//! Required protocol components for one transport and advertised ALPN set.

use rama_net::tls::{ApplicationProtocol, TlsAlpn};
use serde::{Deserialize, Serialize};

use crate::profile::selection::variants::SelectionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Transport used to validate an advertised HTTP ALPN set.
pub enum SelectionTransport {
    TcpPlain,
    TcpTls,
    Quic,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
/// Protocol components a selected profile must provide together.
pub struct CapabilitySet {
    pub h1: bool,
    pub h2: bool,
    pub h3: bool,
    pub tls_tcp: bool,
    pub tls_quic: bool,
    pub quic: bool,
}

impl CapabilitySet {
    pub fn for_alpn(alpn: &TlsAlpn, transport: SelectionTransport) -> Result<Self, SelectionError> {
        let mut required = Self::default();
        for protocol in &alpn.0 {
            match protocol {
                ApplicationProtocol::HTTP_09
                | ApplicationProtocol::HTTP_10
                | ApplicationProtocol::HTTP_11 => required.h1 = true,
                ApplicationProtocol::HTTP_2 | ApplicationProtocol::HTTP_2_TCP => {
                    required.h2 = true;
                }
                ApplicationProtocol::HTTP_3 => required.h3 = true,
                other => {
                    return Err(SelectionError::UnsupportedAlpn(
                        other.as_bytes().to_vec().into(),
                    ));
                }
            }
        }
        if !required.h1 && !required.h2 && !required.h3 {
            return Err(SelectionError::MissingHttpAlpn);
        }
        match transport {
            SelectionTransport::TcpPlain => {
                if required.h3 {
                    return Err(SelectionError::IncompatibleTransport);
                }
            }
            SelectionTransport::TcpTls => {
                if required.h3 {
                    return Err(SelectionError::IncompatibleTransport);
                }
                required.tls_tcp = true;
            }
            SelectionTransport::Quic => {
                if required.h1 || required.h2 || !required.h3 {
                    return Err(SelectionError::IncompatibleTransport);
                }
                required.tls_quic = true;
                required.quic = true;
            }
        }
        Ok(required)
    }

    pub(super) fn supports(self, required: Self) -> bool {
        (!required.h1 || self.h1)
            && (!required.h2 || self.h2)
            && (!required.h3 || self.h3)
            && (!required.tls_tcp || self.tls_tcp)
            && (!required.tls_quic || self.tls_quic)
            && (!required.quic || self.quic)
    }

    pub(super) fn bytes(self) -> [u8; 6] {
        [
            self.h1 as u8,
            self.h2 as u8,
            self.h3 as u8,
            self.tls_tcp as u8,
            self.tls_quic as u8,
            self.quic as u8,
        ]
    }
}

impl From<crate::profile::selection::database::ProfileCapabilities> for CapabilitySet {
    fn from(value: crate::profile::selection::database::ProfileCapabilities) -> Self {
        Self {
            h1: value.h1,
            h2: value.h2,
            h3: value.h3,
            tls_tcp: value.tls_tcp,
            tls_quic: value.tls_quic,
            quic: value.quic,
        }
    }
}
