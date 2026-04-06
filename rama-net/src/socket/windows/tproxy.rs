use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::windows::io::{AsRawSocket, RawSocket},
    ptr,
};

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::ExtensionsMut,
};
use windows_sys::Win32::Networking::WinSock::{
    SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, SOCKET, SOCKET_ERROR, WSAGetLastError, WSAIoctl,
};

use crate::{address::SocketAddress, proxy::ProxyTarget};

const RAMA_WFP_CONTEXT_MAGIC: [u8; 4] = *b"RWTP";
const RAMA_WFP_CONTEXT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Rama's default fixed-format WFP redirect context payload.
pub struct WfpRedirectContext {
    pub original_destination: SocketAddress,
    pub process_id: u32,
}

impl WfpRedirectContext {
    pub const ENCODED_LEN: usize = 32;

    #[inline(always)]
    #[must_use]
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[..4].copy_from_slice(&RAMA_WFP_CONTEXT_MAGIC);
        bytes[4] = RAMA_WFP_CONTEXT_VERSION;
        bytes[5] = match self.original_destination.ip_addr {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        };
        bytes[8..12].copy_from_slice(&self.process_id.to_le_bytes());
        bytes[12..14].copy_from_slice(&self.original_destination.port.to_be_bytes());

        match self.original_destination.ip_addr {
            IpAddr::V4(ip) => bytes[16..20].copy_from_slice(&ip.octets()),
            IpAddr::V6(ip) => bytes[16..32].copy_from_slice(&ip.octets()),
        }

        bytes
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid WFP redirect context length: expected {}, got {}",
                    Self::ENCODED_LEN,
                    bytes.len()
                ),
            ));
        }

        if bytes[..4] != RAMA_WFP_CONTEXT_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid WFP redirect context magic",
            ));
        }

        if bytes[4] != RAMA_WFP_CONTEXT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported WFP redirect context version: {}", bytes[4]),
            ));
        }

        if bytes[6..8] != [0, 0] || bytes[14..16] != [0, 0] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported WFP redirect context flags or reserved bytes",
            ));
        }

        let process_id = u32::from_le_bytes(bytes[8..12].try_into().expect("fixed length slice"));
        let port = u16::from_be_bytes(bytes[12..14].try_into().expect("fixed length slice"));

        let ip_addr = match bytes[5] {
            4 => IpAddr::V4(Ipv4Addr::from(
                bytes[16..20].try_into().expect("fixed length slice"),
            )),
            6 => IpAddr::V6(Ipv6Addr::from(
                bytes[16..32].try_into().expect("fixed length slice"),
            )),
            family => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported WFP redirect context address family: {family}"),
                ));
            }
        };

        Ok(Self {
            original_destination: SocketAddress { ip_addr, port },
            process_id,
        })
    }
}

impl TryFrom<&WfpRedirectContext> for ProxyTarget {
    type Error = std::convert::Infallible;

    fn try_from(value: &WfpRedirectContext) -> Result<Self, Self::Error> {
        Ok(ProxyTarget(value.original_destination.into()))
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Decoder for Rama's default fixed-format WFP redirect context payload.
pub struct WfpRedirectContextDecoder;

impl WfpRedirectContextDecoder {
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

pub trait WfpContextDecoder: Send + Sync + 'static {
    type Context: Send + Sync + 'static;
    type Error: Into<BoxError>;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Context, Self::Error>;
}

impl WfpContextDecoder for WfpRedirectContextDecoder {
    type Context = WfpRedirectContext;
    type Error = io::Error;

    fn decode(&self, bytes: &[u8]) -> Result<Self::Context, Self::Error> {
        WfpRedirectContext::decode(bytes)
    }
}

#[derive(Debug, Clone)]
/// Layer to create [`ProxyTargetFromWfpContext`] middleware.
///
/// This middleware is intended for Windows transparent proxy setups where a
/// WFP-based redirector or driver stores per-socket redirect context retrievable
/// via `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, ...)`.
///
/// The queried bytes are decoded into a context value using the configured
/// decoder. That context is inserted into the input extensions, and
/// [`ProxyTarget`] is derived from it using `TryFrom<&T>`.
pub struct ProxyTargetFromWfpContextLayer<D = WfpRedirectContextDecoder> {
    decoder: D,
}

impl ProxyTargetFromWfpContextLayer<WfpRedirectContextDecoder> {
    #[inline(always)]
    /// Create a new [`ProxyTargetFromWfpContextLayer`] using Rama's default
    /// fixed-format WFP context decoder.
    pub fn new() -> Self {
        Self::with_decoder(WfpRedirectContextDecoder::new())
    }
}

impl Default for ProxyTargetFromWfpContextLayer<WfpRedirectContextDecoder> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D> ProxyTargetFromWfpContextLayer<D> {
    #[inline(always)]
    /// Create a new [`ProxyTargetFromWfpContextLayer`] using a custom decoder.
    pub fn with_decoder(decoder: D) -> Self {
        Self { decoder }
    }
}

impl<S, D> Layer<S> for ProxyTargetFromWfpContextLayer<D>
where
    D: Clone,
{
    type Service = ProxyTargetFromWfpContext<S, D>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyTargetFromWfpContext {
            inner,
            decoder: self.decoder.clone(),
        }
    }
}

#[derive(Debug, Clone)]
/// Middleware that queries WFP redirect context, decodes it, stores it in
/// extensions, and inserts the corresponding [`ProxyTarget`].
///
/// Created using [`ProxyTargetFromWfpContextLayer`].
pub struct ProxyTargetFromWfpContext<S, D = WfpRedirectContextDecoder> {
    inner: S,
    decoder: D,
}

impl<S, Input, D> Service<Input> for ProxyTargetFromWfpContext<S, D>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: AsRawSocket + ExtensionsMut + Send + 'static,
    D: WfpContextDecoder,
    for<'a> ProxyTarget: TryFrom<&'a D::Context, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        let context_bytes = query_wfp_redirect_context(input.as_raw_socket())
            .context("query WFP context from input stream")?;

        let context = self
            .decoder
            .decode(&context_bytes)
            .context("decode WFP context")?;

        let proxy_target =
            ProxyTarget::try_from(&context).context("derive ProxyTarget from WFP context")?;

        input.extensions_mut().insert(context);
        input.extensions_mut().insert(proxy_target);

        self.inner.serve(input).await.context("inner serve tcp")
    }
}

fn query_wfp_redirect_context(socket: RawSocket) -> io::Result<Box<[u8]>> {
    let socket = socket as SOCKET;
    let mut bytes_returned = 0u32;

    let first_rc = unsafe {
        // SAFETY: the socket value comes from `AsRawSocket`; this is a synchronous
        // `WSAIoctl` query with no input buffer, no output buffer, and valid
        // pointers for `bytes_returned`; overlapped parameters are null.
        WSAIoctl(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            ptr::null(),
            0,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
            None,
        )
    };

    if first_rc == 0 && bytes_returned == 0 {
        return Ok(Box::default());
    }

    if bytes_returned == 0 {
        return Err(last_wsa_error());
    }

    let mut buffer = vec![0u8; bytes_returned as usize];
    let mut final_bytes_returned = 0u32;
    let second_rc = unsafe {
        // SAFETY: the output buffer is valid for `buffer.len()` bytes and
        // writable; `final_bytes_returned` is a valid out-pointer; overlapped
        // parameters are null for synchronous operation.
        WSAIoctl(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            ptr::null(),
            0,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut final_bytes_returned,
            ptr::null_mut(),
            None,
        )
    };

    if second_rc == SOCKET_ERROR {
        return Err(last_wsa_error());
    }

    buffer.truncate(final_bytes_returned as usize);
    Ok(buffer.into_boxed_slice())
}

fn last_wsa_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe {
        // SAFETY: `WSAGetLastError` has no preconditions.
        WSAGetLastError()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ipv4_context() -> WfpRedirectContext {
        WfpRedirectContext {
            original_destination: SocketAddress::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
                8080,
            ),
            process_id: 1234,
        }
    }

    #[test]
    fn encode_decode_round_trip_ipv4() {
        let ctx = sample_ipv4_context();
        let bytes = ctx.encode();
        let decoded = WfpRedirectContext::decode(&bytes).expect("decode succeeded");
        assert_eq!(decoded, ctx);
    }

    #[test]
    fn encode_decode_round_trip_ipv6() {
        let ctx = WfpRedirectContext {
            original_destination: SocketAddress::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 15001),
            process_id: 5678,
        };
        let bytes = ctx.encode();
        let decoded = WfpRedirectContext::decode(&bytes).expect("decode succeeded");
        assert_eq!(decoded, ctx);
    }

    #[test]
    fn decoder_rejects_invalid_magic() {
        let mut bytes = sample_ipv4_context().encode();
        bytes[0..4].copy_from_slice(b"BAD!");
        let err = WfpRedirectContext::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("magic"));
    }

    #[test]
    fn decoder_rejects_unsupported_version() {
        let mut bytes = sample_ipv4_context().encode();
        bytes[4] = 99;
        let err = WfpRedirectContext::decode(&bytes).unwrap_err();
        assert!(err.to_string().contains("version"));
    }
}
