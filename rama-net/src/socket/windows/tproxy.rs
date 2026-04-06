use std::{
    fmt, io, os::windows::io::{AsRawSocket, RawSocket}, ptr
};

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsMut,
};
use rama_utils::collections::smallvec::SmallVec;
use windows_sys::Win32::Networking::WinSock::{
    SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, SOCKET, SOCKET_ERROR, WSAGetLastError, WSAIoctl,
};

use crate::{proxy::ProxyTarget};

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
pub struct ProxyTargetFromWfpContextLayer<D> {
    decoder: D,
}

pub trait WfpContextDecoder: Send + Sync + 'static {
    type Context: fmt::Debug + Clone + Send + Sync + 'static;
    type Error: Into<BoxError>;

    fn decode(&self, bytes: &[u8]) -> Result<(Self::Context, ProxyTarget), Self::Error>;
}

impl<D> ProxyTargetFromWfpContextLayer<D> {
    #[inline(always)]
    /// Create a new [`ProxyTargetFromWfpContextLayer`] using
    /// the provided WFP Context Decoder.
    pub fn new(decoder: D) -> Self {
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
pub struct ProxyTargetFromWfpContext<S, D> {
    inner: S,
    decoder: D,
}

impl<S, Input, D> Service<Input> for ProxyTargetFromWfpContext<S, D>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: AsRawSocket + ExtensionsMut + Send + 'static,
    D: WfpContextDecoder,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        let context_bytes = query_wfp_redirect_context(input.as_raw_socket())
            .context("query WFP context from input stream")?;

        let (context, proxy_target) = self
            .decoder
            .decode(&context_bytes)
            .context("decode WFP context")?;

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

    let mut buffer: SmallVec<[u8; 64]> = SmallVec::with_capacity(bytes_returned as usize);
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
