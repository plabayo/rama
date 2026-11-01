use std::{io, os::windows::io::AsRawSocket, ptr};

use crate::client::ConnectorTarget;

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::{Extension, ExtensionsRef},
};
use rama_utils::{collections::smallvec::SmallVec, macros::generate_set_and_with, octets::kib};

use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::Networking::WinSock::{
    SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, SOCKET, WSAEFAULT, WSAEINVAL, WSAGetLastError,
    WSAIoctl,
};
const WFP_CONTEXT_BUFFER_STACK_LEN: usize = 128;
/// Upper bound on the driver-reported context size honoured by the retry.
const WFP_CONTEXT_BUFFER_MAX_LEN: usize = kib(64);
/// Queries per socket: the stack buffer, the reported size, and once more if
/// the context grew in between.
const WFP_CONTEXT_QUERY_ATTEMPTS: usize = 3;

/// The internal buffer type used for WFP context.
type WfpContextBuffer = SmallVec<[u8; WFP_CONTEXT_BUFFER_STACK_LEN]>;

#[derive(Debug, Clone)]
pub struct ConnectorTargetFromWfpContextLayer<D> {
    decoder: D,
    context_optional: bool,
}

pub trait WfpContextDecoder: Send + Sync + 'static {
    type Context: Extension;
    type Error: Into<BoxError>;

    fn decode(&self, bytes: &[u8]) -> Result<(Self::Context, ConnectorTarget), Self::Error>;
}

impl<D> ConnectorTargetFromWfpContextLayer<D> {
    pub fn new(decoder: D) -> Self {
        Self {
            decoder,
            context_optional: false,
        }
    }

    generate_set_and_with! {
        pub fn optional(mut self, optional: bool) -> Self {
            self.context_optional = optional;
            self
        }
    }
}

impl<S, D> Layer<S> for ConnectorTargetFromWfpContextLayer<D>
where
    D: Clone,
{
    type Service = ConnectorTargetFromWfpContext<S, D>;

    fn layer(&self, inner: S) -> Self::Service {
        ConnectorTargetFromWfpContext {
            inner,
            decoder: self.decoder.clone(),
            context_optional: self.context_optional,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectorTargetFromWfpContext<S, D> {
    inner: S,
    decoder: D,
    context_optional: bool,
}

impl<S, Input, D> Service<Input> for ConnectorTargetFromWfpContext<S, D>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: AsRawSocket + ExtensionsRef + Send + 'static,
    D: WfpContextDecoder,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let context_bytes = match query_wfp_redirect_context(&input)
            .context("query WFP context from input stream")?
        {
            Some(context_bytes) => context_bytes,
            None if self.context_optional => {
                return self
                    .inner
                    .serve(input)
                    .await
                    .context("inner service failed");
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "missing WFP redirect context",
                )
                .into());
            }
        };

        let (context, connector_target) = self
            .decoder
            .decode(&context_bytes)
            .context("decode WFP context")?;

        input.extensions().insert(context);
        input.extensions().insert(connector_target);

        self.inner
            .serve(input)
            .await
            .context("inner service failed")
    }
}

fn query_wfp_redirect_context(socket: &impl AsRawSocket) -> io::Result<Option<WfpContextBuffer>> {
    // Start with our stack allocated capacity.
    let mut buffer = WfpContextBuffer::from_elem(0u8, WFP_CONTEXT_BUFFER_STACK_LEN);

    for _ in 0..WFP_CONTEXT_QUERY_ATTEMPTS {
        let mut bytes_returned = 0u32;
        // SAFETY: per the WSAIoctl docs, with `lpOverlapped` and
        // `lpCompletionRoutine` null the call is non-overlapped: it completes
        // before returning, writes at most `cbOutBuffer` bytes to
        // `lpvOutBuffer` and the byte count to `*lpcbBytesReturned`, and reads
        // no input buffer (null, length 0). The handle is the one `socket`
        // reports, and `socket` is borrowed for the whole call, so its owner
        // cannot close it meanwhile (I/O safety); whichever socket it names,
        // the query writes only `buffer`, writable for `buffer.len()` bytes (at
        // most 64 KiB, so the `u32` cast is exact), and the live `bytes_returned`.
        let rc = unsafe {
            WSAIoctl(
                socket.as_raw_socket() as SOCKET,
                SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
                ptr::null(),
                0,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &raw mut bytes_returned,
                ptr::null_mut(),
                None,
            )
        };

        if rc == 0 {
            buffer.truncate(bytes_returned as usize);
            return Ok(Some(buffer));
        }

        // SAFETY: `WSAGetLastError` reads the calling thread's last Winsock
        // error and has no preconditions.
        let err_code = unsafe { WSAGetLastError() };

        // Retry if the buffer was too small and a larger required size was returned.
        let too_small = err_code == ERROR_INSUFFICIENT_BUFFER as i32 || err_code == WSAEFAULT;
        if !too_small || bytes_returned as usize <= buffer.len() {
            // Treat missing redirect context as absence, not as an error.
            // Other failures are returned to the caller.
            if is_no_wfp_redirect_context_error(err_code) {
                return Ok(None);
            }
            return Err(io::Error::from_raw_os_error(err_code));
        }
        if bytes_returned as usize > WFP_CONTEXT_BUFFER_MAX_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WFP redirect context exceeds 64 KiB",
            ));
        }
        buffer.resize(bytes_returned as usize, 0u8);
    }

    Err(io::Error::other("WFP redirect context kept growing"))
}

fn is_no_wfp_redirect_context_error(err_code: i32) -> bool {
    // The socket carries no redirect record: it was not redirected by a WFP
    // callout. WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT) reports this
    // as WSAEINVAL, which WSAGetLastError returns (never SOCKET_ERROR/-1, which
    // is only the WSAIoctl *return* sentinel). Treat it as "no context", not a
    // hard error, so the absent-context path is handled gracefully.
    err_code == WSAEINVAL
}
