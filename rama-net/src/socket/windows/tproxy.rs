use std::{io, ptr};

#[cfg(target_os = "windows")]
use std::os::windows::io::{AsRawSocket, RawSocket};

// Doc-only stubs: when rendering docs on a non-Windows host with `rama_docsrs`,
// the `std::os::windows::io` module isn't in std at all. We provide same-shape
// local definitions so the public bound `Input: AsRawSocket` resolves and the
// rendered API has correct signatures. The `cfg_attr(docsrs, doc(cfg(...)))`
// labels on items make the platform requirement explicit to readers.
#[cfg(all(rama_docsrs, not(target_os = "windows")))]
mod _doc_std_os_windows_io {
    /// Doc-only stub for [`std::os::windows::io::RawSocket`].
    pub type RawSocket = u64;
    /// Doc-only stub for [`std::os::windows::io::AsRawSocket`].
    pub trait AsRawSocket {
        /// Stub for [`std::os::windows::io::AsRawSocket::as_raw_socket`].
        fn as_raw_socket(&self) -> RawSocket;
    }
}
#[cfg(all(rama_docsrs, not(target_os = "windows")))]
use _doc_std_os_windows_io::{AsRawSocket, RawSocket};

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::{Extension, ExtensionsRef},
};
use rama_utils::{collections::smallvec::SmallVec, macros::generate_set_and_with};
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::Networking::WinSock::{
    SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, SOCKET, SOCKET_ERROR, WSAEFAULT, WSAGetLastError,
    WSAIoctl,
};

use crate::proxy::ProxyTarget;

const WFP_CONTEXT_BUFFER_STACK_LEN: usize = 128;

/// The internal buffer type used for WFP context.
type WfpContextBuffer = SmallVec<[u8; WFP_CONTEXT_BUFFER_STACK_LEN]>;

#[derive(Debug, Clone)]
pub struct ProxyTargetFromWfpContextLayer<D> {
    decoder: D,
    context_optional: bool,
}

pub trait WfpContextDecoder: Send + Sync + 'static {
    type Context: Extension;
    type Error: Into<BoxError>;

    fn decode(&self, bytes: &[u8]) -> Result<(Self::Context, ProxyTarget), Self::Error>;
}

impl<D> ProxyTargetFromWfpContextLayer<D> {
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

impl<S, D> Layer<S> for ProxyTargetFromWfpContextLayer<D>
where
    D: Clone,
{
    type Service = ProxyTargetFromWfpContext<S, D>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyTargetFromWfpContext {
            inner,
            decoder: self.decoder.clone(),
            context_optional: self.context_optional,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyTargetFromWfpContext<S, D> {
    inner: S,
    decoder: D,
    context_optional: bool,
}

impl<S, Input, D> Service<Input> for ProxyTargetFromWfpContext<S, D>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: AsRawSocket + ExtensionsRef + Send + 'static,
    D: WfpContextDecoder,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let context_bytes = match query_wfp_redirect_context(input.as_raw_socket())
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

        let (context, proxy_target) = self
            .decoder
            .decode(&context_bytes)
            .context("decode WFP context")?;

        input.extensions().insert(context);
        input.extensions().insert(proxy_target);

        self.inner
            .serve(input)
            .await
            .context("inner service failed")
    }
}

fn query_wfp_redirect_context(socket: RawSocket) -> io::Result<Option<WfpContextBuffer>> {
    let socket = socket as SOCKET;
    let mut bytes_returned = 0u32;

    // Start with our stack allocated capacity.
    let mut buffer = WfpContextBuffer::from_elem(0u8, WFP_CONTEXT_BUFFER_STACK_LEN);

    // SAFETY:
    // 1. `socket` is a raw socket handle obtained from `AsRawSocket`.
    // 2. `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` is used as a synchronous IOCTL.
    // 3. `buffer.as_mut_ptr()` points to writable memory for `buffer.len()` bytes.
    // 4. `bytes_returned` is a valid out pointer for the result size.
    // 5. Overlapped and completion routine parameters are null for synchronous operation.
    let rc = unsafe {
        WSAIoctl(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            ptr::null(),
            0,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut bytes_returned,
            ptr::null_mut(),
            None,
        )
    };

    if rc == 0 {
        buffer.truncate(bytes_returned as usize);
        return Ok(Some(buffer));
    }

    let err_code = unsafe { WSAGetLastError() };

    // Retry if the initial buffer was too small and the required size was returned.
    if (err_code == ERROR_INSUFFICIENT_BUFFER as i32 || err_code == WSAEFAULT) && bytes_returned > 0
    {
        buffer.resize(bytes_returned as usize, 0u8);
        let mut final_bytes = 0u32;

        // SAFETY:
        // 1. `buffer` has been resized, so `buffer.as_mut_ptr()` is valid for `buffer.len()` bytes.
        // 2. All other pointer and handle requirements remain the same as above.
        let second_rc = unsafe {
            WSAIoctl(
                socket,
                SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
                ptr::null(),
                0,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut final_bytes,
                ptr::null_mut(),
                None,
            )
        };

        if second_rc == 0 {
            buffer.truncate(final_bytes as usize);
            return Ok(Some(buffer));
        }

        return Err(last_wsa_error());
    }

    // Treat missing redirect context as absence, not as an error.
    // Other failures are returned to the caller.
    if is_no_wfp_redirect_context_error(err_code) {
        return Ok(None);
    }

    Err(io::Error::from_raw_os_error(err_code))
}

fn last_wsa_error() -> io::Error {
    // SAFETY: `WSAGetLastError` is thread local and has no preconditions.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

fn is_no_wfp_redirect_context_error(err_code: i32) -> bool {
    err_code == SOCKET_ERROR
}
