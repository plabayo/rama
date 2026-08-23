//! Standalone streaming ICAP server transactions.

mod service;
#[doc(inline)]
pub use service::{Server, ServerError, ServerErrorKind};

mod types;
#[doc(inline)]
pub use types::{
    BodyError, BodyFrame, IncomingBody, IncomingRequest, OptionsResponse, OutgoingBody,
    OutgoingBodyEnd, OutgoingResponse,
};

use core::future::Future;
use std::pin::pin;

use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
    io::Io,
};
use tokio::io::AsyncRead;

use crate::{
    io::{
        BodyContext, BodyEnd, BodyReader, ConnectionOptions, Error, FramedIo, FramedRead, Terminal,
    },
    message::{Request, Response, TrailerBlock},
    proto::StatusCode,
};

/// A sequential ICAP server over one established byte stream.
///
/// [`ServerConnection::accept`] returns a transaction which streams request
/// body data and makes the Preview decision explicit. Dropping any
/// transaction before its response completes poisons the connection.
pub struct ServerConnection<IO> {
    framed: FramedIo<IO>,
    closed: bool,
    poisoned: bool,
}

impl<IO> ServerConnection<IO>
where
    IO: Io + Unpin + ExtensionsRef,
{
    /// Wrap an accepted stream with default connection options.
    ///
    /// Bare streams can use [`rama_core::ServiceInput`] to supply the Rama
    /// connection extension store required by this protocol wrapper.
    pub fn new(io: IO) -> Self {
        Self::with_options(io, ConnectionOptions::new())
    }

    /// Wrap an accepted stream with explicit bounds and parser policy.
    ///
    /// The connection retains the extension store supplied by `io`.
    pub fn with_options(io: IO, options: ConnectionOptions) -> Self {
        Self {
            framed: FramedIo::new(io, options),
            closed: false,
            poisoned: false,
        }
    }

    /// Return whether the next request can be read safely.
    #[must_use]
    pub const fn is_reusable(&self) -> bool {
        !self.poisoned
    }

    /// Return whether a completed transaction closed the connection.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Return the connection bounds and parser policy.
    #[must_use]
    pub const fn options(&self) -> &ConnectionOptions {
        self.framed.options()
    }

    /// Recover the underlying stream.
    ///
    /// Any bytes read ahead by the ICAP decoder are discarded. Use
    /// [`into_parts`](Self::into_parts) to retain them.
    pub fn into_inner(self) -> IO {
        self.framed.into_parts().0
    }

    /// Recover the underlying stream and bytes read ahead by the decoder.
    pub fn into_parts(self) -> (IO, Bytes) {
        self.framed.into_parts()
    }
}

impl<IO> ExtensionsRef for ServerConnection<IO> {
    fn extensions(&self) -> &Extensions {
        self.framed.extensions()
    }
}

impl<IO> ServerConnection<IO>
where
    IO: Io + Unpin,
{
    /// Read the next ICAP request head and encapsulated HTTP head sections.
    ///
    /// Cancelling this future abandons the connection. This fail-closed rule
    /// prevents a partially consumed request head or HTTP prefix from being
    /// mistaken for the start of a later transaction.
    pub async fn accept(&mut self) -> Result<Option<ServerTransaction<'_, IO>>, Error> {
        if self.poisoned {
            return Err(Error::InvalidState(
                "ICAP server connection is not reusable",
            ));
        }
        self.closed = false;
        self.poisoned = true;
        let Some(request) = self.framed.read.read_request().await? else {
            self.poisoned = false;
            return Ok(None);
        };
        let has_body = request.encapsulated().is_some_and(|parts| parts.has_body());
        let body = if has_body {
            Some(BodyReader::new(if let Some(limit) = request.preview() {
                BodyContext::Preview(limit)
            } else {
                BodyContext::Request
            }))
        } else {
            None
        };
        let end = (!has_body).then_some(BodyEnd::Complete);
        Ok(Some(ServerTransaction {
            connection: self,
            request,
            body,
            end,
            continued: false,
            write_in_progress: false,
        }))
    }
}

/// One inbound ICAP request and its response transaction.
pub struct ServerTransaction<'a, IO> {
    connection: &'a mut ServerConnection<IO>,
    request: Request,
    body: Option<BodyReader>,
    end: Option<BodyEnd>,
    continued: bool,
    write_in_progress: bool,
}

impl<IO> ExtensionsRef for ServerTransaction<'_, IO> {
    fn extensions(&self) -> &Extensions {
        self.connection.extensions()
    }
}

impl<'a, IO> ServerTransaction<'a, IO>
where
    IO: Io + Unpin,
{
    /// Return the request metadata and encapsulated HTTP heads.
    #[must_use]
    pub const fn request(&self) -> &Request {
        &self.request
    }

    /// Read the next zero-copy request-body data segment.
    ///
    /// A returned segment may be smaller than the peer's wire chunk. When a
    /// Preview ends without `ieof`, this returns `None` and
    /// [`body_end`](Self::body_end) returns [`BodyEnd::Preview`].
    pub async fn next_data(&mut self) -> Result<Option<Bytes>, Error> {
        if self.write_in_progress {
            return Err(Error::InvalidState(
                "a previous ICAP response write was cancelled",
            ));
        }
        let Some(body) = &mut self.body else {
            return Ok(None);
        };
        let data = body.next_data(&mut self.connection.framed.read).await?;
        if data.is_none() {
            self.end = body.end();
        }
        Ok(data)
    }

    /// Return the terminal state after `next_data` returns `None`.
    #[must_use]
    pub const fn body_end(&self) -> Option<BodyEnd> {
        self.end
    }

    /// Return trailers from the most recently completed body segment.
    #[must_use]
    pub fn trailers(&self) -> Option<&TrailerBlock> {
        self.body.as_ref().and_then(BodyReader::trailers)
    }

    /// Send a tagged 100 Continue response and read the post-Preview body.
    pub async fn continue_preview(&mut self, response: Response) -> Result<(), Error> {
        if self.write_in_progress {
            return Err(Error::InvalidState(
                "a previous ICAP response write was cancelled",
            ));
        }
        if self.end != Some(BodyEnd::Preview) {
            return Err(Error::InvalidState(
                "the ICAP request is not awaiting a Preview decision",
            ));
        }
        if response.method() != self.request.method() {
            return Err(Error::InvalidSequence(
                "response method does not match the ICAP request",
            ));
        }
        if response.status() != StatusCode::CONTINUE {
            return Err(Error::InvalidSequence(
                "Preview continuation requires a 100 response",
            ));
        }
        self.write_in_progress = true;
        self.connection
            .framed
            .write
            .write_response(&response)
            .await?;
        self.connection.framed.write.flush().await?;
        self.write_in_progress = false;
        let received_bytes = self.body.as_ref().map_or(0, BodyReader::received_bytes);
        self.body = Some(BodyReader::with_received_bytes(
            BodyContext::Continuation,
            received_bytes,
        ));
        self.end = None;
        self.continued = true;
        Ok(())
    }

    /// Start the final response after reaching a request-body boundary.
    pub async fn respond(self, response: Response) -> Result<ServerResponse<'a, IO>, Error> {
        if self.write_in_progress {
            return Err(Error::InvalidState(
                "a previous ICAP response write was cancelled",
            ));
        }
        if self.end.is_none() {
            return Err(Error::InvalidState(
                "the ICAP request body has not reached a boundary",
            ));
        }
        if response.method() != self.request.method() {
            return Err(Error::InvalidSequence(
                "response method does not match the ICAP request",
            ));
        }
        if response.status() == StatusCode::CONTINUE {
            return Err(Error::InvalidSequence(
                "use continue_preview for a 100 response",
            ));
        }
        validate_negotiated_response(
            &self.request,
            self.request.preview().is_some() && !self.continued,
            response.status(),
        )?;

        let original_body_bytes_received = self.body.as_ref().map_or(0, BodyReader::received_bytes);
        let original_body_len = completed_original_body_len(
            self.request
                .encapsulated()
                .is_some_and(|parts| parts.has_body()),
            self.body.as_ref(),
            self.end,
        );
        self.connection
            .framed
            .write
            .write_response(&response)
            .await?;
        let has_body = response
            .encapsulated()
            .is_some_and(|parts| parts.has_body());
        let close = self.request.should_close() || response.should_close();
        Ok(ServerResponse {
            connection: self.connection,
            status: response.status(),
            has_body,
            close,
            drain_while_writing: true,
            write_in_progress: false,
            request_body: None,
            request_end: Some(BodyEnd::Complete),
            original_body_bytes_received,
            original_body_len,
        })
    }

    /// Send a final response before the request body reaches a boundary.
    ///
    /// The response writer discards the remaining request concurrently with
    /// response writes so a keep-alive connection can remain synchronized.
    /// Read any request data an adaptation needs before responding. A closing
    /// request or response instead uses the transport-close fallback permitted
    /// by the ICAP errata.
    pub async fn respond_early(self, response: Response) -> Result<ServerResponse<'a, IO>, Error> {
        self.respond_before_boundary(response, true).await
    }

    /// Start a final response while retaining the unread request body.
    ///
    /// Unlike [`respond_early`](Self::respond_early), response writes do not
    /// discard request data to make progress. Use
    /// [`ServerResponse::next_request_data`] between response writes to stream
    /// an adapted body without buffering the complete request. The peer must
    /// monitor for an early ICAP response while it transmits its request body,
    /// as required by the ICAP errata.
    pub async fn respond_streaming(
        self,
        response: Response,
    ) -> Result<ServerResponse<'a, IO>, Error> {
        self.respond_before_boundary(response, false).await
    }

    async fn respond_before_boundary(
        self,
        response: Response,
        drain_while_writing: bool,
    ) -> Result<ServerResponse<'a, IO>, Error> {
        if self.write_in_progress {
            return Err(Error::InvalidState(
                "a previous ICAP response write was cancelled",
            ));
        }
        if self.end.is_some() {
            return Err(Error::InvalidState(
                "use respond after the ICAP request reaches a boundary",
            ));
        }
        if response.method() != self.request.method() {
            return Err(Error::InvalidSequence(
                "response method does not match the ICAP request",
            ));
        }
        if response.status() == StatusCode::CONTINUE {
            return Err(Error::InvalidSequence(
                "use continue_preview for a 100 response",
            ));
        }
        validate_negotiated_response(
            &self.request,
            self.request.preview().is_some() && !self.continued,
            response.status(),
        )?;
        let mut close = self.request.should_close() || response.should_close();
        let mut original_body_bytes_received =
            self.body.as_ref().map_or(0, BodyReader::received_bytes);
        let mut request_body = self.body;
        let mut request_end = self.end;
        let framed = &mut self.connection.framed;
        if close || !drain_while_writing {
            framed.write.write_response(&response).await?;
            framed.write.flush().await?;
        } else {
            let write = async {
                framed.write.write_response(&response).await?;
                framed.write.flush().await
            };
            close |= finish_write_while_draining(
                &mut framed.read,
                &mut request_body,
                &mut request_end,
                write,
            )
            .await?;
        }
        let original_body_len =
            completed_original_body_len(true, request_body.as_ref(), request_end);
        if let Some(body) = &request_body {
            original_body_bytes_received = body.received_bytes();
        }
        Ok(ServerResponse {
            connection: self.connection,
            status: response.status(),
            has_body: response
                .encapsulated()
                .is_some_and(|parts| parts.has_body()),
            close,
            drain_while_writing,
            write_in_progress: false,
            request_body,
            request_end,
            original_body_bytes_received,
            original_body_len,
        })
    }
}

/// A streaming final response being sent by an ICAP server.
pub struct ServerResponse<'a, IO> {
    connection: &'a mut ServerConnection<IO>,
    status: StatusCode,
    has_body: bool,
    close: bool,
    drain_while_writing: bool,
    write_in_progress: bool,
    request_body: Option<BodyReader>,
    request_end: Option<BodyEnd>,
    original_body_bytes_received: u64,
    original_body_len: Option<u64>,
}

impl<IO> ExtensionsRef for ServerResponse<'_, IO> {
    fn extensions(&self) -> &Extensions {
        self.connection.extensions()
    }
}

impl<IO> ServerResponse<'_, IO>
where
    IO: Io + Unpin,
{
    /// Read the next unread request-body data segment.
    ///
    /// This is intended for a response created by
    /// [`ServerTransaction::respond_streaming`]. A returned segment is a
    /// zero-copy [`Bytes`] view. `None` marks the current body boundary; use
    /// [`request_body_end`](Self::request_body_end) to distinguish a complete
    /// body from an incomplete Preview.
    pub async fn next_request_data(&mut self) -> Result<Option<Bytes>, Error> {
        if self.write_in_progress {
            return Err(Error::InvalidState(
                "a previous ICAP body write was cancelled",
            ));
        }
        if self.drain_while_writing {
            return Err(Error::InvalidState(
                "respond_streaming is required to retain request data",
            ));
        }
        let Some(body) = &mut self.request_body else {
            return Ok(None);
        };
        let data = body.next_data(&mut self.connection.framed.read).await?;
        if data.is_none() {
            self.request_end = body.end();
            self.update_original_body_state();
        }
        Ok(data)
    }

    /// Return the terminal state of the unread request body.
    #[must_use]
    pub const fn request_body_end(&self) -> Option<BodyEnd> {
        self.request_end
    }

    /// Return trailers from the unread request body.
    #[must_use]
    pub fn request_trailers(&self) -> Option<&TrailerBlock> {
        self.request_body.as_ref().and_then(BodyReader::trailers)
    }

    /// Write one response entity-body data segment as an ICAP chunk.
    pub async fn write_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.write_in_progress {
            return Err(Error::InvalidState(
                "a previous ICAP body write was cancelled",
            ));
        }
        if !self.has_body {
            return Err(Error::InvalidState("this ICAP response has no entity body"));
        }
        self.write_in_progress = true;
        let framed = &mut self.connection.framed;
        if self.close || !self.drain_while_writing {
            framed.write.write_data(data).await?;
            framed.write.flush().await?;
        } else {
            let write = async {
                framed.write.write_data(data).await?;
                framed.write.flush().await
            };
            self.close |= finish_write_while_draining(
                &mut framed.read,
                &mut self.request_body,
                &mut self.request_end,
                write,
            )
            .await?;
            self.update_original_body_state();
        }
        self.write_in_progress = false;
        Ok(())
    }

    /// Finish a response without HTTP trailers.
    pub async fn finish(self) -> Result<(), Error> {
        self.finish_with_trailers(&TrailerBlock::empty()).await
    }

    /// Finish a response with negotiated HTTP trailers.
    pub async fn finish_with_trailers(mut self, trailers: &TrailerBlock) -> Result<(), Error> {
        if self.write_in_progress {
            return Err(Error::InvalidState(
                "a previous ICAP body write was cancelled",
            ));
        }
        let framed = &mut self.connection.framed;
        if self.has_body {
            if self.close {
                framed.write.write_end(Terminal::Complete, trailers).await?;
                framed.write.flush().await?;
            } else {
                let write = async {
                    framed.write.write_end(Terminal::Complete, trailers).await?;
                    framed.write.flush().await
                };
                self.close |= finish_write_while_draining(
                    &mut framed.read,
                    &mut self.request_body,
                    &mut self.request_end,
                    write,
                )
                .await?;
                self.update_original_body_state();
            }
        } else if !trailers.is_empty() {
            return Err(Error::InvalidSequence(
                "a null body cannot carry HTTP trailers",
            ));
        } else {
            framed.write.flush().await?;
        }
        if !self.close {
            self.drain_request().await?;
        }
        if self.close {
            self.connection.framed.write.shutdown().await?;
        }
        self.connection.closed = self.close;
        self.connection.poisoned = self.close;
        Ok(())
    }

    /// Finish a 206 response with its original-body resume offset.
    pub async fn finish_partial(self, use_original_body: u64) -> Result<(), Error> {
        self.finish_partial_with_trailers(use_original_body, &TrailerBlock::empty())
            .await
    }

    /// Finish a 206 response with negotiated HTTP trailers.
    pub async fn finish_partial_with_trailers(
        mut self,
        use_original_body: u64,
        trailers: &TrailerBlock,
    ) -> Result<(), Error> {
        if self.write_in_progress {
            return Err(Error::InvalidState(
                "a previous ICAP body write was cancelled",
            ));
        }
        if self.status != StatusCode::PARTIAL_CONTENT || !self.has_body {
            return Err(Error::InvalidState(
                "partial completion requires a body-bearing 206 response",
            ));
        }
        self.update_original_body_state();
        let offset_is_invalid = self.original_body_len.map_or_else(
            || use_original_body >= self.original_body_bytes_received,
            |len| use_original_body >= len,
        );
        if offset_is_invalid {
            return Err(Error::InvalidSequence(
                "use-original-body exceeds the original body",
            ));
        }
        let framed = &mut self.connection.framed;
        if self.close {
            framed
                .write
                .write_end(Terminal::UseOriginalBody(use_original_body), trailers)
                .await?;
            framed.write.flush().await?;
        } else {
            let write = async {
                framed
                    .write
                    .write_end(Terminal::UseOriginalBody(use_original_body), trailers)
                    .await?;
                framed.write.flush().await
            };
            self.close |= finish_write_while_draining(
                &mut framed.read,
                &mut self.request_body,
                &mut self.request_end,
                write,
            )
            .await?;
            self.update_original_body_state();
        }
        if !self.close {
            self.drain_request().await?;
        }
        if self.close {
            self.connection.framed.write.shutdown().await?;
        }
        self.connection.closed = self.close;
        self.connection.poisoned = self.close;
        Ok(())
    }

    async fn drain_request(&mut self) -> Result<(), Error> {
        loop {
            let Some(body) = &mut self.request_body else {
                return Ok(());
            };
            match body.next_data(&mut self.connection.framed.read).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    self.request_end = body.end();
                    self.update_original_body_state();
                    return Ok(());
                }
                Err(error) if is_request_abandonment(&error) => {
                    self.request_body = None;
                    self.close = true;
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn update_original_body_state(&mut self) {
        if let Some(body) = &self.request_body {
            self.original_body_bytes_received = body.received_bytes();
        }
        if self.original_body_len.is_none()
            && self.request_end == Some(BodyEnd::Complete)
            && self.request_body.is_some()
        {
            self.original_body_len = Some(self.original_body_bytes_received);
        }
    }
}

async fn finish_write_while_draining<R, F>(
    read: &mut FramedRead<R>,
    request_body: &mut Option<BodyReader>,
    request_end: &mut Option<BodyEnd>,
    write: F,
) -> Result<bool, Error>
where
    R: AsyncRead + Unpin,
    F: Future<Output = Result<(), Error>>,
{
    let mut write = pin!(write);
    loop {
        let Some(body) = request_body.as_mut() else {
            return write.await.map(|()| false);
        };
        if request_end.is_some() {
            return write.await.map(|()| false);
        }
        tokio::select! {
            biased;
            result = &mut write => return result.map(|()| false),
            data = body.next_data(read) => {
                match data {
                    Ok(None) => *request_end = body.end(),
                    // Early responses intentionally discard request data.
                    Ok(Some(_)) => {}
                    Err(error) if is_request_abandonment(&error) => {
                        *request_body = None;
                        write.await?;
                        return Ok(true);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
}

fn completed_original_body_len(
    has_body: bool,
    body: Option<&BodyReader>,
    end: Option<BodyEnd>,
) -> Option<u64> {
    if !has_body {
        Some(0)
    } else if end == Some(BodyEnd::Complete) {
        body.map(BodyReader::received_bytes)
    } else {
        None
    }
}

fn is_request_abandonment(error: &Error) -> bool {
    matches!(
        error,
        Error::Io(error) if error.kind() == std::io::ErrorKind::UnexpectedEof
    )
}

fn validate_negotiated_response(
    request: &Request,
    in_preview: bool,
    status: StatusCode,
) -> Result<(), Error> {
    let accepted = if status == StatusCode::NO_MODIFICATION_NEEDED {
        in_preview || request.allows_204()
    } else if status == StatusCode::PARTIAL_CONTENT {
        request.allows_206() && (in_preview || request.allows_204())
    } else {
        true
    };
    if accepted {
        Ok(())
    } else {
        Err(Error::InvalidSequence(
            "ICAP response was not negotiated by the request",
        ))
    }
}
