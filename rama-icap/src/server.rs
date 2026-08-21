//! Standalone streaming ICAP server transactions.

use rama_core::bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    io::{BodyContext, BodyEnd, BodyReader, ConnectionOptions, Error, FramedIo, Terminal},
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
    poisoned: bool,
}

impl<IO> ServerConnection<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap an accepted stream with default connection options.
    pub fn new(io: IO) -> Self {
        Self::with_options(io, ConnectionOptions::new())
    }

    /// Wrap an accepted stream with explicit bounds and parser policy.
    pub fn with_options(io: IO, options: ConnectionOptions) -> Self {
        Self {
            framed: FramedIo::new(io, options),
            poisoned: false,
        }
    }

    /// Return whether the next request can be read safely.
    #[must_use]
    pub const fn is_reusable(&self) -> bool {
        !self.poisoned
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

impl<IO> ServerConnection<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Read the next ICAP request head and encapsulated HTTP head sections.
    pub async fn accept(&mut self) -> Result<Option<ServerTransaction<'_, IO>>, Error> {
        if self.poisoned {
            return Err(Error::InvalidState(
                "ICAP server connection is not reusable",
            ));
        }
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
}

impl<'a, IO> ServerTransaction<'a, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
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

    /// Send 100 Continue and begin reading the post-Preview body.
    pub async fn continue_preview(&mut self) -> Result<(), Error> {
        if self.end != Some(BodyEnd::Preview) {
            return Err(Error::InvalidState(
                "the ICAP request is not awaiting a Preview decision",
            ));
        }
        self.connection.framed.write.write_continue().await?;
        self.body = Some(BodyReader::new(BodyContext::Continuation));
        self.end = None;
        self.continued = true;
        Ok(())
    }

    /// Start the final response after reaching a request-body boundary.
    pub async fn respond(self, response: Response) -> Result<ServerResponse<'a, IO>, Error> {
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
        })
    }

    /// Send a final response before the request body reaches a boundary.
    ///
    /// This initial early-response path deliberately requires
    /// `Connection: close`. The client may stop transmitting after observing
    /// the response, leaving a partial request body that cannot be reused.
    pub async fn respond_early(self, response: Response) -> Result<ServerResponse<'a, IO>, Error> {
        if self.end.is_some() {
            return Err(Error::InvalidState(
                "use respond after the ICAP request reaches a boundary",
            ));
        }
        if !response.should_close() {
            return Err(Error::InvalidSequence(
                "an early ICAP response must close the connection",
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
        self.connection
            .framed
            .write
            .write_response(&response)
            .await?;
        self.connection.framed.write.flush().await?;
        Ok(ServerResponse {
            connection: self.connection,
            status: response.status(),
            has_body: response
                .encapsulated()
                .is_some_and(|parts| parts.has_body()),
            close: true,
        })
    }
}

/// A streaming final response being sent by an ICAP server.
pub struct ServerResponse<'a, IO> {
    connection: &'a mut ServerConnection<IO>,
    status: StatusCode,
    has_body: bool,
    close: bool,
}

impl<IO> ServerResponse<'_, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Write one response entity-body data segment as an ICAP chunk.
    pub async fn write_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if !self.has_body {
            return Err(Error::InvalidState("this ICAP response has no entity body"));
        }
        self.connection.framed.write.write_data(data).await?;
        self.connection.framed.write.flush().await
    }

    /// Finish a response without HTTP trailers.
    pub async fn finish(self) -> Result<(), Error> {
        self.finish_with_trailers(&TrailerBlock::empty()).await
    }

    /// Finish a response with negotiated HTTP trailers.
    pub async fn finish_with_trailers(self, trailers: &TrailerBlock) -> Result<(), Error> {
        if self.has_body {
            self.connection
                .framed
                .write
                .write_end(Terminal::Complete, trailers)
                .await?;
        } else if !trailers.is_empty() {
            return Err(Error::InvalidSequence(
                "a null body cannot carry HTTP trailers",
            ));
        }
        self.connection.framed.write.flush().await?;
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
        self,
        use_original_body: u64,
        trailers: &TrailerBlock,
    ) -> Result<(), Error> {
        if self.status != StatusCode::PARTIAL_CONTENT || !self.has_body {
            return Err(Error::InvalidState(
                "partial completion requires a body-bearing 206 response",
            ));
        }
        self.connection
            .framed
            .write
            .write_end(Terminal::UseOriginalBody(use_original_body), trailers)
            .await?;
        self.connection.framed.write.flush().await?;
        self.connection.poisoned = self.close;
        Ok(())
    }
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
