//! Standalone streaming ICAP client transactions.

mod service;
#[doc(inline)]
pub use service::Client;

pub mod options;

use core::future::Future;
use std::{
    pin::pin,
    sync::atomic::{AtomicBool, Ordering},
};

use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
    io::Io,
};
use rama_net::conn::{ConnectionHealth, ConnectionHealthWatcher};
use tokio::io::AsyncRead;

use crate::{
    io::{
        BodyContext, BodyEnd, BodyReader, ConnectionOptions, Error, FramedIo, FramedRead, Terminal,
    },
    message::{Request, Response, TrailerBlock},
    proto::{MethodKind, Preview, StatusCode},
};

/// A sequential ICAP client over an established byte stream.
///
/// Create a streaming request with [`ClientConnection::start`]. A
/// connection is reusable only after the returned response body reaches its
/// terminal chunk. Dropping a transaction early leaves it poisoned so a
/// later request cannot accidentally reuse desynchronized framing.
pub struct ClientConnection<IO> {
    // Fields drop in declaration order. Poison the shared health state before
    // dropping `framed`, which may return its underlying lease to a pool.
    poison: PoisonOnDrop,
    framed: FramedIo<IO>,
    poisoned: bool,
}

struct PoisonOnDrop {
    extensions: Extensions,
    armed: bool,
}

impl Drop for PoisonOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.extensions
                .get_ref_or_insert(ConnectionHealthWatcher::default)
                .mark_broken();
        }
    }
}

impl<IO> ClientConnection<IO>
where
    IO: Io + Unpin + ExtensionsRef,
{
    /// Wrap an established stream with default connection options.
    ///
    /// Bare streams can use [`rama_core::ServiceInput`] to supply the Rama
    /// connection extension store required by this protocol wrapper.
    pub fn new(io: IO) -> Self {
        Self::with_options(io, ConnectionOptions::new())
    }

    /// Wrap an established stream with explicit bounds and parser policy.
    ///
    /// The connection retains the extension store supplied by `io`.
    pub fn with_options(io: IO, options: ConnectionOptions) -> Self {
        let extensions = io.extensions().clone();
        ConnectionHealthWatcher::install(&extensions);
        Self {
            poison: PoisonOnDrop {
                extensions,
                armed: false,
            },
            framed: FramedIo::new(io, options),
            poisoned: false,
        }
    }

    /// Return whether another transaction may safely start.
    #[must_use]
    pub fn is_reusable(&self) -> bool {
        !self.poisoned
            && self
                .extensions()
                .get_ref::<ConnectionHealthWatcher>()
                .is_none_or(|health| health.health() != ConnectionHealth::Broken)
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

    fn set_reusable(&mut self, reusable: bool) {
        self.poisoned = !reusable;
        self.poison.armed = !reusable;
    }

    pub(crate) fn mark_broken(&mut self) {
        self.set_reusable(false);
        self.extensions()
            .get_ref_or_insert(ConnectionHealthWatcher::default)
            .mark_broken();
    }
}

impl<IO> ExtensionsRef for ClientConnection<IO> {
    fn extensions(&self) -> &Extensions {
        self.framed.extensions()
    }
}

impl<IO> ClientConnection<IO>
where
    IO: Io + Unpin + ExtensionsRef,
{
    /// Start sending one ICAP request.
    pub async fn start(&mut self, request: Request) -> Result<ClientTransaction<'_, IO>, Error> {
        if !self.is_reusable() {
            return Err(Error::InvalidState(
                "ICAP client connection is not reusable",
            ));
        }
        self.set_reusable(false);
        let method = request.method();
        let has_body = request.encapsulated().is_some_and(|parts| parts.has_body());
        let preview = request.preview();
        let original_body_len = request
            .original_body_len()
            .or_else(|| (!has_body).then_some(0));
        let request_close = request.should_close();
        let request_head_started = AtomicBool::new(false);
        let head_race = {
            let framed = &mut self.framed;
            race_response(
                &mut framed.read,
                method,
                !request_close,
                Some(&request_head_started),
                async {
                    framed
                        .write
                        .write_request_head_tracked(&request, &request_head_started)
                        .await
                },
            )
            .await
        };
        let head_race = match head_race {
            Ok(race) => race,
            Err(error) => {
                self.mark_broken();
                return Err(error);
            }
        };
        let mut transaction = ClientTransaction {
            connection: self,
            method,
            has_body,
            close: request_close,
            allow_204: request.allows_204(),
            allow_206: request.allows_206(),
            allow_icap_trailers: request.allows_icap_trailers(),
            phase: if let Some(limit) = preview {
                SendPhase::Preview { limit }
            } else {
                SendPhase::Body
            },
            original_body_len,
            body_bytes_supplied: 0,
            write_in_progress: false,
            write_shutdown_complete: false,
            response_read_in_progress: false,
            pending_response: None,
        };
        if let Race::Response {
            response,
            write_completed,
            write_started,
        } = head_race
        {
            if !write_started {
                transaction.connection.mark_broken();
                return Err(Error::InvalidSequence(
                    "ICAP response arrived before the request head was written",
                ));
            }
            transaction
                .store_monitored_response(response, preview.is_some(), !write_completed)
                .await?;
            if transaction.pending_response_closes() {
                return Ok(transaction);
            }
            transaction
                .connection
                .framed
                .write
                .write_request_prefix(&request)
                .await?;
            transaction.connection.framed.write.flush().await?;
            return Ok(transaction);
        }
        let race = race_response(
            &mut transaction.connection.framed.read,
            transaction.method,
            !transaction.close,
            None,
            async {
                transaction
                    .connection
                    .framed
                    .write
                    .write_request_prefix(&request)
                    .await?;
                transaction.connection.framed.write.flush().await
            },
        )
        .await?;
        if let Race::Response {
            response,
            write_completed,
            ..
        } = race
        {
            transaction
                .store_monitored_response(response, preview.is_some(), !write_completed)
                .await?;
        }
        Ok(transaction)
    }
}

#[derive(Clone, Copy, Debug)]
enum SendPhase {
    Preview { limit: Preview },
    Body,
    Continuation,
}

/// Result of writing one request-body segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum WriteOutcome {
    /// The segment was written and the transaction still accepts body data.
    Written,
    /// A final early response arrived.
    ///
    /// The request still accepts body data for a non-closing, bodyless
    /// response. A body-bearing response takes the transport-close fallback
    /// so its body can be consumed without unbounded buffering. Call
    /// [`ClientTransaction::finish`] to complete either path, or
    /// [`ClientTransaction::abandon`] to explicitly stop a bodyless path.
    ResponseAvailable,
}

struct PendingResponse {
    response: Response,
    close: bool,
}

/// A streaming ICAP request body being sent by a client.
pub struct ClientTransaction<'a, IO> {
    connection: &'a mut ClientConnection<IO>,
    method: MethodKind,
    has_body: bool,
    close: bool,
    allow_204: bool,
    allow_206: bool,
    allow_icap_trailers: bool,
    phase: SendPhase,
    original_body_len: Option<u64>,
    body_bytes_supplied: u64,
    write_in_progress: bool,
    write_shutdown_complete: bool,
    response_read_in_progress: bool,
    pending_response: Option<PendingResponse>,
}

impl<IO> ExtensionsRef for ClientTransaction<'_, IO> {
    fn extensions(&self) -> &Extensions {
        self.connection.extensions()
    }
}

impl<'a, IO> ClientTransaction<'a, IO>
where
    IO: Io + Unpin + ExtensionsRef,
{
    #[cfg(feature = "http")]
    pub(crate) async fn next_source_or_response<T, F>(
        &mut self,
        source: F,
    ) -> Result<SourceOutcome<T>, Error>
    where
        F: Future<Output = T>,
    {
        self.ensure_response_read_complete()?;
        if self.pending_response.is_some() {
            self.ensure_write_shutdown().await?;
            return Ok(SourceOutcome::ResponseAvailable);
        }
        if self.write_in_progress {
            return Err(Error::InvalidState(
                "a previous ICAP body write was cancelled",
            ));
        }

        self.response_read_in_progress = true;
        let mut source = pin!(source);
        tokio::select! {
            biased;
            item = &mut source => {
                self.response_read_in_progress = false;
                Ok(SourceOutcome::Item(item))
            }
            response = self.connection.framed.read.read_response(self.method) => {
                let response = response?;
                let in_preview = matches!(self.phase, SendPhase::Preview { .. });
                let request_must_stop = response_has_body(&response);
                self.store_monitored_response(
                    response,
                    in_preview,
                    request_must_stop,
                )
                .await?;
                Ok(SourceOutcome::ResponseAvailable)
            }
        }
    }

    /// Write one entity-body data segment as an ICAP chunk.
    ///
    /// Preview segments may not exceed the advertised Preview limit. The
    /// caller retains ownership of the source body and decides how to replay
    /// preview bytes after a final 204 or 206 response.
    pub async fn write_data(&mut self, data: &[u8]) -> Result<WriteOutcome, Error> {
        self.ensure_response_read_complete()?;
        if self.pending_response_closes() {
            self.ensure_write_shutdown().await?;
            return Ok(WriteOutcome::ResponseAvailable);
        }
        if self.write_in_progress {
            return Err(Error::InvalidState(
                "a previous ICAP body write was cancelled",
            ));
        }
        if !self.has_body {
            return Err(Error::InvalidState("this ICAP request has no entity body"));
        }
        let len = u64::try_from(data.len())
            .map_err(|_error| Error::InvalidSequence("ICAP data segment is too large"))?;
        let next = self
            .body_bytes_supplied
            .checked_add(len)
            .ok_or(Error::InvalidSequence("ICAP body length overflowed"))?;
        if let SendPhase::Preview { limit } = self.phase
            && next > limit.as_u64()
        {
            return Err(Error::InvalidSequence(
                "ICAP Preview exceeds its advertised limit",
            ));
        }
        if self.original_body_len.is_some_and(|total| next > total) {
            return Err(Error::InvalidSequence(
                "ICAP body exceeds its declared original length",
            ));
        }
        self.write_in_progress = true;
        let race = if self.pending_response.is_some() {
            self.connection.framed.write.write_data(data).await?;
            self.connection.framed.write.flush().await?;
            Race::Written
        } else {
            self.response_read_in_progress = true;
            let framed = &mut self.connection.framed;
            race_response(&mut framed.read, self.method, !self.close, None, async {
                framed.write.write_data(data).await?;
                framed.write.flush().await
            })
            .await?
        };
        match race {
            Race::Written => {
                self.response_read_in_progress = false;
                self.body_bytes_supplied = next;
                self.write_in_progress = false;
                if self.pending_response.is_some() {
                    Ok(WriteOutcome::ResponseAvailable)
                } else {
                    Ok(WriteOutcome::Written)
                }
            }
            Race::Response {
                response,
                write_completed,
                ..
            } => {
                if write_completed {
                    self.body_bytes_supplied = next;
                    self.write_in_progress = false;
                }
                let in_preview = matches!(self.phase, SendPhase::Preview { .. });
                self.store_monitored_response(response, in_preview, !write_completed)
                    .await?;
                Ok(WriteOutcome::ResponseAvailable)
            }
        }
    }

    /// Wait for an early final response while the body source is idle.
    ///
    /// [`write_data`](Self::write_data) monitors the read side while each
    /// segment is written. Callers waiting asynchronously for the next source
    /// segment must race that wait with this method so early ICAP responses are
    /// always consumed. The transaction keeps accepting body data after a
    /// non-closing, bodyless response. A body-bearing response automatically
    /// takes the transport-close fallback so its body can be streamed.
    pub async fn monitor_response(&mut self) -> Result<WriteOutcome, Error> {
        self.ensure_response_read_complete()?;
        if self.pending_response.is_some() {
            self.ensure_write_shutdown().await?;
            return Ok(WriteOutcome::ResponseAvailable);
        }
        self.response_read_in_progress = true;
        let response = self
            .connection
            .framed
            .read
            .read_response(self.method)
            .await?;
        let in_preview = matches!(self.phase, SendPhase::Preview { .. });
        let request_must_stop = response_has_body(&response);
        self.store_monitored_response(response, in_preview, request_must_stop)
            .await?;
        Ok(WriteOutcome::ResponseAvailable)
    }

    /// Finish a non-Preview request and read its final response head.
    pub async fn finish(self) -> Result<ClientResponse<'a, IO>, Error> {
        self.finish_with_trailers(&TrailerBlock::empty()).await
    }

    /// Finish a non-Preview request with negotiated HTTP trailers.
    pub async fn finish_with_trailers(
        mut self,
        trailers: &TrailerBlock,
    ) -> Result<ClientResponse<'a, IO>, Error> {
        self.ensure_response_read_complete()?;
        if self.write_in_progress && !self.pending_response_closes() {
            return Err(Error::InvalidState(
                "a previous ICAP body write was cancelled",
            ));
        }
        if matches!(self.phase, SendPhase::Preview { .. }) {
            return Err(Error::InvalidState(
                "finish_preview must end an ICAP Preview",
            ));
        }
        if self.pending_response_closes() {
            let original_body_len = self.original_body_len;
            return self.into_pending_response(original_body_len).await;
        }
        let original_body_len = self.complete_original_body_len()?;
        if self.has_body {
            if self.pending_response.is_some() {
                self.connection
                    .framed
                    .write
                    .write_end(Terminal::Complete, trailers, None)
                    .await?;
                self.connection.framed.write.flush().await?;
            } else {
                let race = {
                    let framed = &mut self.connection.framed;
                    race_response(&mut framed.read, self.method, !self.close, None, async {
                        framed
                            .write
                            .write_end(Terminal::Complete, trailers, None)
                            .await?;
                        framed.write.flush().await
                    })
                    .await?
                };
                if let Race::Response {
                    response,
                    write_completed,
                    ..
                } = race
                {
                    self.store_monitored_response(response, false, !write_completed)
                        .await?;
                    return self.into_pending_response(original_body_len).await;
                }
            }
        } else if !trailers.is_empty() {
            return Err(Error::InvalidSequence(
                "a null body cannot carry HTTP trailers",
            ));
        }
        if self.pending_response.is_some() {
            return self.into_pending_response(original_body_len).await;
        }
        let response = self
            .connection
            .framed
            .read
            .read_response(self.method)
            .await?;
        if response.status() == StatusCode::CONTINUE {
            return Err(Error::InvalidSequence(
                "100 Continue received outside Preview",
            ));
        }
        validate_negotiated_response(
            &response,
            NegotiatedResponse {
                in_preview: false,
                allow_204: self.allow_204,
                allow_206: self.allow_206,
                allow_icap_trailers: self.allow_icap_trailers,
            },
        )?;
        let close = self.close || response.should_close();
        ClientResponse::new(
            self.connection,
            response,
            close,
            self.body_bytes_supplied,
            original_body_len,
        )
    }

    /// Stop sending after an early final response and close the write side.
    ///
    /// Finishing a bodyless response path is preferred. This explicit
    /// fallback satisfies the ICAP requirement to terminate the transport
    /// when the remainder is not sent. Body-bearing early responses already
    /// take this fallback automatically.
    pub async fn abandon(mut self) -> Result<ClientResponse<'a, IO>, Error> {
        self.ensure_response_read_complete()?;
        if self.pending_response.is_none() {
            return Err(Error::InvalidState("no early ICAP response is available"));
        }
        if !self.pending_response_closes()
            && let Some(pending) = &mut self.pending_response
        {
            pending.close = true;
        }
        let original_body_len = self.original_body_len;
        self.into_pending_response(original_body_len).await
    }

    /// Finish a Preview and read either 100 Continue or a final response.
    ///
    /// Set `end_of_body` only when the supplied preview contains the complete
    /// entity body. This emits the `ieof` terminal extension.
    pub async fn finish_preview(self, end_of_body: bool) -> Result<PreviewOutcome<'a, IO>, Error> {
        self.finish_preview_with_trailers(end_of_body, &TrailerBlock::empty())
            .await
    }

    /// Finish a Preview with negotiated HTTP trailers.
    pub async fn finish_preview_with_trailers(
        mut self,
        end_of_body: bool,
        trailers: &TrailerBlock,
    ) -> Result<PreviewOutcome<'a, IO>, Error> {
        self.ensure_response_read_complete()?;
        if self.write_in_progress && !self.pending_response_closes() {
            return Err(Error::InvalidState(
                "a previous ICAP body write was cancelled",
            ));
        }
        let SendPhase::Preview { .. } = self.phase else {
            return Err(Error::InvalidState(
                "this ICAP request is not in Preview mode",
            ));
        };
        let original_body_len = if end_of_body {
            self.complete_original_body_len()?
        } else {
            self.original_body_len
        };
        if !end_of_body && !trailers.is_empty() {
            return Err(Error::InvalidSequence(
                "an incomplete Preview cannot carry HTTP trailers",
            ));
        }
        if self.pending_response_closes() {
            return self
                .into_pending_response(original_body_len)
                .await
                .map(PreviewOutcome::Response);
        }
        if self.pending_response.is_some() {
            self.connection
                .framed
                .write
                .write_end(
                    if end_of_body {
                        Terminal::PreviewEof
                    } else {
                        Terminal::Complete
                    },
                    trailers,
                    None,
                )
                .await?;
            self.connection.framed.write.flush().await?;
            return self
                .into_pending_response(original_body_len)
                .await
                .map(PreviewOutcome::Response);
        }
        let (response, terminal_complete) = {
            let framed = &mut self.connection.framed;
            let read = &mut framed.read;
            let write = &mut framed.write;
            let write_terminal = async {
                write
                    .write_end(
                        if end_of_body {
                            Terminal::PreviewEof
                        } else {
                            Terminal::Complete
                        },
                        trailers,
                        None,
                    )
                    .await?;
                write.flush().await
            };
            let mut write_terminal = pin!(write_terminal);
            tokio::select! {
                biased;
                response = read.read_response(self.method) => {
                    let response = response?;
                    if response.status() == StatusCode::CONTINUE
                        || (!self.close
                            && !response.should_close()
                            && !response_has_body(&response))
                    {
                        write_terminal.await?;
                        (response, true)
                    } else {
                        (response, false)
                    }
                }
                result = &mut write_terminal => {
                    result?;
                    (read.read_response(self.method).await?, true)
                }
            }
        };
        if response.status() == StatusCode::CONTINUE {
            if end_of_body {
                return Err(Error::InvalidSequence(
                    "100 Continue received after Preview ieof",
                ));
            }
            if response
                .encapsulated()
                .is_some_and(|parts| parts.has_body())
            {
                return Err(Error::InvalidSequence(
                    "100 Continue cannot carry an entity body",
                ));
            }
            Ok(PreviewOutcome::Continue(ClientTransaction {
                connection: self.connection,
                method: self.method,
                has_body: true,
                close: self.close,
                allow_204: self.allow_204,
                allow_206: self.allow_206,
                allow_icap_trailers: self.allow_icap_trailers,
                phase: SendPhase::Continuation,
                original_body_len: self.original_body_len,
                body_bytes_supplied: self.body_bytes_supplied,
                write_in_progress: false,
                write_shutdown_complete: false,
                response_read_in_progress: false,
                pending_response: None,
            }))
        } else {
            self.store_monitored_response(response, true, !terminal_complete)
                .await?;
            self.into_pending_response(original_body_len)
                .await
                .map(PreviewOutcome::Response)
        }
    }

    async fn store_monitored_response(
        &mut self,
        response: Response,
        in_preview: bool,
        write_interrupted: bool,
    ) -> Result<(), Error> {
        self.response_read_in_progress = true;
        if response.status() == StatusCode::CONTINUE {
            return Err(Error::InvalidSequence(
                "100 Continue arrived before the Preview boundary",
            ));
        }
        validate_negotiated_response(
            &response,
            NegotiatedResponse {
                in_preview,
                allow_204: self.allow_204,
                allow_206: self.allow_206,
                allow_icap_trailers: self.allow_icap_trailers,
            },
        )?;
        let close =
            monitored_response_closes(self.close, response.should_close(), write_interrupted);
        self.pending_response = Some(PendingResponse { response, close });
        self.response_read_in_progress = false;
        if close {
            self.ensure_write_shutdown().await?;
        }
        Ok(())
    }

    fn ensure_response_read_complete(&self) -> Result<(), Error> {
        if self.response_read_in_progress {
            Err(Error::InvalidState(
                "a previous ICAP response read did not complete",
            ))
        } else {
            Ok(())
        }
    }

    async fn ensure_write_shutdown(&mut self) -> Result<(), Error> {
        if self.pending_response_closes() && !self.write_shutdown_complete {
            self.connection.framed.write.shutdown().await?;
            self.write_shutdown_complete = true;
        }
        Ok(())
    }

    fn pending_response_closes(&self) -> bool {
        self.pending_response
            .as_ref()
            .is_some_and(|pending| pending.close)
    }

    async fn into_pending_response(
        mut self,
        original_body_len: Option<u64>,
    ) -> Result<ClientResponse<'a, IO>, Error> {
        self.ensure_write_shutdown().await?;
        let pending = self
            .pending_response
            .take()
            .ok_or(Error::InvalidState("no early ICAP response is available"))?;
        Ok(ClientResponse::from_pending(
            self.connection,
            pending,
            self.body_bytes_supplied,
            original_body_len,
        ))
    }

    fn complete_original_body_len(&self) -> Result<Option<u64>, Error> {
        if !self.has_body {
            return Ok(self.original_body_len);
        }
        if self
            .original_body_len
            .is_some_and(|len| len != self.body_bytes_supplied)
        {
            return Err(Error::InvalidSequence(
                "ICAP body differs from its declared original length",
            ));
        }
        Ok(Some(self.body_bytes_supplied))
    }
}

#[cfg(feature = "http")]
pub(crate) enum SourceOutcome<T> {
    Item(T),
    ResponseAvailable,
}

#[expect(
    clippy::large_enum_variant,
    reason = "boxing the response would allocate on every raced transaction"
)]
enum Race {
    Written,
    Response {
        response: Response,
        write_completed: bool,
        write_started: bool,
    },
}

#[derive(Clone, Copy)]
struct NegotiatedResponse {
    in_preview: bool,
    allow_204: bool,
    allow_206: bool,
    allow_icap_trailers: bool,
}

async fn race_response<R, F>(
    read: &mut FramedRead<R>,
    method: MethodKind,
    finish_write_after_response: bool,
    actual_write_started: Option<&AtomicBool>,
    write: F,
) -> Result<Race, Error>
where
    R: AsyncRead + Unpin,
    F: Future<Output = Result<(), Error>>,
{
    let write_polled = AtomicBool::new(false);
    let mut write = pin!(write);
    let mut tracked_write = pin!(core::future::poll_fn(|context| {
        write_polled.store(true, Ordering::Relaxed);
        write.as_mut().poll(context)
    }));
    let mut response = pin!(async {
        if let Some(started) = actual_write_started {
            read.read_response_after_request_started(method, started)
                .await
        } else {
            read.read_response(method).await
        }
    });
    tokio::select! {
        biased;
        response = &mut response => {
            let response = response?;
            let started = actual_write_started
                .unwrap_or(&write_polled)
                .load(Ordering::Acquire);
            if (actual_write_started.is_none() || started)
                && finish_write_after_response
                && !response.should_close()
                && !response_has_body(&response)
            {
                tracked_write.await?;
                Ok(Race::Response {
                    response,
                    write_completed: true,
                    write_started: started,
                })
            } else {
                Ok(Race::Response {
                    response,
                    write_completed: false,
                    write_started: started,
                })
            }
        },
        result = &mut tracked_write => result.map(|()| Race::Written),
    }
}

fn response_has_body(response: &Response) -> bool {
    response
        .encapsulated()
        .is_some_and(|parts| parts.has_body())
}

fn validate_negotiated_response(
    response: &Response,
    negotiated: NegotiatedResponse,
) -> Result<(), Error> {
    let status = response.status();
    let accepted = if status == StatusCode::NO_MODIFICATION_NEEDED {
        negotiated.in_preview || negotiated.allow_204
    } else if status == StatusCode::PARTIAL_CONTENT {
        negotiated.allow_206 && (negotiated.in_preview || negotiated.allow_204)
    } else {
        true
    };
    if !accepted {
        return Err(Error::InvalidSequence(
            "ICAP response was not negotiated by the request",
        ));
    }
    if response.icap_trailer_names().is_some()
        && (!negotiated.allow_icap_trailers
            || !matches!(response.method(), MethodKind::Reqmod | MethodKind::Respmod)
            || matches!(
                status,
                StatusCode::CONTINUE | StatusCode::NO_MODIFICATION_NEEDED
            )
            || response
                .encapsulated()
                .is_none_or(|parts| !parts.has_body()))
    {
        return Err(Error::InvalidSequence(
            "outer ICAP response trailers were not negotiated by the request",
        ));
    }
    Ok(())
}

const fn monitored_response_closes(
    request_close: bool,
    response_close: bool,
    write_interrupted: bool,
) -> bool {
    request_close || response_close || write_interrupted
}

/// The server decision after a client sends a Preview.
pub enum PreviewOutcome<'a, IO> {
    /// The server sent 100 Continue; stream the remaining request body.
    Continue(ClientTransaction<'a, IO>),
    /// The server returned a final response without requesting the remainder.
    Response(ClientResponse<'a, IO>),
}

/// A streaming final response received by an ICAP client.
pub struct ClientResponse<'a, IO> {
    connection: &'a mut ClientConnection<IO>,
    state: ClientResponseState,
}

pub(crate) struct ClientResponseState {
    response: Response,
    body: Option<BodyReader>,
    end: Option<BodyEnd>,
    close: bool,
    original_body_bytes_sent: u64,
    original_body_len: Option<u64>,
}

impl<IO> ExtensionsRef for ClientResponse<'_, IO> {
    fn extensions(&self) -> &Extensions {
        self.connection.extensions()
    }
}

impl<'a, IO> ClientResponse<'a, IO>
where
    IO: Io + Unpin + ExtensionsRef,
{
    fn new(
        connection: &'a mut ClientConnection<IO>,
        response: Response,
        close: bool,
        original_body_bytes_sent: u64,
        original_body_len: Option<u64>,
    ) -> Result<Self, Error> {
        if response.status() == StatusCode::CONTINUE {
            return Err(Error::InvalidSequence(
                "interim response exposed as a final response",
            ));
        }
        Ok(Self::from_pending(
            connection,
            PendingResponse { response, close },
            original_body_bytes_sent,
            original_body_len,
        ))
    }

    fn from_pending(
        connection: &'a mut ClientConnection<IO>,
        pending: PendingResponse,
        original_body_bytes_sent: u64,
        original_body_len: Option<u64>,
    ) -> Self {
        let state =
            ClientResponseState::from_pending(pending, original_body_bytes_sent, original_body_len);
        if state.end.is_some() {
            connection.set_reusable(!state.close && connection.framed.read.is_idle());
        }
        Self { connection, state }
    }

    #[cfg(feature = "http")]
    pub(crate) fn connection_and_state(
        &mut self,
    ) -> (&mut ClientConnection<IO>, &mut ClientResponseState) {
        (self.connection, &mut self.state)
    }

    #[cfg(feature = "http")]
    pub(crate) fn into_state(self) -> ClientResponseState {
        self.state
    }

    /// Return the final response metadata.
    #[must_use]
    pub const fn response(&self) -> &Response {
        self.state.response()
    }

    /// Read the next zero-copy entity-body data segment.
    ///
    /// A returned segment may be smaller than the peer's wire chunk so the
    /// decoder never buffers a hostile, very large declared chunk.
    pub async fn next_data(&mut self) -> Result<Option<Bytes>, Error> {
        self.state.next_data(self.connection).await
    }

    /// Return the terminal body state after `next_data` returns `None`.
    #[must_use]
    pub const fn body_end(&self) -> Option<BodyEnd> {
        self.state.body_end()
    }

    /// Return original entity-body bytes sent in complete ICAP chunks.
    #[must_use]
    pub const fn original_body_bytes_sent(&self) -> u64 {
        self.state.original_body_bytes_sent()
    }

    /// Return the exact original entity-body length, when known.
    #[must_use]
    pub const fn original_body_len(&self) -> Option<u64> {
        self.state.original_body_len()
    }

    /// Return whether a received original-body offset was locally verified.
    ///
    /// `None` means the response did not end with `use-original-body`.
    /// `Some(false)` means the peer supplied a syntactically valid offset but
    /// the client did not have enough original-body metadata to check it.
    #[must_use]
    pub const fn original_body_offset_is_verified(&self) -> Option<bool> {
        self.state.original_body_offset_is_verified()
    }

    /// Return received HTTP trailers after the body completes.
    #[must_use]
    pub fn trailers(&self) -> Option<&TrailerBlock> {
        self.state.trailers()
    }

    /// Return negotiated outer ICAP trailers after the body completes.
    ///
    /// These fields are distinct from the encapsulated HTTP trailers returned
    /// by [`trailers`](Self::trailers).
    #[must_use]
    pub fn icap_trailers(&self) -> Option<&TrailerBlock> {
        self.state.icap_trailers()
    }

    /// Drain and discard the remaining response body.
    pub async fn drain(&mut self) -> Result<(), Error> {
        while self.next_data().await?.is_some() {}
        Ok(())
    }

    /// Return the response once its body is complete.
    pub fn into_response(self) -> Result<Response, Error> {
        self.state.into_response()
    }
}

impl ClientResponseState {
    fn from_pending(
        pending: PendingResponse,
        original_body_bytes_sent: u64,
        original_body_len: Option<u64>,
    ) -> Self {
        let has_body = pending
            .response
            .encapsulated()
            .is_some_and(|parts| parts.has_body());
        let body = has_body.then(|| {
            let context = BodyContext::Response {
                status: pending.response.status(),
                original_body_len,
            };
            pending.response.icap_trailer_names().cloned().map_or_else(
                || BodyReader::new(context),
                |names| BodyReader::with_icap_trailer_names(context, names),
            )
        });
        let end = (!has_body).then_some(BodyEnd::Complete);
        Self {
            response: pending.response,
            body,
            end,
            close: pending.close,
            original_body_bytes_sent,
            original_body_len,
        }
    }

    /// Return the final response metadata.
    #[must_use]
    pub(crate) const fn response(&self) -> &Response {
        &self.response
    }

    /// Read the next zero-copy entity-body data segment.
    ///
    /// A returned segment may be smaller than the peer's wire chunk so the
    /// decoder never buffers a hostile, very large declared chunk.
    pub(crate) async fn next_data<IO>(
        &mut self,
        connection: &mut ClientConnection<IO>,
    ) -> Result<Option<Bytes>, Error>
    where
        IO: Io + Unpin + ExtensionsRef,
    {
        let Some(body) = &mut self.body else {
            return Ok(None);
        };
        let data = body.next_data(&mut connection.framed.read).await?;
        if data.is_none() {
            self.end = body.end();
            connection.set_reusable(!self.close && connection.framed.read.is_idle());
        }
        Ok(data)
    }

    /// Return the terminal body state after `next_data` returns `None`.
    #[must_use]
    pub(crate) const fn body_end(&self) -> Option<BodyEnd> {
        self.end
    }

    /// Return original entity-body bytes sent in complete ICAP chunks.
    #[must_use]
    pub(crate) const fn original_body_bytes_sent(&self) -> u64 {
        self.original_body_bytes_sent
    }

    /// Return the exact original entity-body length, when known.
    #[must_use]
    pub(crate) const fn original_body_len(&self) -> Option<u64> {
        self.original_body_len
    }

    /// Return whether a received original-body offset was locally verified.
    ///
    /// `None` means the response did not end with `use-original-body`.
    /// `Some(false)` means the peer supplied a syntactically valid offset but
    /// the client did not have enough original-body metadata to check it.
    #[must_use]
    pub(crate) const fn original_body_offset_is_verified(&self) -> Option<bool> {
        let Some(BodyEnd::PartialContent { use_original_body }) = self.end else {
            return None;
        };
        Some(
            use_original_body < self.original_body_bytes_sent
                || matches!(self.original_body_len, Some(len) if use_original_body < len),
        )
    }

    /// Return received HTTP trailers after the body completes.
    #[must_use]
    pub(crate) fn trailers(&self) -> Option<&TrailerBlock> {
        self.body.as_ref().and_then(BodyReader::trailers)
    }

    /// Return received outer ICAP trailers after the body completes.
    #[must_use]
    pub(crate) fn icap_trailers(&self) -> Option<&TrailerBlock> {
        self.body.as_ref().and_then(BodyReader::icap_trailers)
    }

    /// Return the response once its body is complete.
    pub(crate) fn into_response(self) -> Result<Response, Error> {
        if self.end.is_none() {
            Err(Error::InvalidState("ICAP response body has not completed"))
        } else {
            Ok(self.response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::monitored_response_closes;

    #[test]
    fn every_monitored_close_reason_is_independent() {
        for request_close in [false, true] {
            for response_close in [false, true] {
                for request_incomplete in [false, true] {
                    assert_eq!(
                        monitored_response_closes(
                            request_close,
                            response_close,
                            request_incomplete,
                        ),
                        request_close || response_close || request_incomplete,
                    );
                }
            }
        }
    }
}
