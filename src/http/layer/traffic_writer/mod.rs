//! Middleware to write Http traffic in std format.
//!
//! Can be useful for cli / debug purposes.

use crate::{
    http::{
        io::{write_http_request, write_http_response},
        Request, Response,
    },
    rt::Executor,
};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::mpsc::{channel, unbounded_channel, Sender, UnboundedSender},
};

mod request;
#[doc(inline)]
pub use request::{DoNotWriteRequest, RequestWriter, RequestWriterLayer, RequestWriterService};

mod response;
#[doc(inline)]
pub use response::{
    DoNotWriteResponse, ResponseWriter, ResponseWriterLayer, ResponseWriterService,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Http writer mode.
pub enum WriterMode {
    /// Print the entire request / response.
    All,
    /// Print only the headers of the request / response.
    Headers,
    /// Print only the body of the request / response.
    Body,
}

/// A writer that can write both requests and responses.
pub struct BidirectionalWriter<S> {
    sender: S,
}

impl<S> std::fmt::Debug for BidirectionalWriter<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BidirectionalWriter")
            .field("sender", &format_args!("{}", std::any::type_name::<S>()))
            .finish()
    }
}

impl<S: Clone> Clone for BidirectionalWriter<S> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl BidirectionalWriter<UnboundedSender<BidirectionalMessage>> {
    /// Create a new [`BidirectionalWriter`] with a custom writer gated behind an unbounded sender.
    pub fn unbounded<W>(
        executor: &Executor,
        mut writer: W,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = unbounded_channel();
        let (write_request_headers, write_request_body) = match request_mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };

        let (write_response_headers, write_response_body) = match response_mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };

        executor.spawn_task(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    BidirectionalMessage::Request(req) => {
                        if let Err(err) = write_http_request(
                            &mut writer,
                            req,
                            write_request_headers,
                            write_request_body,
                        )
                        .await
                        {
                            tracing::error!(err = %err, "failed to write http request to writer")
                        }
                    }
                    BidirectionalMessage::Response(res) => {
                        if let Err(err) = write_http_response(
                            &mut writer,
                            res,
                            write_response_headers,
                            write_response_body,
                        )
                        .await
                        {
                            tracing::error!(err = %err, "failed to write http response to writer")
                        }
                    }
                }
                if let Err(err) = writer.write_all(b"\r\n").await {
                    tracing::error!(err = %err, "failed to write separator to writer")
                }
            }
        });

        Self { sender: tx }
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stdout
    /// over an unbounded channel.
    pub fn stdout_unbounded(
        executor: &Executor,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::unbounded(executor, tokio::io::stdout(), request_mode, response_mode)
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stderr
    /// over an unbounded channel.
    pub fn stderr_unbounded(
        executor: &Executor,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::unbounded(executor, tokio::io::stderr(), request_mode, response_mode)
    }
}

impl BidirectionalWriter<Sender<BidirectionalMessage>> {
    /// Create a new [`BidirectionalWriter`] with a custom writer gated behind a custom bounded channel.
    pub fn new<W>(
        executor: &Executor,
        mut writer: W,
        buffer: usize,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = channel(buffer);
        let (write_request_headers, write_request_body) = match request_mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };

        let (write_response_headers, write_response_body) = match response_mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };

        executor.spawn_task(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    BidirectionalMessage::Request(req) => {
                        if let Err(err) = write_http_request(
                            &mut writer,
                            req,
                            write_request_headers,
                            write_request_body,
                        )
                        .await
                        {
                            tracing::error!(err = %err, "failed to write http request to writer")
                        }
                    }
                    BidirectionalMessage::Response(res) => {
                        if let Err(err) = write_http_response(
                            &mut writer,
                            res,
                            write_response_headers,
                            write_response_body,
                        )
                        .await
                        {
                            tracing::error!(err = %err, "failed to write http response to writer")
                        }
                    }
                }
                if let Err(err) = writer.write_all(b"\r\n").await {
                    tracing::error!(err = %err, "failed to write separator to writer")
                }
            }
        });

        Self { sender: tx }
    }

    /// Create a new [`BidirectionalWriter`] with a custom writer that only writes the last request and response received.
    pub fn last<W>(
        executor: &Executor,
        mut writer: W,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self
    where
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let (tx, mut rx) = channel(2);
        let (write_request_headers, write_request_body) = match request_mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };

        let (write_response_headers, write_response_body) = match response_mode {
            Some(WriterMode::All) => (true, true),
            Some(WriterMode::Headers) => (true, false),
            Some(WriterMode::Body) => (false, true),
            None => (false, false),
        };

        executor.spawn_task(async move {
            let mut last_request = None;
            let mut last_response = None;

            while let Some(msg) = rx.recv().await {
                match msg {
                    BidirectionalMessage::Request(req) => last_request = Some(req),
                    BidirectionalMessage::Response(res) => last_response = Some(res),
                }
            }

            if let Some(req) = last_request {
                if let Err(err) =
                    write_http_request(&mut writer, req, write_request_headers, write_request_body)
                        .await
                {
                    tracing::error!(err = %err, "failed to write last http request to writer")
                }
                if let Err(err) = writer.write_all(b"\r\n").await {
                    tracing::error!(err = %err, "failed to write separator to writer")
                }
            }

            if let Some(res) = last_response {
                if let Err(err) = write_http_response(
                    &mut writer,
                    res,
                    write_response_headers,
                    write_response_body,
                )
                .await
                {
                    tracing::error!(err = %err, "failed to write last http response to writer")
                }
                if let Err(err) = writer.write_all(b"\r\n").await {
                    tracing::error!(err = %err, "failed to write separator to writer")
                }
            }
        });

        Self { sender: tx }
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stdout
    /// over a bounded channel.
    pub fn stdout(
        executor: &Executor,
        buffer: usize,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::new(
            executor,
            tokio::io::stdout(),
            buffer,
            request_mode,
            response_mode,
        )
    }

    /// Create a new [`BidirectionalWriter`] that prints the last request and response to stdout.
    pub fn stdout_last(
        executor: &Executor,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::last(executor, tokio::io::stdout(), request_mode, response_mode)
    }

    /// Create a new [`BidirectionalWriter`] that prints requests and responses to stderr
    /// over a bounded channel.
    pub fn stderr(
        executor: &Executor,
        buffer: usize,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::new(
            executor,
            tokio::io::stderr(),
            buffer,
            request_mode,
            response_mode,
        )
    }

    /// Create a new [`BidirectionalWriter`] that prints the last request and responses to stderr.
    pub fn stderr_last(
        executor: &Executor,
        request_mode: Option<WriterMode>,
        response_mode: Option<WriterMode>,
    ) -> Self {
        Self::last(executor, tokio::io::stderr(), request_mode, response_mode)
    }
}

impl RequestWriter for BidirectionalWriter<UnboundedSender<BidirectionalMessage>> {
    async fn write_request(&self, req: Request) {
        if let Err(err) = self.sender.send(BidirectionalMessage::Request(req)) {
            tracing::error!(err = %err, "failed to send request to writer over unbounded channel")
        }
    }
}

impl ResponseWriter for BidirectionalWriter<UnboundedSender<BidirectionalMessage>> {
    async fn write_response(&self, res: Response) {
        if let Err(err) = self.sender.send(BidirectionalMessage::Response(res)) {
            tracing::error!(err = %err, "failed to send response to writer over unbounded channel")
        }
    }
}

impl RequestWriter for BidirectionalWriter<Sender<BidirectionalMessage>> {
    async fn write_request(&self, req: Request) {
        if let Err(err) = self.sender.send(BidirectionalMessage::Request(req)).await {
            tracing::error!(err = %err, "failed to send request to writer over bounded channel")
        }
    }
}

impl ResponseWriter for BidirectionalWriter<Sender<BidirectionalMessage>> {
    async fn write_response(&self, res: Response) {
        if let Err(err) = self.sender.send(BidirectionalMessage::Response(res)).await {
            tracing::error!(err = %err, "failed to send response to writer over bounded channel")
        }
    }
}

/// The internal message type for the [`BidirectionalWriter`].
#[derive(Debug)]
pub enum BidirectionalMessage {
    /// A request to be written.
    Request(Request),
    /// A response to be written.
    Response(Response),
}
