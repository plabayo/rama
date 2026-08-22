use core::{fmt, future::Future};
use std::pin::pin;

use rama_core::{
    Service, error::BoxError, extensions::ExtensionsRef, futures::StreamExt as _, io::Io,
};

use crate::{
    io::{ConnectionOptions, Error},
    message::TrailerBlock,
};

use super::{
    ServerConnection, ServerResponse, ServerTransaction,
    types::{
        BodyCommand, BodyError, BodyFrame, BodyReply, IncomingBody, IncomingRequest,
        OutgoingBodyEnd, OutgoingResponse,
    },
};

const BODY_COMMAND_CAPACITY: usize = 1;

/// ICAP server backed by an ordinary Rama request service.
///
/// `Server` owns connection reuse, close handling, Preview decisions, and the
/// bounded driver between the wire transaction and [`IncomingRequest`]. The
/// inner service receives a lifetime-independent request with a backpressured
/// streaming body and returns an [`OutgoingResponse`]. It can therefore use
/// the normal Rama service layers. An outgoing body may retain the incoming
/// body and transform it incrementally; the connection driver continues
/// serving body reads while it writes response frames.
///
/// `Server` itself implements [`Service`] for Rama streams with
/// [`ExtensionsRef`](rama_core::extensions::ExtensionsRef), so it can be
/// passed directly to listeners such as
/// `rama_tcp::server::TcpListener::serve`.
#[derive(Clone, Debug)]
pub struct Server<S> {
    inner: S,
    options: ConnectionOptions,
}

impl<S> Server<S> {
    /// Create an ICAP server wrapping `inner`.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            options: ConnectionOptions::new(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the options used by each accepted ICAP connection.
        pub const fn options(
            mut self,
            options: ConnectionOptions,
        ) -> Self {
            self.options = options;
            self
        }
    }

    /// Return the options used by accepted ICAP connections.
    #[must_use]
    pub const fn options(&self) -> &ConnectionOptions {
        &self.options
    }

    rama_utils::macros::define_inner_service_accessors!();

    /// Serve one established stream.
    pub fn serve_connection<IO>(
        &self,
        io: IO,
    ) -> impl Future<Output = Result<(), ServerError>> + Send + '_
    where
        IO: Io + Unpin + ExtensionsRef,
        S: Service<IncomingRequest, Output = OutgoingResponse, Error: Into<BoxError>>,
    {
        serve_connection(&self.inner, io, self.options)
    }
}

async fn serve_connection<S, IO>(
    service: &S,
    io: IO,
    options: ConnectionOptions,
) -> Result<(), ServerError>
where
    IO: Io + Unpin + ExtensionsRef,
    S: Service<IncomingRequest, Output = OutgoingResponse, Error: Into<BoxError>>,
{
    let mut connection = ServerConnection::with_options(io, options);
    while let Some(transaction) = connection.accept().await.map_err(ServerError::connection)? {
        let request = transaction.request().clone();
        let extensions = transaction.extensions().clone();
        let has_body = request.encapsulated().is_some_and(|parts| parts.has_body());
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(BODY_COMMAND_CAPACITY);
        let request =
            IncomingRequest::new(request, IncomingBody::new(command_tx, has_body), extensions);
        drive_transaction(transaction, service.serve(request), command_rx).await?;
        if connection.is_closed() {
            return Ok(());
        }
        if !connection.is_reusable() {
            return Err(ServerError::connection(Error::InvalidState(
                "ICAP request service left its transaction incomplete",
            )));
        }
    }
    Ok(())
}

async fn drive_transaction<IO, F, E>(
    mut transaction: ServerTransaction<'_, IO>,
    service: F,
    mut command_rx: tokio::sync::mpsc::Receiver<BodyCommand>,
) -> Result<(), ServerError>
where
    IO: Io + Unpin,
    F: Future<Output = Result<OutgoingResponse, E>> + Send,
    E: Into<BoxError>,
{
    let mut service = pin!(service);

    let (outgoing, pending_command) = loop {
        let command = tokio::select! {
            biased;
            result = &mut service => {
                break (result.map_err(ServerError::service)?, None);
            }
            command = command_rx.recv() => command,
        };
        let Some(command) = command else {
            break (service.await.map_err(ServerError::service)?, None);
        };
        match command {
            BodyCommand::Next(reply) => {
                let result = {
                    let mut operation = pin!(transaction.next_data());
                    tokio::select! {
                        biased;
                        result = &mut service => {
                            Err(result)
                        }
                        result = &mut operation => Ok(result),
                    }
                };
                match result {
                    Err(outgoing) => {
                        break (
                            outgoing.map_err(ServerError::service)?,
                            Some(BodyCommand::Next(reply)),
                        );
                    }
                    Ok(Ok(data)) => {
                        _ = reply.send(Ok(BodyReply::Data {
                            data,
                            end: transaction.body_end(),
                            trailers: transaction.trailers().cloned(),
                        }));
                    }
                    Ok(Err(error)) => {
                        let error = BodyError::connection(error);
                        _ = reply.send(Err(error.clone()));
                        return Err(ServerError::request_body(error));
                    }
                }
            }
            BodyCommand::Continue(reply) => {
                let result = {
                    let mut operation = pin!(transaction.continue_preview());
                    tokio::select! {
                        biased;
                        result = &mut service => {
                            Err(result)
                        }
                        result = &mut operation => Ok(result),
                    }
                };
                match result {
                    Err(outgoing) => {
                        break (
                            outgoing.map_err(ServerError::service)?,
                            Some(BodyCommand::Continue(reply)),
                        );
                    }
                    Ok(Ok(())) => {
                        _ = reply.send(Ok(BodyReply::Continued));
                    }
                    Ok(Err(error)) => {
                        let error = BodyError::connection(error);
                        _ = reply.send(Err(error.clone()));
                        return Err(ServerError::request_body(error));
                    }
                }
            }
        }
    };

    write_outgoing_response(transaction, outgoing, command_rx, pending_command).await
}

impl<S, IO> Service<IO> for Server<S>
where
    IO: Io + Unpin + ExtensionsRef,
    S: Service<IncomingRequest, Output = OutgoingResponse, Error: Into<BoxError>>,
{
    type Output = ();
    type Error = ServerError;

    fn serve(&self, io: IO) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        self.serve_connection(io)
    }
}

async fn write_outgoing_response<IO>(
    transaction: ServerTransaction<'_, IO>,
    outgoing: OutgoingResponse,
    mut commands: tokio::sync::mpsc::Receiver<BodyCommand>,
    mut pending_command: Option<BodyCommand>,
) -> Result<(), ServerError>
where
    IO: Io + Unpin,
{
    if pending_command
        .as_ref()
        .is_some_and(BodyCommand::is_abandoned)
    {
        pending_command = None;
    }
    let early = transaction.body_end().is_none();
    let (response, mut body, body_end, _extensions) = outgoing.into_parts();
    let mut response = if early {
        if pending_command.is_some() || !commands.is_closed() {
            transaction.respond_streaming(response).await
        } else {
            transaction.respond_early(response).await
        }
    } else {
        transaction.respond(response).await
    }
    .map_err(ServerError::connection)?;
    let mut trailers = None;
    loop {
        let frame = loop {
            if let Some(command) = pending_command.take() {
                if command.is_abandoned() {
                    continue;
                }
                fulfill_body_command(&mut response, command).await?;
                continue;
            }
            tokio::select! {
                biased;
                command = commands.recv() => {
                    if let Some(command) = command {
                        if command.is_abandoned() {
                            continue;
                        }
                        fulfill_body_command(&mut response, command).await?;
                        continue;
                    }
                    break body.next().await;
                }
                frame = body.next() => break frame,
            }
        };
        let Some(frame) = frame else {
            break;
        };
        match frame.map_err(ServerError::response_body)? {
            BodyFrame::Data(data) => {
                if trailers.is_some() {
                    return Err(ServerError::connection(Error::InvalidSequence(
                        "ICAP response data follows HTTP trailers",
                    )));
                }
                response
                    .write_data(&data)
                    .await
                    .map_err(ServerError::connection)?;
            }
            BodyFrame::Trailers(value) => {
                if trailers.replace(value).is_some() {
                    return Err(ServerError::connection(Error::InvalidSequence(
                        "ICAP response has multiple HTTP trailer blocks",
                    )));
                }
            }
        }
    }
    let trailers = trailers.unwrap_or_else(TrailerBlock::empty);
    match body_end {
        OutgoingBodyEnd::Complete => response
            .finish_with_trailers(&trailers)
            .await
            .map_err(ServerError::connection),
        OutgoingBodyEnd::UseOriginalBody(offset) => response
            .finish_partial_with_trailers(offset, &trailers)
            .await
            .map_err(ServerError::connection),
    }
}

async fn fulfill_body_command<IO>(
    response: &mut ServerResponse<'_, IO>,
    command: BodyCommand,
) -> Result<(), ServerError>
where
    IO: Io + Unpin,
{
    match command {
        BodyCommand::Next(reply) => match response.next_request_data().await {
            Ok(data) => {
                _ = reply.send(Ok(BodyReply::Data {
                    data,
                    end: response.request_body_end(),
                    trailers: response.request_trailers().cloned(),
                }));
                Ok(())
            }
            Err(error) => {
                let error = BodyError::connection(error);
                _ = reply.send(Err(error.clone()));
                Err(ServerError::request_body(error))
            }
        },
        BodyCommand::Continue(reply) => {
            let error = BodyError::invalid_state(
                "Preview cannot continue after the final ICAP response starts",
            );
            _ = reply.send(Err(error.clone()));
            Err(ServerError::request_body(error))
        }
    }
}

/// Error returned while serving an ICAP connection.
#[derive(Debug)]
pub struct ServerError {
    kind: ServerErrorKind,
    source: BoxError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ServerErrorKind {
    /// ICAP framing, sequencing, or transport failure.
    Connection,
    /// The inner request service failed.
    Service,
    /// The incoming streaming request body failed.
    RequestBody,
    /// The outgoing streaming response body failed.
    ResponseBody,
}

impl ServerError {
    /// Return the broad source category of this error.
    #[must_use]
    pub const fn kind(&self) -> ServerErrorKind {
        self.kind
    }

    fn connection(error: Error) -> Self {
        Self {
            kind: ServerErrorKind::Connection,
            source: Box::new(error),
        }
    }

    fn service(error: impl Into<BoxError>) -> Self {
        Self {
            kind: ServerErrorKind::Service,
            source: error.into(),
        }
    }

    fn request_body(error: BodyError) -> Self {
        Self {
            kind: ServerErrorKind::RequestBody,
            source: Box::new(error),
        }
    }

    fn response_body(error: BoxError) -> Self {
        Self {
            kind: ServerErrorKind::ResponseBody,
            source: error,
        }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            ServerErrorKind::Connection => "ICAP connection error",
            ServerErrorKind::Service => "ICAP request service error",
            ServerErrorKind::RequestBody => "ICAP streaming request-body error",
            ServerErrorKind::ResponseBody => "ICAP streaming response-body error",
        })
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use core::{
        convert::Infallible,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::sync::Arc;

    use rama_core::{
        ServiceInput,
        bytes::{Bytes, BytesMut},
        error::BoxError,
        extensions::{Extension, ExtensionsRef as _},
        futures::stream,
        layer::MapErr,
        service::service_fn,
    };
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        sync::Notify,
    };

    use crate::{
        client::{ClientConnection, PreviewOutcome, WriteOutcome},
        codec::{Header, RequestLine, ResponseLine},
        io::BodyEnd,
        message::{EncapsulatedParts, Request, Response, TrailerBlock},
        proto::{EncapsulatedKind, Method, MethodKind, Preview, StatusCode, header},
    };

    use super::*;
    use crate::server::OutgoingBody;

    #[derive(Debug, Eq, PartialEq)]
    struct Marker(u8);

    impl Extension for Marker {}

    fn request_parts(body_kind: EncapsulatedKind) -> EncapsulatedParts {
        EncapsulatedParts::new(
            Some(Bytes::from_static(
                b"GET /resource HTTP/1.1\r\nHost: example.test\r\n\r\n",
            )),
            None,
            body_kind,
        )
        .unwrap()
    }

    fn options_request(close: bool) -> Request {
        let line = RequestLine::new(Method::Options, "icap://icap.test/echo").unwrap();
        let host = Header::new("Host", b"icap.test").unwrap();
        let connection = close.then(|| Header::new(header::CONNECTION, b"close").unwrap());
        let fields: Vec<_> = [Some(host), connection].into_iter().flatten().collect();
        Request::new(line, &fields, Some(EncapsulatedParts::null())).unwrap()
    }

    fn options_response() -> Response {
        Response::new(
            MethodKind::Options,
            ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
            &[
                Header::new(header::METHODS, b"REQMOD, RESPMOD").unwrap(),
                Header::new(header::ISTAG, b"\"rama-test\"").unwrap(),
            ],
            Some(EncapsulatedParts::null()),
        )
        .unwrap()
    }

    fn preview_request(limit: u64) -> Request {
        Request::with_preview(
            RequestLine::new(Method::Reqmod, "icap://icap.test/echo").unwrap(),
            &[
                Header::new("Host", b"icap.test").unwrap(),
                Header::new(header::ALLOW, b"204, 206").unwrap(),
            ],
            request_parts(EncapsulatedKind::RequestBody),
            Preview::new(limit),
        )
        .unwrap()
    }

    fn reqmod_request() -> Request {
        Request::new(
            RequestLine::new(Method::Reqmod, "icap://icap.test/echo").unwrap(),
            &[Header::new("Host", b"icap.test").unwrap()],
            Some(request_parts(EncapsulatedKind::RequestBody)),
        )
        .unwrap()
    }

    fn response(method: MethodKind, parts: EncapsulatedParts) -> Response {
        Response::new(
            method,
            ResponseLine::new(StatusCode::OK, b"OK").unwrap(),
            &[Header::new(header::ISTAG, b"\"rama-test\"").unwrap()],
            Some(parts),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn dispatches_through_a_standard_layered_service() {
        let (client_io, server_io) = tokio::io::duplex(256);
        let requests = Arc::new(AtomicUsize::new(0));
        let service_requests = Arc::clone(&requests);
        let service = service_fn(move |request: IncomingRequest| {
            let service_requests = Arc::clone(&service_requests);
            async move {
                assert_eq!(request.extensions().get_ref::<Marker>(), Some(&Marker(42)),);
                service_requests.fetch_add(1, Ordering::Relaxed);
                Ok::<_, Infallible>(OutgoingResponse::without_body(options_response()))
            }
        });
        let service = MapErr::new(service, |error: Infallible| -> BoxError { match error {} });
        let server = Server::new(Arc::new(service));
        let server_io = ServiceInput::new(server_io);
        server_io.extensions().insert(Marker(42));
        let server_task = tokio::spawn(async move {
            server.serve(server_io).await.unwrap();
        });

        let mut client = ClientConnection::new(ServiceInput::new(client_io));
        for close in [false, true] {
            let response = client
                .start(options_request(close))
                .await
                .unwrap()
                .finish()
                .await
                .unwrap();
            assert_eq!(response.response().status(), StatusCode::OK);
            response.into_response().unwrap();
        }

        server_task.await.unwrap();
        assert_eq!(requests.load(Ordering::Relaxed), 2);
        assert!(!client.is_reusable());
    }

    #[tokio::test]
    async fn streams_preview_continuation_data_and_trailers() {
        let (client_io, server_io) = tokio::io::duplex(256);
        let response_trailers =
            TrailerBlock::from_bytes(Bytes::from_static(b"X-Response-Digest: def\r\n\r\n"))
                .unwrap();
        let expected_trailers = response_trailers.clone();
        let service = service_fn(move |mut request: IncomingRequest| {
            let expected_trailers = expected_trailers.clone();
            async move {
                let mut received = BytesMut::new();
                loop {
                    while let Some(data) = request.body_mut().next_data().await? {
                        received.extend_from_slice(&data);
                    }
                    if request.body().body_end() != Some(BodyEnd::Preview) {
                        break;
                    }
                    request.body_mut().continue_preview().await?;
                }
                assert_eq!(&received[..], b"hello world");
                let frames = stream::iter([
                    Ok::<_, Infallible>(BodyFrame::Data(Bytes::from_static(b"adapted"))),
                    Ok(BodyFrame::Trailers(expected_trailers)),
                ]);
                Ok::<_, BoxError>(OutgoingResponse::new(
                    response(
                        MethodKind::Reqmod,
                        request_parts(EncapsulatedKind::RequestBody),
                    ),
                    OutgoingBody::from_frames(frames),
                ))
            }
        });
        let server_task = tokio::spawn(async move {
            Server::new(service)
                .serve_connection(ServiceInput::new(server_io))
                .await
                .unwrap();
        });

        let mut client = ClientConnection::new(ServiceInput::new(client_io));
        let mut transaction = client.start(preview_request(5)).await.unwrap();
        assert_eq!(
            transaction.write_data(b"hello").await.unwrap(),
            WriteOutcome::Written,
        );
        let mut transaction = match transaction.finish_preview(false).await.unwrap() {
            PreviewOutcome::Continue(transaction) => transaction,
            PreviewOutcome::Response(_) => panic!("expected 100 Continue"),
        };
        assert_eq!(
            transaction.write_data(b" world").await.unwrap(),
            WriteOutcome::Written,
        );
        let mut response = transaction.finish().await.unwrap();
        let mut adapted = BytesMut::new();
        while let Some(data) = response.next_data().await.unwrap() {
            adapted.extend_from_slice(&data);
        }
        assert_eq!(&adapted[..], b"adapted");
        assert_eq!(response.trailers(), Some(&response_trailers));
        response.into_response().unwrap();
        drop(client);

        server_task.await.unwrap();
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn typed_http_body_drives_preview_and_preserves_trailers() {
        use rama_http_types::body::util::BodyExt as _;

        let (client_io, server_io) = tokio::io::duplex(256);
        let service = service_fn(async |request: crate::http::IncomingRequest| {
            let encapsulated = request.encapsulated().unwrap();
            assert_eq!(encapsulated.request().unwrap().uri().as_str(), "/resource",);
            let (_icap, _parts, body, _extensions) = request.into_parts();
            let collected = body.collect().await?;
            assert_eq!(collected.trailers().unwrap()["x-request-digest"], "abc",);
            assert_eq!(collected.to_bytes(), "hello world");
            Ok::<_, BoxError>(OutgoingResponse::without_body(response(
                MethodKind::Reqmod,
                EncapsulatedParts::null(),
            )))
        });
        let server_task = tokio::spawn(async move {
            Server::new(crate::http::HttpService::new(service))
                .serve_connection(ServiceInput::new(server_io))
                .await
                .unwrap();
        });

        let trailers =
            TrailerBlock::from_bytes(Bytes::from_static(b"X-Request-Digest: abc\r\n\r\n")).unwrap();
        let mut client = ClientConnection::new(ServiceInput::new(client_io));
        let mut transaction = client.start(preview_request(5)).await.unwrap();
        assert_eq!(
            transaction.write_data(b"hello").await.unwrap(),
            WriteOutcome::Written,
        );
        let mut transaction = match transaction.finish_preview(false).await.unwrap() {
            PreviewOutcome::Continue(transaction) => transaction,
            PreviewOutcome::Response(_) => panic!("expected 100 Continue"),
        };
        assert_eq!(
            transaction.write_data(b" world").await.unwrap(),
            WriteOutcome::Written,
        );
        transaction
            .finish_with_trailers(&trailers)
            .await
            .unwrap()
            .into_response()
            .unwrap();
        drop(client);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_owned_body_read_resumes_without_data_loss() {
        let (client_io, server_io) = tokio::io::duplex(256);
        let cancelled = Arc::new(AtomicBool::new(false));
        let service_cancelled = Arc::clone(&cancelled);
        let ready = Arc::new(Notify::new());
        let service_ready = Arc::clone(&ready);
        let service = service_fn(move |mut request: IncomingRequest| {
            let service_cancelled = Arc::clone(&service_cancelled);
            let service_ready = Arc::clone(&service_ready);
            async move {
                let result = tokio::time::timeout(
                    std::time::Duration::from_millis(10),
                    request.body_mut().next_data(),
                )
                .await;
                result.unwrap_err();
                service_cancelled.store(true, Ordering::Release);
                service_ready.notify_one();

                let mut received = BytesMut::new();
                while let Some(data) = request.body_mut().next_data().await? {
                    received.extend_from_slice(&data);
                }
                assert_eq!(&received[..], b"delayed");
                Ok::<_, BoxError>(OutgoingResponse::without_body(response(
                    MethodKind::Reqmod,
                    EncapsulatedParts::null(),
                )))
            }
        });
        let server_task = tokio::spawn(async move {
            Server::new(service)
                .serve_connection(ServiceInput::new(server_io))
                .await
                .unwrap();
        });

        let mut client = ClientConnection::new(ServiceInput::new(client_io));
        let mut transaction = client.start(reqmod_request()).await.unwrap();
        ready.notified().await;
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(
            transaction.write_data(b"delayed").await.unwrap(),
            WriteOutcome::Written,
        );
        let response = transaction.finish().await.unwrap();
        response.into_response().unwrap();
        drop(client);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn response_body_can_stream_from_the_owned_request_body() {
        let (client_io, server_io) = tokio::io::duplex(64);
        let service = service_fn(async |request: IncomingRequest| {
            let (_request, body, _extensions) = request.into_parts();
            let data = stream::try_unfold(body, |mut body| async move {
                let data = body.next_data().await?;
                Ok::<_, BodyError>(data.map(|data| (data, body)))
            });
            Ok::<_, Infallible>(OutgoingResponse::new(
                response(
                    MethodKind::Reqmod,
                    request_parts(EncapsulatedKind::RequestBody),
                ),
                OutgoingBody::from_data_stream(data),
            ))
        });
        let server_task = tokio::spawn(async move {
            Server::new(service)
                .serve_connection(ServiceInput::new(server_io))
                .await
                .unwrap();
        });

        let (mut read, mut write) = tokio::io::split(client_io);
        let send = async move {
            write
                .write_all(
                    b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
                      Host: icap.test\r\n\
                      Connection: close\r\n\
                      Encapsulated: req-hdr=0, req-body=18\r\n\r\n\
                      GET / HTTP/1.1\r\n\r\n",
                )
                .await
                .unwrap();
            for (line, data) in [
                (b"3\r\n".as_slice(), b"one".as_slice()),
                (b"3\r\n", b"two"),
                (b"5\r\n", b"three"),
            ] {
                write.write_all(line).await.unwrap();
                write.write_all(data).await.unwrap();
                write.write_all(b"\r\n").await.unwrap();
            }
            write.write_all(b"0\r\n\r\n").await.unwrap();
        };
        let receive = async move {
            let mut response = Vec::new();
            read.read_to_end(&mut response).await.unwrap();
            response
        };
        let ((), response) = tokio::join!(send, receive);

        assert!(response.starts_with(b"ICAP/1.0 200 OK\r\n"));
        assert!(response.ends_with(b"3\r\none\r\n3\r\ntwo\r\n5\r\nthree\r\n0\r\n\r\n"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_preview_continuation_resumes_the_same_write() {
        let (client_io, server_io) = tokio::io::duplex(8);
        let service = service_fn(async |mut request: IncomingRequest| {
            let mut received = BytesMut::new();
            while let Some(data) = request.body_mut().next_data().await? {
                received.extend_from_slice(&data);
            }
            assert_eq!(request.body().body_end(), Some(BodyEnd::Preview));
            let timed_out = tokio::time::timeout(
                std::time::Duration::from_millis(10),
                request.body_mut().continue_preview(),
            )
            .await;
            timed_out.unwrap_err();
            request.body_mut().continue_preview().await?;
            while let Some(data) = request.body_mut().next_data().await? {
                received.extend_from_slice(&data);
            }
            assert_eq!(&received[..], b"onetwo");
            Ok::<_, BoxError>(OutgoingResponse::without_body(response(
                MethodKind::Reqmod,
                EncapsulatedParts::null(),
            )))
        });
        let server_task = tokio::spawn(async move {
            Server::new(service)
                .serve_connection(ServiceInput::new(server_io))
                .await
                .unwrap();
        });

        let (mut read, mut write) = tokio::io::split(client_io);
        let continued = Arc::new(Notify::new());
        let writer_continued = Arc::clone(&continued);
        let send = async move {
            write
                .write_all(
                    b"REQMOD icap://icap.test/echo ICAP/1.0\r\n\
                      Host: icap.test\r\n\
                      Connection: close\r\n\
                      Preview: 3\r\n\
                      Encapsulated: req-hdr=0, req-body=18\r\n\r\n\
                      GET / HTTP/1.1\r\n\r\n\
                      3\r\none\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
            writer_continued.notified().await;
            write.write_all(b"3\r\ntwo\r\n0\r\n\r\n").await.unwrap();
        };
        let receive = async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let mut interim = vec![0; b"ICAP/1.0 100 Continue\r\n\r\n".len()];
            read.read_exact(&mut interim).await.unwrap();
            assert_eq!(&interim, b"ICAP/1.0 100 Continue\r\n\r\n");
            continued.notify_one();
            let mut response = Vec::new();
            read.read_to_end(&mut response).await.unwrap();
            response
        };
        let ((), response) = tokio::join!(send, receive);

        assert!(response.starts_with(b"ICAP/1.0 200 OK\r\n"));
        server_task.await.unwrap();
    }
}
