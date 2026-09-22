//! Rama-native HTTP/3 request sender.

use super::{
    Error, body,
    connection::{Config, Driver, Shared},
    control::Role,
    headers,
    quic::Writer,
    stream::{Phase, Reader},
};
use rama_core::{error::BoxError, extensions::ExtensionsRef, rt::Executor};
use rama_http_types::{
    Method, Request, Response,
    body::StreamingBody,
    proto::{
        h1::ext::informational::OnInformational,
        h3::{Code, FrameType},
    },
};
use std::{marker::PhantomData, sync::Arc};
use tokio::sync::Semaphore;

/// Cloneable sender for a multiplexed HTTP/3 connection.
pub struct SendRequest<B> {
    connection: rama_quic::Connection,
    shared: Arc<Shared>,
    admission: Arc<Semaphore>,
    lifetime: Arc<ConnectionLifetime>,
    executor: Executor,
    _body: PhantomData<fn(B)>,
}
// The driver owns a transport handle too, so transport reference counting alone
// cannot detect when the application has stopped using this connection.
pub(crate) struct ConnectionLifetime(rama_quic::Connection);
impl Drop for ConnectionLifetime {
    fn drop(&mut self) {
        self.0
            .close(Code::H3_NO_ERROR.value() as u32, b"HTTP/3 client released");
    }
}

impl<B> Clone for SendRequest<B> {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            shared: self.shared.clone(),
            admission: self.admission.clone(),
            lifetime: self.lifetime.clone(),
            executor: self.executor.clone(),
            _body: PhantomData,
        }
    }
}

impl<B> std::fmt::Debug for SendRequest<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3SendRequest")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

/// Prepare a client connection. The returned driver must be run concurrently.
///
/// Application data is sent only after handshake confirmation. The QUIC endpoint
/// must negotiate `h3` and allow at least three peer unidirectional streams.
pub fn handshake<B>(
    connection: rama_quic::Connection,
    config: Config,
    executor: Executor,
) -> Result<(SendRequest<B>, Driver), Error> {
    if connection.side() != rama_quic_proto::Side::Client {
        return Err(Error::connection(
            Code::H3_INTERNAL_ERROR,
            "client requires client-side QUIC connection",
        ));
    }
    config.settings()?;
    let admission = Arc::new(Semaphore::new(config.max_requests));
    let shared = Shared::from_connection(config, Role::Client, &connection)?;
    let driver = Driver::new(connection.clone(), shared.clone(), Role::Client);
    Ok((
        SendRequest {
            lifetime: Arc::new(ConnectionLifetime(connection.clone())),
            connection,
            shared,
            admission,
            executor,
            _body: PhantomData,
        },
        driver,
    ))
}

impl<B> SendRequest<B> {
    #[cfg(test)]
    pub(crate) fn dynamic_insert_count(&self) -> u64 {
        self.shared.dynamic_insert_count()
    }

    /// Take the opt-in push consumer once per connection, shared across sender clones.
    pub fn take_pushes(&self) -> Option<super::push::Pushes> {
        super::push::Pushes::take(self.shared.clone(), self.lifetime.clone())
    }

    /// Whether the underlying connection is terminal.
    pub fn is_closed(&self) -> bool {
        self.shared.error().is_some() || self.connection.close_reason().is_some()
    }

    /// Whether the peer has begun graceful shutdown.
    pub fn is_draining(&self) -> bool {
        self.shared.goaway().is_some()
    }

    /// Wait until the peer stops admitting requests or the connection fails.
    /// Active streams may continue after graceful shutdown begins.
    pub fn closed_or_draining(&self) -> impl Future<Output = Error> + Send + 'static {
        let shared = self.shared.clone();
        async move { shared.rejected(None).await }
    }

    /// Check whether this connection still admits new work.
    pub async fn ready(&mut self) -> Result<(), Error> {
        self.connection
            .handshake_confirmed()
            .await
            .map_err(|_error| {
                Error::connection(Code::H3_GENERAL_PROTOCOL_ERROR, "QUIC handshake failed")
            })?;
        if let Some(error) = self.shared.error() {
            return Err(error);
        }
        if self
            .connection
            .handshake_data()
            .and_then(|data| data.application_layer_protocol)
            != Some(rama_net::tls::ApplicationProtocol::HTTP_3)
        {
            return Err(Error::connection(
                Code::H3_GENERAL_PROTOCOL_ERROR,
                "HTTP/3 requires h3 ALPN",
            ));
        }
        if self.is_draining() {
            return Err(Error::stream(
                Code::H3_REQUEST_REJECTED,
                "connection draining",
            ));
        }
        Ok(())
    }
}

impl<B> SendRequest<B>
where
    B: StreamingBody + Unpin + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    /// Send a request on its own bidirectional QUIC stream.
    pub async fn send_request(
        &mut self,
        request: Request<B>,
    ) -> Result<Response<crate::body::Incoming>, Error> {
        self.ready().await?;
        let permit = tokio::select! {
            error = self.shared.rejected(None) => return Err(error),
            permit = self.admission.clone().acquire_owned() => Arc::new(permit.map_err(|_error| Error::stream(Code::H3_REQUEST_REJECTED, "connection draining"))?),
        };
        let (send, recv) = tokio::select! {
            error = self.shared.rejected(None) => return Err(error),
            streams = self.connection.open_bi() => streams.map_err(|_error| Error::connection(Code::H3_GENERAL_PROTOCOL_ERROR, "cannot open request stream"))?,
        };
        let id = u64::from(send.id());
        let mut reader = Reader::new(recv, self.shared.clone(), id);
        reader.abort = Some(send.abort_handle());
        let mut writer = Writer::new(send);
        reader.client_lifetime = Some(self.lifetime.clone());
        // GOAWAY and newly available stream credit can become ready together.
        // Its limit classifies existing requests; even the maximum limit forbids
        // starting this new request (RFC 9114 section 5.2).
        if self.shared.goaway().is_some() {
            return Err(Error::stream(
                Code::H3_REQUEST_REJECTED,
                "connection draining",
            ));
        }
        reader.origin = Some(request.uri().clone());
        let method = request.method().clone();
        let informational = request.extensions().get_ref::<OnInformational>().cloned();
        if method == Method::CONNECT && !request.body().is_end_stream() {
            return Err(Error::stream(
                Code::H3_MESSAGE_ERROR,
                "CONNECT requires the upgrade API for tunnel data",
            ));
        }
        let encoded = headers::encode_request(&self.shared, id, &request)?;
        writer.queue(FrameType::HEADERS, encoded)?;
        if method == Method::CONNECT {
            std::future::poll_fn(|cx| writer.poll_flush(cx)).await?;
            loop {
                let fields = tokio::select! {
                    error = self.shared.rejected(Some(id)) => return Err(error),
                    fields = reader.headers() => fields?,
                };
                let response = headers::response_for_method(fields, method == Method::CONNECT)
                    .map_err(|error| reader.reject(error))?;
                response
                    .extensions()
                    .insert(super::PriorityHandle::new(&self.shared, id, false));
                if response.status().is_informational() {
                    if let Some(callback) = &informational {
                        callback.call(response);
                    }
                    tokio::task::yield_now().await;
                    continue;
                }
                if response.status().is_success() {
                    let (pending, upgrade) = rama_http::io::upgrade::pending();
                    pending.fulfill(super::upgrade::new(reader, writer, permit, None));
                    response.extensions().insert(upgrade);
                    return Ok(response.map(|()| crate::body::Incoming::empty()));
                }
                std::future::poll_fn(|cx| writer.poll_finish(cx)).await?;
                let length = headers::content_length(response.headers())?;
                reader.phase = Phase::Body;
                return Ok(response
                    .map(|()| crate::body::Incoming::h3(body::Body::new(reader, length, permit))));
            }
        }
        let shared = self.shared.clone();
        let upload_permit = permit.clone();
        let upload_lifetime = self.lifetime.clone();
        let remaining = headers::content_length(request.headers())?;
        let (_, request_body) = request.into_parts();
        let task = self.executor.spawn_task(async move {
            let _permit = upload_permit;
            let _lifetime = upload_lifetime;
            let result = body::send(writer, request_body, shared.clone(), id, remaining).await;
            if let Err(error) = result
                && error.scope() == super::qpack::ErrorScope::Connection
            {
                shared.fail(error);
            }
            result
        });
        // Aborting the upload drops Writer, which resets partial output rather than FINishing it.
        struct Upload(Option<tokio::task::JoinHandle<Result<(), Error>>>);
        impl Drop for Upload {
            fn drop(&mut self) {
                if let Some(task) = &self.0 {
                    task.abort();
                }
            }
        }
        let mut upload = Upload(Some(task));
        loop {
            let fields = {
                let head = reader.headers();
                let mut head = std::pin::pin!(head);
                loop {
                    tokio::select! {
                        error = self.shared.rejected(Some(id)) => return Err(error),
                        result = &mut head => break result?,
                        result = async {
                            match upload.0.as_mut() {
                                Some(task) => task.await,
                                None => std::future::pending().await,
                            }
                        } => {
                            upload.0 = None;
                            if let Err(error) = result.map_err(|_error| Error::stream(Code::H3_INTERNAL_ERROR, "upload task failed"))?
                                && !error.is_peer_stop() { return Err(error); }
                        }
                    }
                }
            };
            let response = headers::response_for_method(fields, method == Method::CONNECT)
                .map_err(|error| reader.reject(error))?;
            response
                .extensions()
                .insert(super::PriorityHandle::new(&self.shared, id, false));
            if response.status().is_informational() {
                if let Some(callback) = &informational {
                    callback.call(response);
                }
                tokio::task::yield_now().await;
                continue;
            }
            let length = if method == Method::HEAD
                || response.status() == rama_http_types::StatusCode::NOT_MODIFIED
                || response.status() == rama_http_types::StatusCode::NO_CONTENT
            {
                Some(0)
            } else {
                headers::content_length(response.headers())?
            };
            reader.phase = Phase::Body;
            // The upload may legitimately outlive receipt of response headers. Its lifetime
            // is transferred to the response body together with the admission permit.
            let task = upload.0.take();
            let incoming = body::Body::new(reader, length, permit).with_upload(task);
            return Ok(response.map(|()| crate::body::Incoming::h3(incoming)));
        }
    }
}
