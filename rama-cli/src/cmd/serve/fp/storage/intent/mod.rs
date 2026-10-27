//! Request-owned preparation, before display middleware rewrites headers.

use std::{sync::Arc, time::Duration};

use parking_lot::Mutex;
use rama::{
    Service,
    error::BoxError,
    extensions::{Extension, Extensions, ExtensionsRef},
    http::{
        Method, Request, Version, header::USER_AGENT, proto::h3::observation::H3RequestObservation,
    },
    layer::Layer,
    net::uri::Uri,
    ua::profile::{
        capture::{
            joint::{CapturedSlot, CapturedSlotKind, JointCaptureLimits},
            observation::ProfileCapture,
            runtime::RuntimeProfileCapture,
        },
        format::canonical::ProfileDataError,
        model::{identity::FlowKey, js::JsProfileWebApis, ua::UserAgentSourceInfo},
    },
};
use tokio::{
    task::AbortHandle,
    time::{Instant, sleep_until},
};

use super::{
    super::{
        StorageAuthorized,
        collection::{CollectionClaim, CollectionLease, CollectionOwner, ConnectionHandover},
        data::{self, Http3Info, Initiator},
    },
    collector,
    startup::current_day,
    worker::{CollectionQueue, CollectionReservation},
};

const PREPARATION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub(in super::super) struct CaptureLayer {
    queue: CollectionQueue,
}

impl CaptureLayer {
    pub(super) fn new(queue: CollectionQueue) -> Self {
        Self { queue }
    }
}

impl<S> Layer<S> for CaptureLayer {
    type Service = CaptureService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        CaptureService {
            inner,
            queue: self.queue.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        CaptureService {
            inner,
            queue: self.queue,
        }
    }
}

#[derive(Debug, Clone)]
pub(in super::super) struct CaptureService<S> {
    inner: S,
    queue: CollectionQueue,
}

#[derive(Debug, Extension)]
struct CaptureIntent(Mutex<Option<PreparedRequest>>);
#[derive(Debug)]
struct PreparedRequest {
    reservation: CollectionReservation,
    day: u32,
    request: ProfileCapture,
    timer: Option<PreparationTimer>,
}

#[derive(Debug)]
struct PreparationTimer(AbortHandle);

impl Drop for PreparationTimer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(in super::super) fn is_protocol_probe(uri: &Uri) -> bool {
    uri.query().is_some_and(|query| {
        query
            .as_encoded_str()
            .split('&')
            .any(|pair| pair.split('=').next() == Some("h3_probe"))
    })
}

fn initiator(method: &Method, uri: &Uri) -> Option<Initiator> {
    let path = uri.path()?.as_encoded_str();
    if method == Method::GET && path == "/report" && !is_protocol_probe(uri) {
        Some(Initiator::Navigator)
    } else if method == Method::POST && path.starts_with("/api/fetch/number/") {
        Some(Initiator::Fetch)
    } else if method == Method::POST && path.starts_with("/api/xml/number/") {
        Some(Initiator::XMLHttpRequest)
    } else if (method == Method::GET || method == Method::POST) && path == "/form" {
        Some(Initiator::Form)
    } else if (method == Method::GET || method == Method::CONNECT) && path == "/api/ws" {
        Some(Initiator::Ws)
    } else {
        None
    }
}

impl<S, B> Service<Request<B>> for CaptureService<S>
where
    B: Send + 'static,
    S: Service<Request<B>>,
{
    type Output = S::Output;
    type Error = S::Error;
    async fn serve(&self, request: Request<B>) -> Result<Self::Output, Self::Error> {
        // A connection can begin with an untracked asset. Its safe native first
        // request recipe must precede the connection's Bootstrap reference.
        let initiator = initiator(request.method(), request.uri());
        let bootstrap_only =
            initiator.is_none()
                && request.version() == Version::HTTP_3
                && request
                    .extensions()
                    .get_ref::<H3RequestObservation>()
                    .is_some_and(|observed| {
                        observed.fields_complete
                            && observed.connection.encoder_bindings.as_ref().is_some_and(
                                |bindings| {
                                    bindings.complete && bindings.stream_id == observed.stream_id
                                },
                            )
                    });
        let navigation = bootstrap_only
            && request.method() == Method::GET
            && request
                .headers()
                .get("sec-fetch-mode")
                .is_some_and(|mode| mode.as_bytes() == b"navigate")
            && request
                .headers()
                .get("sec-fetch-dest")
                .is_some_and(|destination| destination.as_bytes() == b"document");
        let initiator = initiator.or_else(|| navigation.then_some(Initiator::Navigator));
        let mut completed = None;
        if (initiator.is_some() || bootstrap_only)
            && let Some(reservation) = self.queue.try_reserve()
        {
            let day = match current_day() {
                Ok(day) => day,
                Err(_error) => {
                    reservation.reject_clock();
                    return self.inner.serve(request).await;
                }
            };
            let result = prepare(&request, initiator.as_ref());
            match result {
                Ok(captured) => {
                    let intent = Arc::new(CaptureIntent(Mutex::new(Some(PreparedRequest {
                        reservation,
                        day,
                        request: captured,
                        timer: None,
                    }))));
                    let deadline = Instant::now() + PREPARATION_TIMEOUT;
                    let weak = Arc::downgrade(&intent);
                    let timer = tokio::spawn(async move {
                        sleep_until(deadline).await;
                        if let Some(intent) = weak.upgrade() {
                            drop(intent.0.lock().take());
                        }
                    });
                    if let Some(prepared) = intent.0.lock().as_mut() {
                        prepared.timer = Some(PreparationTimer(timer.abort_handle()));
                    }
                    request.extensions().insert_arc(intent);
                    if bootstrap_only {
                        completed = Some(request.extensions().clone());
                    }
                }
                Err(_error) => reservation.reject_capture(),
            }
        }
        let result = self.inner.serve(request).await;
        if let Some(extensions) = completed {
            // Authentication has run, but display middleware cannot change the
            // already prepared safe recipe. Queue it with its own connection.
            let h3 = data::http3_info(&extensions).await;
            submit(&extensions, h3.as_ref());
        }
        result
    }
}

fn prepare<B>(
    request: &Request<B>,
    initiator: Option<&Initiator>,
) -> Result<ProfileCapture, BoxError> {
    let ua = request
        .headers()
        .get(USER_AGENT)
        .ok_or(ProfileDataError::Incomplete("client identity"))?
        .to_str()?;
    let profile = collector::profile_key(ua)?;
    let connection = collector::connection_context(request.extensions());
    let captured = collector::request_capture(
        profile,
        connection,
        request.version(),
        request.method().clone(),
        initiator,
        request.headers(),
        request.extensions(),
    )?;
    Ok(captured)
}

pub(super) fn attach_runtime(
    ext: &Extensions,
    source: Option<&UserAgentSourceInfo>,
    web_apis: Option<&JsProfileWebApis>,
) {
    if source.is_none() && web_apis.is_none() {
        return;
    }
    let Some(intent) = ext.get_ref::<CaptureIntent>() else {
        return;
    };
    let mut guard = intent.0.lock();
    let Some(mut prepared) = guard.take() else {
        return;
    };
    if prepared
        .request
        .joint
        .slots
        .iter()
        .any(|slot| slot.kind == CapturedSlotKind::RuntimeMetadata)
    {
        prepared.reservation.reject_capture();
        return;
    }
    let maximum = JointCaptureLimits::default().value_bytes;
    let value = RuntimeProfileCapture::capture_report(source, web_apis, maximum)
        .and_then(|capture| capture.canonical(maximum));
    match value {
        Ok(value) => {
            let mut slots = prepared.request.joint.slots.into_vec();
            slots.push(CapturedSlot {
                kind: CapturedSlotKind::RuntimeMetadata,
                value,
            });
            prepared.request.joint.slots = slots.into();
            *guard = Some(prepared);
        }
        Err(_error) => prepared.reservation.reject_capture(),
    }
}

pub(super) fn submit(ext: &Extensions, h3: Option<&Http3Info>) {
    let Some(prepared) = ext
        .get_ref::<CaptureIntent>()
        .and_then(|intent| intent.0.lock().take())
    else {
        return;
    };
    let PreparedRequest {
        reservation,
        day,
        request,
        timer: _timer,
    } = prepared;
    let owner = match request
        .profile
        .canonical(JointCaptureLimits::default().value_bytes)
    {
        Ok(profile) => CollectionOwner {
            authorized: ext.contains::<StorageAuthorized>(),
            profile: profile.id,
        },
        Err(_error) => {
            reservation.reject_capture();
            return;
        }
    };
    let Some(lease) = ext.get_arc::<CollectionLease>() else {
        reservation.reject_capture();
        return;
    };
    let connection = match lease.claim(owner) {
        CollectionClaim::OwnerMismatch => {
            reservation.reject_capture();
            return;
        }
        CollectionClaim::RequestOnly => None,
        CollectionClaim::Connection(permit, Some(handover)) => {
            // The handed-over bootstrap recipe takes this request's slot: the connection
            // capture refers to its first request, which this one is not.
            let ConnectionHandover {
                request,
                connection,
            } = *handover;
            _ = reservation.submit(owner, day, request, Some((connection, permit)));
            return;
        }
        CollectionClaim::Connection(permit, None) => {
            let Some(FlowKey::Http { version, .. }) = &request.flow else {
                reservation.reject_capture();
                return;
            };
            match collector::connection_capture(
                request.profile.clone(),
                request.connection.clone(),
                *version,
                ext,
                h3,
                Some(&request),
            ) {
                Ok(Some(capture)) => {
                    if !owner.authorized
                        && capture
                            .joint
                            .slots
                            .iter()
                            .any(|slot| slot.kind == CapturedSlotKind::Http3Bootstrap)
                    {
                        lease.offer_handover(Box::new(ConnectionHandover {
                            request: request.clone(),
                            connection: capture.clone(),
                        }));
                    }
                    Some((capture, permit))
                }
                Ok(None) => None,
                Err(_error) => {
                    reservation.reject_capture();
                    return;
                }
            }
        }
    };
    // Validation failures are counted by submit; collection cannot fail the response.
    _ = reservation.submit(owner, day, request, connection);
}

#[cfg(test)]
mod tests;
