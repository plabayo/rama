use core::{convert::Infallible, fmt, future::poll_fn, pin::Pin};

use rama_core::futures::stream;
use rama_http_types::{
    Body, HeaderMap, HeaderValue, Response as HttpResponse,
    body::{Frame, StreamingBody},
};

use super::{
    Encapsulated, Error, IncomingRequest, IncomingRequestParts, ParsedEncapsulatedParts,
    prepare_response_head, with_promoted_headers,
};
use crate::{
    codec::{Header, ResponseLine},
    message::{BuildError, Response as IcapResponse},
    proto::{EncapsulatedKind, MethodKind, StatusCode, header},
    server::OutgoingResponse,
};

impl IncomingRequest {
    /// Convert this request into a checked unchanged-response capability.
    ///
    /// The conversion selects a negotiated 204 response when legal. Otherwise
    /// it retains the untouched HTTP message for a streaming 200 echo. If
    /// mutable access may have changed or consumed data needed by that echo,
    /// the original request is returned unchanged.
    pub fn try_into_unchanged(self) -> Result<UnchangedRequest, Self> {
        let method = self.icap().method();
        if !matches!(method, MethodKind::Reqmod | MethodKind::Respmod) {
            return Err(self);
        }
        if self.icap().allows_204()
            || (self.icap().preview().is_some() && !self.body_exposed_mutably)
        {
            return Ok(UnchangedRequest {
                request: self,
                kind: UnchangedKind::NoModification,
            });
        }
        if self.encapsulated_exposed_mutably || !self.echo_body_is_available() {
            return Err(self);
        }
        Ok(UnchangedRequest {
            request: self,
            kind: UnchangedKind::Echo,
        })
    }

    fn echo_body_is_available(&self) -> bool {
        let Some(encapsulated) = self.encapsulated() else {
            return false;
        };
        let valid_head = match self.icap().method() {
            MethodKind::Reqmod => encapsulated.request.is_some(),
            MethodKind::Respmod => encapsulated.response.is_some(),
            MethodKind::Options | MethodKind::Extension => false,
        };
        valid_head
            && (!matches!(
                encapsulated.body_kind,
                EncapsulatedKind::RequestBody | EncapsulatedKind::ResponseBody
            ) || !self.body_exposed_mutably)
    }

    /// Return a 204 response and leave the HTTP message unchanged.
    ///
    /// `service_tag` may be supplied as text or bytes.
    ///
    /// # Contract
    ///
    /// Do not return 204 after Preview has continued unless the request
    /// contains `Allow: 204`.
    pub fn respond_no_modification(
        self,
        service_tag: impl AsRef<[u8]>,
    ) -> Result<OutgoingResponse, Error> {
        let method = self.icap().method();
        if !matches!(method, MethodKind::Reqmod | MethodKind::Respmod) {
            return Err(Error::invalid_method());
        }
        response_without_body(
            method,
            StatusCode::NO_MODIFICATION_NEEDED,
            b"No Modification Needed",
            service_tag.as_ref(),
        )
    }

    /// Return a 405 response for this ICAP request method.
    ///
    /// `service_tag` may be supplied as text or bytes.
    pub fn respond_method_not_allowed(
        self,
        service_tag: impl AsRef<[u8]>,
    ) -> Result<OutgoingResponse, Error> {
        response_without_body(
            self.icap().method(),
            StatusCode::METHOD_NOT_ALLOWED,
            b"Method Not Allowed",
            service_tag.as_ref(),
        )
    }

    /// Return the current RESPMOD response head and preserve its body.
    ///
    /// `service_tag` may be supplied as text or bytes.
    ///
    /// A non-empty body uses offset-zero 206 replay. The request must contain
    /// both `Allow: 204` and `Allow: 206` because reading may continue Preview.
    pub async fn adapt_response_head(
        self,
        service_tag: impl AsRef<[u8]>,
    ) -> Result<OutgoingResponse, Error> {
        let (parts, mut body) = self.into_parts();
        let IncomingRequestParts {
            icap, encapsulated, ..
        } = parts;
        if icap.method() != MethodKind::Respmod {
            return Err(Error::invalid_method());
        }
        let ParsedEncapsulatedParts {
            response,
            body_kind,
            ..
        } = encapsulated
            .ok_or_else(|| Error::invalid_sequence("RESPMOD request has no HTTP metadata"))?
            .into_parts();
        let mut response = response
            .ok_or_else(|| Error::invalid_sequence("RESPMOD request has no HTTP response"))?;
        let original_body = match body_kind {
            EncapsulatedKind::ResponseBody => classify_original_body(&mut body).await?,
            EncapsulatedKind::NullBody => OriginalBodyKind::Empty,
            _ => return Err(Error::invalid_body_kind()),
        };
        let fields = [Header::new(header::ISTAG, service_tag.as_ref()).map_err(BuildError::from)?];

        match original_body {
            OriginalBodyKind::HasOctet => {
                if !icap.allows_204() || !icap.allows_206() {
                    return Err(Error::invalid_sequence(
                        "response-head adaptation requires Allow: 204 and Allow: 206",
                    ));
                }
                let (prepared, promoted, _trailer_forbidden) = prepare_response_head(&response);
                let parts = Encapsulated::from_prepared_response(
                    &prepared,
                    EncapsulatedKind::ResponseBody,
                )?;
                let fields = with_promoted_headers(&fields, &promoted)?;
                let response = IcapResponse::new(
                    MethodKind::Respmod,
                    ResponseLine::new(StatusCode::PARTIAL_CONTENT, b"Partial Content")?,
                    &fields,
                    Some(parts),
                )?;
                Ok(OutgoingResponse::without_body(response).with_use_original_body(0))
            }
            OriginalBodyKind::Trailers(trailers) => {
                declare_trailers(&mut response, &trailers)?;
                let body = Body::from_frame_stream(stream::iter([Ok::<_, Infallible>(
                    Frame::trailers(trailers),
                )]));
                OutgoingResponse::from_http_response(
                    MethodKind::Respmod,
                    ResponseLine::new(StatusCode::OK, b"OK")?,
                    &fields,
                    response.map(|_| body),
                )
            }
            OriginalBodyKind::Empty => {
                let (prepared, promoted, _trailer_forbidden) = prepare_response_head(&response);
                let parts =
                    Encapsulated::from_prepared_response(&prepared, EncapsulatedKind::NullBody)?;
                let fields = with_promoted_headers(&fields, &promoted)?;
                let response = IcapResponse::new(
                    MethodKind::Respmod,
                    ResponseLine::new(StatusCode::OK, b"OK")?,
                    &fields,
                    Some(parts),
                )?;
                Ok(OutgoingResponse::without_body(response))
            }
        }
    }
}

/// A checked capability for returning an HTTP message unchanged.
///
/// Construct this with [`IncomingRequest::try_into_unchanged`]. The selected
/// response is guaranteed not to rely on caller-managed negotiation or on
/// HTTP message bytes that may already have been changed or consumed.
pub struct UnchangedRequest {
    request: IncomingRequest,
    kind: UnchangedKind,
}

#[derive(Clone, Copy, Debug)]
enum UnchangedKind {
    NoModification,
    Echo,
}

impl UnchangedRequest {
    /// Build the negotiated 204 or streaming 200 echo response.
    pub fn respond(self, service_tag: impl AsRef<[u8]>) -> Result<OutgoingResponse, Error> {
        let method = self.request.icap().method();
        if matches!(self.kind, UnchangedKind::NoModification) {
            return response_without_body(
                method,
                StatusCode::NO_MODIFICATION_NEEDED,
                b"No Modification Needed",
                service_tag.as_ref(),
            );
        }
        let fields = [Header::new(header::ISTAG, service_tag.as_ref()).map_err(BuildError::from)?];
        match method {
            MethodKind::Reqmod => OutgoingResponse::from_http_request(
                ResponseLine::new(StatusCode::OK, b"OK")?,
                &fields,
                self.request.into_request()?,
            ),
            MethodKind::Respmod => OutgoingResponse::from_http_response(
                MethodKind::Respmod,
                ResponseLine::new(StatusCode::OK, b"OK")?,
                &fields,
                self.request.into_response()?,
            ),
            MethodKind::Options | MethodKind::Extension => Err(Error::invalid_method()),
        }
    }
}

impl fmt::Debug for UnchangedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnchangedRequest")
            .field("method", &self.request.icap().method())
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

enum OriginalBodyKind {
    HasOctet,
    Trailers(HeaderMap),
    Empty,
}

async fn classify_original_body(body: &mut Body) -> Result<OriginalBodyKind, Error> {
    while let Some(frame) = poll_fn(|context| Pin::new(&mut *body).poll_frame(context)).await {
        let frame = frame.map_err(Error::http_body)?;
        match frame.into_data() {
            Ok(data) if !data.is_empty() => return Ok(OriginalBodyKind::HasOctet),
            Ok(_empty) => {}
            Err(frame) => {
                let trailers = frame.into_trailers().map_err(|_frame| {
                    Error::invalid_frame("HTTP body produced an unsupported frame")
                })?;
                return Ok(OriginalBodyKind::Trailers(trailers));
            }
        }
    }
    Ok(OriginalBodyKind::Empty)
}

fn declare_trailers<B>(response: &mut HttpResponse<B>, trailers: &HeaderMap) -> Result<(), Error> {
    let mut names = String::new();
    for name in trailers.keys() {
        if !names.is_empty() {
            names.push_str(", ");
        }
        names.push_str(name.as_str());
    }
    response.headers_mut().insert(
        rama_http_types::header::TRAILER,
        HeaderValue::from_str(&names).map_err(|error| Error::http_head(error.into()))?,
    );
    Ok(())
}

fn response_without_body(
    method: MethodKind,
    status: StatusCode,
    reason: &[u8],
    service_tag: &[u8],
) -> Result<OutgoingResponse, Error> {
    let response = IcapResponse::new(
        method,
        ResponseLine::new(status, reason)?,
        &[Header::new(header::ISTAG, service_tag).map_err(BuildError::from)?],
        None,
    )?;
    Ok(OutgoingResponse::without_body(response))
}
