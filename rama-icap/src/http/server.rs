use core::{convert::Infallible, future::poll_fn, pin::Pin};

use rama_core::futures::stream;
use rama_http_types::{
    Body, HeaderMap, HeaderValue, Response as HttpResponse,
    body::{Frame, StreamingBody},
};

use super::{Encapsulated, Error, IncomingRequest};
use crate::{
    codec::{Header, ResponseLine},
    message::{BuildError, Response as IcapResponse},
    proto::{EncapsulatedKind, MethodKind, StatusCode, header},
    server::OutgoingResponse,
};

impl IncomingRequest {
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
        let (icap, encapsulated, mut body, _extensions) = self.into_parts();
        if icap.method() != MethodKind::Respmod {
            return Err(Error::invalid_method());
        }
        let (_request, response, body_kind) = encapsulated
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
                let parts = Encapsulated::from_response(&response, EncapsulatedKind::ResponseBody)?;
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
                let parts = Encapsulated::from_response(&response, EncapsulatedKind::NullBody)?;
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
