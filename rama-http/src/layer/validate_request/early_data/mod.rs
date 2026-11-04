//! Early-data decisions composed with ordinary request validation.
//!
//! Install [`require_confirmed`] through [`ValidateRequestHeaderLayer::custom_fn`]
//! on routes which wait for current-hop confirmation and reject inherited
//! replay exposure. Gateways use [`forward_to`] with their
//! origin-capability predicate. These helpers do not retry responses; original
//! clients own 425 recovery through `retry::early_data::with_recovery`.

use super::{ValidateRequest, ValidateRequestHeaderLayer};
use crate::{
    Body, Request, Response, StatusCode, header,
    headers::{EarlyData, HeaderMapExt as _},
    proto::ext::early_data::EarlyDataReceived,
};
use rama_core::{extensions::ExtensionsRef as _, futures::FutureExt as _};
use rama_net::tls::ForbidEarlyData;

/// Whether the request has actual current-hop receipt or inherited exposure.
/// Presence of a malformed field is treated conservatively as exposure.
#[must_use]
pub fn is_exposed<B>(request: &Request<B>) -> bool {
    request.headers().contains_key(header::EARLY_DATA)
        || request.extensions().contains::<EarlyDataReceived>()
}

fn too_early() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::TOO_EARLY;
    response
}

/// Wait for current-hop confirmation; reject inherited exposure with 425.
///
/// Use as a `custom_fn` validator for routes which must not process replayable
/// input. An already-confirmed current-hop receipt passes immediately. Waiting
/// cannot discharge an inherited `Early-Data` field. Failed confirmation returns
/// 425 without calling the route.
pub async fn require_confirmed<B>(request: Request<B>) -> Result<Request<B>, Response> {
    if request.headers().contains_key(header::EARLY_DATA) {
        return Err(too_early());
    }

    if let Some(received) = request.extensions().get_ref::<EarlyDataReceived>()
        && received.confirmed().await.is_err()
    {
        return Err(too_early());
    }

    Ok(request)
}

/// Forward only according to the selected origin's early-data capability.
///
/// The predicate must mean the origin understands `Early-Data` and correctly
/// returns 425 for requests it cannot safely process. It is not permission to
/// replay arbitrary methods or payloads. The existing client retry policy still
/// controls upstream early sending.
///
/// Inherited exposure cannot be cleared by waiting on this hop: an incapable
/// origin produces 425 without being called. Actual current-hop-only receipt
/// waits for confirmation and forwards unmarked with upstream early data
/// forbidden. A capable origin receives the marker while confirmation is pending;
/// an already-confirmed current hop stays unmarked and forbids upstream early sending. Its
/// 425 must pass back unchanged. Confirmed unmarked ingress stays unmarked.
/// Apply this after routing chooses the origin and before sending upstream.
pub fn forward_to<B, P>(
    supports_early_data: P,
) -> ValidateRequestHeaderLayer<impl ValidateRequest<B, ResponseBody = Body> + Clone>
where
    B: Send + Sync + 'static,
    P: Fn(&Request<B>) -> bool + Clone + Send + Sync + 'static,
{
    ValidateRequestHeaderLayer::custom_fn(move |mut request: Request<B>| {
        let capable = supports_early_data(&request);

        async move {
            let inherited = request.headers().contains_key(header::EARLY_DATA);
            let received = request.extensions().get_ref::<EarlyDataReceived>().cloned();

            if capable {
                if !inherited && let Some(received) = &received {
                    match received.confirmed().now_or_never() {
                        Some(Ok(())) => {
                            request.extensions().insert(ForbidEarlyData::default());
                        }
                        Some(Err(_)) => return Err(too_early()),
                        None => request.headers_mut().typed_insert(EarlyData::default()),
                    }
                }
            } else if inherited {
                return Err(too_early());
            } else if let Some(received) = received {
                if received.confirmed().await.is_err() {
                    return Err(too_early());
                }
                request.extensions().insert(ForbidEarlyData::default());
            }

            Ok(request)
        }
    })
}

#[cfg(test)]
mod tests;
