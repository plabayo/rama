//! Compose one confirmed early-data recovery with an application retry rule.
//!
//! Install this inside one [`Retry`](super::Retry) owner, outside the client and
//! its connection selection. A 425 or typed TLS early rejection is always
//! handled here, even when ineligible; it never falls through to an application
//! rule that retries every status or error. Other results keep the application
//! rule's normal behavior and limits, including after a confirmed recovery.

use super::{
    RetryBody,
    managed::{DoNotRetry, RetryRule},
};
use crate::{
    Request, Response, StatusCode, StreamingBody,
    body::{CollectOptions, SizeHint},
    header,
    proto::ext::{
        Protocol,
        early_data::{EarlyDataAttempt, EarlyDataRejected},
    },
    request::Parts,
};
use rama_core::{
    error::error_chain,
    extensions::{Extensions, ExtensionsRef, Ingress},
};
use rama_net::tls::{EarlyDataPermit, ForbidEarlyData};
use std::{error::Error, sync::Arc};

/// Recognize a per-request TLS early rejection through contextual error wrappers.
///
/// Pass `error.as_ref()` for a boxed error, or `&error` for a concrete error.
#[must_use]
pub fn is_early_data_rejected(error: &(dyn Error + 'static)) -> bool {
    error_chain(error).any(|error| error.is::<EarlyDataRejected>())
}

/// Prepare only safe, truly empty requests for automatic early-data recovery.
///
/// A zero byte hint does not suffice: trailers can follow. Payload-bearing or
/// unsafe requests stream once under this initial policy. Applications needing
/// ordinary payload retries can supply a different preparation function; the
/// early-send admission checks remain safe-method and empty-body only.
#[must_use]
pub fn prepare_bodyless(
    parts: &Parts,
    is_end_stream: bool,
    _: &SizeHint,
) -> Option<CollectOptions> {
    (parts.method.is_safe() && is_end_stream && !parts.extensions.contains::<Protocol>())
        .then(CollectOptions::new)
}

/// Grant early admission to an eligible attempt inside its owning Retry layer.
///
/// Use with [`rama_core::layer::MapInput`] inside Retry, above connection
/// selection, and pair it with [`with_recovery`]. The attempt must already have
/// forked extensions. A forwarded, confirmed and unmarked input never gains
/// early exposure merely because its gateway enabled early sending.
#[must_use]
pub fn permit_attempt(request: Request<RetryBody>) -> Request<RetryBody> {
    if eligible(&request)
        && (!request.extensions().contains::<Ingress<Extensions>>()
            || request.headers().contains_key(header::EARLY_DATA))
    {
        request
            .extensions()
            .insert(EarlyDataPermit::with_recovery_owner());
    }
    request
}

fn eligible(request: &Request<RetryBody>) -> bool {
    request.body().is_replayable()
        && request.body().is_end_stream()
        && request.method().is_safe()
        && !request.extensions().contains::<Protocol>()
        && !request.extensions().contains::<ForbidEarlyData>()
        && !request.extensions().contains::<DoNotRetry>()
}

/// Handle 425 and typed TLS early rejection before an application's retry rule.
///
/// The classifier keeps the caller's error type unchanged. For example,
/// `|error: &BoxError| is_early_data_rejected(error.as_ref())` works with boxed
/// errors; concrete errors can be passed directly to the chain walker.
///
/// Recovery requires a replayable safe, empty request and actual transport
/// evidence. It writes [`ForbidEarlyData`] into the policy's caller store before
/// requesting one confirmed retry. A repeated 425 or TLS rejection is terminal.
/// Forwarded marked requests never recover a 425 locally; actual upstream TLS
/// rejection can still be recovered. [`DoNotRetry`] always takes precedence.
///
/// Compose application rules here instead of nesting separate Retry owners:
/// each owner has its own attempt forks. Ordinary non-425 responses and other
/// errors delegate to the application rule, whose retry budget still applies.
pub fn with_recovery<B, E, R, F>(
    application_rule: R,
    is_rejection: F,
) -> impl RetryRule<Request<RetryBody>, Response<B>, E> + Clone
where
    B: Send + 'static,
    E: Send + Sync + 'static,
    R: RetryRule<Request<RetryBody>, Response<B>, E>,
    F: Fn(&E) -> bool + Send + Sync + 'static,
{
    let rules = Arc::new((application_rule, is_rejection));
    move |request: Request<RetryBody>, result: Result<Response<B>, E>| {
        let rules = rules.clone();
        async move {
            let evidence = match &result {
                Ok(response) if response.status() == StatusCode::TOO_EARLY => Some(
                    !request.headers().contains_key(header::EARLY_DATA)
                        && response
                            .extensions()
                            .get_ref::<EarlyDataAttempt>()
                            .is_some_and(|attempt| attempt.permits_425_recovery()),
                ),
                Err(error) if (rules.1)(error) => Some(true),
                _ => None,
            };
            if let Some(evidence) = evidence {
                let retry = evidence && eligible(&request);
                if retry {
                    request.extensions().insert(ForbidEarlyData::default());
                }
                (request, result, retry)
            } else {
                rules.0.retry(request, result).await
            }
        }
    }
}

#[cfg(test)]
mod tests;
