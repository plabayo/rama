use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use rama_core::Service;
use rama_core::extensions::ExtensionsRef;
use rama_utils::macros::define_inner_service_accessors;

use super::origin::{CsrfOrigin, Origins};
use super::{
    BypassFn, DebugFn, DefaultResponseForProtectionError, ProtectionError, ProtectionErrorKind,
    ResponseForProtectionError,
};
use crate::headers::{HeaderMapExt as _, Host, Origin, SecFetchSite};
use crate::{Request, Response, header};

/// Middleware that enforces cross-origin request forgery (CSRF) protection.
///
/// See the [module docs](crate::layer::csrf) for more details.
#[derive(Clone)]
#[must_use]
pub struct Csrf<S, T = DefaultResponseForProtectionError> {
    inner: S,
    insecure_bypass: Option<Arc<BypassFn>>,
    rejection_response: T,
    trusted_origins: Origins,
}

impl<S, T> Csrf<S, T> {
    pub(super) fn new(
        inner: S,
        insecure_bypass: Option<Arc<BypassFn>>,
        rejection_response: T,
        trusted_origins: Origins,
    ) -> Self {
        Self {
            inner,
            insecure_bypass,
            rejection_response,
            trusted_origins,
        }
    }

    define_inner_service_accessors!();

    /// Verify a request against the configured CSRF protection.
    pub(super) fn verify<Body>(&self, req: &Request<Body>) -> Result<(), ProtectionError> {
        // RFC 9110 §9.2.1 safe-ish set used by the reference: only GET/HEAD/OPTIONS are exempt
        // (deliberately not `Method::is_safe`, which also exempts TRACE).
        if matches!(
            req.method(),
            &crate::Method::GET | &crate::Method::HEAD | &crate::Method::OPTIONS
        ) {
            return Ok(());
        }

        // The usable request origin (present, not `null`, with an `http`/`https` scheme).
        let csrf_origin = req
            .headers()
            .typed_get::<Origin>()
            .filter(|origin| !origin.is_null())
            .and_then(|origin| {
                CsrfOrigin::from_parts(origin.scheme(), origin.hostname().as_ref(), origin.port())
            });

        let is_exempt = || {
            if let Some(bypass) = self.insecure_bypass.as_ref()
                && bypass(req.method(), req.uri())
            {
                return true;
            }
            csrf_origin
                .as_ref()
                .is_some_and(|origin| self.trusted_origins.contains(origin))
        };

        match req.headers().typed_get::<SecFetchSite>() {
            Some(SecFetchSite::SameOrigin | SecFetchSite::None) => return Ok(()),
            Some(SecFetchSite::CrossSite | SecFetchSite::SameSite) => {
                return if is_exempt() {
                    Ok(())
                } else {
                    Err(ProtectionError::new(
                        ProtectionErrorKind::CrossOriginRequest,
                    ))
                };
            }
            // Absent or unrecognized: fall through to the Origin/Host check.
            Some(SecFetchSite::Unknown(_)) | None => {}
        }

        // No usable cross-origin signal at all → same-origin or non-browser request.
        if req
            .headers()
            .get(header::ORIGIN)
            .is_none_or(|value| value.is_empty())
        {
            return Ok(());
        }

        // Origin is present; compare its authority to the request's effective host. Per RFC 7230
        // §5.3 the effective host is the request-target authority if present, else the `Host`
        // header.
        if let Some(origin) = csrf_origin.as_ref() {
            let matched = if let Some(authority) = req.uri().authority() {
                origin.matches_host(authority.host().to_str().as_ref(), authority.port_u16())
            } else if let Some(host) = req.headers().typed_get::<Host>() {
                origin.matches_host(&host.0.host.to_string(), host.0.port.into())
            } else {
                false
            };
            if matched {
                return Ok(());
            }
        }

        if is_exempt() {
            return Ok(());
        }

        Err(ProtectionError::new(
            ProtectionErrorKind::CrossOriginRequestFromOldBrowser,
        ))
    }
}

impl<S, T> Default for Csrf<S, T>
where
    S: Default,
    T: Default,
{
    fn default() -> Self {
        Self {
            inner: S::default(),
            insecure_bypass: None,
            rejection_response: T::default(),
            trusted_origins: Origins::default(),
        }
    }
}

impl<S: Debug, T> Debug for Csrf<S, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Csrf")
            .field("inner", &self.inner)
            .field(
                "insecure_bypass",
                &self.insecure_bypass.as_ref().map(|_| DebugFn),
            )
            .field("trusted_origins", &self.trusted_origins)
            .field("rejection_response", &DebugFn)
            .finish()
    }
}

impl<S, T, ReqBody, ResBody> Service<Request<ReqBody>> for Csrf<S, T>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    T: ResponseForProtectionError<ResBody>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response<ResBody>;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        match self.verify(&req) {
            Ok(()) => self.inner.serve(req).await,
            Err(err) => {
                let response = self
                    .rejection_response
                    .response_for_protection_error(err.clone());
                // Attach the cause so surrounding layers can inspect it regardless of the builder.
                response.extensions().insert(err);
                Ok(response)
            }
        }
    }
}
