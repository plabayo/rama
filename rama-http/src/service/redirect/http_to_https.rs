use crate::{
    Request, Response, Scheme, StatusCode, Uri,
    headers::Location,
    service::web::response::{Headers, IntoResponse},
    utils::request_uri,
};
use rama_core::{Service, telemetry::tracing};
use rama_net::http::uri::{UriMatchError, UriMatchReplace, match_replace::UriMatchReplaceNever};
use rama_utils::macros::generate_set_and_with;
use std::convert::Infallible;

/// Service that redirects all HTTP requests to HTTPS
#[derive(Debug, Clone)]
pub struct RedirectHttpToHttps<R> {
    status_code: StatusCode,
    overwrite_port: Option<u16>,
    drop_query: bool,
    rewrite_uri_rule: R,
}

impl RedirectHttpToHttps<UriMatchReplaceNever> {
    #[must_use]
    /// Create a new [`RedirectHttpToHttps`] using its [`Default`] implementation.
    pub fn new() -> Self {
        Default::default()
    }
}

impl Default for RedirectHttpToHttps<UriMatchReplaceNever> {
    fn default() -> Self {
        Self {
            status_code: StatusCode::PERMANENT_REDIRECT,
            overwrite_port: None,
            drop_query: false,
            rewrite_uri_rule: UriMatchReplaceNever::new(),
        }
    }
}

impl<R> RedirectHttpToHttps<R> {
    generate_set_and_with! {
        /// Overwrite status code with 301 — Moved Permanently.
        ///
        /// The default status code is 308 — Permanent Redirect.
        pub fn status_code_moved(mut self) -> Self {
            self.status_code = StatusCode::MOVED_PERMANENTLY;
            self
        }
    }

    generate_set_and_with! {
        /// Overwrite status code with 302 — Found.
        ///
        /// The default status code is 308 — Permanent Redirect.
        pub fn status_code_found(mut self) -> Self {
            self.status_code = StatusCode::FOUND;
            self
        }
    }

    generate_set_and_with! {
        /// Overwrite status code with 303 — See Other.
        ///
        /// The default status code is 308 — Permanent Redirect.
        pub fn status_code_other(mut self) -> Self {
            self.status_code = StatusCode::SEE_OTHER;
            self
        }
    }

    generate_set_and_with! {
        /// Overwrite status code with 307 — Temporary Redirect.
        ///
        /// The default status code is 308 — Permanent Redirect.
        pub fn status_code_temporary(mut self) -> Self {
            self.status_code = StatusCode::TEMPORARY_REDIRECT;
            self
        }
    }

    generate_set_and_with! {
        /// Set a port to overwrite in the redirect Uri, when `None` (the [`Default`]),
        /// it erases the port, assuming the default https port (443).
        pub fn overwrite_port(mut self, port: Option<u16>) -> Self {
            self.overwrite_port = port;
            self
        }
    }

    generate_set_and_with! {
        /// Drop query parameters should they be available in the [`Uri`],
        /// by default they are preserved.
        pub fn drop_query(mut self, drop: bool) -> Self {
            self.drop_query = drop;
            self
        }
    }

    /// Opt-in to a uri-match-replace rule that conditionally
    /// can replace the request's full Uri prior to doing the work on it.
    pub fn with_rewrite_uri_rule<S: UriMatchReplace>(self, rule: S) -> RedirectHttpToHttps<S> {
        RedirectHttpToHttps {
            status_code: self.status_code,
            overwrite_port: self.overwrite_port,
            drop_query: self.drop_query,
            rewrite_uri_rule: rule,
        }
    }
}

impl<R, Body> Service<Request<Body>> for RedirectHttpToHttps<R>
where
    R: UriMatchReplace + Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Response, Self::Error> {
        let full_uri = match self.rewrite_uri_rule.match_replace_uri(request_uri(&req)) {
            Ok(uri) => uri,
            Err(UriMatchError::NoMatch(uri)) => {
                tracing::trace!("no uri match found for uri {uri}; do not rewrite");
                uri
            }
            Err(UriMatchError::Unexpected(err)) => {
                tracing::debug!(
                    "an unexpected error ({err}happened while rewriting uri; re-compute og uri and use it preserved"
                );
                request_uri(&req)
            }
        };

        let mut uri_parts = full_uri.into_owned().into_parts();

        uri_parts.scheme = Some(Scheme::HTTPS);

        let Some(authority) = uri_parts.authority.as_mut() else {
            tracing::debug!("failed to get authority from full Uri (report bug)");
            return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        };

        match (authority.port_u16(), self.overwrite_port) {
            // use port to overwrite
            (_, Some(port)) => {
                match smol_str::format_smolstr!("{}:{port}", authority.host()).parse() {
                    Ok(new_authority) => *authority = new_authority,
                    Err(err) => {
                        tracing::debug!(
                            "failed to overwrite authority using custom port: {err} (bug??)"
                        );
                        return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
                    }
                }
            }
            // drop port
            (Some(_), _) => {
                *authority = authority.host().parse().unwrap();
            }
            (None, None) => (), // nothing to do
        }

        if self.drop_query
            && let Some(path_and_query) = uri_parts.path_and_query.take()
        {
            if path_and_query.query().is_some() {
                // TOOD: open issue in http to perhaps more easily drop query??
                uri_parts.path_and_query = Some(path_and_query.path().parse().unwrap());
            } else {
                uri_parts.path_and_query = Some(path_and_query);
            }
        }

        match Uri::from_parts(uri_parts) {
            Ok(uri) => {
                let loc = Location::from(uri);
                Ok((Headers::single(loc), self.status_code).into_response())
            }
            Err(err) => {
                tracing::debug!("failed to re-create Uri using modified parts: {err} (bug??)");
                Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        }
    }
}
