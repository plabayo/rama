//! The http-backed pac script provider.

use std::fmt;
use std::time::Duration;

use rama_core::error::{BoxError, BoxErrorExt, ErrorContext, ErrorExt, extra::OpaqueError};
use rama_core::{Service, service::BoxService};
use rama_http::service::client::HttpClientExt as _;
use rama_http::{BodyExtractExt as _, Request, Response, body::CollectOptions};
use rama_net::uri::Uri;
use rama_utils::macros::generate_set_and_with;

use crate::PacScript;

/// Always fetches the script, through the given http client.
///
/// The client decides which schemes work: layer it with
/// [`FileUriLayer`][rama_http::layer::uri::FileUriLayer] and
/// [`DataUriLayer`][rama_http::layer::uri::DataUriLayer] to also accept
/// `file://` and `data:` script uris.
pub struct FetchPacScript {
    client: BoxService<Request, Response, OpaqueError>,
    max_size: usize,
    timeout: Duration,
}

impl fmt::Debug for FetchPacScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchPacScript")
            .field("max_size", &self.max_size)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl FetchPacScript {
    /// Largest script accepted by default; browsers cap PAC files
    /// around this size.
    pub const DEFAULT_MAX_SIZE: usize = rama_utils::octets::mib(1);

    /// Default budget for one fetch: connect, headers and body.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Fetch PAC scripts with the given http client.
    pub fn new<S>(client: S) -> Self
    where
        S: Service<Request, Output = Response, Error: std::error::Error + Send + Sync + 'static>,
    {
        Self {
            client: rama_core::layer::MapErr::into_opaque_error(client).boxed(),
            max_size: Self::DEFAULT_MAX_SIZE,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    generate_set_and_with! {
        /// Reject scripts larger than this
        /// (defaults to [`Self::DEFAULT_MAX_SIZE`]).
        pub fn max_size(mut self, max_size: usize) -> Self {
            self.max_size = max_size;
            self
        }
    }

    generate_set_and_with! {
        /// Budget for one fetch — connect, headers and body
        /// (defaults to [`Self::DEFAULT_TIMEOUT`]).
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }
}

impl Service<Uri> for FetchPacScript {
    type Output = PacScript;
    type Error = OpaqueError;

    async fn serve(&self, uri: Uri) -> Result<Self::Output, Self::Error> {
        // `Debug` redacts the userinfo password, `Display` does not
        let fetch = async {
            let response = self
                .client
                .get(uri.clone())
                .send()
                .await
                .with_context(|| format!("fetch pac script from {uri:?}"))?;

            let status = response.status();
            if !status.is_success() {
                return Err(BoxError::from_static_str("pac script fetch failed")
                    .context_field("status", status));
            }

            response
                .try_into_string_with(CollectOptions::new().with_max_size(self.max_size))
                .await
                .context("collect pac script body")
        };

        // the timeout covers connect, headers and body alike
        let source = tokio::time::timeout(self.timeout, fetch)
            .await
            .map_err(|_elapsed| BoxError::from_static_str("pac script fetch timed out"))
            .and_then(|result| result)
            .into_opaque_error()?;

        Ok(PacScript::from(source))
    }
}
