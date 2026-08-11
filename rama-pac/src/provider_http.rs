//! The http-backed pac script provider.

use std::fmt;
use std::time::Duration;

use rama_core::error::{BoxError, BoxErrorExt, ErrorContext, ErrorExt, extra::OpaqueError};
use rama_core::{Service, service::BoxService};
use rama_http::service::client::HttpClientExt as _;
use rama_http::{Request, Response, body::CollectOptions, body::util::BodyExt as _};
use rama_net::uri::Uri;
use rama_utils::macros::generate_set_and_with;
use rama_utils::str::decode_utf8_or_latin1;

use crate::PacScript;

/// Always fetches the script, through the given http client.
///
/// The client decides what works: layer it with
/// [`FileUriLayer`][rama_http::layer::uri::FileUriLayer] and
/// [`DataUriLayer`][rama_http::layer::uri::DataUriLayer] to also accept
/// `file://` and `data:` script uris, and with a redirect policy if the
/// script url redirects — a non-2xx answer is a failed fetch here. Bodies
/// are decoded as UTF-8 when valid and otherwise as Latin-1, matching
/// Firefox's PAC loader compatibility behavior.
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
    /// Largest script accepted by default; Chromium caps PAC files at
    /// this size.
    pub const DEFAULT_MAX_SIZE: usize = rama_utils::octets::mib(1);

    /// Default budget for one fetch: connect, headers and body.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Fetch PAC scripts with the given http client.
    pub fn new<S>(client: S) -> Self
    where
        // `Into<BoxError>` rather than `Error`: a layered client answers with
        // a `BoxError`, which is a `Box<dyn Error>` and so is not itself one
        S: Service<Request, Output = Response, Error: Into<BoxError> + Send + Sync + 'static>,
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
        let fetch = async {
            let response = self
                .client
                .get(uri.clone())
                .send()
                .await
                .context("fetch pac script")
                // `Debug` redacts the userinfo password, `Display` does not
                .map_err(|err| err.context_debug_field("uri", uri.clone()))?;

            let status = response.status();
            if !status.is_success() {
                return Err(BoxError::from_static_str("pac script fetch failed")
                    .context_field("status", status));
            }

            let bytes = response
                .into_body()
                .collect_with(CollectOptions::new().with_max_size(self.max_size))
                .await
                .context("collect pac script body")?
                .to_bytes();
            let source = decode_utf8_or_latin1(bytes.as_ref());
            Ok::<_, BoxError>(PacScript::from(source.as_ref()))
        };

        // the timeout covers connect, headers and body alike
        tokio::time::timeout(self.timeout, fetch)
            .await
            .map_err(|_elapsed| BoxError::from_static_str("pac script fetch timed out"))
            .and_then(|result| result)
            .into_opaque_error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::bytes::Bytes;
    use rama_core::service::service_fn;
    use rama_http::{Body, StatusCode};

    fn uri() -> Uri {
        "http://pac.example/proxy.pac".parse().unwrap()
    }

    fn client(
        status: StatusCode,
        body: &'static str,
    ) -> impl Service<Request, Output = Response, Error = OpaqueError> {
        service_fn(move |_req: Request| async move {
            Ok::<_, OpaqueError>(
                Response::builder()
                    .status(status)
                    .body(Body::from(body))
                    .unwrap(),
            )
        })
    }

    fn byte_client(
        status: StatusCode,
        body: &'static [u8],
    ) -> impl Service<Request, Output = Response, Error = OpaqueError> {
        service_fn(move |_req: Request| async move {
            Ok::<_, OpaqueError>(
                Response::builder()
                    .status(status)
                    .body(Body::from(Bytes::from_static(body)))
                    .unwrap(),
            )
        })
    }

    #[tokio::test]
    async fn fetches_the_script_body() {
        let src = "function FindProxyForURL(url, host) { return \"DIRECT\"; }";
        let fetcher = FetchPacScript::new(client(StatusCode::OK, src));
        let script = fetcher.serve(uri()).await.unwrap();
        assert_eq!(script.as_str(), src);
    }

    #[tokio::test]
    async fn valid_utf8_is_not_misdecoded_as_latin1() {
        let src = "function café() {}";
        let fetcher = FetchPacScript::new(byte_client(StatusCode::OK, src.as_bytes()));
        let script = fetcher.serve(uri()).await.unwrap();
        assert_eq!(script.as_str(), src);
    }

    #[tokio::test]
    async fn invalid_utf8_falls_back_to_latin1() {
        let fetcher = FetchPacScript::new(byte_client(StatusCode::OK, b"function caf\xe9() {}"));
        let script = fetcher.serve(uri()).await.unwrap();
        assert_eq!(script.as_str(), "function café() {}");
    }

    #[tokio::test]
    async fn non_2xx_is_a_failed_fetch() {
        let fetcher = FetchPacScript::new(client(StatusCode::NOT_FOUND, "not here"));
        let err = fetcher.serve(uri()).await.unwrap_err();
        assert!(err.to_string().contains("fetch failed"), "{err}");
    }

    #[tokio::test]
    async fn oversized_script_is_rejected() {
        let fetcher =
            FetchPacScript::new(client(StatusCode::OK, "way too much script")).with_max_size(4);
        fetcher.serve(uri()).await.unwrap_err();
    }

    #[tokio::test]
    async fn slow_fetch_times_out() {
        // real time, wide margin: a 50ms budget against a client that would
        // take 30s can only resolve by timing out
        let slow = service_fn(|_req: Request| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok::<_, OpaqueError>(Response::builder().body(Body::empty()).unwrap())
        });
        let fetcher = FetchPacScript::new(slow).with_timeout(Duration::from_millis(50));
        let err = fetcher.serve(uri()).await.unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
    }
}
