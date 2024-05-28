//! Middleware to print Http traffic in std format.
//!
//! Can be useful for cli / debug purposes.
//!
//! This currently is only ever printing to stdout, open a feature request
//! if you want to be able to provide your own writer.

use crate::error::{ErrorContext, OpaqueError};
use crate::http::dep::http_body;
use crate::http::io::{write_http_request, write_http_response};
use crate::http::{Body, Request, Response};
use crate::service::{Context, Layer, Service};
use bytes::Bytes;
use tokio::io::stdout;

/// Layer that applies [`TrafficPrinter`] which prints the http traffic in std format.
#[derive(Debug, Clone, Copy)]
pub struct TrafficPrinterLayer {
    request_mode: Option<PrintMode>,
    response_mode: Option<PrintMode>,
}

#[derive(Debug, Clone, Copy)]
/// Print mode for the [`TrafficPrinter`].
pub enum PrintMode {
    /// Print the entire request / response.
    All,
    /// Print only the headers of the request / response.
    Headers,
    /// Print only the body of the request / response.
    Body,
}

impl TrafficPrinterLayer {
    /// Create a new [`TrafficPrinterLayer`] that does not print anything.
    pub fn none() -> Self {
        TrafficPrinterLayer {
            request_mode: None,
            response_mode: None,
        }
    }

    /// Create a new [`TrafficPrinterLayer`] to print requests.
    pub fn requests(mode: PrintMode) -> Self {
        TrafficPrinterLayer {
            request_mode: Some(mode),
            response_mode: None,
        }
    }

    /// Create a new [`TrafficPrinterLayer`] to print responses.
    pub fn responses(mode: PrintMode) -> Self {
        TrafficPrinterLayer {
            request_mode: None,
            response_mode: Some(mode),
        }
    }

    /// Create a new [`TrafficPrinterLayer`] to print both requests and responses.
    pub fn bidirectional(request_mode: PrintMode, response_mode: PrintMode) -> Self {
        TrafficPrinterLayer {
            request_mode: Some(request_mode),
            response_mode: Some(response_mode),
        }
    }
}

impl<S> Layer<S> for TrafficPrinterLayer {
    type Service = TrafficPrinter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TrafficPrinter {
            inner,
            request_mode: self.request_mode,
            response_mode: self.response_mode,
        }
    }
}

/// Middleware to print Http traffic in std format.
///
/// See the [module docs](self) for more details.
#[derive(Debug, Clone, Copy)]
pub struct TrafficPrinter<S> {
    inner: S,
    request_mode: Option<PrintMode>,
    response_mode: Option<PrintMode>,
}

impl<S> TrafficPrinter<S> {
    /// Create a new [`TrafficPrinter`] that does not print anything.
    pub fn none(inner: S) -> Self {
        TrafficPrinter {
            inner,
            request_mode: None,
            response_mode: None,
        }
    }

    /// Create a new [`TrafficPrinter`] to print requests.
    pub fn requests(mode: PrintMode, inner: S) -> Self {
        TrafficPrinter {
            inner,
            request_mode: Some(mode),
            response_mode: None,
        }
    }

    /// Create a new [`TrafficPrinter`] to print responses.
    pub fn responses(mode: PrintMode, inner: S) -> Self {
        TrafficPrinter {
            inner,
            request_mode: None,
            response_mode: Some(mode),
        }
    }

    /// Create a new [`TrafficPrinter`] to print both requests and responses.
    pub fn bidirectional(request_mode: PrintMode, response_mode: PrintMode, inner: S) -> Self {
        TrafficPrinter {
            inner,
            request_mode: Some(request_mode),
            response_mode: Some(response_mode),
        }
    }
}

impl<State, S, ReqBody, ResBody> Service<State, Request<ReqBody>> for TrafficPrinter<S>
where
    State: Send + Sync + 'static,
    S: Service<State, Request, Response = Response<ResBody>>,
    S::Error: std::error::Error + Send + Sync + 'static,
    ReqBody: http_body::Body<Data = Bytes> + Send + Sync + 'static,
    ReqBody::Error: std::error::Error + Send + Sync + 'static,
    ResBody: http_body::Body<Data = Bytes> + Send + Sync + 'static,
    ResBody::Error: std::error::Error + Send + Sync + 'static,
{
    type Response = Response;
    type Error = OpaqueError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let req = if let Some(mode) = self.request_mode {
            let (write_headers, writer_body) = match mode {
                PrintMode::All => (true, true),
                PrintMode::Headers => (true, false),
                PrintMode::Body => (false, true),
            };
            let mut stdout = stdout();
            write_http_request(&mut stdout, req, write_headers, writer_body)
                .await
                .map_err(OpaqueError::from_boxed)
                .context("print http request in std format to stdout")?
        } else {
            req.map(Body::new)
        };

        let resp = self
            .inner
            .serve(ctx, req)
            .await
            .map_err(OpaqueError::from_std)?;

        let resp = if let Some(mode) = self.response_mode {
            let (write_headers, writer_body) = match mode {
                PrintMode::All => (true, true),
                PrintMode::Headers => (true, false),
                PrintMode::Body => (false, true),
            };
            let mut stdout = stdout();
            write_http_response(&mut stdout, resp, write_headers, writer_body)
                .await
                .map_err(OpaqueError::from_boxed)
                .context("print http response in std format to stdout")?
        } else {
            resp.map(Body::new)
        };

        Ok(resp)
    }
}
