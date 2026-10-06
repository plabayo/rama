use rama::{
    Layer, Service,
    extensions::ExtensionsRef,
    http::{
        Request, Version,
        proto::{
            ext,
            h2::{PseudoHeader, PseudoHeaderOrder, frame::Pseudo},
        },
    },
};

use super::VerboseLogs;

#[derive(Debug, Clone)]
pub(super) struct RequestHeaderLoggerService<S> {
    inner: S,
}

impl<S> RequestHeaderLoggerService<S> {
    pub(super) fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for RequestHeaderLoggerService<S>
where
    S: Service<Request<ReqBody>>,
    ReqBody: Send + 'static,
{
    type Error = S::Error;
    type Output = S::Output;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        if req.extensions().contains::<VerboseLogs>() {
            eprintln!("* using {:?}", req.version());

            if req.version() == Version::HTTP_2 || req.version() == Version::HTTP_3 {
                let pseudo_headers = req
                    .extensions()
                    .get_ref::<PseudoHeaderOrder>()
                    .cloned()
                    .unwrap_or_else(|| {
                        PseudoHeaderOrder::from_iter([
                            PseudoHeader::Method,
                            PseudoHeader::Scheme,
                            PseudoHeader::Authority,
                            PseudoHeader::Path,
                            PseudoHeader::Protocol,
                        ])
                    });
                // Pseudo-header values as `Pseudo::request` derives them, not the raw URI parts.
                let pseudo = Pseudo::request(
                    req.method().clone(),
                    req.uri(),
                    req.extensions().get_ref::<ext::Protocol>().cloned(),
                );
                for header in pseudo_headers.iter() {
                    if let Some(value) = pseudo.value(header) {
                        eprintln!("* [{:?}] [{header}: {value}]", req.version());
                    }
                }
            }

            eprintln!(
                "> {} {} {:?}",
                req.method(),
                req.uri().request_target(),
                req.version()
            );

            let header_map = req.headers().clone();
            for (name, value) in header_map.ordered_iter() {
                match req.version() {
                    Version::HTTP_2 | Version::HTTP_3 => {
                        eprintln!(
                            "> {}: {}",
                            name.display_lowercase(),
                            value.to_str().unwrap_or("<???>")
                        );
                    }
                    _ => {
                        eprintln!("> {name}: {}", value.to_str().unwrap_or("<???>"));
                    }
                }
            }

            eprintln!(">");
        }

        self.inner.serve(req).await
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub(super) struct RequestHeaderLoggerLayer;

impl<S> Layer<S> for RequestHeaderLoggerLayer {
    type Service = RequestHeaderLoggerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestHeaderLoggerService::new(inner)
    }
}
