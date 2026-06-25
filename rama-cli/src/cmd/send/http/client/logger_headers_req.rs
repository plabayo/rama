use rama::{
    Layer, Service,
    extensions::ExtensionsRef,
    http::{
        Request, Version,
        proto::{
            h1::Http1HeaderMap,
            h2::{self, PseudoHeader, PseudoHeaderOrder},
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
                for header in pseudo_headers.iter() {
                    eprintln!(
                        "* [HTTP/2] [{}: {}]",
                        header,
                        match header {
                            PseudoHeader::Method => {
                                req.method().to_string()
                            }
                            PseudoHeader::Scheme => {
                                req.uri()
                                    .scheme()
                                    .map(|p| p.as_str().to_owned())
                                    .unwrap_or_else(|| "?".to_owned())
                            }
                            PseudoHeader::Authority => {
                                req.uri()
                                    .authority()
                                    .map(|a| a.to_string())
                                    .unwrap_or_else(|| "?".to_owned())
                            }
                            PseudoHeader::Path => req.uri().path_or_root().into_owned(),
                            PseudoHeader::Status => "<???>".to_owned(),
                            PseudoHeader::Protocol => {
                                if let Some(proto) = req.extensions().get_ref::<h2::ext::Protocol>()
                                {
                                    proto.as_str().to_owned()
                                } else {
                                    continue;
                                }
                            }
                        }
                    );
                }
            }

            eprintln!(
                "> {} {} {:?}",
                req.method(),
                req.uri().request_target(),
                req.version()
            );

            let header_map = Http1HeaderMap::new(req.headers().clone(), Some(req.extensions()));
            for (name, value) in header_map {
                match req.version() {
                    Version::HTTP_2 | Version::HTTP_3 => {
                        // write lower-case for H2/H3
                        eprintln!(
                            "> {}: {}",
                            name.header_name().as_str(),
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
