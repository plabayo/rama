use rama::{
    Service,
    extensions::ExtensionsRef,
    http::{
        Request, Version,
        proto::{
            h1::Http1HeaderMap,
            h2::{self, PseudoHeader, PseudoHeaderOrder},
        },
    },
};

use std::convert::Infallible;

use super::VerboseLogs;

#[derive(Debug, Clone)]
pub(super) struct RequestHeaderLogger;

impl<ReqBody> Service<Request<ReqBody>> for RequestHeaderLogger
where
    ReqBody: Send + 'static,
{
    type Error = Infallible;
    type Response = Request<ReqBody>;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        if req.extensions().contains::<VerboseLogs>() {
            eprintln!("* using {:?}", req.version());

            if req.version() == Version::HTTP_2 || req.version() == Version::HTTP_3 {
                let pseudo_headers = req
                    .extensions()
                    .get::<PseudoHeaderOrder>()
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
                                req.uri().scheme_str().unwrap_or("?").to_owned()
                            }
                            PseudoHeader::Authority => {
                                req.uri()
                                    .authority()
                                    .map(|a| a.as_str())
                                    .unwrap_or("?")
                                    .to_owned()
                            }
                            PseudoHeader::Path => {
                                req.uri().path().to_owned()
                            }
                            PseudoHeader::Status => "<???>".to_owned(),
                            PseudoHeader::Protocol => {
                                if let Some(proto) = req.extensions().get::<h2::ext::Protocol>() {
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
                "> {} {}{} {:?}",
                req.method(),
                req.uri().path(),
                req.uri()
                    .query()
                    .map(|q| format!("?{q}"))
                    .unwrap_or_default(),
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

        Ok(req)
    }
}
