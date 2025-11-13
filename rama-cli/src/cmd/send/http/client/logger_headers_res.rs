use rama::{
    Service,
    extensions::ExtensionsRef,
    http::{
        Request, Response, Version,
        proto::{
            h1::Http1HeaderMap,
            h2::{self, PseudoHeader, PseudoHeaderOrder},
        },
    },
};

use super::VerboseLogs;

#[derive(Debug)]
pub(super) struct ResponseHeaderLogger<S> {
    pub(super) inner: S,
    pub(super) show_headers: bool,
}

impl<S: Clone> Clone for ResponseHeaderLogger<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            show_headers: self.show_headers,
        }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseHeaderLogger<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Error = S::Error;
    type Response = S::Response;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        let res = self.inner.serve(req).await?;
        if self.show_headers || res.extensions().contains::<VerboseLogs>() {
            eprintln!(
                "* {:?} {} {}",
                res.version(),
                res.status().as_u16(),
                res.status().canonical_reason().unwrap_or_default()
            );

            if let Some(pseudo_headers) = res.extensions().get::<PseudoHeaderOrder>() {
                for header in pseudo_headers.iter() {
                    eprintln!(
                        "* [HTTP/2] [{}: {}]",
                        header,
                        match header {
                            PseudoHeader::Status => {
                                res.status().to_string()
                            }
                            PseudoHeader::Protocol => {
                                res.extensions()
                                    .get::<h2::ext::Protocol>()
                                    .map(|p| p.as_str())
                                    .unwrap_or("<???>")
                                    .to_owned()
                            }
                            PseudoHeader::Authority
                            | PseudoHeader::Method
                            | PseudoHeader::Path
                            | PseudoHeader::Scheme => "<???>".to_owned(),
                        }
                    );
                }
            }

            let header_map = Http1HeaderMap::new(res.headers().clone(), Some(res.extensions()));
            for (name, value) in header_map {
                match res.version() {
                    Version::HTTP_2 | Version::HTTP_3 => {
                        // write lower-case for H2/H3
                        eprintln!(
                            "< {}: {}",
                            name.header_name().as_str(),
                            value.to_str().unwrap_or("<???>")
                        );
                    }
                    _ => {
                        eprintln!("< {name}: {}", value.to_str().unwrap_or("<???>"));
                    }
                }
            }
        }

        Ok(res)
    }
}
