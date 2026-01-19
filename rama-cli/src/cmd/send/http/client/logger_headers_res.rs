use rama::{
    Service,
    extensions::ExtensionsRef,
    http::{
        Request, Response, Version,
        proto::{
            h1::{Http1HeaderMap, ext::ReasonPhrase},
            h2::{self, PseudoHeader, PseudoHeaderOrder},
        },
    },
};

use super::VerboseLogs;

#[derive(Debug, Clone)]
pub(super) struct ResponseHeaderLogger<S> {
    pub(super) inner: S,
    pub(super) show_headers: bool,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseHeaderLogger<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Error = S::Error;
    type Output = S::Output;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let res = self.inner.serve(req).await?;
        if self.show_headers || res.extensions().contains::<VerboseLogs>() {
            eprintln!(
                "* {:?} {} {}",
                res.version(),
                res.status().as_u16(),
                match res.extensions().get::<ReasonPhrase>() {
                    Some(reason) => String::from_utf8_lossy(reason.as_bytes()),
                    None => res.status().canonical_reason().unwrap_or_default().into(),
                },
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
