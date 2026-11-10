//! Same-site and cross-site probes: the report page loads subresources, API calls
//! and navigations from other hosts of this service, so browsers record those
//! request flows too.
//!
//! Requests to those hosts carry no storage cookie: a short-lived site token in
//! the URL, minted for the page that links them, carries its authorization and
//! names that page's origin, the only one allowed to read the responses.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rama::{
    Layer, Service,
    crypto::hmac::HmacSha2,
    error::{BoxError, ErrorContext as _},
    extensions::{Extension, ExtensionsRef},
    http::{
        Body, HeaderName, HeaderValue, Method, Request, Response, StatusCode,
        header::{
            ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
            ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_REQUEST_HEADERS,
            ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
        },
        headers::{ContentSecurityPolicy, HostSource, SourceList},
    },
    net::{Protocol, address::Domain},
};
use serde::Serialize;

/// Query parameter holding a site token.
pub(super) const SITE_TOKEN_PARAM: &str = "rama-fp-site";

/// Long enough for a slow device journey, short enough to be useless when leaked.
const TOKEN_LIFETIME: Duration = Duration::from_mins(15);
const TOKEN_LABEL: &[u8] = b"rama-fp-site-token\0";
/// Expiry and authorization; the page origin follows them.
const HEADER_BYTES: usize = 9;
const MAX_ORIGIN_BYTES: usize = 255;
const MAC_BYTES: usize = 32;

static TIMING_ALLOW_ORIGIN: HeaderName = HeaderName::from_static("timing-allow-origin");

/// How a probe host relates to the page that uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SiteKind {
    SameSite,
    CrossSite,
}

#[derive(Debug, Clone)]
struct Site {
    kind: SiteKind,
    host: Domain,
}

/// The other hosts of this service and the tokens that authorize their use.
#[derive(Debug, Clone)]
pub(super) struct Sites {
    sites: Arc<[Site]>,
    tokens: SiteTokens,
}

/// One probe host as the report page receives it.
#[derive(Debug, Serialize)]
pub(super) struct SiteProbe {
    site: SiteKind,
    origin: Box<str>,
    token: Box<str>,
}

impl Sites {
    /// `None` without any probe host.
    pub(super) fn try_new(
        same_site: Option<Domain>,
        cross_site: Option<Domain>,
        storage_secret: Option<&str>,
    ) -> Result<Option<Self>, BoxError> {
        let sites: Arc<[Site]> = [
            same_site.map(|host| Site {
                kind: SiteKind::SameSite,
                host,
            }),
            cross_site.map(|host| Site {
                kind: SiteKind::CrossSite,
                host,
            }),
        ]
        .into_iter()
        .flatten()
        .collect();
        if sites.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            sites,
            tokens: SiteTokens::new(storage_secret)?,
        }))
    }

    pub(super) fn tokens(&self) -> &SiteTokens {
        &self.tokens
    }

    /// Whether `host` is one of the probe hosts, which link to no further hosts.
    pub(super) fn is_site_host(&self, host: &Domain) -> bool {
        self.sites.iter().any(|site| site.host == *host)
    }

    /// The probe hosts for a page at `page_origin`, with tokens carrying its authorization.
    pub(super) fn probes(
        &self,
        authorized: bool,
        page_origin: &str,
        now: SystemTime,
    ) -> Option<Vec<SiteProbe>> {
        self.sites
            .iter()
            .map(|site| {
                Some(SiteProbe {
                    site: site.kind,
                    origin: format!("https://{}", site.host).into_boxed_str(),
                    token: self.tokens.mint(authorized, page_origin, now)?,
                })
            })
            .collect()
    }

    /// Let pages load subresources, call the APIs and submit forms on the probe hosts.
    pub(super) fn extend_csp(&self, csp: ContentSecurityPolicy) -> ContentSecurityPolicy {
        let with_scheme = |sources: SourceList, scheme: Protocol| {
            self.sites.iter().fold(sources, |sources, site| {
                sources.with_host(HostSource::new(site.host.clone()).with_scheme(scheme.clone()))
            })
        };
        let with_sites = |sources| with_scheme(sources, Protocol::HTTPS);
        csp.with_script_src(with_sites(SourceList::self_origin()))
            .with_style_src(with_sites(SourceList::self_origin()))
            .with_img_src(with_sites(SourceList::self_origin().with_data()))
            // Browsers do not let an https source match wss, as CSP3 allows.
            .with_connect_src(with_scheme(
                with_sites(SourceList::self_origin()),
                Protocol::WSS,
            ))
            .with_frame_src(with_sites(SourceList::empty()))
            .with_form_action(with_sites(SourceList::self_origin()))
    }
}

/// Signs site tokens with a key derived from the storage secret, so every
/// instance of the service accepts them.
#[derive(Clone)]
pub(super) struct SiteTokens {
    key: HmacSha2,
    /// Without a storage secret no request is authorized, so neither is a token.
    authorizes: bool,
}

impl fmt::Debug for SiteTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SiteTokens")
            .field("authorizes", &self.authorizes)
            .finish_non_exhaustive()
    }
}

/// A valid site token on a request.
#[derive(Debug, Clone, PartialEq, Eq, Extension)]
pub(super) struct SiteGrant {
    pub(super) authorized: bool,
    /// The page the token was minted for, the only origin that may read responses.
    pub(super) origin: Box<str>,
}

impl SiteTokens {
    pub(super) fn new(storage_secret: Option<&str>) -> Result<Self, BoxError> {
        let Some(secret) = storage_secret else {
            return Ok(Self {
                key: HmacSha2::try_rand_256().context("generate site token key")?,
                authorizes: false,
            });
        };
        // HKDF-Extract with a zero salt (RFC 5869 §2.2) turns the secret into a key.
        let mut key = [0; MAC_BYTES];
        HmacSha2::new_256(&[0; MAC_BYTES]).sign(secret.as_bytes(), &mut key);
        Ok(Self {
            key: HmacSha2::new_256(&key),
            authorizes: true,
        })
    }

    /// `None` for a page origin longer than a token holds.
    pub(super) fn mint(
        &self,
        authorized: bool,
        page_origin: &str,
        now: SystemTime,
    ) -> Option<Box<str>> {
        if page_origin.is_empty() || page_origin.len() > MAX_ORIGIN_BYTES {
            return None;
        }
        let expiry = now
            .checked_add(TOKEN_LIFETIME)
            .and_then(|expiry| expiry.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |expiry| expiry.as_secs());
        let mut token = Vec::with_capacity(HEADER_BYTES + page_origin.len() + MAC_BYTES);
        token.extend_from_slice(&expiry.to_be_bytes());
        token.push(u8::from(authorized && self.authorizes));
        token.extend_from_slice(page_origin.as_bytes());
        let mut mac = [0; MAC_BYTES];
        self.key.sign(&signed_message(&token), &mut mac);
        token.extend_from_slice(&mac);
        Some(URL_SAFE_NO_PAD.encode(token).into_boxed_str())
    }

    pub(super) fn verify(&self, token: &str, now: SystemTime) -> Option<SiteGrant> {
        let token = URL_SAFE_NO_PAD.decode(token).ok()?;
        let signed_len = token.len().checked_sub(MAC_BYTES)?;
        if !(HEADER_BYTES + 1..=HEADER_BYTES + MAX_ORIGIN_BYTES).contains(&signed_len) {
            return None;
        }
        let (signed, mac) = token.split_at(signed_len);
        self.key.verify(&signed_message(signed), mac).ok()?;
        let expiry = u64::from_be_bytes(signed[..8].try_into().ok()?);
        let now = now.duration_since(UNIX_EPOCH).ok()?.as_secs();
        if now >= expiry {
            return None;
        }
        Some(SiteGrant {
            authorized: self.authorizes && signed[8] == 1,
            origin: str::from_utf8(&signed[HEADER_BYTES..]).ok()?.into(),
        })
    }

    /// The grant of the request's site token, if it has a valid one.
    pub(super) fn grant<B>(&self, req: &Request<B>, now: SystemTime) -> Option<SiteGrant> {
        let query = req.uri().query()?;
        query
            .as_encoded_str()
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(name, _)| *name == SITE_TOKEN_PARAM)
            .and_then(|(_, token)| self.verify(token, now))
    }
}

fn signed_message(signed: &[u8]) -> Vec<u8> {
    [TOKEN_LABEL, signed].concat()
}

/// Lets the page a site token was minted for read its probe responses and their
/// timing. CORS preflights from that page are answered here; any other origin gets
/// no cross-origin access.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct SiteCorsLayer;

impl<S> Layer<S> for SiteCorsLayer {
    type Service = SiteCorsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SiteCorsService { inner }
    }
}

#[derive(Debug, Clone, ExtensionsRef)]
pub(super) struct SiteCorsService<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for SiteCorsService<S>
where
    B: Send + 'static,
    S: Service<Request<B>, Output = Response>,
{
    type Output = Response;
    type Error = S::Error;

    async fn serve(&self, req: Request<B>) -> Result<Self::Output, Self::Error> {
        let Some(page) = req
            .extensions()
            .get_ref::<SiteGrant>()
            .and_then(|grant| HeaderValue::from_str(&grant.origin).ok())
        else {
            return self.inner.serve(req).await;
        };
        let origin = req.headers().get(ORIGIN);
        if origin.is_some_and(|origin| *origin != page) {
            return self.inner.serve(req).await;
        }
        if origin.is_some()
            && req.method() == Method::OPTIONS
            && let Some(method) = req.headers().get(ACCESS_CONTROL_REQUEST_METHOD)
        {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::NO_CONTENT;
            let headers = response.headers_mut();
            headers.insert(ACCESS_CONTROL_ALLOW_METHODS, method.clone());
            if let Some(requested) = req.headers().get(ACCESS_CONTROL_REQUEST_HEADERS) {
                headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, requested.clone());
            }
            allow_page(&mut response, page);
            return Ok(response);
        }
        let cors = origin.is_some();
        let mut response = self.inner.serve(req).await?;
        if cors {
            allow_page(&mut response, page);
        } else {
            // A subresource request has no Origin: only its timing is shared.
            response
                .headers_mut()
                .insert(TIMING_ALLOW_ORIGIN.clone(), page);
        }
        Ok(response)
    }
}

fn allow_page(response: &mut Response, page: HeaderValue) {
    let headers = response.headers_mut();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, page.clone());
    headers.insert(TIMING_ALLOW_ORIGIN.clone(), page);
    headers.append(VARY, HeaderValue::from_static("Origin"));
}

#[cfg(test)]
mod tests;
