//! exposes context capability to configure http requests and connector via [`HttpProfile`]

// use rama_core::Context;
// use serde::{Deserialize, Serialize};

// use crate::{
//     HeaderName, Request, Version,
//     proto::{h1::Http1HeaderMap, h2::PseudoHeaderOrder},
// };

mod runtime_hints;
pub use runtime_hints::*;

mod types;
pub use types::*;

// pub static CUSTOM_HEADER_MARKER: HeaderName =
//     HeaderName::from_static("x-rama-custom-header-marker");

// #[derive(Debug, Clone, Deserialize, Serialize)]
// pub struct HttpProfile {
//     pub h1: Http1Profile,
//     pub h2: Http2Profile,
// }

// impl HttpProfile {
//     pub fn mod_http_request<Body, State>(&self, ctx: &mut Context<State>, req: &mut Request<Body>) {
//         self.emulate_http_settings(ctx, req);
//         match get_base_http_headers(&ctx, &req, profile) {
//             Some(base_http_headers) => {
//                 let original_http_header_order =
//                     get_original_http_header_order(&ctx, &req, self.input_header_order.as_ref())
//                         .context("collect original http header order")?;

//                 let original_headers = req.headers().clone();

//                 let preserve_ua_header = ctx
//                     .get::<UserAgent>()
//                     .map(|ua| ua.preserve_ua_header())
//                     .unwrap_or_default();

//                 let is_secure_request = match ctx.get::<RequestContext>() {
//                     Some(request_ctx) => request_ctx.protocol.is_secure(),
//                     None => req
//                         .uri()
//                         .scheme()
//                         .map(|s| Protocol::from(s.clone()).is_secure())
//                         .unwrap_or_default(),
//                 };

//                 original_requested_encodings = Some(
//                     parse_accept_encoding_headers(&original_headers, true)
//                         .map(|qv| qv.value)
//                         .collect::<Vec<_>>(),
//                 );

//                 let output_headers = merge_http_headers(
//                     base_http_headers,
//                     original_http_header_order,
//                     original_headers,
//                     preserve_ua_header,
//                     is_secure_request,
//                     requested_client_hints.as_deref(),
//                 );

//                 tracing::trace!(
//                     ua_kind = %profile.ua_kind,
//                     ua_version = ?profile.ua_version,
//                     platform = ?profile.platform,
//                     "user agent emulation: http settings and headers emulated"
//                 );
//                 let (output_headers, original_headers) = output_headers.into_parts();
//                 *req.headers_mut() = output_headers;
//                 req.extensions_mut().insert(original_headers);
//             }
//             None => {
//                 tracing::debug!(
//                     "user agent emulation: no http headers to emulate: no base http headers found"
//                 );
//             }
//         }
//     }

//     fn emulate_http_settings<Body, State>(
//         &self,
//         ctx: &mut Context<State>,
//         req: &mut Request<Body>,
//     ) {
//         match req.version() {
//             Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
//                 ctx.insert(self.h1.settings.clone());
//             }
//             Version::HTTP_2 => {
//                 req.extensions_mut().insert(PseudoHeaderOrder::from_iter(
//                     self.h2.settings.http_pseudo_headers.iter().flatten(),
//                 ));
//             }
//             Version::HTTP_3 => tracing::debug!(
//                 "UA emulation not yet supported for h3: not applying anything h3-specific"
//             ),
//             _ => tracing::debug!(
//                 version = ?req.version(),
//                 "UA emulation not supported for unknown http version: not applying anything version-specific",
//             ),
//         }
//     }

//     fn get_base_http_headers<Body, State>(
//         &self,
//         ctx: &Context<State>,
//         req: &Request<Body>,
//     ) -> Option<&Http1HeaderMap> {
//         let headers_profile = match req.version() {
//             Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => &self.h1.headers,
//             Version::HTTP_2 => &self.h2.headers,
//             _ => {
//                 tracing::debug!(
//                     version = ?req.version(),
//                     "UA emulation not supported for unknown http version: not applying anything version-specific",
//                 );
//                 return None;
//             }
//         };
//         Some(
//             match ctx.get::<UserAgent>().and_then(|ua| ua.request_initiator()) {
//                 Some(req_init) => {
//                     tracing::trace!(%req_init, "base http headers defined based on hint from UserAgent (overwrite)");
//                     get_base_http_headers_from_req_init(req_init, headers_profile)
//                 }
//                 // NOTE: the primitive checks below are pretty bad,
//                 // feel free to help improve. Just need to make sure it has good enough fallbacks,
//                 // and that they are cheap enough to check.
//                 None => match *req.method() {
//                     Method::GET => {
//                         let req_init = if headers_contains_partial_value(
//                             req.headers(),
//                             &X_REQUESTED_WITH,
//                             "XmlHttpRequest",
//                         ) {
//                             RequestInitiator::Xhr
//                         } else {
//                             RequestInitiator::Navigate
//                         };
//                         tracing::trace!(%req_init, "base http headers defined based on Get=NavigateOrXhr assumption");
//                         get_base_http_headers_from_req_init(req_init, headers_profile)
//                     }
//                     Method::POST => {
//                         let req_init = if headers_contains_partial_value(
//                             req.headers(),
//                             &X_REQUESTED_WITH,
//                             "XmlHttpRequest",
//                         ) {
//                             RequestInitiator::Xhr
//                         } else if headers_contains_partial_value(
//                             req.headers(),
//                             &CONTENT_TYPE,
//                             "form-",
//                         ) {
//                             RequestInitiator::Form
//                         } else {
//                             RequestInitiator::Fetch
//                         };
//                         tracing::trace!(%req_init, "base http headers defined based on Post=FormOrFetch assumption");
//                         get_base_http_headers_from_req_init(req_init, headers_profile)
//                     }
//                     _ => {
//                         let req_init = if headers_contains_partial_value(
//                             req.headers(),
//                             &X_REQUESTED_WITH,
//                             "XmlHttpRequest",
//                         ) {
//                             RequestInitiator::Xhr
//                         } else {
//                             RequestInitiator::Fetch
//                         };
//                         tracing::trace!(%req_init, "base http headers defined based on XhrOrFetch assumption");
//                         get_base_http_headers_from_req_init(req_init, headers_profile)
//                     }
//                 },
//             },
//         )
//     }
// }

// static X_REQUESTED_WITH: HeaderName = HeaderName::from_static("x-requested-with");

// fn headers_contains_partial_value(headers: &HeaderMap, name: &HeaderName, value: &str) -> bool {
//     headers
//         .get(name)
//         .and_then(|value| value.to_str().ok())
//         .map(|s| contains_ignore_ascii_case(s, value).is_some())
//         .unwrap_or_default()
// }

// fn get_base_http_headers_from_req_init(
//     req_init: RequestInitiator,
//     headers: &HttpHeadersProfile,
// ) -> &Http1HeaderMap {
//     match req_init {
//         RequestInitiator::Navigate => &headers.navigate,
//         RequestInitiator::Form => headers.form.as_ref().unwrap_or(&headers.navigate),
//         RequestInitiator::Xhr => headers
//             .xhr
//             .as_ref()
//             .or(headers.fetch.as_ref())
//             .unwrap_or(&headers.navigate),
//         RequestInitiator::Fetch => headers
//             .fetch
//             .as_ref()
//             .or(headers.xhr.as_ref())
//             .unwrap_or(&headers.navigate),
//     }
// }

// fn get_original_http_header_order<Body, State>(
//     ctx: &Context<State>,
//     req: &Request<Body>,
//     input_header_order: Option<&HeaderName>,
// ) -> Result<Option<OriginalHttp1Headers>, OpaqueError> {
//     if let Some(header) = input_header_order.and_then(|name| req.headers().get(name)) {
//         let s = header.to_str().context("interpret header as a utf-8 str")?;
//         let mut headers = OriginalHttp1Headers::with_capacity(s.matches(',').count());
//         for s in s.split(',') {
//             let s = s.trim();
//             if s.is_empty() {
//                 continue;
//             }
//             headers.push(s.parse().context("parse header part as h1 headern name")?);
//         }
//         return Ok(Some(headers));
//     }
//     Ok(ctx.get().or_else(|| req.extensions().get()).cloned())
// }

// fn merge_http_headers(
//     base_http_headers: &Http1HeaderMap,
//     original_http_header_order: Option<OriginalHttp1Headers>,
//     original_headers: HeaderMap,
//     preserve_ua_header: bool,
//     is_secure_request: bool,
//     requested_client_hints: Option<&[ClientHint]>,
// ) -> Http1HeaderMap {
//     let mut original_headers = HeaderMapValueRemover::from(original_headers);

//     let mut output_headers_a = Vec::new();
//     let mut output_headers_b = Vec::new();

//     let mut output_headers_ref = &mut output_headers_a;

//     let is_header_allowed = |header_name: &HeaderName| {
//         if let Some(hint) = ClientHint::match_header_name(header_name) {
//             is_secure_request
//                 && (hint.is_low_entropy()
//                     || requested_client_hints
//                         .map(|hints| hints.contains(&hint))
//                         .unwrap_or_default())
//         } else {
//             is_secure_request || !starts_with_ignore_ascii_case(header_name.as_str(), "sec-fetch")
//         }
//     };

//     // put all "base" headers in correct order, and with proper name casing
//     for (base_name, base_value) in base_http_headers.clone().into_iter() {
//         let base_header_name = base_name.header_name();
//         let original_value = original_headers.remove(base_header_name);
//         match base_header_name {
//             &ACCEPT | &ACCEPT_LANGUAGE => {
//                 let value = original_value.unwrap_or(base_value);
//                 output_headers_ref.push((base_name, value));
//             }
//             &REFERER | &COOKIE | &AUTHORIZATION | &HOST | &ORIGIN | &CONTENT_LENGTH
//             | &CONTENT_TYPE => {
//                 if let Some(value) = original_value {
//                     output_headers_ref.push((base_name, value));
//                 }
//             }
//             &USER_AGENT => {
//                 if preserve_ua_header {
//                     let value = original_value.unwrap_or(base_value);
//                     output_headers_ref.push((base_name, value));
//                 } else {
//                     output_headers_ref.push((base_name, base_value));
//                 }
//             }
//             _ => {
//                 if base_header_name == CUSTOM_HEADER_MARKER {
//                     output_headers_ref = &mut output_headers_b;
//                 } else if is_header_allowed(base_header_name) {
//                     output_headers_ref.push((base_name, base_value));
//                 }
//             }
//         }
//     }

//     // respect original header order of original headers where possible
//     for header_name in original_http_header_order.into_iter().flatten() {
//         if let Some(value) = original_headers.remove(header_name.header_name()) {
//             if is_header_allowed(header_name.header_name()) {
//                 output_headers_a.push((header_name, value));
//             }
//         }
//     }

//     let original_headers_iter = original_headers
//         .into_iter()
//         .filter(|(header_name, _)| is_header_allowed(header_name.header_name()));

//     Http1HeaderMap::from_iter(
//         output_headers_a
//             .into_iter()
//             .chain(original_headers_iter) // add all remaining original headers in any order within the right loc
//             .chain(output_headers_b),
//     )
// }
