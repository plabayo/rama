use rama_core::extensions::Extension;
use rama_http_headers::ContentType;
use rama_http_types::header::{self, content_type::parse_essence};
use rama_utils::str::ends_with_ignore_ascii_case;

use crate::{request::Parts, service::web::extract::has_any_content_type};

/// Which `Content-Type` the JSON body extractors accept.
///
/// Without it, [`Json`](super::Json) is [`Self::Strict`] while
/// [`JsonArrayItems`](super::JsonArrayItems) and [`JsonLines`](super::JsonLines)
/// accept [`Self::Any`]. Insert it into the request extensions, for example with
/// an add-extension layer on a route, to set the policy for all three.
#[derive(Debug, Clone, Copy, Extension)]
#[extension(tags(http))]
#[non_exhaustive]
pub enum JsonContentTypePolicy {
    /// Accept any or no `Content-Type`.
    Any,
    /// Accept `application/json`, `application/*+json` and the newline-delimited
    /// JSON types `application/{x-ndjson, ndjson, jsonl, x-jsonlines, jsonlines}`.
    JsonFamily,
    /// Accept only the extractor's own type: `application/json` or
    /// `application/*+json` for JSON documents and arrays, and
    /// `application/x-ndjson` for JSON Lines.
    Strict,
}

/// The payload shape an extractor reads, which selects its [`JsonContentTypePolicy::Strict`] type.
#[derive(Debug, Clone, Copy)]
pub(super) enum JsonPayload {
    Document,
    Lines,
}

/// Unregistered types clients send for newline-delimited JSON, all `application/*`.
const JSON_LINES: [ContentType; 5] = [
    ContentType::ndjson(),
    ContentType::ndjson_unprefixed(),
    ContentType::jsonl(),
    ContentType::x_jsonlines(),
    ContentType::jsonlines(),
];

/// Whether the request's `Content-Type` is accepted by its policy, or `default` without one.
pub(super) fn accepts_json_content_type(
    parts: &Parts,
    payload: JsonPayload,
    default: JsonContentTypePolicy,
) -> bool {
    // Flow scoped: a route or layer choice for this request, not a connection fact.
    let policy = parts
        .extensions
        .get_ref::<JsonContentTypePolicy>()
        .copied()
        .unwrap_or(default);
    match (policy, payload) {
        (JsonContentTypePolicy::Any, _) => true,
        (JsonContentTypePolicy::Strict, JsonPayload::Lines) => {
            has_any_content_type(&parts.headers, &[ContentType::ndjson().mime()])
        }
        (JsonContentTypePolicy::Strict, JsonPayload::Document) => {
            application_subtype(parts).is_some_and(is_json_subtype)
        }
        (JsonContentTypePolicy::JsonFamily, _) => {
            application_subtype(parts).is_some_and(|subtype| {
                is_json_subtype(subtype)
                    || JSON_LINES
                        .iter()
                        .any(|lines| subtype.eq_ignore_ascii_case(lines.mime().subtype().as_str()))
            })
        }
    }
}

fn application_subtype(parts: &Parts) -> Option<&str> {
    let essence = parse_essence(parts.headers.get_all(header::CONTENT_TYPE))?;
    let (kind, subtype) = essence.split_once('/')?;
    kind.eq_ignore_ascii_case("application").then_some(subtype)
}

fn is_json_subtype(subtype: &str) -> bool {
    subtype.eq_ignore_ascii_case("json") || ends_with_ignore_ascii_case(subtype, "+json")
}

#[cfg(test)]
mod tests {
    use super::JsonContentTypePolicy;
    use crate::{
        Body, Request, Response, StatusCode, header,
        service::web::{
            extract::{
                FromRequest, Json, OptionalFromRequest,
                body::{JsonArrayItems, JsonLines},
            },
            response::IntoResponse,
        },
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Extractor {
        Json,
        JsonArrayItems,
        JsonLines,
    }

    /// What a `Content-Type` header value is, independent of any policy.
    #[derive(Debug, Clone, Copy)]
    enum Kind {
        Absent,
        Json,
        CanonicalLines,
        OtherLines,
        Unrelated,
    }

    const HEADERS: [(Option<&str>, Kind); 13] = [
        (None, Kind::Absent),
        (Some("application/json"), Kind::Json),
        (Some("application/json; charset=utf-8"), Kind::Json),
        (Some("Application/JSON"), Kind::Json),
        (Some("application/problem+json"), Kind::Json),
        (Some("application/x-ndjson"), Kind::CanonicalLines),
        (
            Some("Application/X-NDJSON; charset=utf-8"),
            Kind::CanonicalLines,
        ),
        (Some("application/ndjson"), Kind::OtherLines),
        (Some("application/jsonl"), Kind::OtherLines),
        (Some("application/x-jsonlines"), Kind::OtherLines),
        (Some("APPLICATION/JSONLINES"), Kind::OtherLines),
        (Some("text/plain"), Kind::Unrelated),
        (Some("application/octet-stream"), Kind::Unrelated),
    ];

    const POLICIES: [Option<JsonContentTypePolicy>; 4] = [
        None,
        Some(JsonContentTypePolicy::Any),
        Some(JsonContentTypePolicy::JsonFamily),
        Some(JsonContentTypePolicy::Strict),
    ];

    fn accepted(extractor: Extractor, policy: Option<JsonContentTypePolicy>, kind: Kind) -> bool {
        // Without the extension `Json` is strict and the streaming extractors accept anything.
        let policy = policy.unwrap_or(if extractor == Extractor::Json {
            JsonContentTypePolicy::Strict
        } else {
            JsonContentTypePolicy::Any
        });
        match (policy, kind) {
            (JsonContentTypePolicy::Any, _) => true,
            (_, Kind::Absent | Kind::Unrelated)
            | (JsonContentTypePolicy::Strict, Kind::OtherLines) => false,
            (JsonContentTypePolicy::JsonFamily, _) => true,
            (JsonContentTypePolicy::Strict, Kind::Json) => extractor != Extractor::JsonLines,
            (JsonContentTypePolicy::Strict, Kind::CanonicalLines) => {
                extractor == Extractor::JsonLines
            }
        }
    }

    fn request(policy: Option<JsonContentTypePolicy>, content_type: Option<&str>) -> Request {
        let mut builder = Request::builder();
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        if let Some(policy) = policy {
            builder = builder.extension(policy);
        }
        builder.body(Body::from("[1]")).unwrap()
    }

    /// `Ok(true)` when extracted, `Ok(false)` when absent, `Err(status)` when rejected.
    async fn extract(
        extractor: Extractor,
        req: Request,
        optional: bool,
    ) -> Result<bool, StatusCode> {
        let status = |rejection: Response| rejection.status();
        match (extractor, optional) {
            (Extractor::Json, false) => <Json<serde_json::Value> as FromRequest>::from_request(req)
                .await
                .map(|_| true)
                .map_err(|r| status(r.into_response())),
            (Extractor::Json, true) => {
                <Json<serde_json::Value> as OptionalFromRequest>::from_request(req)
                    .await
                    .map(|value| value.is_some())
                    .map_err(|r| status(r.into_response()))
            }
            (Extractor::JsonArrayItems, false) => {
                <JsonArrayItems<u8> as FromRequest>::from_request(req)
                    .await
                    .map(|_| true)
                    .map_err(|r| status(r.into_response()))
            }
            (Extractor::JsonArrayItems, true) => {
                <JsonArrayItems<u8> as OptionalFromRequest>::from_request(req)
                    .await
                    .map(|value| value.is_some())
                    .map_err(|r| status(r.into_response()))
            }
            (Extractor::JsonLines, false) => <JsonLines<u8> as FromRequest>::from_request(req)
                .await
                .map(|_| true)
                .map_err(|r| status(r.into_response())),
            (Extractor::JsonLines, true) => {
                <JsonLines<u8> as OptionalFromRequest>::from_request(req)
                    .await
                    .map(|value| value.is_some())
                    .map_err(|r| status(r.into_response()))
            }
        }
    }

    #[tokio::test]
    async fn content_type_policy_matrix() {
        for extractor in [
            Extractor::Json,
            Extractor::JsonArrayItems,
            Extractor::JsonLines,
        ] {
            for policy in POLICIES {
                for (content_type, kind) in HEADERS {
                    let accept = accepted(extractor, policy, kind);
                    let case = format!("{extractor:?} {policy:?} {content_type:?}");

                    let required = extract(extractor, request(policy, content_type), false).await;
                    assert_eq!(
                        required,
                        if accept {
                            Ok(true)
                        } else {
                            Err(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                        },
                        "{case}"
                    );

                    // The optional form is absent without a header, whatever the policy.
                    let optional = extract(extractor, request(policy, content_type), true).await;
                    let expected = match kind {
                        Kind::Absent => Ok(false),
                        _ if accept => Ok(true),
                        _ => Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
                    };
                    assert_eq!(optional, expected, "optional {case}");
                }
            }
        }
    }
}
