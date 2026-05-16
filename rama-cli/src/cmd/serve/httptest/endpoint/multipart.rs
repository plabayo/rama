use rama::{
    Layer as _, Service,
    http::{
        Request, Response,
        layer::error_handling::ErrorHandlerLayer,
        service::web::{
            IntoEndpointService,
            extract::multipart::{Multipart, MultipartConfig},
            response::{Html, IntoResponse, Json, Result as ResponseResult},
        },
    },
    layer::add_extension::AddInputExtensionLayer,
    utils::octets::kib_u64,
};
use serde::Serialize;
use std::convert::Infallible;

const HTML_FORM: &str = r##"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>multipart upload</title></head>
<body>
<h1>multipart/form-data upload</h1>
<form action="/multipart" method="post" enctype="multipart/form-data">
    <p><label>name: <input type="text" name="username"></label></p>
    <p><label>file: <input type="file" name="attachment"></label></p>
    <button type="submit">submit</button>
</form>
</body>
</html>"##;

/// `GET /multipart` — serves a small HTML form for browser interaction.
pub(in crate::cmd::serve::httptest) async fn get_form() -> impl IntoResponse {
    Html(HTML_FORM)
}

#[derive(Serialize)]
pub(in crate::cmd::serve::httptest) struct PartSummary {
    name: Option<String>,
    filename: Option<String>,
    content_type: Option<String>,
    size: u64,
    /// Present only when the part is small and decodes as UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

#[derive(Serialize)]
pub(in crate::cmd::serve::httptest) struct MultipartReport {
    parts: Vec<PartSummary>,
}

const TEXT_ECHO_LIMIT: u64 = kib_u64(4);

/// Per-field cap of 256 KiB. The global body limit on this server is 1 MiB
/// (set by `BodyLimitLayer::symmetric` in `httptest/mod.rs`); a per-field cap
/// stops a single field from exhausting the entire request budget.
const PER_FIELD_LIMIT: u64 = kib_u64(256);

/// Build the `POST /multipart` service with the per-field cap installed as a
/// `MultipartConfig` request extension. Anything exceeding the cap returns
/// `413 Payload Too Large`.
pub(in crate::cmd::serve::httptest) fn post_service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    (
        AddInputExtensionLayer::new(
            MultipartConfig::new().with_default_field_limit(PER_FIELD_LIMIT),
        ),
        ErrorHandlerLayer::new(),
    )
        .into_layer(post_handler.into_endpoint_service())
}

async fn post_handler(mut multipart: Multipart) -> ResponseResult<Json<MultipartReport>> {
    let mut parts = Vec::new();
    while let Some(field) = multipart.next_field().await? {
        let name = field.name().map(str::to_owned);
        let filename = field.file_name().map(str::to_owned);
        // Preserve any parameters (e.g. `text/plain; charset=utf-8`) — the
        // earlier `essence_str` call dropped them.
        let content_type = field.content_type().map(|m| m.as_ref().to_owned());
        let bytes = field.bytes().await?;
        let size = bytes.len() as u64;
        let text = if size <= TEXT_ECHO_LIMIT {
            std::str::from_utf8(&bytes).ok().map(str::to_owned)
        } else {
            None
        };
        parts.push(PartSummary {
            name,
            filename,
            content_type,
            size,
            text,
        });
    }
    Ok(Json(MultipartReport { parts }))
}
