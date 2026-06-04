use rama::{
    Layer, Service,
    futures::{StreamExt as _, async_stream::stream_fn},
    http::{
        Request, Response,
        headers::{Accept, HeaderMapExt as _},
        mime,
        protocols::html::*,
        service::web::response::{Css, IntoResponse, Script, Sse},
        sse::{
            Event,
            server::{KeepAlive, KeepAliveStream},
        },
    },
    layer::ConsumeErrLayer,
    service::service_fn,
};
use std::{convert::Infallible, time::Duration};

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    ConsumeErrLayer::trace_as_debug().into_layer(service_fn(async |req: Request| {
        Ok::<_, Infallible>(
            if req
                .headers()
                .typed_get::<Accept>()
                .map(|Accept(values)| values.iter().any(|item| item.value.subtype() == mime::HTML))
                .unwrap_or_default()
            {
                return Ok(render_html_page().into_response());
            } else {
                Sse::new(KeepAliveStream::new(
                    KeepAlive::new(),
                    stream_fn(move |mut yielder| async move {
                        for (index, item) in [
                            "Wake up slowly, enjoy morning light",
                            "Make loose plans, feel excited",
                            "Do one thing, celebrate it",
                            "Go to bed, feeling okay",
                        ]
                        .into_iter()
                        .enumerate()
                        {
                            tokio::time::sleep(Duration::from_millis((100 * (index + 1)) as u64))
                                .await;
                            yielder.yield_item(Event::new().with_data(item)).await;
                        }
                    })
                    .map(Ok::<_, Infallible>),
                ))
                .into_response()
            },
        )
    }))
}

/// CSS sidecar for the SSE HTML demo page. Separate response (mounted
/// at `/style/sse.css` by the router) so the defence-in-depth CSP can
/// keep `style-src 'self'` — blocking inline `<style>` — without
/// breaking the demo.
pub(in crate::cmd::serve::httptest) const STYLE_CSS: Css<&'static str> =
    Css(include_str!("sse.css"));

/// JS sidecar for the SSE HTML demo page. Wires the `EventSource`
/// subscription. Separate response (mounted at `/script/sse.js`) for
/// the same reason as [`STYLE_CSS`] — `script-src 'self'` blocks
/// inline `<script>` blocks.
pub(in crate::cmd::serve::httptest) const SCRIPT_JS: Script<&'static str> =
    Script(include_str!("sse.js"));

fn render_html_page() -> impl IntoHtml + IntoResponse {
    html!(
        lang = "en",
        head!(
            meta!(charset = "utf-8"),
            meta!(
                name = "viewport",
                content = "width=device-width,initial-scale=1"
            ),
            title!("Rama HTTP SSE Test"),
            link!(
                rel = "stylesheet",
                r#type = "text/css",
                href = "/style/sse.css"
            ),
        ),
        body!(
            main!(div!(
                h1!("TODO:"),
                ul!(id = "todos"),
                div!(class = "hint", id = "status", "Connecting…"),
            )),
            script!(src = "/script/sse.js"),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard against the bug audited 2026-05-18: the SSE
    /// HTML fallback page must reference its CSS and JS via
    /// `<link>` / `<script src>` because the surrounding service
    /// applies `style-src 'self'` and `script-src 'self'`.
    #[test]
    fn render_html_page_uses_external_assets() {
        let out = render_html_page().into_string();
        assert!(
            !out.contains("<style>") && !out.contains("<style "),
            "SSE page must not embed inline <style>; CSP blocks it",
        );
        assert!(
            !out.contains("<script>"),
            "SSE page must not embed inline <script>; CSP blocks it",
        );
        assert!(
            out.contains(r#"<link rel="stylesheet" type="text/css" href="/style/sse.css">"#),
            "SSE page must link to /style/sse.css",
        );
        assert!(
            out.contains(r#"<script src="/script/sse.js">"#),
            "SSE page must source /script/sse.js",
        );
    }

    #[test]
    fn render_html_page_contains_expected_dom_anchors() {
        let out = render_html_page().into_string();
        assert!(out.starts_with("<!DOCTYPE html><html lang=\"en\">"));
        assert!(out.contains("<title>Rama HTTP SSE Test</title>"));
        // The DOM IDs the JS bootstrap looks up.
        assert!(out.contains(r#"id="todos""#));
        assert!(out.contains(r#"id="status""#));
    }
}
