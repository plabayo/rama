use std::convert::Infallible;

use rama::{
    Service,
    http::{
        Request, Response,
        html::*,
        service::web::{IntoEndpointService, response::IntoResponse},
    },
    service::service_fn,
};

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    service_fn(async || Ok::<_, Infallible>(render_index().into_response())).into_endpoint_service()
}

fn render_index() -> impl IntoHtml + IntoResponse {
    html!(
        lang = "en",
        head!(
            meta!(charset = "UTF-8"),
            meta!(
                name = "viewport",
                content = "width=device-width, initial-scale=1.0"
            ),
            title!("ラマ | FP"),
            link!(
                rel = "icon",
                href = PreEscaped(
                    "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2210 0 100 100%22>\
                     <text y=%22.90em%22 font-size=%2290%22>🦙</text></svg>"
                ),
            ),
            meta!(name = "description", content = "rama http test service"),
            meta!(name = "robots", content = "none"),
            link!(rel = "canonical", href = "https://ramaproxy.org/"),
            meta!(property = "og:title", content = "ramaproxy.org"),
            meta!(property = "og:locale", content = "en_US"),
            meta!(property = "og:type", content = "website"),
            meta!(
                property = "og:description",
                content = "rama http test service"
            ),
            meta!(property = "og:url", content = "https://ramaproxy.org/"),
            meta!(property = "og:site_name", content = "ramaproxy.org"),
            meta!(
                property = "og:image",
                content =
                    "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg"
            ),
            style!(PreEscaped(INDEX_STYLE)),
        ),
        body!(main!(
            h1!(
                a!(href = "/", title = "rama http test's home page", "ラマ"),
                PreEscaped(" &nbsp; | &nbsp; "),
                "Rama Public Http(s) Tests",
            ),
            div!(id = "content", index_list()),
            br!(),
            div!(
                p!(
                    "See also our public echo service for a dedicated HTTP(S) / WS(S) echo service:"
                ),
                ul!(
                    li!(
                        a!(
                            href = "http://echo.ramaproxy.org:80",
                            "http://echo.ramaproxy.org"
                        ),
                        ": echo service, plain-text (incl. WS support)",
                    ),
                    li!(
                        a!(
                            href = "https://echo.ramaproxy.org:443",
                            "https://echo.ramaproxy.org"
                        ),
                        ": echo service, TLS (incl. WSS support)",
                    ),
                )
            ),
            br!(),
            div!(p!(
                "Contributions to improve existing tests to this listing or add new ones are welcome. \
                 For more information visit our public Git repository at: ",
                a!(
                    href = "https://github.com/plabayo/rama",
                    "https://github.com/plabayo/rama"
                ),
                ".",
            )),
            br!(),
            div!(
                class = "small",
                p!(
                    "Hosting for this service is sponsored by ",
                    a!(href = "https://fly.io", "fly.io"),
                    "."
                ),
            ),
            div!(
                id = "banner",
                a!(
                    href = "https://ramaproxy.org",
                    title = "rama proxy website",
                    img!(
                        src = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg",
                        alt = "rama banner",
                    ),
                ),
            ),
        )),
    )
}

fn index_list() -> impl IntoHtml {
    ul!(
        li!(
            a!(
                href = "/bytes?size=1048576&chunk=16384&delay_ms=0",
                "GET /bytes"
            ),
            " — query params: ",
            code!("size"),
            " (default 1 KiB, max 32 MiB), ",
            code!("chunk"),
            " (bytes per chunk, default 16 KiB, max 4 MiB), ",
            code!("delay_ms"),
            " (sleep between chunks, default 0, max 60 000 ms). \
             Streams exactly ",
            code!("size"),
            " zero bytes as ",
            code!("application/octet-stream"),
            " in chunks of ",
            code!("chunk"),
            " bytes with an optional inter-chunk delay. Useful for exercising backpressure, \
             timeout, and h1/h2 stream-framing behaviour deterministically.",
        ),
        li!(
            code!("POST /sink"),
            ": accepts an arbitrarily large upload, reads and discards the body, then returns ",
            code!(r#"{"bytes": <n>}"#),
            " with the total number of bytes received. Useful for stressing ingress upload paths \
             without echoing the body back.",
        ),
        li!(
            a!(href = "/method", "HTTP Method"),
            ": any HTTP method used will be echod back your way as ",
            code!("text/plain"),
            ".",
        ),
        li!(
            a!(href = "/request-compression", "Request Payload Compression"),
            ": your http compressed request payload will be echod back as response payload (decompressed) \
             ; note that we have an upper limit on how large the payload is allowed to be!",
        ),
        li!(
            a!(
                href = "/response-compression",
                "Response Payload Compression"
            ),
            ": response payload which is compressed (only when requested).",
        ),
        li!(
            a!(href = "/response-stream", "Response Payload Stream"),
            ":",
            ul!(
                li!("For ", code!("HTTP 1.0"), ": until ", code!("EOF"), ";"),
                li!("For ", code!("HTTP 1.1"), ": chunked encoding;"),
                li!("For ", code!("HTTP 2"), ": h2 data frames."),
            ),
        ),
        li!(
            a!(
                href = "/response-stream-compression",
                "Response Payload Stream With Compression"
            ),
            ": Version of the Response Stream test with compression supported.",
        ),
        li!(
            a!(href = "/sse", "Server-Side Events"),
            " (SSE) version of the Response Stream test.",
        ),
        li!(
            a!(href = "/multipart", "Multipart Form Upload"),
            ": ",
            code!("GET"),
            " serves a small HTML upload form; ",
            code!("POST multipart/form-data"),
            " returns a JSON summary of each part received.",
        ),
        li!(
            code!("POST /octet-stream"),
            ": echoes the raw binary request body back as ",
            code!("application/octet-stream"),
            ".",
        ),
    )
}

const INDEX_STYLE: &str = include_str!("index.css");

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the basic shape of the index page so neither the chrome nor the
    /// embedded link list silently regresses.
    #[test]
    fn render_index_contains_expected_structure() {
        let out = render_index().into_string();
        assert!(out.starts_with("<!DOCTYPE html><html lang=\"en\">"));
        assert!(out.contains("<title>ラマ | FP</title>"));
        assert!(out.contains("Rama Public Http(s) Tests"));
        assert!(out.contains(r#"<a href="/multipart">Multipart Form Upload</a>"#));
        assert!(out.contains(r#"<a href="/bytes?size=1048576&amp;chunk=16384&amp;delay_ms=0">"#));
    }
}
