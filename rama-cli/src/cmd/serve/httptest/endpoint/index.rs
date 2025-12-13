use std::convert::Infallible;

use rama::{
    Service,
    http::{
        Request, Response,
        service::web::{StaticService, response::Html},
    },
};

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    StaticService::new(Html(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">

            <title>ラマ | FP</title>

            <link rel="icon"
                href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%2210 0 100 100%22><text y=%22.90em%22 font-size=%2290%22>🦙</text></svg>">

            <meta name="description" content="rama http test service">
            <meta name="robots" content="none">

            <link rel="canonical" href="https://ramaproxy.org/">

            <meta property="og:title" content="ramaproxy.org" />
            <meta property="og:locale" content="en_US" />
            <meta property="og:type" content="website">
            <meta property="og:description" content="rama http test service" />
            <meta property="og:url" content="https://ramaproxy.org/" />
            <meta property="og:site_name" content="ramaproxy.org" />
            <meta property="og:image" content="https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg">

            <style>
            *,
            *::before,
            *::after {
                box-sizing: border-box;
            }

            * {
                margin: 0;
            }

            body {
                line-height: 1.5;
                -webkit-font-smoothing: antialiased;
            }

            img,
            picture,
            video,
            canvas,
            svg {
                display: block;
                max-width: 100%;
            }

            input,
            button,
            textarea,
            select {
                font: inherit;
            }

            p,
            h1,
            h2,
            h3,
            h4,
            h5,
            h6 {
                overflow-wrap: break-word;
            }

            h1 a {
                text-decoration: none;
                font-weight: bold;
                color: darkblue;
            }

            #root,
            #__next {
                isolation: isolate;
            }

            main {
                max-width: 800px;
                margin: 0 auto;
                padding: 0 15px;
            }

            main h1 {
                margin-bottom: 20px;
            }

            .small {
                font-size: 0.8em;
                color: darkgrey;
            }
            </style>
        </head>
        <body>
            <main>
                <h1>
                    <a href="/" title="rama http test's home page">ラマ</a>
                    &nbsp;
                    |
                    &nbsp;
                    Rama Public Http(s) Tests
                </h1>
                <div id="content">
                <ul>
                    <li>
                        <a href="/method">HTTP Method</a>:
                        any HTTP method used will be echod back your way as <code>text/plain</code>.
                    </li>
                    <li>
                        <a href="/request-compression">Request Payload Compression</a>:
                        your http compressed request payload will be echod back as response payload (decompressed)
                        ; note that we have an upper limit on how large the payload is allowed to be!
                    </li>
                    <li>
                        <a href="/response-compression">Response Payload Compression</a>:
                        response payload which is compressed (only when requested)</a>.
                    </li>
                    <li>
                        <a href="/response-stream">Response Payload Stream</a>:
                        <ul>
                            <li>For <code>HTTP 1.0</code>: until <code>EOF</code>;</li>
                            <li>For <code>HTTP 1.1</code>: chunked encoding;</li>
                            <li>For <code>HTTP 2</code>: h2 data frames.</li>
                        </ul>
                    </li>
                    <li>
                        <a href="/response-stream-compression">Response Payload Stream With Compression</a>:
                        Version of the Response Stream test with compression supported.
                    </li>
                    <li>
                        <a href="/sse">Server-Side Events</a> (SSE) version of the Response Stream test.
                    </li>
                </ul>
                </div>
                <br>
                <div>
                    <p>
                        See also our public echo service for a dedicated HTTP(S) / WS(S) echo service:
                    </p>
                    <ul>
                        <li><a href="http://echo.ramaproxy.org:80">http://echo.ramaproxy.org</a>: echo service, plain-text (incl. WS support)</li>
                        <li><a href="https://echo.ramaproxy.org:443">https://echo.ramaproxy.org</a>: echo service, TLS (incl. WSS support)</li>
                    </ul>
                </div>
                <br>
                <div>
                    <p>
                        Contributions to improve existing tests to this listing or add new ones are welcome.
                        For more information visit our public Git repository at:
                        <a href="https://github.com/plabayo/rama">https://github.com/plabayo/rama</a>.
                    </p>
                </div>
                <br>
                <div class="small">
                    <p>
                        Hosting for this service is sponsored by
                        <a href="https://fly.io">fly.io</a>.
                    </p>
                </div>
                <div id="banner">
                    <a href="https://ramaproxy.org" title="rama proxy website">
                        <img src="https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_banner.jpeg" alt="rama banner" />
                    </a>
                </div>
            </main>
        </body>
        </html>
    "#,
    ))
}
