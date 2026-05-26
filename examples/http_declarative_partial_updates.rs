//! Declarative Partial Updates — stream an HTML shell first, fill in
//! slow fragments out-of-order as each future completes.
//!
//! Based on: <https://developer.chrome.com/blog/declarative-partial-updates>
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_declarative_partial_updates --features=http-full
//! ```
//!
//! # Expected output
//!
//! Server listens on `:64805`. Open in a browser:
//!
//! ```sh
//! open http://127.0.0.1:64805
//! ```
//!
//! The 🦙 dashboard shell appears immediately with a "loading…" banner and
//! three spinning-llama skeletons declared `recs → herd → ping`. Fragments
//! stream back in the reverse order: `ping` (~500ms), `herd` (~2s),
//! `recs` (~4s) — each skeleton swaps out as its content lands; the banner
//! disappears once all three have arrived.
//!
//! The shell carries a small inline polyfill (`<script>` in `<head>`,
//! synchronous) that wires up the `<?marker …>` ↔ `<template for=…>` swap
//! via `MutationObserver`. We can't reuse GoogleChromeLabs'
//! `template-for-polyfill` for this — it explicitly batches body-level
//! template swaps until `DOMContentLoaded` fires, which only happens after
//! the streaming response closes, so every fragment would appear at once
//! at the end. Chrome 148+ ships native support behind
//! `chrome://flags/#enable-experimental-web-platform-features`; the inline
//! polyfill is harmless when native already swapped.
//!
//! The pipeline also layers in [`StreamCompressionLayer`] (so each
//! fragment chunk is compressed and flushed on its own, not held back
//! until the body ends) and [`AddRequiredResponseHeadersLayer`] (so the
//! response carries the usual server/date/request-id headers).
//!
//! [`StreamCompressionLayer`]: rama::http::layer::compression::stream::StreamCompressionLayer
//! [`AddRequiredResponseHeadersLayer`]: rama::http::layer::required_header::AddRequiredResponseHeadersLayer

#![expect(
    clippy::expect_used,
    reason = "example: panic-on-error is the standard demo pattern"
)]

use rama::{
    Layer,
    http::{
        Response,
        html::{
            IntoHtml, PreEscaped, body, div, h1, h2, head, html, li, marker, meta, p, script,
            section, span, style, title, ul,
        },
        layer::{
            compression::stream::StreamCompressionLayer,
            required_header::AddRequiredResponseHeadersLayer, trace::TraceLayer,
        },
        server::HttpServer,
        service::web::{
            Router,
            response::{IntoResponse, PartialUpdates},
        },
    },
    layer::ArcLayer,
    net::address::SocketAddress,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};
use std::time::Duration;

const POLYFILL: &str = "\
(()=>{\
  /* Feature-detect native declarative-partial-updates: if the marker is\
     consumed during fragment parsing, the firstChild of the parsed fragment\
     is null. When that's the case we skip our marker->template swap and\
     let the browser do it; we still run the mutation observer so the loaded\
     state attributes get set the same way for both code paths. */\
  let native=false;\
  try{\
    native=document.createRange()\
      .createContextualFragment('<?marker name=__dpu_t><template for=__dpu_t></template>')\
      .firstChild===null;\
  }catch{}\
  const findMarker=(name)=>{\
    const it=document.createNodeIterator(document,NodeFilter.SHOW_COMMENT);\
    let n;\
    while((n=it.nextNode())){\
      const d=n.data||'';\
      if(/^\\?marker\\b/.test(d)){\
        const m=d.match(/\\bname *= *\"?([^\"\\s]+)\"?/);\
        if(m&&m[1]===name)return n;\
      }\
    }\
    return null;\
  };\
  const swap=(t)=>{\
    if(native)return;\
    const name=t.getAttribute('for');\
    if(!name)return;\
    const m=findMarker(name);\
    if(!m)return;\
    m.replaceWith(t.content.cloneNode(true));\
    t.remove();\
  };\
  const markLoaded=(panel)=>{\
    if(panel.hasAttribute('data-dpu-loaded'))return;\
    panel.setAttribute('data-dpu-loaded','');\
    const ps=document.querySelectorAll('section.panel');\
    const ld=document.querySelectorAll('section.panel[data-dpu-loaded]');\
    if(ps.length>0&&ps.length===ld.length)\
      document.body.setAttribute('data-dpu-done','');\
  };\
  if(!native)document.querySelectorAll('template[for]').forEach(swap);\
  new MutationObserver(ms=>{\
    for(const m of ms){\
      if(!native)for(const n of m.addedNodes)\
        if(n.nodeType===1&&n.tagName==='TEMPLATE'&&n.hasAttribute('for'))swap(n);\
      if(m.target instanceof HTMLElement&&m.target.matches('section.panel'))\
        for(const n of m.addedNodes)\
          if(n.nodeType===1&&n.tagName!=='H2'&&!(n.classList&&n.classList.contains('spinner'))){\
            markLoaded(m.target);break;\
          }\
    }\
  }).observe(document,{childList:true,subtree:true});\
})();\
";

async fn dashboard() -> Response {
    let shell = html!(
        lang = "en",
        head!(
            meta!(charset = "utf-8"),
            title!("🦙 rama partial updates"),
            style!(PreEscaped(STYLE)),
            // Synchronous so the MutationObserver is armed before any
            // body content (and any `<template for=…>`) streams in.
            script!(PreEscaped(POLYFILL)),
        ),
        body!(
            div!(class = "banner", "loading dashboard… (this can take ~4s)"),
            h1!("🦙 llama dashboard"),
            p!(
                class = "lede",
                "Three async panels — declared slow → medium → fast — stream \
                 in reverse as each completes. Their skeletons swap out as \
                 their fragments arrive.",
            ),
            panel("Feed recommendations", "recs"),
            panel("Herd telemetry", "herd"),
            panel("Edge ping", "ping"),
        ),
    );

    PartialUpdates::new(shell)
        .fragment("recs", async {
            tokio::time::sleep(Duration::from_millis(4000)).await;
            recs()
        })
        .fragment("herd", async {
            tokio::time::sleep(Duration::from_millis(2000)).await;
            herd()
        })
        .fragment("ping", async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            ping()
        })
        .into_response()
}

fn panel(heading: &'static str, name: &'static str) -> impl IntoHtml {
    section!(
        class = "panel",
        h2!(heading),
        div!(class = "spinner", span!(class = "llama", "🦙"), " loading…",),
        marker(name),
    )
}

fn recs() -> impl IntoHtml {
    ul!(
        li!("Build a proxy in a weekend"),
        li!("Llama your TLS termination"),
        li!("Read the rama book over coffee"),
    )
}

fn herd() -> impl IntoHtml {
    p!(
        "alive: ",
        span!(class = "metric", "42"),
        " · egress: ",
        span!(class = "metric", "3.7 MB/s"),
    )
}

fn ping() -> impl IntoHtml {
    p!(class = "ok", "all edge nodes responding in <50ms")
}

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();
    let exec = Executor::graceful(graceful.guard());

    let listener = TcpListener::bind_address(SocketAddress::default_ipv4(64805), exec.clone())
        .await
        .expect("tcp port to be bound");
    let bind_address = listener.local_addr().expect("retrieve bind address");

    tracing::info!(
        network.local.address = %bind_address.ip(),
        network.local.port = %bind_address.port(),
        "http's tcp listener ready to serve",
    );
    tracing::info!("open http://{bind_address} in your browser");

    graceful.spawn_task(async move {
        let app = (
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::default(),
            StreamCompressionLayer::new(),
            ArcLayer::new(),
        )
            .into_layer(Router::new().with_get("/", dashboard));
        listener.serve(HttpServer::auto(exec).service(app)).await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

const STYLE: &str = "\
body { font-family: system-ui, sans-serif; max-width: 42rem; \
       margin: 0 auto; padding: 3rem 1rem 2rem; }\
.banner { position: fixed; top: 1rem; left: 50%; \
          transform: translateX(-50%); padding: 0.4rem 1rem; \
          background: #fff3a8; border: 1px solid #c9b400; \
          border-radius: 999px; font-size: 0.9em; z-index: 100; \
          transition: opacity 0.25s ease-out; }\
.lede { color: #555; }\
.panel { background: #f6f7f9; border-radius: 8px; padding: 1rem; \
         margin: 1rem 0; min-height: 4rem; }\
.spinner { display: flex; align-items: center; gap: 0.5em; color: #888; }\
.spinner .llama { display: inline-block; font-size: 1.6em; \
                  animation: spin 1.5s linear infinite; }\
@keyframes spin { from { transform: rotate(0); } \
                  to   { transform: rotate(360deg); } }\
.metric { font-family: monospace; font-weight: bold; }\
.ok { color: #096; }\
\
/* the inline polyfill sets these attributes as fragments swap in. */\
.panel[data-dpu-loaded] .spinner { display: none; }\
body[data-dpu-done] .banner { opacity: 0; pointer-events: none; }\
";
