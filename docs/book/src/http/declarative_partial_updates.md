# Declarative Partial Updates

<div class="book-article-intro">
    <div>
        Declarative Partial Updates let a server stream an HTML "shell" first
        and then fill in slow fragments out-of-order — in the same response —
        as each fragment becomes ready. The page lays out instantly; each
        panel pops in when its data arrives.
        <p>— <a href="https://developer.chrome.com/blog/declarative-partial-updates">developer.chrome.com</a></p>
    </div>
</div>

## Description

This is **not** SSE and **not** a new protocol. It's a plain `text/html`
streaming response, with two pieces the browser parser knows how to interpret
incrementally:

- `<?marker name="x">` processing instructions in the shell mark insertion
  points.
- `<template for="x">…</template>` blocks emitted later in the same response
  carry the rendered fragment; the parser swaps each template's contents into
  the matching marker as it appears.

The wire is just HTTP/1.1 chunked transfer (or HTTP/2 DATA frames):

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked

  -- chunk 1: the shell with <?marker …> placeholders, flushed immediately
  -- chunk 2: <template for="ping">…</template>   (200ms later)
  -- chunk 3: <template for="herd">…</template>   (900ms later)
  -- chunk 4: <template for="recs">…</template>   (1500ms later)
```

Native support shipped in Chrome 148+ behind
`chrome://flags/#enable-experimental-web-platform-features`. Since that
flag is rarely on, the example ships a tiny inline polyfill in the shell
(synchronous, in `<head>`) that scans for `<?marker …>` comment nodes and
applies `<template for=…>` blocks via `MutationObserver` as they stream
in. (The GoogleChromeLabs `template-for-polyfill` exists, but it batches
body-level swaps until `DOMContentLoaded`, which only fires after the
streaming body completes — fragments would all appear at once at the end.)

## Rama Support

> 📚 Rust Docs: <https://ramaproxy.org/docs/rama/http/service/web/response/struct.PartialUpdates.html>

Enable the `http` feature and the `html` feature (or even better `http-full` to cover it all),
then use `PartialUpdates` together with the `marker()` helper from `rama::http::html`:

```rust,ignore
use rama::http::html::*;
use rama::http::service::web::response::PartialUpdates;
use rama::http::Response;
use std::time::Duration;

async fn dashboard() -> Response {
    let shell = html!(
        head!(title!("dashboard")),
        body!(
            section!(marker("ping")),
            section!(marker("herd")),
            section!(marker("recs")),
        ),
    );

    PartialUpdates::new(shell)
        .fragment("recs", async {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            ul!(li!("rec 1"), li!("rec 2"))
        })
        .fragment("herd", async {
            tokio::time::sleep(Duration::from_millis(900)).await;
            p!("42 alive")
        })
        .fragment("ping", async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            p!("ok")
        })
        .into_response()
}
```

Fragments are raced via `FuturesUnordered` and each completion flushes its
own `<template for=…>` body chunk — so the browser sees fragments arrive in
*completion order*, not declaration order.

### Example

[`http_declarative_partial_updates.rs`](https://github.com/plabayo/rama/blob/main/examples/http_declarative_partial_updates.rs)
serves a llama-themed dashboard with three slow panels and demonstrates
the UA-driven CDN polyfill injection for non-Chrome-148 browsers.

## Relation to SSE

[Server-Sent Events](./sse.md) push *typed events* on `text/event-stream`
and are consumed by JS via `EventSource`. Declarative partial updates push
*HTML fragments* on `text/html` and are consumed by the browser parser
directly — no JS needed (on Chrome 148+). Use SSE for live data streams
that the page renders; use partial updates for the first page render itself
when some panels are slower than others.
