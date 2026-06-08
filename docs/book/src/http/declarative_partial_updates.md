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
`chrome://flags/#enable-experimental-web-platform-features`. Other browsers
need the [`template-for-polyfill`][polyfill] (the example loads the latest
from `unpkg.com/template-for-polyfill`).

> **Polyfill caveats** (native Chrome 148+ has none). The polyfill defers a
> swap while either the `<template>`, its `<?start>`, or its `<?end>` has no
> `nextElementSibling`, so `PartialUpdates` appends `\n<wbr>` after each
> fragment chunk — the trailing `<wbr>` gives every template an element
> sibling at its own arrival, mirroring the spirit of Google's
> [photo-album demo][demo]. Markers also support the **range form**
> `<?start name="x">…<?end>` ([`start`] / [`end`]): the skeleton between
> is replaced wholesale on swap, so no CSS gymnastics to hide loading
> chrome — drop a `<wbr>` (or any element) right after `<?end>` though, so
> it isn't last-sibling either. See Google's [explainer][exp] for the spec.

[polyfill]: https://github.com/GoogleChromeLabs/template-for-polyfill
[demo]: https://github.com/GoogleChromeLabs/web-perf-demos/blob/main/patching-demos/server.js
[`start`]: https://ramaproxy.org/docs/rama/http/protocols/html/fn.start.html
[`end`]: https://ramaproxy.org/docs/rama/http/protocols/html/fn.end.html
[exp]: https://github.com/WICG/declarative-partial-updates

## Rama Support

> 📚 Rust Docs: <https://ramaproxy.org/docs/rama/http/service/web/response/struct.PartialUpdates.html>

Enable the `http` feature and the `html` feature (or even better `http-full` to cover it all),
then use `PartialUpdates` together with the `marker()` helper from `rama::http::protocols::html`.

### Example

[`http_declarative_partial_updates.rs`](https://github.com/plabayo/rama/blob/main/examples/http_declarative_partial_updates.rs)
serves a llama-themed dashboard with three slow panels, fragments
streaming in completion order, and the unpkg-hosted polyfill in the
shell `<head>` so the swap works on browsers without native support.
Pass `?polyfill=false` to skip the polyfill (useful for testing native
Chrome 148+ behind the experimental flag, or measuring the baseline
shell).

## Relation to SSE

[Server-Sent Events](./sse.md) push *typed events* on `text/event-stream`
and are consumed by JS via `EventSource`. Declarative partial updates push
*HTML fragments* on `text/html` and are consumed by the browser parser
directly — no JS needed (on Chrome 148+). Use SSE for live data streams
that the page renders; use partial updates for the first page render itself
when some panels are slower than others.
