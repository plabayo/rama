use rama::{
    Layer, Service,
    futures::{StreamExt as _, async_stream::stream_fn},
    http::{
        Request, Response,
        headers::{Accept, HeaderMapExt as _},
        mime,
        service::web::response::{Html, IntoResponse, Sse},
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
                return Ok(html_web_page());
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

fn html_web_page() -> Response {
    Html(
        r##"<!doctype html>
<html lang="en">
    <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Rama HTTP SSE Test</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 0; padding: 0; }
        main { min-height: 100vh; display: grid; justify-items: center; }
        ul { list-style: none; padding: 0; margin: 0; width: min(560px, 92vw); }
        li { padding: 10px 12px; border: 1px solid #ddd; border-radius: 10px; margin: 10px 0; }
        .hint { opacity: 0.7; font-size: 14px; margin-top: 10px; text-align: center; }
        label { display: inline-flex; gap: 8px; cursor: pointer; }
        input:checked + label { text-decoration: line-through; opacity: 0.6; }
    </style>
    </head>
    <body>
    <main>
        <div>
        <h1>TODO:</h1>
        <ul id="todos"></ul>
        <div class="hint" id="status">Connecting…</div>
        </div>
    </main>

    <script>
        let nextId = 0;
        const list = document.getElementById("todos");
        const statusEl = document.getElementById("status");

        const es = new EventSource("/sse");

        function addTodo(text) {
          const li = document.createElement("li");

          const id = "todo-" + nextId++;

          const checkbox = document.createElement("input");
          checkbox.type = "checkbox";
          checkbox.id = id;

          const label = document.createElement("label");
          label.htmlFor = id;
          label.textContent = text;

          li.appendChild(checkbox);
          li.appendChild(label);
          list.appendChild(li);
        }

        es.onopen = () => { statusEl.textContent = "Connected"; };
        es.onerror = () => { es.close(); statusEl.textContent = "Disconnected"; };

        es.onmessage = (ev) => {
            if (!ev.data) return;
            addTodo(ev.data);
        };
    </script>
    </body>
</html>
"##,
    )
    .into_response()
}
