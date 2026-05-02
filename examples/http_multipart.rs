//! An example to show how to accept `multipart/form-data` uploads using the
//! [`Multipart`] extractor.
//!
//! [`HttpServer`]: crate::http::server::HttpServer
//! [`Multipart`]: crate::http::service::web::extract::multipart::Multipart
//!
//! This example will create a server that listens on `127.0.0.1:62028`.
//!
//! # Run the example
//!
//! ```sh
//! RUST_LOG=trace cargo run --example http_multipart --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server starts and listens on `:62028`. Submit a multipart upload with
//! `curl`:
//!
//! ```sh
//! echo "hello rama" > /tmp/rama-upload.txt
//! curl -v -X POST http://127.0.0.1:62028/upload \
//!   -F "username=glen" \
//!   -F "attachment=@/tmp/rama-upload.txt;type=text/plain"
//! ```
//!
//! You should see a `200 OK` response containing a summary of the parts the
//! server received.
//!
//! Or open the page in a browser:
//!
//! ```sh
//! open http://127.0.0.1:62028
//! ```
//!
//! and use the upload form.

use rama::{
    Layer,
    http::{
        Response,
        layer::trace::TraceLayer,
        matcher::HttpMatcher,
        server::HttpServer,
        service::web::{
            WebService,
            extract::multipart::{Multipart, MultipartError},
            response::{Html, IntoResponse},
        },
    },
    rt::Executor,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

use std::time::Duration;

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

    graceful.spawn_task_fn(async move |guard| {
        let exec = Executor::graceful(guard);
        HttpServer::auto(exec)
            .listen(
                "127.0.0.1:62028",
                TraceLayer::new_for_http().layer(
                    WebService::default()
                        .with_get(
                            "/",
                            Html(
                                r##"<html>
                                        <body>
                                            <h1>Upload</h1>
                                            <form action="/upload" method="post" enctype="multipart/form-data">
                                                <label>Username: <input type="text" name="username"></label><br>
                                                <label>File: <input type="file" name="attachment"></label><br>
                                                <button type="submit">Send</button>
                                            </form>
                                        </body>
                                    </html>"##,
                            ),
                        )
                        .with_matcher(
                            HttpMatcher::method_post().and_path("/upload"),
                            handle_upload,
                        ),
                ),
            )
            .await
            .expect("failed to run service");
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn handle_upload(mut multipart: Multipart) -> Result<Response, MultipartError> {
    let mut summary = String::new();
    while let Some(field) = multipart.next_field().await? {
        let name = field.name().unwrap_or("<unnamed>").to_owned();
        let file_name = field.file_name().map(str::to_owned);
        let content_type = field.content_type().map(|m| m.essence_str().to_owned());

        let bytes = field.bytes().await?;

        tracing::info!(
            field.name = %name,
            field.file_name = ?file_name,
            field.content_type = ?content_type,
            field.size = bytes.len(),
            "received multipart field",
        );

        summary.push_str(&format!(
            "field={name} file_name={file_name:?} content_type={content_type:?} size={}\n",
            bytes.len()
        ));
    }
    Ok(summary.into_response())
}
