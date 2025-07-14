//! An example to show how to create a minimal server that accepts form data for a request.
//! using the [`HttpServer`] and [`Executor`] from Rama.
//!
//! [`HttpServer`]: crate::http::server::HttpServer
//! [`Executor`]: crate::rt::Executor
//!
//! This example will create a server that listens on `127.0.0.1:62002`.
//!
//! # Run the example
//!
//! ```sh
//! RUST_LOG=trace cargo run --example http_form --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62002`. You can use `curl` to check if the server is running:
//!
//! ```sh
//! curl -X POST http://127.0.0.1:62002/form \
//!   -H "Content-Type: application/x-www-form-urlencoded" \
//!   -d "name=John&age=32"
//!
//! curl -v 'http://127.0.0.1:62002/form?name=John&age=32'
//! ```
//!
//! You should see in both cases a response with `HTTP/1.1 200 OK` and `John is 32 years old.`.
//!
//! Alternatively you can
//!
//! ```sh
//! open http://127.0.0.1:62002
//! ```
//!
//! and fill the form in the browser, you should see a response page after submitting the form,
//! stating your name and age.

use rama::Layer;
use rama::http::Response;
use rama::http::layer::trace::TraceLayer;
use rama::http::matcher::HttpMatcher;
use rama::http::service::web::response::{Html, IntoResponse};
use rama::http::service::web::{WebService, extract::Form};
use rama::telemetry::tracing::{self, level_filters::LevelFilter};
use rama::{http::server::HttpServer, rt::Executor};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Serialize, Deserialize, Debug)]
struct Payload {
    name: String,
    age: i32,
    html: Option<bool>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
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
                "127.0.0.1:62002",
                TraceLayer::new_for_http().
                    layer(
                        WebService::default()
                            .get(
                                "/",
                                Html(
                                    r##"<html>
                                            <body>
                                                <form action="/form" method="post">
                                                    <label for="name">Name:</label><br>
                                                    <input type="text" id="name" name="name"><br>
                                                    <label for="age">Age:</label><br>
                                                    <input type="number" id="age" name="age"><br><br>
                                                    <input type="hidden" id="html" name="html" value="true"><br>
                                                    <input type="submit" value="Submit">
                                                </form>
                                            </body>
                                        </html>"##,
                                ),
                            )
                            .on(HttpMatcher::method_get().or_method_post().and_path("/form"), send_form_data),
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

async fn send_form_data(Form(payload): Form<Payload>) -> Response {
    tracing::info!(
        payload.name = %payload.name,
        "send_form_data",
    );

    let name = payload.name;
    let age = payload.age;

    if payload.html.unwrap_or_default() {
        Html(format!(
            r##"<html>
                    <body>
                        <h1>Success</h1>
                        <p>Thank you for submitting the form {name}, {age} years old.</p>
                    </body>
                </html>"##
        ))
        .into_response()
    } else {
        format!("{name} is {age} years old.").into_response()
    }
}
