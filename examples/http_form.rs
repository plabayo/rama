//! An example to show how to create a minimal server that accepts form data for a request.
//! using the [`HttpServer`] and [`Executor`] from Rama.
//!
//! [`HttpServer`]: crate::http::server::HttpServer
//! [`Executor`]: crate::rt::Executor
//!
//! This example will create a server that listens on `127.0.0.1:8080`.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_form
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:8080`. You can use `curl` to check if the server is running:
//!
//! ```sh
//! curl -X POST -F 'name=John' -F 'age=32' http://127.0.0.1:8080/form
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and `John is 32 years old.`.

use rama::http::layer::trace::TraceLayer;
use rama::http::service::web::extract::Form;
use rama::http::service::web::WebService;
use rama::service::ServiceBuilder;
use rama::{http::server::HttpServer, rt::Executor};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Payload {
    name: String,
    age: i32,
}

#[tokio::main]
async fn main() {
    let exec = Executor::default();
    HttpServer::auto(exec)
        .listen(
            "127.0.0.1:8080",
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .service(WebService::default().post("/form", send_form_data)),
        )
        .await
        .expect("failed to run service");
}

async fn send_form_data(Form(payload): Form<Payload>) -> String {
    tracing::info!("{:?}", payload.name);

    let name = payload.name;
    let age = payload.age;

    format!("{} is {} years old.", name, age)
}
