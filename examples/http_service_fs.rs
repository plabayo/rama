use rama::{
    http::{server::HttpServer, service::fs::ServeDir},
    rt::Executor,
    service::ServiceBuilder,
    tcp::server::TcpListener,
};

#[tokio::main]
async fn main() {
    let exec = Executor::default();

    let listener = TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("bind TCP Listener");

    // This will serve files in the current working dir
    let cwd = std::env::current_dir().expect("current working dir");
    println!("Serving files from: {:?}", cwd);
    let http_fs_server = HttpServer::auto(exec).service(ServeDir::new(cwd));

    // Serve the HTTP server over TCP,
    // ...once running you can go in browser for example to:
    println!("open: http://localhost:8080/test-files/index.html");
    listener
        .serve(ServiceBuilder::new().trace_err().service(http_fs_server))
        .await;
}
