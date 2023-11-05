use rama::{server::tcp::TcpListener, stream::AsyncWriteExt};

#[tokio::main]
async fn main() {
    TcpListener::bind("127.0.0.1:9000")
        .await
        .expect("bind TCP Listener")
        .serve_fn(|mut stream| async move {
            stream
                .write_all(b"Hello and bye!")
                .await
                .expect("write to stream");
            Ok::<_, std::convert::Infallible>(())
        })
        .await
        .expect("serve incoming TCP connections");
}
