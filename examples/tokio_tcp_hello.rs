use rama::tcp::server::TcpListener;
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() {
    TcpListener::bind("127.0.0.1:9000")
        .await
        .expect("bind TCP Listener")
        .serve_fn(|_, mut stream| async move {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-type: text/plain\r\nContent-length: 14\r\n\r\nHello and bye!\r\n")
                .await
                .expect("write to stream");
            Ok::<_, std::convert::Infallible>(())
        })
        .await;
}
