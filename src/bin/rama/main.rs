// use std::time::Duration;

// use rama::core::transport::tcp::server::{echo::echo, Listener};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let _ = tokio::join!(
    //     Listener::bind("0.0.0.0:8080")
    //         .graceful_ctrl_c()
    //         .timeout(Some(Duration::from_secs(5)))
    //         .serve(echo),
    //     Listener::bind("0.0.0.0:8443")
    //         .graceful_ctrl_c()
    //         .timeout(Some(Duration::from_secs(5)))
    //         .serve(echo),
    // );
    let listener_plain = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    let listener_secure = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
    loop {
        let (socket, _) = tokio::select! {
            result = listener_plain.accept() => result,
            result = listener_secure.accept() => result,
        }?;
        tokio::spawn(async move {
            let mut socket = socket;
            let (mut reader_half, mut writer_half) = socket.split();
            if let Err(err) = tokio::io::copy(&mut reader_half, &mut writer_half).await {
                eprintln!("failed to copy: {}", err);
            }
        });
    }
}
