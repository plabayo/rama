use rama::http::Request;
use rama::http::core::h2::{
    RecvStream, client,
    server::{self, SendResponse},
};

use bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use std::{
    error::Error,
    time::{Duration, Instant},
};

const NUM_REQUESTS_TO_SEND: usize = 100_000;

// The actual server.
async fn server(addr: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;

    loop {
        if let Ok((socket, _peer_addr)) = listener.accept().await {
            tokio::spawn(async move {
                if let Err(e) = serve(socket).await {
                    println!("  -> err={:?}", e);
                }
            });
        }
    }
}

async fn serve(socket: TcpStream) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut connection = server::handshake(socket).await?;
    while let Some(result) = connection.accept().await {
        let (request, respond) = result?;
        tokio::spawn(async move {
            if let Err(e) = handle_request(request, respond).await {
                println!("error while handling request: {}", e);
            }
        });
    }
    Ok(())
}

async fn handle_request(
    mut request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let body = request.body_mut();
    while let Some(data) = body.data().await {
        let data = data?;
        let _ = body.flow_control().release_capacity(data.len());
    }
    let response = http::Response::new(());
    let mut send = respond.send_response(response, false)?;
    send.send_data(Bytes::from_static(b"pong"), true)?;

    Ok(())
}

// The benchmark
async fn send_requests(addr: &str) -> Result<(), Box<dyn Error>> {
    let tcp = loop {
        let Ok(tcp) = TcpStream::connect(addr).await else {
            continue;
        };
        break tcp;
    };
    let (client, h2) = client::handshake(tcp).await?;
    // Spawn a task to run the conn...
    tokio::spawn(async move {
        if let Err(e) = h2.await {
            println!("GOT ERR={:?}", e);
        }
    });

    let mut handles = Vec::with_capacity(NUM_REQUESTS_TO_SEND);
    for _i in 0..NUM_REQUESTS_TO_SEND {
        let mut client = client.clone();
        let task = tokio::spawn(async move {
            let request = Request::builder().body(()).unwrap();

            let instant = Instant::now();
            let (response, _) = client.send_request(request, true).unwrap();
            let response = response.await.unwrap();
            let mut body = response.into_body();
            while let Some(_chunk) = body.data().await {}
            instant.elapsed()
        });
        handles.push(task);
    }

    let instant = Instant::now();
    let mut result = Vec::with_capacity(NUM_REQUESTS_TO_SEND);
    for handle in handles {
        result.push(handle.await.unwrap());
    }
    let mut sum = Duration::new(0, 0);
    for r in result.iter() {
        sum = sum.checked_add(*r).unwrap();
    }

    println!("Overall: {}ms.", instant.elapsed().as_millis());
    println!("Fastest: {}ms", result.iter().min().unwrap().as_millis());
    println!("Slowest: {}ms", result.iter().max().unwrap().as_millis());
    println!(
        "Avg    : {}ms",
        sum.div_f64(NUM_REQUESTS_TO_SEND as f64).as_millis()
    );
    Ok(())
}

fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let addr = "127.0.0.1:63802";
    println!("H2 running in current-thread runtime at {addr}:");
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(server(addr)).unwrap();
    });

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(send_requests(addr)).unwrap();

    let addr = "127.0.0.1:63803";
    println!("H2 running in multi-thread runtime at {addr}:");
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(server(addr)).unwrap();
    });

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(send_requests(addr)).unwrap();
}
