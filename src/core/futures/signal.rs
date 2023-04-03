use tokio::signal;

pub async fn ctrl_c() {
    let _ = signal::ctrl_c().await;
}
