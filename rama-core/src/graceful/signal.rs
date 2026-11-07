/// Completes on Ctrl+C, and on SIGTERM (unix) or Ctrl+Break, close and shutdown events
/// (windows).
pub async fn default_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let terminate = async {
            let mut signal =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            signal.recv().await;
            std::io::Result::Ok(())
        };
        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate => {}
        }
    }
    #[cfg(windows)]
    {
        let ctrl_break = async {
            let mut signal = tokio::signal::windows::ctrl_break()?;
            signal.recv().await;
            std::io::Result::Ok(())
        };
        let ctrl_close = async {
            let mut signal = tokio::signal::windows::ctrl_close()?;
            signal.recv().await;
            std::io::Result::Ok(())
        };
        let ctrl_shutdown = async {
            let mut signal = tokio::signal::windows::ctrl_shutdown()?;
            signal.recv().await;
            std::io::Result::Ok(())
        };
        tokio::select! {
            _ = ctrl_c => {}
            _ = ctrl_break => {}
            _ = ctrl_close => {}
            _ = ctrl_shutdown => {}
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _result = ctrl_c.await;
    }
}
