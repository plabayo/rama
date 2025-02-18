use tokio::net::TcpStream;
use tokio::time::timeout;
use std::sync::Arc;
use parking_lot::Mutex;
use std::collections::HashMap;
use super::role::ClientConfig;
use super::conn::Conn;
use super::request::Request;
use super::response::Response;
use crate::Error;

#[derive(Debug)]
pub(crate) struct Transport {
    config: ClientConfig,
    conns: Arc<Mutex<HashMap<String, Vec<PooledConn>>>>,
}

struct PooledConn {
    conn: Conn,
    last_used: std::time::Instant,
}

impl Transport {
    pub(crate) fn new(config: &ClientConfig) -> Self {
        Self {
            config: config.clone(),
            conns: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) async fn send_request(&self, req: Request) -> Result<Response, Error> {
        let host = req.url.host_str()
            .ok_or_else(|| Error {
                kind: ErrorKind::InvalidRequest,
                message: "missing host in URL".to_string(),
            })?;
        
        let conn = self.get_conn(host).await?;
        
        // Send request and get response
        let response = conn.send_request(req).await
            .map_err(|e| Error {
                kind: ErrorKind::Transport,
                message: e.to_string(),
            })?;

        Ok(response)
    }

    async fn get_conn(&self, host: &str) -> Result<Conn, Error> {
        // Try to get an existing connection from the pool
        if let Some(conn) = self.get_pooled_conn(host) {
            return Ok(conn);
        }

        // Create a new connection
        let stream = self.dial(host).await?;
        let conn = Conn::new(stream);

        Ok(conn)
    }

    fn get_pooled_conn(&self, host: &str) -> Option<Conn> {
        let mut conns = self.conns.lock();
        if let Some(pool) = conns.get_mut(host) {
            while let Some(pooled) = pool.pop() {
                if pooled.last_used.elapsed() < self.config.idle_timeout {
                    return Some(pooled.conn);
                }
            }
        }
        None
    }

    async fn dial(&self, host: &str) -> Result<TcpStream, Error> {
        timeout(self.config.dial_timeout, TcpStream::connect(host))
            .await
            .map_err(|_| Error {
                kind: ErrorKind::Timeout,
                message: "connection timed out".to_string(),
            })?
            .map_err(|e| Error {
                kind: ErrorKind::Transport,
                message: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use super::*;

    #[tokio::test]
    async fn test_transport_connection_pooling() {
        start_test_server().await;

        let config = ClientConfig {
            max_idle_conns: 2,
            idle_timeout: Duration::from_secs(1),
            max_conns_per_host: 5,
            dial_timeout: Duration::from_secs(5),
        };

        let transport = Transport::new(&config);

        // First connection should be created
        let conn1 = transport.get_conn("127.0.0.1:1344").await.unwrap();
        
        // Second connection should also be created
        let conn2 = transport.get_conn("127.0.0.1:1344").await.unwrap();
        
        // Wait for connections to be idle
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Third connection should reuse one of the idle connections
        let conn3 = transport.get_conn("127.0.0.1:1344").await.unwrap();
        
        // Wait for idle timeout
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Fourth connection should create new connection as previous ones timed out
        let conn4 = transport.get_conn("127.0.0.1:1344").await.unwrap();
    }

    #[tokio::test]
    async fn test_transport_dial_timeout() {
        let config = ClientConfig {
            max_idle_conns: 1,
            idle_timeout: Duration::from_secs(60),
            max_conns_per_host: 1,
            dial_timeout: Duration::from_millis(100),
        };

        let transport = Transport::new(&config);

        // Try to connect to a non-existent server
        let result = transport.get_conn("127.0.0.1:9999").await;
        assert!(result.is_err());
        
        match result.unwrap_err() {
            Error { kind: ErrorKind::Timeout, .. } => (),
            _ => panic!("Expected timeout error"),
        }
    }

    #[tokio::test]
    async fn test_transport_max_conns() {
        start_test_server().await;

        let config = ClientConfig {
            max_idle_conns: 1,
            idle_timeout: Duration::from_secs(60),
            max_conns_per_host: 2,
            dial_timeout: Duration::from_secs(5),
        };

        let transport = Transport::new(&config);

        // Create two connections (maximum allowed)
        let conn1 = transport.get_conn("127.0.0.1:1344").await.unwrap();
        let conn2 = transport.get_conn("127.0.0.1:1344").await.unwrap();

        // Third connection should fail
        let result = transport.get_conn("127.0.0.1:1344").await;
        assert!(result.is_err());
        
        match result.unwrap_err() {
            Error { kind: ErrorKind::Transport, .. } => (),
            _ => panic!("Expected transport error"),
        }
    }
}
