use std::convert::Infallible;

use rama::{
    Service,
    error::BoxError,
    extensions::ExtensionsRef as _,
    net::{
        apple::networkextension::{Datagram, UdpFlow, tproxy::TransparentProxyServiceContext},
        proxy::ProxyTarget,
    },
    service::service_fn,
    telemetry::tracing,
};
use tokio::net::UdpSocket;

pub(super) async fn try_new_service(
    _: TransparentProxyServiceContext,
) -> Result<impl Service<UdpFlow, Output = (), Error = Infallible>, BoxError> {
    Ok(service_fn(service))
}

/// UDP flow handler used by the transparent proxy engine.
///
/// The engine hands the service the ingress flow only; egress is the
/// service's responsibility. This example opens one [`UdpSocket`] per
/// flow connected to the originating app's target peer, and pumps
/// datagrams between ingress and egress until either side goes quiet.
///
/// Real deployments may pool sockets across flows and use `send_to` /
/// `recv_from` to dispatch by per-datagram peer.
async fn service(mut ingress: UdpFlow) -> Result<(), Infallible> {
    let Some(ProxyTarget(target_addr)) = ingress.extensions().get_ref().cloned() else {
        tracing::error!("tproxy udp missing target endpoint, draining flow");
        while ingress.recv().await.is_some() {}
        return Ok(());
    };

    let egress = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(%err, "tproxy udp failed to bind egress socket");
            while ingress.recv().await.is_some() {}
            return Ok(());
        }
    };
    if let Err(err) = egress.connect(target_addr.to_string()).await {
        tracing::error!(%err, remote = %target_addr, "tproxy udp failed to connect egress socket");
        while ingress.recv().await.is_some() {}
        return Ok(());
    }
    let egress_peer = match egress.peer_addr() {
        Ok(addr) => addr,
        Err(err) => {
            tracing::error!(%err, "tproxy udp failed to read egress peer address");
            while ingress.recv().await.is_some() {}
            return Ok(());
        }
    };

    tracing::info!(remote = %target_addr, peer = %egress_peer, "tproxy udp forwarding started");

    let mut up_packets: u64 = 0;
    let mut down_packets: u64 = 0;
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        tokio::select! {
            maybe_datagram = ingress.recv() => {
                let Some(datagram) = maybe_datagram else { break };
                up_packets += 1;
                up_bytes += datagram.payload.len() as u64;
                if let Err(err) = egress.send(&datagram.payload).await {
                    tracing::warn!(%err, "tproxy udp egress send failed");
                    break;
                }
            }
            recv = egress.recv(&mut buf) => {
                let n = match recv {
                    Ok(n) => n,
                    Err(err) => {
                        tracing::warn!(%err, "tproxy udp egress recv failed");
                        break;
                    }
                };
                down_packets += 1;
                down_bytes += n as u64;
                let payload = rama::bytes::Bytes::copy_from_slice(&buf[..n]);
                ingress.send(Datagram::new(payload, egress_peer));
            }
        }
    }

    tracing::info!(
        up_packets,
        up_bytes,
        down_packets,
        down_bytes,
        "tproxy udp forwarding done"
    );

    Ok(())
}
