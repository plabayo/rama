use std::convert::Infallible;

use rama::{
    Service, extensions::ExtensionsRef as _, net::apple::networkextension::UdpFlow,
    service::service_fn, telemetry::tracing, udp::bind_udp_socket_with_connect_default_dns,
};

use crate::utils::resolve_target_from_extensions;

pub(super) fn new_service() -> impl Service<UdpFlow, Output = (), Error = Infallible> {
    service_fn(service)
}

/// UDP flow handler used by the transparent proxy engine.
///
/// This resolves the remote target, binds a local UDP socket, connects it to the upstream,
/// then forwards datagrams in both directions until either side closes or an error occurs.
async fn service(mut flow: UdpFlow) -> Result<(), Infallible> {
    let target = resolve_target_from_extensions(flow.extensions());

    let Some(target_addr) = target else {
        tracing::error!("tproxy udp missing target endpoint, draining flow");
        while flow.recv().await.is_some() {}
        return Ok(());
    };

    let socket = match bind_udp_socket_with_connect_default_dns(
        target_addr.clone(),
        Some(flow.extensions()),
    )
    .await
    {
        Ok(socket) => socket,
        Err(err) => {
            tracing::error!(error = %err, "tproxy udp bind failed w/ bind + connect to address: {target_addr}");
            while flow.recv().await.is_some() {}
            return Ok(());
        }
    };

    tracing::info!(
        remote = %target_addr,
        local_addr = ?socket.local_addr().ok(),
        peer_addr = ?socket.peer_addr().ok(),
        "tproxy udp forwarding started"
    );

    let mut up_packets: u64 = 0;
    let mut down_packets: u64 = 0;
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            maybe_datagram = flow.recv() => {
                let Some(datagram) = maybe_datagram else {
                    break;
                };
                if datagram.is_empty() {
                    continue;
                }

                up_packets += 1;
                up_bytes += datagram.len() as u64;

                if let Err(err) = socket.send(&datagram).await {
                    tracing::error!(error = %err, "tproxy udp upstream send failed");
                    break;
                }
            }
            recv_result = socket.recv(&mut buf) => {
                match recv_result {
                    Ok(0) => break,
                    Ok(n) => {
                        down_packets += 1;
                        down_bytes += n as u64;
                        flow.send(rama::bytes::Bytes::copy_from_slice(&buf[..n]));
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "tproxy udp upstream recv failed");
                        break;
                    }
                }
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
