use std::convert::Infallible;

use rama::{
    Service,
    error::BoxError,
    extensions::ExtensionsRef as _,
    io::BridgeIo,
    net::{
        apple::networkextension::{NwUdpSocket, UdpFlow, tproxy::TransparentProxyServiceContext},
        proxy::ProxyTarget,
    },
    service::service_fn,
    telemetry::tracing,
};

pub(super) async fn try_new_service(
    _: TransparentProxyServiceContext,
) -> Result<
    impl Service<BridgeIo<UdpFlow, NwUdpSocket>, Output = (), Error = Infallible>,
    BoxError,
> {
    Ok(service_fn(service))
}

/// UDP flow handler used by the transparent proxy engine.
///
/// The egress `NwUdpSocket` is pre-connected by Swift via `NWConnection`.
/// This service simply forwards datagrams between the intercepted flow and the
/// egress socket until either side closes.
async fn service(bridge: BridgeIo<UdpFlow, NwUdpSocket>) -> Result<(), Infallible> {
    let BridgeIo(mut ingress, mut egress) = bridge;

    let Some(ProxyTarget(target_addr)) = ingress.extensions().get_ref().cloned() else {
        tracing::error!("tproxy udp missing target endpoint, draining flow");
        while ingress.recv().await.is_some() {}
        return Ok(());
    };

    tracing::info!(
        remote = %target_addr,
        "tproxy udp forwarding started (pre-connected egress)"
    );

    let mut up_packets: u64 = 0;
    let mut down_packets: u64 = 0;
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;

    loop {
        tokio::select! {
            maybe_datagram = ingress.recv() => {
                let Some(datagram) = maybe_datagram else {
                    break;
                };
                if datagram.is_empty() {
                    continue;
                }

                up_packets += 1;
                up_bytes += datagram.len() as u64;
                egress.send(datagram);
            }
            maybe_datagram = egress.recv() => {
                let Some(datagram) = maybe_datagram else {
                    break;
                };
                if datagram.is_empty() {
                    continue;
                }

                down_packets += 1;
                down_bytes += datagram.len() as u64;
                ingress.send(datagram);
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
