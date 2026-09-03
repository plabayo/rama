use std::io::{self, IoSliceMut};

use rama_net::socket::core::{MaybeUninitSlice, SockAddr};

use super::{RecvMeta, SocketCapabilities, Transmit, UdpSockRef};

#[derive(Debug)]
pub(crate) struct UdpSocketState;

impl UdpSocketState {
    pub(crate) fn new(
        socket: UdpSockRef<'_>,
        _receive_original_destination: bool,
    ) -> io::Result<Self> {
        socket.0.set_nonblocking(true)?;
        Ok(Self)
    }

    pub(crate) fn try_send(
        &self,
        socket: &UdpSockRef<'_>,
        transmit: &Transmit<'_>,
    ) -> io::Result<()> {
        socket
            .0
            .send_to(transmit.contents, &SockAddr::from(transmit.destination))?;
        Ok(())
    }

    pub(crate) fn recv(
        &self,
        socket: &UdpSockRef<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> io::Result<usize> {
        // SAFETY: IoSliceMut and MaybeUninitSlice have the platform iovec layout.
        // The socket initializes only the bytes it reports as received.
        let buffers =
            unsafe { &mut *(buffers as *mut [IoSliceMut<'_>] as *mut [MaybeUninitSlice<'_>]) };
        let (len, _flags, address) = socket.0.recv_from_vectored(buffers)?;
        metadata[0] = RecvMeta {
            len,
            original_len: len,
            stride: len,
            addr: address.as_socket().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UDP peer address is not an IP socket",
                )
            })?,
            ecn: None,
            dst_ip: None,
            interface_index: None,
            original_destination: None,
            timestamp: None,
            truncated: false,
        };
        Ok(1)
    }

    pub(crate) fn max_gso_segments(&self) -> usize {
        1
    }

    pub(crate) fn gro_segments(&self) -> usize {
        1
    }

    pub(crate) fn may_fragment(&self) -> bool {
        true
    }

    pub(crate) fn capabilities(&self) -> SocketCapabilities {
        SocketCapabilities {
            send_ecn: false,
            receive_ecn: false,
            send_source_ip: false,
            receive_local_ip: false,
            receive_interface: false,
            receive_original_destination: false,
            receive_timestamp: false,
            receive_truncation: false,
        }
    }
}

pub(crate) const BATCH_SIZE: usize = 1;
