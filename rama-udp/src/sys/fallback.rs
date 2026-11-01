use std::{
    io::{self, IoSliceMut},
    mem::MaybeUninit,
    ptr,
};

use rama_net::socket::core::SockAddr;

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
        // One datagram per call, as `BATCH_SIZE` says, into the first buffer.
        let buffer: &mut [u8] = &mut buffers[0];
        // SAFETY: the cast keeps the length and needs `MaybeUninit<u8>` laid out as `u8`,
        // which std guarantees; the new reference reborrows `buffer` exclusively. Every
        // initialized byte is a valid `MaybeUninit<u8>`, and socket2 documents that `recv_from`
        // writes no uninitialized byte, so `buffer` stays initialized afterwards.
        let buffer = unsafe { &mut *(ptr::from_mut::<[u8]>(buffer) as *mut [MaybeUninit<u8>]) };
        let (len, address) = socket.0.recv_from(buffer)?;
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
