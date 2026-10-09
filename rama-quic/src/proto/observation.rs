//! Bounded first-flight recording from authenticated packets.

use rama_core::{bytes::BytesMut, extensions::Extensions};
use rama_quic_proto::{
    ConnectionId,
    capture::{
        self, CaptureCompleteness, CaptureLimits, FirstFlight, ObservedFrame, PacketKind,
        QuicObservation,
    },
    frame::{self, Frame},
    packet::{Header, Packet},
    profile::PaddingPlacement,
};
use rama_tls::{SecureTransport, client::ClientHello};

use super::first_flight::{ClientHelloPeek, HelloAssembly, LIMIT};

#[derive(Debug)]
struct Datagram {
    size: usize,
    trailing: usize,
    coalesced: bool,
}

/// Allocated only for servers explicitly configured to retain observations.
#[derive(Debug)]
pub(crate) struct ServerObservation {
    limits: CaptureLimits,
    pub(crate) hello: HelloAssembly,
    value: QuicObservation,
    pending: Option<Datagram>,
    bytes: usize,
    frames: usize,
    fragments: usize,
    done: bool,
    published: bool,
    pub(crate) defer_completion: bool,
    parsed: Option<ClientHello>,
}

impl ServerObservation {
    pub(crate) fn new(limits: CaptureLimits, first: &[u8], rest: Option<&[u8]>) -> Self {
        let mut this = Self {
            limits,
            hello: HelloAssembly::default(),
            value: QuicObservation {
                connection_id: Vec::new(),
                attempt_id: Vec::new(),
                retry_parent: None,
                first_flight: None,
                transport_parameters: Vec::new(),
                client_hello_message: Vec::new(),
                completeness: CaptureCompleteness {
                    datagrams: true,
                    frames: true,
                    original_attempt: true,
                    ..CaptureCompleteness::default()
                },
            },
            pending: None,
            bytes: 0,
            frames: 0,
            fragments: 0,
            done: false,
            published: false,
            defer_completion: true,
            parsed: None,
        };
        this.begin_datagram(first, rest);
        this
    }

    pub(crate) fn identify(
        &mut self,
        local: ConnectionId,
        attempt: ConnectionId,
        original: ConnectionId,
        retried: bool,
    ) {
        self.value.connection_id = local.to_vec();
        self.value.attempt_id = attempt.to_vec();
        if retried {
            self.value.retry_parent = Some(original.to_vec());
            self.value.completeness.original_attempt = false;
        }
    }

    pub(crate) fn begin_datagram(&mut self, first: &[u8], rest: Option<&[u8]>) {
        self.pending = None;
        if self.done {
            return;
        }
        let size = first.len().saturating_add(rest.map_or(0, <[u8]>::len));
        let count = self
            .value
            .first_flight
            .as_ref()
            .map_or(0, |f| f.datagram_sizes.len());
        if count >= self.limits.datagrams || size > self.limits.bytes.saturating_sub(self.bytes) {
            self.value.completeness.datagrams = false;
            self.done = true;
            return;
        }
        // The split decoder owns separate buffers; this temporary copy is charged before allocation.
        let mut wire = Vec::with_capacity(size);
        wire.extend_from_slice(first);
        wire.extend_from_slice(rest.unwrap_or_default());
        if let Ok(observed) = capture::observe_with_limits(&wire, &self.limits) {
            self.pending = Some(Datagram {
                size,
                trailing: observed.trailing,
                coalesced: observed
                    .packets
                    .iter()
                    .any(|p| p.kind != PacketKind::Initial),
            });
        } else {
            self.value.completeness.datagrams = false;
            self.done = true;
        }
    }

    pub(crate) fn packet(&mut self, packet: &Packet, number: u64) {
        if self.done {
            return;
        }
        let Header::Initial(header) = &packet.header else {
            return;
        };
        let flight = self.value.first_flight.get_or_insert_with(|| FirstFlight {
            datagram_sizes: Vec::new(),
            trailing_bytes: Vec::new(),
            version: header.version.version(),
            dcid_len: header.dst_cid.len(),
            scid_len: header.src_cid.len(),
            token_len: header.token.len(),
            first_packet_number: number,
            packet_number_len: header.number.len() as u8,
            frames: Vec::new(),
            padding: PaddingPlacement::Frames,
            coalesced: false,
            parameters: Vec::new(),
            chosen_version: None,
            available_versions: Vec::new(),
            packet_numbers: Vec::new(),
            complete: false,
        });
        if let Some(datagram) = self.pending.take() {
            self.bytes += datagram.size;
            flight.datagram_sizes.push(datagram.size);
            flight.trailing_bytes.push(datagram.trailing);
            flight.coalesced |= datagram.coalesced;
            if datagram.trailing > 0 {
                flight.padding = PaddingPlacement::DatagramTail;
            }
        }
        if flight.packet_numbers.len() >= self.limits.packets {
            self.value.completeness.frames = false;
            self.done = true;
            return;
        }
        let duplicate = flight.packet_numbers.contains(&number);
        flight.packet_numbers.push(number);
        if duplicate {
            return;
        }
        let mut observed = Vec::new();
        let Ok(iter) = frame::Iter::new(BytesMut::from(&packet.payload[..]).freeze()) else {
            self.value.completeness.frames = false;
            self.done = true;
            return;
        };
        for item in iter {
            let Ok(item) = item else {
                self.value.completeness.frames = false;
                self.done = true;
                break;
            };
            if matches!(item, Frame::Padding)
                && let Some(ObservedFrame::Padding { len }) = observed.last_mut()
            {
                *len += 1;
                continue;
            }
            if self.frames >= self.limits.frames {
                self.value.completeness.frames = false;
                self.done = true;
                break;
            }
            self.frames += 1;
            observed.push(match item {
                Frame::Padding => ObservedFrame::Padding { len: 1 },
                Frame::Ping => ObservedFrame::Ping,
                Frame::Ack(_) => ObservedFrame::Ack,
                Frame::Crypto(crypto) => {
                    if self.fragments >= self.limits.crypto_fragments {
                        self.value.completeness.frames = false;
                        self.done = true;
                        break;
                    }
                    self.fragments += 1;
                    let end = crypto.offset.checked_add(crypto.data.len() as u64);
                    if end.is_none_or(|end| end > self.limits.client_hello_bytes.min(LIMIT) as u64)
                    {
                        self.value.completeness.frames = false;
                        self.done = true;
                    } else {
                        self.hello.take_in(crypto.offset, crypto.data.clone());
                    }
                    ObservedFrame::Crypto {
                        offset: crypto.offset,
                        len: crypto.data.len(),
                    }
                }
                other => ObservedFrame::Other {
                    ty: other.ty().as_u64(),
                },
            });
        }
        flight.frames.push(observed);
    }

    pub(crate) fn end_datagram(&mut self) {
        self.pending = None;
        if self.defer_completion || self.value.completeness.client_hello {
            return;
        }
        if let ClientHelloPeek::Complete(message) = self.hello.peek() {
            if message.message().len() <= self.limits.client_hello_bytes {
                self.value.client_hello_message = message.message().to_vec();
                self.value.completeness.client_hello = true;
                if let Ok(parameters) =
                    capture::transport_parameters_from_hello(message.client_hello(), &self.limits)
                {
                    if let Some(flight) = self.value.first_flight.as_mut() {
                        flight.parameters = parameters.iter().map(|p| p.id).collect();
                        if let Some(info) = capture::version_information(&parameters) {
                            flight.chosen_version = Some(info.chosen());
                            flight.available_versions = info.available().to_vec();
                        }
                        flight.complete = self.value.completeness.datagrams
                            && self.value.completeness.frames
                            && self.value.completeness.original_attempt;
                    }
                    self.value.transport_parameters = parameters;
                    self.value.completeness.transport_parameters = true;
                }
                self.parsed = Some(message.into_client_hello());
            }
            self.done = true;
        }
        if self.done {
            self.hello = HelloAssembly::default();
        }
    }

    pub(crate) fn publish(&mut self, extensions: &Extensions, initial: bool, closed: bool) {
        if self.published || (!initial && !self.done && !closed) {
            return;
        }
        if let Some(hello) = self.parsed.take() {
            extensions.insert(SecureTransport::with_client_hello(hello));
        }
        extensions.insert(self.value.clone());
        self.published = self.done || closed;
    }
}
