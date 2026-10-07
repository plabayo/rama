//! Forwarded, Via and the proxy client IP headers.

use crate::{
    forwarded::{
        CFConnectingIp, ClientIp, Forwarded, TrueClientIp, Via, XClientIp, XForwardedFor,
        XForwardedHost, XForwardedProto, XRealIp,
    },
    fuzz::{
        ValuesExercise,
        parts::{forward_header, forwarded_authority, forwarded_element, net_host},
        support::{display, sink},
    },
};
use rama_net::forwarded::{ForwardedSelectionPolicy, ForwardedSide, NodeId};

pub(super) const HEADERS: &[ValuesExercise] = &[
    decode!(Forwarded, |h| {
        display(&*h);
        // The client element as either side of the selection policy picks it.
        for side in [ForwardedSide::Rightmost, ForwardedSide::Leftmost] {
            if let Some(client) = h.client(&ForwardedSelectionPolicy::new().with_side(side)) {
                let node = client.forwarded_for();
                sink((
                    node.and_then(NodeId::port),
                    node.and_then(NodeId::ip),
                    client.forwarded_proto(),
                ));
                sink((
                    client.forwarded_version(),
                    node.and_then(NodeId::socket_address),
                ));
                if let Some(authority) = client.forwarded_host() {
                    forwarded_authority(authority);
                }
            }
        }
        for element in h.iter() {
            forwarded_element(element);
        }
        forward_header(&h);
    }),
    decode!(Via, forward_header),
    decode!(XForwardedFor, |h| {
        for ip in h.iter() {
            display(ip);
        }
        forward_header(&h);
    }),
    decode!(XForwardedHost, |h| {
        net_host(h.host());
        sink(h.port());
        forwarded_authority(h.inner());
        forward_header(&h);
    }),
    decode!(XForwardedProto, |h| {
        let protocol = h.protocol();
        display(protocol);
        sink((protocol.as_str(), protocol.is_http(), protocol.is_secure()));
        sink(protocol.as_scheme());
        forward_header(&h);
    }),
    decode!(CFConnectingIp, forward_header),
    decode!(TrueClientIp, forward_header),
    decode!(XRealIp, forward_header),
    decode!(ClientIp, forward_header),
    decode!(XClientIp, forward_header),
];
