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

pub(super) const HEADERS: &[ValuesExercise] = &[
    decode!(Forwarded, |h| {
        display(&*h);
        sink((h.client_port(), h.client_ip(), h.client_proto()));
        sink((h.client_version(), h.client_socket_addr()));
        if let Some(authority) = h.client_host() {
            forwarded_authority(authority);
        }
        for element in h.iter() {
            forwarded_element(element);
        }
        forward_header(&h);
    }),
    decode!(Via, |h| {
        forward_header(&h);
    }),
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
    decode!(CFConnectingIp, |h| {
        forward_header(&h);
    }),
    decode!(TrueClientIp, |h| {
        forward_header(&h);
    }),
    decode!(XRealIp, |h| {
        forward_header(&h);
    }),
    decode!(ClientIp, |h| {
        forward_header(&h);
    }),
    decode!(XClientIp, |h| {
        forward_header(&h);
    }),
];
