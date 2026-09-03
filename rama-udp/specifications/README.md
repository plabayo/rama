# UDP specifications

Official RFC Editor texts used by `rama-udp`:

- [`rfc768.txt`](rfc768.txt): UDP datagrams (`packet`, `packet_socket`).
- [`rfc3168.txt`](rfc3168.txt) and [`rfc8311.txt`](rfc8311.txt): Explicit
  Congestion Notification (ECN) codepoints and ECT(1) experimentation
  (`rama-net::ip`, `meta`, `packet`, `sys`).
- [`rfc8085.txt`](rfc8085.txt): UDP usage requirements (`packet`, `service`).

RFC 4301 and RFC 6040 update tunnel handling; RFC 9768 updates TCP feedback.
RFC 9868 UDP Options are also outside this raw datagram layer.
