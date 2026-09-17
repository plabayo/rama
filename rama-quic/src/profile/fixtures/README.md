# Browser first-flight fixtures

Raw UDP payloads of the first two Initial datagrams each browser sent to
`www.cloudflare.com` over IPv6, captured with tshark 4.6.6 on macOS on 2026-09-16:

- `chrome-153-initial-*.hex`: Google Chrome 153.0.8010.48, fresh profile.
- `firefox-156-initial-*.hex`: Firefox 156.0, fresh profile, with
  `network.http.http3.version_negotiation.enabled` set.

Each file is one datagram as hex. The tests in `src/profile/tests.rs` read them back with
`profile::capture` and check the browser profiles against them.
