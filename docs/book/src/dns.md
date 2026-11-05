# DNS

> The Domain Name System (DNS) is a hierarchical and distributed name service
> that provides a naming system for computers, services, and other resources
> on the Internet or other Internet Protocol (IP) networks.
> 
> It associates various information with domain names (identification strings)
> assigned to each of the associated entities. Most prominently,
> it translates readily memorized domain names to the numerical IP addresses
> needed for locating and identifying computer services and devices with
> the underlying network protocols. The Domain Name System
> has been an essential component of the functionality of the Internet since 1985.
>
> Source: <https://en.wikipedia.org/wiki/Domain_Name_System>

Dns is essential to most of Rama, as it is what:

- Translates domains into IP addresses, allowing the ability to filter IP addresses,
  and establish connections to such addresses;
- Looks up meta information associated with a domain such as TXT data.

See [rama-dns](https://ramaproxy.org/docs/rama/dns/index.html) for more information.
It is available as `rama::dns` with the `dns` feature.

## Resolvers

All resolvers implement the `DnsResolver` trait, which looks up A, AAAA, TXT, CNAME,
SVCB and HTTPS records. The resolvers in `rama::dns::client` are:

- `NativeDnsResolver`: an alias for the platform resolver: `AppleDnsResolver` (`dns_sd`)
  on Apple targets, `WindowsDnsResolver` (`DnsQueryEx`) on Windows, `LinuxDnsResolver`
  on Linux (systemd-resolved when available, otherwise libc), and `TokioDnsResolver` elsewhere.
  Linux CNAME, TXT, SVCB and HTTPS lookups through libc require glibc.
- `TokioDnsResolver`: portable, backed by `getaddrinfo`. It only resolves A and AAAA
  records and returns an error for CNAME, TXT, SVCB and HTTPS lookups.
- `HickoryDnsResolver`: a wire-level resolver using Hickory DNS, behind the `dns-hickory` feature.
  Use it when you need exact TXT octets on Windows or a resolver configuration independent
  of the host.
- `DenyAllDnsResolver` and `EmptyDnsResolver`: return an error or no records, useful for
  tests and for disabling DNS.

Rama uses a global resolver by default, which is the native resolver unless you replace it
with `init_global_dns_resolver` (or `try_init_global_dns_resolver`) early in your program.

## Examples


- [/examples/src/native_dns.rs](https://github.com/plabayo/rama/blob/main/examples/src/native_dns.rs):
  Resolve one or more domains using Rama's best-effort native DNS support.
