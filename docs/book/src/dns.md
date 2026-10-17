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

- Translated domains into IP addreses, allowing the ability to filter IP addresses,
  and establish connections to such addresses;
- Lookup meta information associated with a domain such as TXT data.

See [rama-dns](https://ramaproxy.org/docs/rama/tcp/index.html) for more information.

On GNU/Linux the native resolver uses systemd-resolved when NSS selects it and
`getaddrinfo` otherwise. Enable `dns-libresolv` to back it with glibc's libresolv stub instead, which
also answers CNAME, TXT, SVCB and HTTPS lookups without systemd-resolved; this
needs a C compiler and libclang at build time.

## Examples


- [/examples/src/native_dns.rs](https://github.com/plabayo/rama/blob/main/examples/src/native_dns.rs):
  Resolve one or more domains using Rama's best-effort native DNS support.
