# 🔌 Network proxies (Layer 3)

<div class="book-article-intro">
<div>
A Layer 3 proxy, often called a <b>Network Layer Proxy</b> or <b>IP Proxy</b>, operates at the IP level of the OSI model. Unlike application proxies that understand specific protocols like HTTP or FTP, a Layer 3 proxy is protocol-agnostic. It treats every communication as a series of raw IP packets, focusing solely on routing and forwarding data based on source and destination IP addresses.
</div>
</div>

## The "Postman" of the Network

If a Layer 7 proxy is like a translator who reads your letter to ensure it’s polite before sending it, a **Layer 3 proxy** is like a postman. The postman doesn't care what’s inside the envelope—whether it’s a web request, a database query, or a VoIP call—they only cares about the address on the outside.

### Key Characteristics of L3 Proxies

* **Protocol Agnostic:** Because it operates at the network layer, it can handle any traffic that sits on top of IP, including TCP, UDP, ICMP, and GRE.
* **Transparent by Nature:** Often implemented as a "routed hop" or gateway, these proxies can intercept traffic without the client application ever knowing a proxy is involved.
* **High Throughput:** Since the proxy doesn't need to decrypt or parse complex application-layer data (like HTTP headers or JSON payloads), it can process packets significantly faster than L7 proxies.

## How it Works: The Routed Path

A Layer 3 proxy typically inserts itself as a gateway or a "next hop" in the network topology.

1. **Interception:** Traffic from the client is routed to the proxy's IP address, often through a **TUN device** or a **Virtual Network Interface**.
2. **Termination:** The proxy "terminates" the IP packet. In a transparent setup, it might use **TPROXY** (Linux) or **WFP** (Windows) to catch the packet.
3. **Encapsulation/Forwarding:** The proxy creates a new IP packet with its own source IP and forwards it to the destination.
4. **Reverse Path:** When the server responds, the proxy receives the packet, matches it to the original client session, and routes it back.

```plaintext
Layer 3 Proxy Flow (IP Forwarding)
----------------------------------

[ Client ] ────▶ [ L3 Proxy (rama) ] ────▶ [ Server ]
 (IP: 10.0.0.5)      (IP: 10.0.0.1)        (IP: 8.8.8.8)

1. Client sends IP packet to 8.8.8.8.
2. Network routing sends packet to 10.0.0.1 (Gateway).
3. Proxy (rama) captures packet via TUN/TPROXY.
4. Proxy creates NEW packet: Source=10.0.0.1, Dest=8.8.8.8.
5. Server sees request from Proxy IP.

```

## L3 Proxies vs. NAT (Network Address Translation)

While both modify IP headers, they serve different masters:

* **NAT:** Usually happens in the kernel (e.g., `iptables MASQUERADE`). It is a simple mapping of private IPs to public IPs. It has no "memory" beyond the connection tracking table.
* **L3 Proxy:** Involves a **user-space application** (like Rama). This allows for complex logic: you can decide to block traffic based on geo-IP, perform rate limiting, or even "upgrade" the connection to a different protocol (like tunneling IP-over-HTTPS via [RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)).

## Common Use Cases for Rama at Layer 3

Using Rama as a Layer 3 proxy allows you to build powerful network infrastructure:

* **Transparent VPN Gateways:** Build a gateway that automatically tunnels all office traffic through an encrypted backbone without configuring individual devices.
* **DDoS Mitigation:** Scrub incoming IP traffic at high speeds before it reaches your application servers.
* **IP-in-IP Tunneling:** Bridge two disjoint networks by encapsulating L3 packets from one network into the payload of another.

When using Rama to build a L3 proxy you can also combine it with the smoltcp feature in rama TCP
such that you can still MITM/inspect L4-L7 data operating on top of TCP.

That said... Most of the times you do not want to build a L3 proxy,
but instead are looking for what we call [transparent proxies](./transparent.md). These are
much simpler in nature (as you basically get a UDP/TCP stream of data without having to deal
with terminating those transport protocols yourself or worrying about the messy world of Layer 3),
and they also coexist much better with other technologies such as VPNs.
