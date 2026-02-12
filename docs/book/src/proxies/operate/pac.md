# 🔀 Proxy Auto-Configuration (PAC)

<div class="book-article-intro">
<div>
A Proxy Auto-Config (PAC) file is a JavaScript function that determines whether web browser requests (HTTP, HTTPS, and FTP) go directly to the destination or are forwarded to a web proxy server.
<p>— <a href="https://en.wikipedia.org/wiki/Proxy_auto-config">Wikipedia</a></p>
</div>
</div>

## The "Smart" Routing Script

While static system proxies are simple (everything goes to one IP), they lack nuance. In a real-world network, you don't want to send traffic to your internal printer or a local dev server through a remote Rama proxy. You need a way to say: "Proxy the internet, but stay direct for the office."

This is exactly what a PAC file does. It is a single JavaScript file containing a function called `FindProxyForURL(url, host)`. Every time your browser wants to load a resource, it runs this function to get instructions.

The client passes two arguments to this function:

* **url**: The full destination URL (e.g., `https://example.com:8443/foo/bar?baz=1`).
* **host**: The host component extracted from the URL (e.g., `example.com`).

The function returns a string instructing the client on how to proceed:

* **`DIRECT`**: Connect to the destination server directly, bypassing the proxy.
* **`PROXY host:port`**: Connect via the specified HTTP proxy.

> [!NOTE]
> While some clients support `SOCKS`, `HTTPS`, or `SOCKS5` directives, `PROXY` and `DIRECT` are the most universally compatible across all platforms and browsers.
>
> Unless you really need to and know for sure it is supported it is best to only use
> the `PROXY` and `DIRECT` directives.

You can return multiple options separated by a semicolon (`;`). The client will attempt them in order.

## Script Example

The power of PAC lies in its simplicity. It provides a set of helper functions that allow you to make decisions based on the destination.

```javascript
function FindProxyForURL(url, host) {
    // 1. Stay direct for local hostnames
    if (isPlainHostName(host) || dnsDomainIs(host, ".local")) {
        return "DIRECT";
    }

    // 2. Stay direct for the internal corporate network
    if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }

    // 3. Send everything else to our Rama proxy
    // If the proxy is down, the browser will try to go DIRECT as a backup
    return "PROXY proxy.rama.internal:8080; DIRECT";
}

```

### Key PAC Functions:

* `isPlainHostName(host)`: True if there are no dots in the hostname (e.g., `http://intranet`).
* `dnsDomainIs(host, ".com")`: Allows for domain-specific routing.
* `isInNet(ip, pattern, mask)`: Allows for IP-range based routing.
* `shExpMatch(str, shellExpression)`: Pattern matching for URLs using shell-style wildcards.

## Distribution: How Browsers Find the File

A PAC file isn't much use if the client doesn't know where it is. There are two primary ways to distribute a PAC script:

1. **Manual URL:** You enter the address (e.g., `http://config.rama.internal/proxy.pac`) into the System Proxy settings.
2. **WPAD (Web Proxy Auto-Discovery):** This is the "zero-config" method. The browser uses DNS or DHCP to look for a server named `wpad`. It then tries to download `http://wpad/wpad.dat`. While convenient, WPAD has significant security risks (like DNS poisoning), which is why many modern environments prefer manual URLs or MDM-pushed configs.

> Learn more about WPAD at <https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol>.

System proxy settings is the more common way to use PAC.

## The Limitations of PAC

As flexible as PAC files are, they share the same weakness as all [System Proxies](./system_proxies.md): **Application Compliance**.

A PAC file is a suggestion, not a law. Furthermore, because PAC relies on JavaScript, many non-browser applications (like low-level CLI tools or embedded devices) don't have a JavaScript engine to run the script. For those "blind" applications, the PAC settings are essentially invisible.

## Rama Support

TOOD... in progress

## More Resources

* **[MDN: Proxy Auto-Configuration](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file)**: Excellent documentation on built-in helper functions (like `shExpMatch`). *Note: These functions can be slow; Safechain often uses optimized custom logic instead.*
* **[Cloudflare: PAC Best Practices](https://developers.cloudflare.com/cloudflare-one/networks/resolvers-and-proxies/proxy-endpoints/best-practices/)**: Modern performance tips.
* **[Microsoft: WinHTTP IPv6 Extensions](https://learn.microsoft.com/en-us/windows/win32/winhttp/ipv6-aware-proxy-helper-api-definitions)**: Information on `FindProxyForURLEx`, used specifically by Win32 applications for IPv6 support (useful only if you need to take advantage of builtin Ipv6 utilities and only supported for windows applications running the Win32 stack).
