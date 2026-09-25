# ⌨️ `rama` binary

The `rama` binary allows you to use a lot of what `rama` has to offer without
having to code yourself. It has an HTTP client, a proxy with traffic inspection,
DNS and TLS tools, and a bunch of small services that come in handy when
testing network clients and proxies.

This page gives a short overview of what is there. The `--help` output of each
command is the place to go for all flags and details.

## Usage

```bash
rama --help
```

Every command also has its own help, e.g. `rama serve proxy --help`.

## HTTP client

`rama <URI>` (or `rama send <URI>`) is the HTTP client. If you know `curl`
you will feel at home, many of its flags work the same way. It speaks
HTTP/1.1, H2 and H3.

Some URIs open a terminal UI instead of printing the response:

- a `ws://` or `wss://` URI opens a WebSocket client, where you can send
  and receive messages;
- an RSS or Atom feed opens in a feed reader. This is detected from the response,
  so any URI serving a feed works. Write to a file with `-o` or pipe the output
  and you get the plain feed instead.

Some things it can do on top of that:

- emulate a browser with `--emulate`, using the User-Agent profiles embedded in rama;
- record the exchange to a HAR file with `--har`;
- print the equivalent `curl` command with `--curl`, without sending anything;
- select values from a JSON response with `--select-json`;
- go via an upstream proxy with `--proxy`. Without it, proxy environment variables
  and the system proxy settings are used.

### Alternative HTTP services

`rama send --alt-svc --location https://example.com` opts in to learning and
using alternative services advertised through response headers or HTTP/2 ALTSVC
frames. Advertisements are kept in memory for that command only, so a redirect
can use an alternative learned from an earlier response. No cache file is read
or written. Alternative-service discovery is disabled by default in the CLI.

`--http3` requires HTTP/3 directly, without an advertisement or `--alt-svc`.
Explicit HTTP version flags continue to constrain selection when `--alt-svc`
is enabled. WebSockets over HTTP/3 require Extended CONNECT support, which is
not yet implemented.

## Proxies

`rama serve proxy` runs a forward proxy. By default it serves HTTP and SOCKS5
on the same port (`127.0.0.1:8080`), and it can serve HTTPS as well. Use
`--protocol` and the protocol specific bind flags to choose what runs where.

### MITM proxy with web UI

Add `--mitm` to `rama serve proxy` and the proxy starts to inspect the traffic
that goes through it. You can follow it live in a web UI that is served by the
proxy itself: requests and responses, WebSocket messages, TLS details and more.
From there you can also export captures as HAR.

The proxy uses an ephemeral CA to do this. Your clients need to trust it,
which is why you can download it from the web UI or write it to a file with
`--mitm-ca-cert`. Captured data is stored encrypted and is bounded by limits
you can configure with the `--capture-*` flags.

More background can be found in the blog article about the
[proxy web GUI inspector](https://plabayo.tech/blog/rama-cli-0-5-proxy-inspector).

### Inspect capture files

`rama inspect <FILE>` opens a HAR or qlog file in a terminal viewer. Useful for
captures you made with the rama CLI or proxy, but it works for files exported
by browsers or other tools as well.

## DNS

`rama resolve <DOMAIN> [TYPE]` resolves DNS queries. Without a type it resolves
the IP addresses using happy eyeballs, the same way the HTTP client would. It
supports A, AAAA, CNAME, TXT, SVCB and HTTPS records. By default the system
resolver is used, use `--nameserver` to query specific servers instead.

## Probing

`rama probe` has a couple of commands to find out things about a server or
your own machine:

- `rama probe tls` shows the TLS capabilities of a server;
- `rama probe tcp` probes the TCP side of a server;
- `rama probe iface` lists your local network interfaces and their addresses.

## PAC

`rama pac eval` evaluates a Proxy Auto-Configuration script for one or more URIs,
so you can see which proxy a browser would pick. `rama pac generate` goes the
other way and writes a PAC script from a list of domain routes.

See the [PAC chapter](../proxies/operate/pac.md) for more about PAC in rama.

## Test and diagnostic services

`rama serve` has more than the proxy. These are small services that are useful
when you develop or test clients and proxies:

- `echo`: returns what it received. Over HTTP(S) that includes the HTTP and TLS
  details of the request, otherwise it echoes raw TCP or UDP bytes;
- `ip`: returns the IP address of the client;
- `fp`: the fingerprinting service we use to collect User-Agent profiles;
- `http-test`: endpoints for testing HTTP clients, such as compression,
  streaming, SSE, multipart and methods;
- `icap`: an ICAP echo service for REQMOD and RESPMOD;
- `fs`: serves a file, a directory or a placeholder page;
- `discard`: the RFC 863 discard service.

All of them have flags to limit rate or throughput, which is handy to mimic
slow or restricted servers. Most can run with TLS as well.

## TLS tunnels

`rama serve stunnel` runs a TLS tunnel, similar to `stunnel`. As an entry node
it encrypts outgoing connections, as an exit node it decrypts incoming TLS and
forwards the plaintext.

We use it ourselves in the [c-icap interoperability tests](https://github.com/plabayo/rama/tree/main/rama-icap/tests/oracle/c-icap),
where `rama serve stunnel exit` puts TLS in front of a plaintext c-icap server.

## Hosted services

Rama also exposes public services that are useful while developing and testing
network clients, proxies, and user-agent emulation.

### Echo service

🔁 <https://echo.ramaproxy.org/> accepts HTTP requests and returns information
about the TLS and HTTP request data received by the server.

```bash
curl -XPOST 'https://echo.ramaproxy.org/foo?bar=baz' \
  -H 'x-magic: 42' --data 'whatever forever'
```

The echo service also supports WebSockets. The default subprotocol is `echo`;
`echo-upper` and `echo-lower` can be used to uppercase or lowercase echoed
messages.

```sh
rama wss://echo.ramaproxy.org
```

Please run your own echo service instead of using `echo.ramaproxy.org` if you
plan to send a lot of traffic.

### Fingerprinting service

The public fingerprinting service at <https://fp.ramaproxy.org/> is used by
Rama's automated User-Agent profile collection. See the
[User Agent chapter](../intro/user_agent.md) for more about HTTP and TLS
fingerprinting, emulation profiles, and the BrowserStack/fly.io sponsored
infrastructure behind it.

## Install

### Cargo

```sh
cargo install rama-cli@0.3.0
```

This will install `rama-cli` from source and make it available
under your cargo _bin_ folder as `rama`. In case you want to install
a pre-built binary when available for your platform you can do so
using [`cargo binstall`](https://github.com/cargo-bins/cargo-binstall):

```sh
cargo binstall rama-cli@0.3.0
```

### Pre-Built Binaries

#### MacOS

On 🍎 MacOS you can also install the `rama` binary using [HomeBrew](https://brew.sh/):

```
brew install plabayo/rama/rama
```

> Contributions to the homebrew distributions can be made via
> <https://github.com/plabayo/homebrew-rama>.

In case you run on a platform for which we do not have (correct) package manager support yet,
you can also download the archive with the ease of running a script.

#### Windows

On windows you can install and update the rama CLI tool using `winget`:

```
winget install Plabayo.Rama
```

See the `winget` docs on how to uninstall, update and do anything else
that this tool offers you.

#### Unix

Using this approach you can install it using `curl`

```
curl https://raw.githubusercontent.com/plabayo/rama/main/rama-cli/scripts/install.sh | bash
```

or `wget`:

```
wget -qO- https://raw.githubusercontent.com/plabayo/rama/main/rama-cli/scripts/install.sh | bash
```

By default the script installs the latest stable release. It also supports
opting in to pre-releases or pinning a specific version:

```
curl https://raw.githubusercontent.com/plabayo/rama/main/rama-cli/scripts/install.sh | bash -s -- --pre
curl https://raw.githubusercontent.com/plabayo/rama/main/rama-cli/scripts/install.sh | bash -s -- --version 0.3.0
```

## Docker

The `rama` "cli" is also available as a docker image:

> 🔗 <https://hub.docker.com/r/glendc/rama>

```
docker pull glendc/rama:latest
docker run --rm glendc/rama:latest example.com
```

## Code Signing

### Windows

Free code signing for the windows (rama CLI) binary is provided by [SignPath.io](https://about.signpath.io/),
certificate by [SignPath Foundation](https://signpath.org/).

- Authors: [Glen De Cauwsemaecker (@glendc)](https://glendc.com)

### MacOS

The MacOS Binary of rama CLI is signed by the Plabayo organisation via the official
Apple-provided tooling.

## Privacy

The Rama CLI tool collects no data of the user or sends anything to any of our servers.
It is a tool to empower you and fully at your control. The full open source code
can be found without compromises on [our GitHub repository](https://github.com/plabayo/rama/).
