# ⌨️ `rama` binary

The `rama` binary allows you to use a lot of what `rama` has to offer without
having to code yourself. It comes with a working http client for CLI, which emulates
User-Agents and has other utilities. And it also comes with IP/Echo services.

It also allows you to run a `rama` proxy, configured to your needs.

## Usage

```bash
rama --help
```

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
winget install Plabayo.Rama.Preview
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
