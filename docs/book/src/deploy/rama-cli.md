# ⌨️ `rama` binary

The `rama` binary allows you to use a lot of what `rama` has to offer without
having to code yourself. It comes with a working http client for CLI, which emulates
User-Agents and has other utilities. And it also comes with IP/Echo services.

It also allows you to run a `rama` proxy, configured to your needs.

## Usage

```text
rama cli to move and transform network packets

Usage: rama <COMMAND>

Commands:
  http   rama http client
  tls    rama tls support
  proxy  rama proxy server
  echo   rama echo service (echos the http request and tls client config)
  ip     rama ip service (returns the ip address of the client)
  fp     rama fp service (used for FP collection in purpose of UA emulation)
  serve  rama serve service (serves a file, directory or placeholder page)
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Install

The easiest way to install `rama` is by using `cargo`:

```sh
cargo install rama-cli@0.3.0-alpha.2
```

This will install `rama-cli` from source and make it available
under your cargo _bin_ folder as `rama`. In case you want to install
a pre-built binary when available for your platform you can do so
using [`cargo binstall`](https://github.com/cargo-bins/cargo-binstall):

```sh
cargo binstall rama-cli@0.3.0-alpha.2
```

On 🍎 MacOS you can also install the `rama` binary using [HomeBrew](https://brew.sh/):

```
brew install plabayo/rama/rama
```

> Contributions to the homebrew distributions can be made via
> <https://github.com/plabayo/homebrew-rama>.

In case you run on a platform for which we do not have (correct) package manager support yet,
you can also download the archive with the ease of running a script.

Using this approach you can install it using `curl`

```
curl https://raw.githubusercontent.com/plabayo/rama/main/rama-cli/scripts/install.sh | bash
```

or `wget`:

```
wget -qO- https://raw.githubusercontent.com/plabayo/rama/main/rama-cli/scripts/install.sh | bash
```

## Docker

The `rama` "cli" is also available as a docker image:

> 🔗 <https://hub.docker.com/r/glendc/rama>

```
docker pull glendc/rama:latest
docker run --rm glendc/rama:latest http example.com
```
