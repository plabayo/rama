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
  echo   rama echo service (echos the http request and tls client config)
  http   rama http client
  proxy  rama proxy runner
  ip     rama ip service (returns the ip address of the client)
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Install

The easiest way to install `rama` is by using `cargo`:

```sh
cargo install rama-cli@0.2.0-alpha.0
```

This will install `rama-cli` from source and make it available
under your cargo _bin_ folder as `rama`. In case you want to install
a pre-built binary when available for your platform you can do so
using [`cargo binstall`](https://github.com/cargo-bins/cargo-binstall):

```sh
cargo binstall rama-cli@0.2.0-alpha.0
```

On 🍎 MacOS you can also install the `rama` binary using [HomeBrew](https://brew.sh/):

```
brew tap plabayo/rama
brew install rama
```

> Contributions to the homebrew distributions can be made via
> <https://github.com/plabayo/homebrew-rama>.
