# Examples

Set of examples that show off the features provided by `rama-grpc`.

In order to build these examples, you must have the `protoc` Protocol Buffers compiler
installed, along with the Protocol Buffers resource files.

Ubuntu:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y protobuf-compiler libprotobuf-dev
```

Alpine Linux:

```sh
sudo apk add protoc protobuf-dev
```

macOS:

Assuming [Homebrew](https://brew.sh/) is already installed. (If not, see instructions for installing Homebrew on [the Homebrew website](https://brew.sh/).)

```zsh
brew install protobuf
```

## Helloworld

### Client

```bash
$ cargo run --bin helloworld-client
```

### Server

```bash
$ cargo run --bin helloworld-server
```
