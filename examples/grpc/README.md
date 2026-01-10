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
cargo run -p rama-grpc-examples --bin helloworld-client
```

### Server

```bash
cargo run -p rama-grpc-examples --bin helloworld-server
```

## Health

gRPC has a [health checking protocol](https://github.com/grpc/grpc/blob/master/doc/health-checking.md) that defines how health checks for services should be carried out. `rama-grpc` supports
it out of the box as long as you have the `protobuf` feature enabled (a default feature).

This example uses the crate to set up a HealthServer that will run alongside the application service. In order to test it, you may use community tools like [grpc-health-probe](https://github.com/grpc-ecosystem/grpc-health-probe).

For example, run the health server example
(which toggles the serve status of the hello world example server every 250ms`):

```bash
cargo run -p rama-grpc-examples --bin health-server
```

And then run the go probe client (ensure to install it first):

```bash
while [ true ]; do
    $HOME/go/bin/grpc-health-probe -addr='[::1]:50051' -service='helloworld.Greeter'
    sleep '0.25'
done
```

will show the change in health status of the service over time:

```
service unhealthy (responded with "NOT_SERVING")
status: SERVING
service unhealthy (responded with "NOT_SERVING")
status: SERVING
...
```
