## Overview of Options

Binaries built with the Rama framework can be deployed in many different ways,
much like most other Rust frameworks. However, not everyone is familiar with running binaries
in production-like environments, so we’re happy to list a few options here.

### Rama CLI

If you have not built a project with Rama directly but are instead using the `rama-cli` tool,
you can find more information on how to install and run it on [the Rama CLI page](./rama-cli.md).

### Docker

The Rama CLI is available as a Docker image, which can be found at <https://hub.docker.com/r/glendc/rama>.
It uses the following Dockerfile: <https://github.com/plabayo/rama/blob/main/rama-cli/infra/Dockerfile>.

Feel free to use it as inspiration for the Dockerfile of your own Rama-based project. We are not Docker experts,
but you’re welcome to send a PR with any improvements.

### Bare-metal

Running your Rama-based project on a bare-metal server or VM is, of course, possible.
There's not much to elaborate on here—it's as simple as:

```bash
cargo build --release .
cargo run ./target/release/<my-binary>
```

For more details, refer to external documentation on cross-platform building, CI/CD options, automation, Cargo, and more.

### WASM

Rama, with Tokio as its only async runtime, is theoretically compatible with WASM.
However, it may not work in all setups or configurations. For example,
enabling features like `boring` could cause issues.

We are enthusiastic about the technology and occasionally experiment with it.
If you have any improvements to share based on your WASM experience with Rama, feel free to submit a PR.
