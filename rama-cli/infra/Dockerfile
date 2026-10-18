FROM rust:1-bookworm AS builder

RUN apt-get update && \
    apt-get install --no-install-recommends -y cmake clang protobuf-compiler

WORKDIR /usr/src/app
ARG RAMA_CLI_FEATURES=""
COPY . .
# Will build and cache the binary and dependent crates in release mode
RUN --mount=type=cache,target=/usr/local/cargo,from=rust:latest,source=/usr/local/cargo \
    --mount=type=cache,target=target \
    cargo build --locked -p rama-cli --release --features "${RAMA_CLI_FEATURES}" && \
    mkdir -p ./bin && mv ./target/release/rama ./bin/rama

# Runtime image
FROM debian:bookworm-slim

WORKDIR /app

# Get compiled binaries from builder's cargo install directory
COPY --from=builder /usr/src/app/bin/rama /app/rama

RUN apt-get update && \
    apt-get install --no-install-recommends -y ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -U -u 1000 appuser && chown -R 1000:1000 /app
USER 1000

# Run the app
ENTRYPOINT ["/app/rama"]
