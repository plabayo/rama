FROM rust:1-bookworm AS builder

RUN apt-get update && \
    apt-get install --no-install-recommends -y cmake clang protobuf-compiler

WORKDIR /usr/src/app
COPY . .
# Will build and cache the binary and dependent crates in release mode
RUN --mount=type=cache,target=/usr/local/cargo,from=rust:latest,source=/usr/local/cargo \
    --mount=type=cache,target=target \
    cargo build -p rama-cli --release && \
    mkdir -p ./bin && mv ./target/release/rama ./bin/rama

# Runtime image
FROM debian:bookworm-slim

WORKDIR /app

# Get compiled binaries from builder's cargo install directory
COPY --from=builder /usr/src/app/bin/rama /app/rama

# Run the app
ENTRYPOINT ["/app/rama"]
