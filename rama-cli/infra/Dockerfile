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

RUN useradd -U -u 1000 appuser && chown -R 1000:1000 /app
# HTTP/3 binds UDP 443 itself: Fly.io does not rewrite UDP ports. Granted after the chown,
# which clears file capabilities. A container dropping all capabilities must add
# NET_BIND_SERVICE back, or the binary cannot start.
RUN apt-get update && \
    apt-get install --no-install-recommends -y libcap2-bin && \
    setcap cap_net_bind_service=+ep /app/rama && \
    apt-get purge -y libcap2-bin && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*
USER 1000

# Run the app
ENTRYPOINT ["/app/rama"]
