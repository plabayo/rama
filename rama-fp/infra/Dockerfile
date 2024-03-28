FROM rust:1-bookworm as builder

WORKDIR /usr/src/app
COPY . .
# Will build and cache the binary and dependent crates in release mode
RUN --mount=type=cache,target=/usr/local/cargo,from=rust:latest,source=/usr/local/cargo \
    --mount=type=cache,target=target \
    cargo build -p rama-fp --release && mkdir ./bin && mv ./target/release/rama-fp ./bin/rama-fp

# Runtime image
FROM debian:bookworm-slim

WORKDIR /app

# Get compiled binaries from builder's cargo install directory
COPY --from=builder /usr/src/app/bin/rama-fp /app/rama-fp

# Run the app
CMD ./rama-fp -i 0.0.0.0 -p 8080