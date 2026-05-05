FROM rust:1.75-slim as builder

WORKDIR /app
COPY rust-parser/ ./
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/zertree /usr/local/bin/zertree
COPY github-action/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
