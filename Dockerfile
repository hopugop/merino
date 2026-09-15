# syntax=docker/dockerfile:1
FROM rust:1.98.1-alpine3.24 AS builder
RUN apk add --no-cache build-base

WORKDIR /app/
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY benches/ benches/

# Cache the registry download and the compiled target dir across builds so
# dependency crates are not recompiled on every source change. The binary is
# copied out of the cache mount because BuildKit cache mounts are not persisted
# into the resulting image layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked && \
    cp target/release/merino /merino

FROM alpine:3.24
RUN addgroup -S merino && \
    adduser -S -G merino merino && \
    apk add --no-cache tini
USER merino
COPY --from=builder /merino /usr/local/bin/merino
EXPOSE 1080
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/merino"]
