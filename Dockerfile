# --- Build Stage ---
FROM rust:1.100-trixie AS builder

WORKDIR /usr/src/ironwarden

# Install build tools and dependencies (OpenSSL, pkg-config, clang)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Copy source code into builder container
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY warden ./warden
COPY worker ./worker
COPY mcp ./mcp
COPY app ./app
COPY cli ./cli
COPY tests ./tests
COPY benchmarks ./benchmarks
COPY config ./config
COPY scripts ./scripts
COPY monitoring ./monitoring

# Build release binaries
RUN cargo build --release -p app -p iw-cli

# --- Runtime Stage ---
FROM debian:trixie-slim AS runner

# Install OCR/TLS runtime packages and ONNX Runtime 1.21.0 (with SHA-256 verification) in one clean layer
ARG ORT_NUPKG_SHA256=359b4782cfa2e288e6c4bbb9da1c231b085fb8e0d149faf8c3c843f54576559b
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-grc \
    tesseract-ocr-ell \
    poppler-utils \
    ca-certificates \
    libssl3 \
    curl \
    unzip \
    && curl -fsSL "https://www.nuget.org/api/v2/package/Microsoft.ML.OnnxRuntime/1.21.0" -o /tmp/ort.nupkg \
    && echo "${ORT_NUPKG_SHA256}  /tmp/ort.nupkg" | sha256sum -c - \
    && unzip -q -j /tmp/ort.nupkg "runtimes/linux-x64/native/libonnxruntime*.so" -d /usr/lib/x86_64-linux-gnu/ \
    && rm -f /tmp/ort.nupkg \
    && apt-get purge -y --auto-remove unzip \
    && rm -rf /var/lib/apt/lists/* \
    && chmod 0755 /usr/lib/x86_64-linux-gnu/libonnxruntime*.so* \
    && ldconfig

# Create unprivileged service account
RUN groupadd -g 10001 ironwarden \
    && useradd -u 10001 -g 10001 -m -d /app -s /usr/sbin/nologin ironwarden

WORKDIR /app

# Copy binary and default configuration from builder
COPY --from=builder /usr/src/ironwarden/target/release/app /usr/local/bin/ironwarden
COPY --from=builder /usr/src/ironwarden/target/release/iw-cli /usr/local/bin/iw-cli
COPY --from=builder /usr/src/ironwarden/config /app/config

# Default configuration mounts & data directories owned by unprivileged user
RUN mkdir -p /app/data/models /app/logs \
    && chown -R ironwarden:ironwarden /app

ENV WARDEN_ENV=production \
    WARDEN_MODE=bridge \
    PORT=8080 \
    BRIDGE_PORT=8080 \
    BRIDGE_ADDR=0.0.0.0 \
    LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu \
    ORT_DYLIB_PATH=/usr/lib/x86_64-linux-gnu/libonnxruntime.so \
    ALLOW_FALLBACK=false \
    RUST_LOG=info

USER ironwarden

EXPOSE 8080 14141

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${BRIDGE_PORT:-8080}/health" || exit 1

CMD ["ironwarden"]
