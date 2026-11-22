# --- Build Stage ---
FROM rust:1-bookworm AS builder

WORKDIR /usr/src/ironwarden

# Install build tools and dependencies (Tesseract OCR dev libs, OpenSSL, pkg-config)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    libtesseract-dev \
    libleptonica-dev \
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

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-grc \
    tesseract-ocr-ell \
    libtesseract5 \
    ca-certificates \
    libssl3 \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install ONNX Runtime 1.21.0 (required by ort crate with load-dynamic feature; falls back to NuGet if GitHub release is 404)
RUN if curl -fsSL "https://github.com/microsoft/onnxruntime/releases/download/v1.21.0/onnxruntime-linux-x64-1.21.0.tgz" -o /tmp/ort.tgz; then \
        tar -xzf /tmp/ort.tgz -C /tmp \
        && cp -a /tmp/onnxruntime-linux-x64-1.21.0/lib/libonnxruntime.so* /usr/lib/x86_64-linux-gnu/ \
        && rm -rf /tmp/ort.tgz /tmp/onnxruntime-linux-x64-1.21.0; \
    else \
        curl -fsSL "https://www.nuget.org/api/v2/package/Microsoft.ML.OnnxRuntime/1.21.0" -o /tmp/ort.nupkg \
        && unzip -q -j /tmp/ort.nupkg "runtimes/linux-x64/native/libonnxruntime*.so" -d /usr/lib/x86_64-linux-gnu/ \
        && rm -f /tmp/ort.nupkg; \
    fi \
    && chmod +x /usr/lib/x86_64-linux-gnu/libonnxruntime*.so* \
    && ldconfig

WORKDIR /app

# Copy binary and default configuration from builder
COPY --from=builder /usr/src/ironwarden/target/release/app /usr/local/bin/ironwarden
COPY --from=builder /usr/src/ironwarden/target/release/iw-cli /usr/local/bin/iw-cli
COPY --from=builder /usr/src/ironwarden/config /app/config

# Default configuration mounts & data directories
RUN mkdir -p /app/data/models /app/logs

EXPOSE 8080 14141

ENV WARDEN_ENV=production \
    WARDEN_MODE=bridge \
    PORT=8080 \
    BRIDGE_PORT=8080 \
    BRIDGE_ADDR=0.0.0.0 \
    LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu \
    ALLOW_FALLBACK=true \
    RUST_LOG=info \
    WARDEN_MCP_SECRET=default_mcp_secret_change_in_production

CMD ["ironwarden"]
