# --- Build Stage ---
FROM rust:1.97-bookworm AS builder

WORKDIR /usr/src/ironwarden

# Install build tools and dependencies (Tesseract OCR dev libs, OpenSSL, pkg-config)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    libtesseract-dev \
    libleptonica-dev \
    clang \
    protobuf-compiler \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source code into builder container
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY warden ./warden
COPY worker ./worker
COPY mcp ./mcp
COPY app ./app
COPY cli ./cli
COPY integration_tests ./integration_tests
COPY config ./config
COPY scripts ./scripts
COPY monitoring ./monitoring



# Build release binary
RUN cargo build --release -p app

# --- Runtime Stage ---
FROM debian:trixie-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libtesseract5 \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install ONNX Runtime 1.20.1 (required by ort crate with load-dynamic feature)
RUN curl -fsSL \
    "https://github.com/microsoft/onnxruntime/releases/download/v1.20.1/onnxruntime-linux-x64-1.20.1.tgz" \
    -o /tmp/ort.tgz \
    && tar -xzf /tmp/ort.tgz -C /tmp \
    && cp /tmp/onnxruntime-linux-x64-1.20.1/lib/libonnxruntime.so.1.20.1 /usr/lib/x86_64-linux-gnu/ \
    && ln -s /usr/lib/x86_64-linux-gnu/libonnxruntime.so.1.20.1 /usr/lib/x86_64-linux-gnu/libonnxruntime.so \
    && rm -rf /tmp/ort.tgz /tmp/onnxruntime-linux-x64-1.20.1

WORKDIR /app

# Copy binary from builder
COPY --from=builder /usr/src/ironwarden/target/release/app /usr/local/bin/ironwarden

# Default configuration mounts & data directories
RUN mkdir -p /app/config/rules /app/data/models /app/logs

EXPOSE 8080 14141

ENV WARDEN_ENV=production \
    PORT=8080 \
    RUST_LOG=info

CMD ["ironwarden"]
