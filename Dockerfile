# --- Build Stage ---
FROM rust:1.80-slim-bookworm AS builder

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
COPY iw_core ./iw_core
COPY warden ./warden
COPY worker ./worker
COPY mcp ./mcp
COPY app ./app

# Build release binary
RUN cargo build --release -p app

# --- Runtime Stage ---
FROM debian:bookworm-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libtesseract5 \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

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
