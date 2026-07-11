# Title: [INFRA] Implement Unified SQLite Connection Pooling (WP-99)

## Category: Infrastructure / Storage Optimization

## Description
Currently, separate database connections are instantiated individually across the storage manager, audit logging worker, and SearchBoost queue. This causes database lock contention, file locks under heavy write surges, and high connection overhead.

We need to implement a unified `SqlitePool` using connection pooling (like `r2d2` with `r2d2_sqlite` or `sqlx` in the future) and share a single pool instance across the storage, search, and audit workers.

## Technical Specifications
1.  **Integrate Pool:** Add `r2d2` and `r2d2_sqlite` to `worker/Cargo.toml`.
2.  **Shared Pool Instance:** Initialize a single `Pool<SqliteConnectionManager>` at startup in `app/src/main.rs`.
3.  **Refactor Connections:** Share the pool using thread-safe reference counting (`Arc<SqlitePool>`).
4.  **Enforce PRAGMAs:** Configure the connection manager to enforce database performance defaults on every pooled connection:
    *   `journal_mode = WAL`
    *   `synchronous = NORMAL`
    *   `busy_timeout = 5000`
