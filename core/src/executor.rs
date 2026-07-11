use std::future::Future;
use tokio::task::JoinHandle;

pub struct BlockingExecutor;

impl BlockingExecutor {
    /// Standardized wrapper around `tokio::task::spawn_blocking`.
    pub fn spawn_blocking<F, R>(f: F) -> JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        tokio::task::spawn_blocking(f)
    }
}
