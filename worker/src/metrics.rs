use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Zero-overhead atomic metrics collector for IronWarden Universal Gateway.
#[derive(Debug)]
pub struct GatewayMetrics {
    start_time: Instant,
    pub requests_chat_completions: AtomicU64,
    pub requests_completions: AtomicU64,
    pub requests_messages: AtomicU64,
    pub requests_enqueue: AtomicU64,
    pub requests_get_result: AtomicU64,
    pub requests_health: AtomicU64,
    pub requests_models: AtomicU64,
    pub injections_blocked: AtomicU64,
    pub pii_entities_redacted: AtomicU64,
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayMetrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            requests_chat_completions: AtomicU64::new(0),
            requests_completions: AtomicU64::new(0),
            requests_messages: AtomicU64::new(0),
            requests_enqueue: AtomicU64::new(0),
            requests_get_result: AtomicU64::new(0),
            requests_health: AtomicU64::new(0),
            requests_models: AtomicU64::new(0),
            injections_blocked: AtomicU64::new(0),
            pii_entities_redacted: AtomicU64::new(0),
        }
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Renders all metrics in standard Prometheus exposition format (`text/plain; version=0.0.4`).
    pub fn render_prometheus(&self, concurrency_available: usize) -> String {
        format!(
            "# HELP ironwarden_uptime_seconds Total process uptime in seconds\n\
             # TYPE ironwarden_uptime_seconds gauge\n\
             ironwarden_uptime_seconds {}\n\n\
             # HELP ironwarden_concurrency_available Number of available ingress permits\n\
             # TYPE ironwarden_concurrency_available gauge\n\
             ironwarden_concurrency_available {}\n\n\
             # HELP ironwarden_requests_total Total number of HTTP requests processed by endpoint\n\
             # TYPE ironwarden_requests_total counter\n\
             ironwarden_requests_total{{endpoint=\"/v1/chat/completions\"}} {}\n\
             ironwarden_requests_total{{endpoint=\"/v1/completions\"}} {}\n\
             ironwarden_requests_total{{endpoint=\"/v1/messages\"}} {}\n\
             ironwarden_requests_total{{endpoint=\"/v1/models\"}} {}\n\
             ironwarden_requests_total{{endpoint=\"/enqueue\"}} {}\n\
             ironwarden_requests_total{{endpoint=\"/results\"}} {}\n\
             ironwarden_requests_total{{endpoint=\"/health\"}} {}\n\n\
             # HELP ironwarden_injections_blocked_total Total prompt injection and jailbreak attempts blocked\n\
             # TYPE ironwarden_injections_blocked_total counter\n\
             ironwarden_injections_blocked_total {}\n\n\
             # HELP ironwarden_pii_entities_redacted_total Total PII tokens and entities detected and redacted\n\
             # TYPE ironwarden_pii_entities_redacted_total counter\n\
             ironwarden_pii_entities_redacted_total {}\n",
            self.uptime_seconds(),
            concurrency_available,
            self.requests_chat_completions.load(Ordering::Relaxed),
            self.requests_completions.load(Ordering::Relaxed),
            self.requests_messages.load(Ordering::Relaxed),
            self.requests_models.load(Ordering::Relaxed),
            self.requests_enqueue.load(Ordering::Relaxed),
            self.requests_get_result.load(Ordering::Relaxed),
            self.requests_health.load(Ordering::Relaxed),
            self.injections_blocked.load(Ordering::Relaxed),
            self.pii_entities_redacted.load(Ordering::Relaxed),
        )
    }
}
