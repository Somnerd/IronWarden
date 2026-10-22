#![allow(clippy::double_must_use)]
#![recursion_limit = "2048"]

pub mod audit;
pub mod bridge;
pub mod grounding;
pub mod librarian;
pub mod metrics;
pub mod ocr;
pub mod proxy;
pub mod router;
pub mod session;
pub mod sse_proxy;
pub mod storage;

pub use audit::AsyncAuditor;
pub use bridge::{create_bridge_router, BridgeState};
pub use grounding::{GroundingQueue, LocalSessionManager, SESSION_IDLE_TIMEOUT};
pub use librarian::LocalLibrarian;
pub use metrics::GatewayMetrics;
pub use ocr::{OcrWorker, TesseractOcr};
pub use router::OpenAIGateway;
pub use storage::WorkerStorage;

#[doc(hidden)]
pub static TEST_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
