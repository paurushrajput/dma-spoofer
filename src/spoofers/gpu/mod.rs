pub mod nvidia;
mod offsets;
mod uuid;

pub use nvidia::{NvidiaSpoofer, UuidCandidate, UuidConfidence};
pub use uuid::GpuUuid;
