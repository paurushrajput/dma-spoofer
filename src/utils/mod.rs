pub mod codecave;
mod random;
pub mod registry;
mod signature;

pub use codecave::{find_best_codecave, CodecaveFinder, CodecaveInfo, CodecaveStrategy};
pub use random::generate_random_bytes;
pub use registry::RegistrySpoofer;
pub use signature::SignatureScanner;
