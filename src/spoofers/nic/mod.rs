mod intel;
mod offsets;
pub(crate) mod scanner;
mod spoofer;
pub(crate) mod types;

pub use intel::IntelWifiSpoofer;
pub use spoofer::NicSpoofer;
