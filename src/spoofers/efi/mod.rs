pub mod offsets;
pub mod shellcode;
pub mod spoofer;
pub mod types;

pub use spoofer::EfiSpoofer;
pub use types::{EfiRuntimeServicesTable, EfiVariable};
