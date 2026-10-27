//! Harness diferencial Landlock × io_uring.

pub mod classify;
pub mod harness;
pub mod landlock;
pub mod uring;

pub use classify::{asymmetry_rate, DiffRow, Outcome};
pub use harness::{measure_ioctl, measure_openat_path_deny, run_openat_suite, HarnessReport};
pub use landlock::abi_version;
