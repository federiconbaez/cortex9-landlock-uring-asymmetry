//! Medición real OPENAT bajo Landlock en la box.

use landlock_uring_asymmetry::{abi_version, run_openat_suite, Outcome};
use std::path::PathBuf;

#[test]
fn openat_path_deny_asymmetry_is_zero() {
    let abi = abi_version().expect("landlock ABI");
    assert!(abi >= 5, "need Landlock ABI >= 5, got {abi}");

    let ws = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/ll-uring-test-ws");
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(&ws).unwrap();

    let report = run_openat_suite(&ws).expect("harness");
    eprintln!(
        "MEASURE openat_asymmetry={:.4} abi={} row={:?}",
        report.openat_asymmetry, report.landlock_abi, report.rows
    );
    assert_eq!(
        report.openat_asymmetry, 0.0,
        "OPENAT path-deny must be equivalent under Landlock"
    );
    let row = &report.rows[0];
    assert_eq!(row.syscall, Outcome::Denied);
    assert_eq!(row.uring, Outcome::Denied);
}
