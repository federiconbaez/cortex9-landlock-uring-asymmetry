use landlock_uring_asymmetry::{asymmetry_rate, DiffRow, Outcome};

#[test]
fn openat_equivalence_is_zero_asymmetry() {
    let rows = vec![DiffRow {
        op: "openat_path_deny".into(),
        syscall: Outcome::Denied,
        uring: Outcome::Denied,
    }];
    assert_eq!(asymmetry_rate(&rows), 0.0);
}

#[test]
fn ioctl_bypass_is_full_asymmetry() {
    let rows = vec![DiffRow {
        op: "ioctl".into(),
        syscall: Outcome::Denied,
        uring: Outcome::Ok,
    }];
    assert_eq!(asymmetry_rate(&rows), 1.0);
}
