//! Control positivo IOCTL_DEV vs URING_CMD.
//!
//! Falla fuerte si:
//! - no hay Landlock,
//! - el device no soporta uring_cmd (EOPNOTSUPP), o
//! - no se observa la asimetría conocida (syscall=Denied, uring=Ok).
//!
//! En la box típica (/dev/zero) uring_cmd → Unsupported: exit 2.
//! En VM/CI con loop/NVMe que implemente uring_cmd: exit 0 si hay asimetría.

use landlock_uring_asymmetry::harness::measure_ioctl;
use landlock_uring_asymmetry::{abi_version, Outcome};
use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let device = env::args()
        .nth(1)
        .unwrap_or_else(|| "/dev/zero".to_string());
    match abi_version() {
        Ok(v) => println!("landlock_abi={v}"),
        Err(e) => {
            eprintln!("landlock unavailable: {e}");
            return ExitCode::from(2);
        }
    }
    match measure_ioctl(&device) {
        Ok(row) => {
            println!(
                "op={} syscall={:?} uring={:?}",
                row.op, row.syscall, row.uring
            );
            if row.uring == Outcome::Unsupported {
                eprintln!(
                    "enforce FAIL: device {device} no implementa uring_cmd \
                     (EOPNOTSUPP/ENOTTY). Hace falta loop/NVMe en VM/CI. \
                     No es un skip."
                );
                return ExitCode::from(2);
            }
            if row.syscall == Outcome::Denied && row.uring == Outcome::Ok {
                println!("control_positive=DETECTED");
                ExitCode::SUCCESS
            } else if row.syscall == Outcome::Denied && row.uring == Outcome::Denied {
                eprintln!(
                    "enforce FAIL: ambos denegados — el bypass reportado no aparece \
                     en este kernel/device (¿hook uring_cmd ya mergeado?)"
                );
                ExitCode::from(3)
            } else {
                eprintln!("enforce FAIL: resultado inesperado {row:?}");
                ExitCode::from(2)
            }
        }
        Err(e) => {
            eprintln!("enforce FAIL: {e}");
            ExitCode::from(2)
        }
    }
}
