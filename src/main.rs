//! CLI del harness Landlock × io_uring.

use clap::{Parser, Subcommand};
use landlock_uring_asymmetry::harness::{
    measure_ioctl, run_child_ioctl, run_child_openat, run_openat_suite,
};
use landlock_uring_asymmetry::{abi_version, asymmetry_rate};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "landlock-uring-asymmetry",
    about = "Diferencial Landlock: syscall vs io_uring"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// Modo hijo (uso interno).
    #[arg(long, hide = true)]
    child_openat: Option<PathBuf>,
    #[arg(long, hide = true)]
    child_ioctl: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Mide asimetría OPENAT (path deny) bajo Landlock. Corre en la box.
    Openat {
        #[arg(long, default_value = "/tmp/ll-uring-ws")]
        workspace: PathBuf,
    },
    /// Intenta ioctl vs URING_CMD sobre un device (suele ser unsupported en char simples).
    Ioctl {
        #[arg(long, default_value = "/dev/zero")]
        device: String,
    },
    /// Imprime ABI Landlock y sale.
    Abi,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Some(ws) = cli.child_openat {
        run_child_openat(&ws);
    }
    if let Some(dev) = cli.child_ioctl {
        run_child_ioctl(&dev);
    }
    match cli.cmd.unwrap_or(Cmd::Abi) {
        Cmd::Abi => match abi_version() {
            Ok(v) => {
                println!("landlock_abi={v}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("abi: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::Openat { workspace } => match run_openat_suite(&workspace) {
            Ok(r) => {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
                println!(
                    "MEASURE openat_asymmetry={:.4} (rows={})",
                    r.openat_asymmetry,
                    r.rows.len()
                );
                if r.openat_asymmetry == 0.0
                    && r.rows.iter().all(|row| {
                        row.both_denied()
                            || row.syscall == landlock_uring_asymmetry::Outcome::Denied
                    })
                {
                    ExitCode::SUCCESS
                } else if r.openat_asymmetry == 0.0 {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::Ioctl { device } => match measure_ioctl(&device) {
            Ok(row) => {
                println!("{}", serde_json::to_string_pretty(&row).unwrap());
                println!("asymmetry={}", asymmetry_rate(std::slice::from_ref(&row)));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
    }
}
