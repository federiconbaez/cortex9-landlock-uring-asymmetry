//! Runner diferencial en un proceso hijo (Landlock es irreversible por proceso).

use crate::classify::{asymmetry_rate, DiffRow, Outcome};
use crate::landlock::{
    abi_version, Ruleset, ALL_FS_ACCESS, LANDLOCK_ACCESS_FS_IOCTL_DEV, LANDLOCK_ACCESS_FS_READ_DIR,
    LANDLOCK_ACCESS_FS_READ_FILE,
};
use crate::uring::Ring;
use serde::Serialize;
use std::ffi::CString;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Serialize)]
pub struct HarnessReport {
    pub landlock_abi: i32,
    pub rows: Vec<DiffRow>,
    pub asymmetry_rate: f64,
    pub openat_asymmetry: f64,
    pub ioctl_note: String,
}

fn parse_outcome(s: &str) -> Outcome {
    match s {
        "ok" => Outcome::Ok,
        "denied" => Outcome::Denied,
        "unsupported" => Outcome::Unsupported,
        _ => Outcome::Error,
    }
}

pub fn outcome_str(o: Outcome) -> &'static str {
    match o {
        Outcome::Ok => "ok",
        Outcome::Denied => "denied",
        Outcome::Unsupported => "unsupported",
        Outcome::Error => "error",
    }
}

fn parse_diff_line(op: &str, line: &str) -> std::io::Result<DiffRow> {
    let mut sc = None;
    let mut ur = None;
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("syscall=") {
            sc = Some(parse_outcome(v));
        }
        if let Some(v) = tok.strip_prefix("uring=") {
            ur = Some(parse_outcome(v));
        }
    }
    match (sc, ur) {
        (Some(syscall), Some(uring)) => Ok(DiffRow {
            op: op.into(),
            syscall,
            uring,
        }),
        _ => Err(std::io::Error::other(format!("bad child output: {line:?}"))),
    }
}

fn resolve_cli_exe() -> std::io::Result<std::path::PathBuf> {
    // Prefer the real CLI binary (integration tests set CARGO_BIN_EXE_*).
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_landlock-uring-asymmetry") {
        return Ok(std::path::PathBuf::from(p));
    }
    let exe = std::env::current_exe()?;
    // If we are inside a test harness, try sibling bin in target/{debug,release}.
    if let Some(dir) = exe.parent() {
        let candidate = dir.join("landlock-uring-asymmetry");
        if candidate.exists() {
            return Ok(candidate);
        }
        // deps/ → ../
        if let Some(parent) = dir.parent() {
            let candidate = parent.join("landlock-uring-asymmetry");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    Ok(exe)
}

fn run_labeled_child(args: &[&str], op: &str) -> std::io::Result<DiffRow> {
    let exe = resolve_cli_exe()?;
    let mut child = Command::new(&exe)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut out = String::new();
    child.stdout.as_mut().unwrap().read_to_string(&mut out)?;
    let mut err = String::new();
    child.stderr.as_mut().unwrap().read_to_string(&mut err)?;
    let status = child.wait()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "child {args:?} failed: {status:?} stderr={err} stdout={out}"
        )));
    }
    parse_diff_line(op, out.trim())
}

pub fn measure_openat_path_deny(workspace: &Path) -> std::io::Result<DiffRow> {
    let marker = workspace.join("DENIED_DIR");
    std::fs::create_dir_all(&marker)?;
    let allowed = workspace.join("ALLOWED_DIR");
    std::fs::create_dir_all(&allowed)?;
    std::fs::write(marker.join("secret.txt"), b"x")?;
    std::fs::write(allowed.join("ok.txt"), b"y")?;
    run_labeled_child(
        &[
            "--child-openat",
            workspace.to_str().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-utf8 path")
            })?,
        ],
        "openat_path_deny",
    )
}

pub fn measure_ioctl(device: &str) -> std::io::Result<DiffRow> {
    run_labeled_child(
        &["--child-ioctl", device],
        &format!("ioctl_vs_uring_cmd:{device}"),
    )
}

pub fn run_child_openat(workspace: &Path) -> ! {
    let code = match child_openat_inner(workspace) {
        Ok(row) => {
            println!(
                "syscall={} uring={}",
                outcome_str(row.syscall),
                outcome_str(row.uring)
            );
            0
        }
        Err(e) => {
            eprintln!("child error: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn child_openat_inner(workspace: &Path) -> std::io::Result<DiffRow> {
    let denied = workspace.join("DENIED_DIR").join("secret.txt");
    let allowed = workspace.join("ALLOWED_DIR").join("ok.txt");

    let handled = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    let rs = Ruleset::create(handled)?;
    // Allow runtime + ALLOWED_DIR; omit DENIED_DIR (covered by no rule under handled access).
    for p in ["/usr", "/lib", "/lib64", "/etc", "/proc", "/dev"] {
        if Path::new(p).exists() {
            let _ = rs.add_path_beneath(p, handled);
        }
    }
    rs.add_path_beneath(allowed.parent().unwrap().to_str().unwrap(), handled)?;
    rs.restrict_self()?;

    let ok_path = CString::new(allowed.to_str().unwrap()).unwrap();
    let fd_ok = unsafe { libc::open(ok_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd_ok < 0 {
        return Err(std::io::Error::other(format!(
            "control open allowed failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    unsafe { libc::close(fd_ok) };

    let den_path = CString::new(denied.to_str().unwrap()).unwrap();
    let sc = unsafe { libc::open(den_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    let sc_out = if sc >= 0 {
        unsafe { libc::close(sc) };
        Outcome::Ok
    } else {
        Outcome::from_io_result(&Err(std::io::Error::last_os_error()))
    };

    let mut ring = Ring::setup(8)?;
    let ur_out = match ring.openat(
        libc::AT_FDCWD,
        &den_path,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    ) {
        Ok(fd) if fd >= 0 => {
            unsafe { libc::close(fd) };
            Outcome::Ok
        }
        Ok(fd) => Outcome::from_errno(fd),
        Err(e) => match e.raw_os_error() {
            Some(n) => Outcome::from_errno(-n),
            None => Outcome::Error,
        },
    };

    Ok(DiffRow {
        op: "openat_path_deny".into(),
        syscall: sc_out,
        uring: ur_out,
    })
}

pub fn run_child_ioctl(device: &str) -> ! {
    let code = match child_ioctl_inner(device) {
        Ok(row) => {
            println!(
                "syscall={} uring={}",
                outcome_str(row.syscall),
                outcome_str(row.uring)
            );
            0
        }
        Err(e) => {
            eprintln!("child error: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn child_ioctl_inner(device: &str) -> std::io::Result<DiffRow> {
    let handled = ALL_FS_ACCESS;
    let allowed = ALL_FS_ACCESS & !LANDLOCK_ACCESS_FS_IOCTL_DEV;
    let rs = Ruleset::create(handled)?;
    for p in [
        "/", "/dev", "/usr", "/lib", "/lib64", "/etc", "/proc", "/tmp",
    ] {
        if Path::new(p).exists() {
            rs.add_path_beneath(p, allowed)?;
        }
    }
    rs.restrict_self()?;

    let path = CString::new(device).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    const FIONREAD: u64 = 0x541B;
    let mut buf: i32 = 0;
    let sc = unsafe { libc::ioctl(fd, FIONREAD, &mut buf as *mut _) };
    let sc_out = if sc == 0 {
        Outcome::Ok
    } else {
        Outcome::from_io_result(&Err(std::io::Error::last_os_error()))
    };

    let mut ring = Ring::setup(8)?;
    let mut buf2: i32 = 0;
    let ur_out = match ring.uring_cmd_ioctl(fd, FIONREAD as u32, &mut buf2 as *mut _ as *mut _) {
        Ok(res) if res >= 0 => Outcome::Ok,
        Ok(res) => Outcome::from_errno(res),
        Err(e) => match e.raw_os_error() {
            Some(n) => Outcome::from_errno(-n),
            None => Outcome::Error,
        },
    };
    unsafe { libc::close(fd) };

    Ok(DiffRow {
        op: format!("ioctl_vs_uring_cmd:{device}"),
        syscall: sc_out,
        uring: ur_out,
    })
}

pub fn run_openat_suite(workspace: &Path) -> std::io::Result<HarnessReport> {
    let abi = abi_version()?;
    let row = measure_openat_path_deny(workspace)?;
    let rows = vec![row];
    let openat_asymmetry = asymmetry_rate(&rows);
    Ok(HarnessReport {
        landlock_abi: abi,
        asymmetry_rate: openat_asymmetry,
        openat_asymmetry,
        rows,
        ioctl_note: "IOCTL/URING_CMD control-positive necesita device con uring_cmd (loop/NVMe); ver landlock-uring-enforce".into(),
    })
}
