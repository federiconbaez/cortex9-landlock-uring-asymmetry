//! Clasificación de resultados syscall vs io_uring.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    Denied,
    Unsupported,
    Error,
}

impl Outcome {
    pub fn from_errno(res: i32) -> Self {
        if res >= 0 {
            return Outcome::Ok;
        }
        match -res {
            libc::EACCES | libc::EPERM => Outcome::Denied,
            libc::EOPNOTSUPP | libc::ENOTTY | libc::EINVAL | libc::ENOSYS => Outcome::Unsupported,
            _ => Outcome::Error,
        }
    }

    pub fn from_io_result(r: &std::io::Result<i32>) -> Self {
        match r {
            Ok(v) if *v >= 0 => Outcome::Ok,
            Ok(v) => Outcome::from_errno(*v),
            Err(e) => match e.raw_os_error() {
                Some(libc::EACCES) | Some(libc::EPERM) => Outcome::Denied,
                Some(libc::EOPNOTSUPP)
                | Some(libc::ENOTTY)
                | Some(libc::EINVAL)
                | Some(libc::ENOSYS) => Outcome::Unsupported,
                _ => Outcome::Error,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffRow {
    pub op: String,
    pub syscall: Outcome,
    pub uring: Outcome,
}

impl DiffRow {
    /// Asimetría de valor: syscall niega y uring permite.
    pub fn is_asymmetry(&self) -> bool {
        self.syscall == Outcome::Denied && self.uring == Outcome::Ok
    }

    /// Ambos niegan (equivalencia esperada bajo Landlock).
    pub fn both_denied(&self) -> bool {
        self.syscall == Outcome::Denied && self.uring == Outcome::Denied
    }
}

/// Tasa de asimetría = (# syscall=Denied ∧ uring=Ok) / N.
pub fn asymmetry_rate(rows: &[DiffRow]) -> f64 {
    if rows.is_empty() {
        return 0.0;
    }
    let n = rows.iter().filter(|r| r.is_asymmetry()).count();
    n as f64 / rows.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asymmetry_detected() {
        let rows = vec![
            DiffRow {
                op: "ioctl".into(),
                syscall: Outcome::Denied,
                uring: Outcome::Ok,
            },
            DiffRow {
                op: "openat".into(),
                syscall: Outcome::Denied,
                uring: Outcome::Denied,
            },
        ];
        assert!(rows[0].is_asymmetry());
        assert!(!rows[1].is_asymmetry());
        assert!((asymmetry_rate(&rows) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn errno_mapping() {
        assert_eq!(Outcome::from_errno(3), Outcome::Ok);
        assert_eq!(Outcome::from_errno(-libc::EACCES), Outcome::Denied);
        assert_eq!(Outcome::from_errno(-libc::EOPNOTSUPP), Outcome::Unsupported);
    }
}
