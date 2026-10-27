//! Minimal io_uring helper for OPENAT and URING_CMD (no liburing).

use libc::{c_int, c_void, syscall};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const SYS_IO_URING_SETUP: c_int = 425;
const SYS_IO_URING_ENTER: c_int = 426;
const IORING_OFF_SQ_RING: u64 = 0;
const IORING_OFF_CQ_RING: u64 = 0x8000000;
const IORING_OFF_SQES: u64 = 0x10000000;
const IORING_ENTER_GETEVENTS: u32 = 1;

pub const IORING_OP_OPENAT: u8 = 18;
pub const IORING_OP_URING_CMD: u8 = 46;

#[repr(C)]
struct SqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
struct CqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
struct Params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SqringOffsets,
    cq_off: CqringOffsets,
}

#[repr(C)]
struct Sqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off_or_cmd: u64, // off / (cmd_op + pad)
    addr: u64,
    len: u32,
    opcode_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    file_index: u32,
    addr3: u64,
    pad2: u64,
}

#[repr(C)]
struct Cqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

pub struct Ring {
    _fd: OwnedFd,
    sq: *mut u8,
    cq: *mut u8,
    sqes: *mut Sqe,
    sq_off: SqringOffsets,
    cq_off: CqringOffsets,
    sq_entries: u32,
    cq_entries: u32,
    sq_map_len: usize,
    cq_map_len: usize,
}

impl Ring {
    pub fn setup(entries: u32) -> io::Result<Self> {
        let mut params: Params = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            syscall(
                SYS_IO_URING_SETUP as _,
                entries as c_int,
                &mut params as *mut Params as *mut c_void,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(rc as c_int) };
        let sq_len = (params.sq_off.array as usize) + (params.sq_entries as usize) * 4;
        let cq_len = (params.cq_off.cqes as usize)
            + (params.cq_entries as usize) * std::mem::size_of::<Cqe>();
        let sq = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                sq_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd.as_raw_fd(),
                IORING_OFF_SQ_RING as i64,
            )
        };
        if sq == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let cq = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cq_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd.as_raw_fd(),
                IORING_OFF_CQ_RING as i64,
            )
        };
        if cq == libc::MAP_FAILED {
            unsafe { libc::munmap(sq, sq_len) };
            return Err(io::Error::last_os_error());
        }
        let sqes = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                (params.sq_entries as usize) * std::mem::size_of::<Sqe>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd.as_raw_fd(),
                IORING_OFF_SQES as i64,
            )
        };
        if sqes == libc::MAP_FAILED {
            unsafe {
                libc::munmap(sq, sq_len);
                libc::munmap(cq, cq_len);
            }
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            _fd: fd,
            sq: sq as *mut u8,
            cq: cq as *mut u8,
            sqes: sqes as *mut Sqe,
            sq_off: params.sq_off,
            cq_off: params.cq_off,
            sq_entries: params.sq_entries,
            cq_entries: params.cq_entries,
            sq_map_len: sq_len,
            cq_map_len: cq_len,
        })
    }

    fn submit_one(&mut self, sqe: Sqe) -> io::Result<i32> {
        unsafe {
            let slot = self.sqes;
            std::ptr::write(slot, sqe);
            let array = self.sq.add(self.sq_off.array as usize) as *mut u32;
            let tail = self.sq.add(self.sq_off.tail as usize) as *mut u32;
            std::ptr::write_volatile(array, 0);
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            std::ptr::write_volatile(tail, 1);
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        }
        let rc = unsafe {
            syscall(
                SYS_IO_URING_ENTER as _,
                self._fd.as_raw_fd(),
                1i32,
                1i32,
                IORING_ENTER_GETEVENTS as c_int,
                std::ptr::null::<c_void>(),
                0usize,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            let head = self.cq.add(self.cq_off.head as usize) as *mut u32;
            let tail = self.cq.add(self.cq_off.tail as usize) as *const u32;
            let h = std::ptr::read_volatile(head);
            let t = std::ptr::read_volatile(tail);
            if t == h {
                return Err(io::Error::other("no CQE"));
            }
            let cqes = self.cq.add(self.cq_off.cqes as usize) as *const Cqe;
            let idx = (h & (self.cq_entries - 1)) as isize;
            let cqe = std::ptr::read(cqes.offset(idx));
            std::ptr::write_volatile(head, h + 1);
            Ok(cqe.res)
        }
    }

    pub fn openat(
        &mut self,
        dfd: i32,
        path: &std::ffi::CStr,
        flags: i32,
        mode: u32,
    ) -> io::Result<i32> {
        let sqe = Sqe {
            opcode: IORING_OP_OPENAT,
            flags: 0,
            ioprio: 0,
            fd: dfd,
            off_or_cmd: 0,
            addr: path.as_ptr() as u64,
            len: mode,
            opcode_flags: flags as u32,
            user_data: 0x4f50454e,
            buf_index: 0,
            personality: 0,
            file_index: 0,
            addr3: 0,
            pad2: 0,
        };
        self.submit_one(sqe)
    }

    /// Submit IORING_OP_URING_CMD with cmd_op (e.g. an ioctl request).
    pub fn uring_cmd_ioctl(&mut self, fd: i32, cmd_op: u32, arg: *mut c_void) -> io::Result<i32> {
        let sqe = Sqe {
            opcode: IORING_OP_URING_CMD,
            flags: 0,
            ioprio: 0,
            fd,
            off_or_cmd: cmd_op as u64, // low 32 = cmd_op
            addr: arg as u64,
            len: 0,
            opcode_flags: 0, // uring_cmd_flags
            user_data: 0x434d44,
            buf_index: 0,
            personality: 0,
            file_index: 0,
            addr3: 0,
            pad2: 0,
        };
        self.submit_one(sqe)
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.sq as *mut c_void, self.sq_map_len);
            libc::munmap(self.cq as *mut c_void, self.cq_map_len);
            libc::munmap(
                self.sqes as *mut c_void,
                (self.sq_entries as usize) * std::mem::size_of::<Sqe>(),
            );
        }
    }
}

// silence unused cq_entries warning via allow in submit
#[allow(dead_code)]
fn _touch(r: &Ring) {
    let _ = r.cq_entries;
}
