//! Symbolic errno names and libuv's messages, so OS errors read as in the TypeScript CLI (`cannot read (ENOENT)`).

/// (errno, name, libuv message) for the platforms the CLI runs on.
#[cfg(target_os = "linux")]
const PLATFORM: &[(i32, &str, &str)] = &[
    (35, "EDEADLK", "resource deadlock avoided"),
    (36, "ENAMETOOLONG", "name too long"),
    (39, "ENOTEMPTY", "directory not empty"),
    (40, "ELOOP", "too many symbolic links encountered"),
    (95, "ENOTSUP", "operation not supported on socket"),
    (122, "EDQUOT", "disk quota exceeded"),
];

#[cfg(not(target_os = "linux"))]
const PLATFORM: &[(i32, &str, &str)] = &[
    (11, "EDEADLK", "resource deadlock avoided"),
    (35, "EAGAIN", "resource temporarily unavailable"),
    (45, "ENOTSUP", "operation not supported on socket"),
    (62, "ELOOP", "too many symbolic links encountered"),
    (63, "ENAMETOOLONG", "name too long"),
    (66, "ENOTEMPTY", "directory not empty"),
    (69, "EDQUOT", "disk quota exceeded"),
];

/// The same on Linux and the BSDs (macOS).
const COMMON: &[(i32, &str, &str)] = &[
    (1, "EPERM", "operation not permitted"),
    (2, "ENOENT", "no such file or directory"),
    (4, "EINTR", "interrupted system call"),
    (5, "EIO", "i/o error"),
    (6, "ENXIO", "no such device or address"),
    (9, "EBADF", "bad file descriptor"),
    (12, "ENOMEM", "not enough memory"),
    (13, "EACCES", "permission denied"),
    (16, "EBUSY", "resource busy or locked"),
    (17, "EEXIST", "file already exists"),
    (18, "EXDEV", "cross-device link not permitted"),
    (19, "ENODEV", "no such device"),
    (20, "ENOTDIR", "not a directory"),
    (21, "EISDIR", "illegal operation on a directory"),
    (22, "EINVAL", "invalid argument"),
    (23, "ENFILE", "file table overflow"),
    (24, "EMFILE", "too many open files"),
    (26, "ETXTBSY", "text file is busy"),
    (27, "EFBIG", "file too large"),
    (28, "ENOSPC", "no space left on device"),
    (30, "EROFS", "read-only file system"),
    (32, "EPIPE", "broken pipe"),
];

fn find(n: i32) -> Option<&'static (i32, &'static str, &'static str)> {
    COMMON.iter().chain(PLATFORM).find(|e| e.0 == n)
}

pub fn errno_name(n: i32) -> Option<&'static str> {
    find(n).map(|e| e.1)
}

/// `ENOENT` for an OS error with a known errno, else the error's own text.
pub fn io_code(e: &std::io::Error) -> String {
    e.raw_os_error().and_then(errno_name).map_or_else(|| e.to_string(), str::to_string)
}

/// Node's form of a failed file call: `ENOENT: no such file or directory, open 'x'`.
pub fn node_message(e: &std::io::Error, syscall: &str, path: &str) -> String {
    match e.raw_os_error().and_then(find) {
        Some((_, name, msg)) => format!("{name}: {msg}, {syscall} '{path}'"),
        None => format!("{e}, {syscall} '{path}'"),
    }
}
