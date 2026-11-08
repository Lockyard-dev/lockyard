// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Opt-in forwarding probes for the bundled SQLite Win32 VFS.
//!
//! SQLite's `xSetSystemCall` changes the Win32 VFS's process-global syscall table,
//! including for other VFS instances. Install only at single-threaded CLI startup;
//! a cloned/named VFS would not make installation safe after threads have started.

use rusqlite::ffi;
use std::{
    ffi::{CStr, c_void},
    io::Write,
    sync::{
        Once,
        atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering},
    },
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE, SetLastError},
    Security::SECURITY_ATTRIBUTES,
    System::IO::OVERLAPPED,
};

/// Installs diagnostic forwarding probes, only when performance tracing is enabled.
/// Missing VFS capabilities leave the corresponding syscall unchanged and emit a
/// payload-free diagnostic marker. No paths, handles or buffer data are recorded.
///
/// # Safety
/// Call at process startup, before creating any threads or SQLite connections.
/// No other code may concurrently use SQLite or change its VFS syscall table
/// during installation. Installed probes remain valid for the process lifetime.
pub unsafe fn install_before_threads() {
    if !super::enabled() {
        return;
    }
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| unsafe { install() });
}

struct Stats {
    calls: AtomicU64,
    total_us: AtomicU64,
    max_us: AtomicU64,
    requested_ms: AtomicU64,
}

impl Stats {
    const fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
            total_us: AtomicU64::new(0),
            max_us: AtomicU64::new(0),
            requested_ms: AtomicU64::new(0),
        }
    }
}

// Capture and restore both the incoming and outgoing last-error value. The FFI
// callback only measures and updates fixed-size atomics: no allocation or stderr
// writes, whose anonymous pipe backpressure could otherwise inflate COMMIT.
fn timed<T>(stats: &Stats, call: impl FnOnce() -> T) -> T {
    let incoming = unsafe { GetLastError() };
    let started = Instant::now();
    unsafe { SetLastError(incoming) };
    let result = call();
    let outgoing = unsafe { GetLastError() };
    let elapsed = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    stats.calls.fetch_add(1, Ordering::Relaxed);
    stats.total_us.fetch_add(elapsed, Ordering::Relaxed);
    stats.max_us.fetch_max(elapsed, Ordering::Relaxed);
    unsafe { SetLastError(outgoing) };
    result
}

macro_rules! probe {
    ($module:ident, ($($arg:ident: $ty:ty),*) -> $ret:ty) => {
        mod $module {
            use super::*;

            pub(super) static ORIGINAL: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
            pub(super) static STATS: Stats = Stats::new();
            type Call = unsafe extern "system" fn($($ty),*) -> $ret;

            pub(super) unsafe extern "system" fn traced($($arg: $ty),*) -> $ret {
                // Installation publishes an original with this exact Win32 ABI
                // before exposing this callback to SQLite. It is never cleared.
                let original = unsafe {
                    std::mem::transmute::<*mut (), Call>(ORIGINAL.load(Ordering::Acquire))
                };
                timed(&STATS, || unsafe { original($($arg),*) })
            }
        }
    };
}

probe!(flush_file_buffers, (file: HANDLE) -> i32);
probe!(write_file, (file: HANDLE, buffer: *const c_void, bytes: u32, written: *mut u32, overlapped: *mut OVERLAPPED) -> i32);
probe!(lock_file_ex, (file: HANDLE, flags: u32, reserved: u32, bytes_low: u32, bytes_high: u32, overlapped: *mut OVERLAPPED) -> i32);
probe!(unlock_file_ex, (file: HANDLE, reserved: u32, bytes_low: u32, bytes_high: u32, overlapped: *mut OVERLAPPED) -> i32);
probe!(create_file_w, (name: *const u16, access: u32, sharing: u32, security: *mut SECURITY_ATTRIBUTES, disposition: u32, attributes: u32, template: HANDLE) -> HANDLE);
probe!(delete_file_w, (name: *const u16) -> i32);
probe!(close_handle, (handle: HANDLE) -> i32);

mod sleep {
    use super::*;

    pub(super) static ORIGINAL: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
    pub(super) static STATS: Stats = Stats::new();
    type Call = unsafe extern "system" fn(u32);

    pub(super) unsafe extern "system" fn traced(milliseconds: u32) {
        // Same publication/ABI invariant as the other forwarding callbacks.
        let original =
            unsafe { std::mem::transmute::<*mut (), Call>(ORIGINAL.load(Ordering::Acquire)) };
        STATS
            .requested_ms
            .fetch_add(u64::from(milliseconds), Ordering::Relaxed);
        timed(&STATS, || unsafe { original(milliseconds) });
    }
}

/// Emits the bounded process totals once, after the measured command returns.
/// All syscall callbacks stay free of output; this preserves COMMIT timings even
/// when the diagnostic process's stderr is an anonymous pipe. Call after SQLite
/// connections have closed to include any close/unlock work.
pub fn flush() {
    if !super::enabled() {
        return;
    }
    let incoming = unsafe { GetLastError() };
    static FLUSHED: AtomicBool = AtomicBool::new(false);
    if !FLUSHED.swap(true, Ordering::Relaxed) {
        for (label, stats) in [
            (
                "windows.sqlite.flush_file_buffers",
                &flush_file_buffers::STATS,
            ),
            ("windows.sqlite.write_file", &write_file::STATS),
            ("windows.sqlite.lock_file_ex", &lock_file_ex::STATS),
            ("windows.sqlite.unlock_file_ex", &unlock_file_ex::STATS),
            ("windows.sqlite.sleep", &sleep::STATS),
            ("windows.sqlite.create_file_w", &create_file_w::STATS),
            ("windows.sqlite.delete_file_w", &delete_file_w::STATS),
            ("windows.sqlite.close_handle", &close_handle::STATS),
        ] {
            let calls = stats.calls.load(Ordering::Relaxed);
            if calls == 0 {
                continue;
            }
            let total = stats.total_us.load(Ordering::Relaxed);
            let max = stats.max_us.load(Ordering::Relaxed);
            let requested = stats.requested_ms.load(Ordering::Relaxed);
            let _ = writeln!(std::io::stderr().lock(), "perf_span {label} us={total}");
            let _ = writeln!(
                std::io::stderr().lock(),
                "perf_io {label} calls={calls} max_us={max} requested_ms={requested}"
            );
        }
    }
    unsafe { SetLastError(incoming) };
}

unsafe fn install() {
    let vfs = unsafe { ffi::sqlite3_vfs_find(std::ptr::null()) };
    if vfs.is_null() || unsafe { (*vfs).iVersion } < 3 {
        let _ = writeln!(
            std::io::stderr().lock(),
            "perf_diag windows.sqlite_syscalls unsupported=vfs_version"
        );
        return;
    }
    let (Some(get), Some(set)) = (unsafe { (*vfs).xGetSystemCall }, unsafe {
        (*vfs).xSetSystemCall
    }) else {
        let _ = writeln!(
            std::io::stderr().lock(),
            "perf_diag windows.sqlite_syscalls unsupported=vfs_methods"
        );
        return;
    };
    let mut installed = 0;
    macro_rules! install_probe {
        ($module:ident, $name:literal) => {{
            let name: &CStr = $name;
            if let Some(original) = unsafe { get(vfs, name.as_ptr()) } {
                $module::ORIGINAL.store(original as *mut (), Ordering::Release);
                // sqlite3_syscall_ptr is an intentionally untyped C function
                // pointer. SQLite casts it back to the documented Win32 ABI.
                let replacement = unsafe {
                    std::mem::transmute::<*const (), unsafe extern "C" fn()>(
                        $module::traced as *const (),
                    )
                };
                if unsafe { set(vfs, name.as_ptr(), Some(replacement)) } == ffi::SQLITE_OK {
                    installed += 1;
                } else {
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "perf_diag windows.sqlite_syscalls unsupported=set_{}",
                        name.to_string_lossy()
                    );
                }
            } else {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "perf_diag windows.sqlite_syscalls unsupported=get_{}",
                    name.to_string_lossy()
                );
            }
        }};
    }
    install_probe!(flush_file_buffers, c"FlushFileBuffers");
    install_probe!(write_file, c"WriteFile");
    install_probe!(lock_file_ex, c"LockFileEx");
    install_probe!(unlock_file_ex, c"UnlockFileEx");
    install_probe!(sleep, c"Sleep");
    install_probe!(create_file_w, c"CreateFileW");
    install_probe!(delete_file_w, c"DeleteFileW");
    install_probe!(close_handle, c"CloseHandle");
    let _ = writeln!(
        std::io::stderr().lock(),
        "perf_diag windows.sqlite_syscalls installed={installed} requested=8"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_preserves_forwarded_results_and_thread_last_error() {
        let stats = Stats::new();
        for (incoming, outgoing, expected) in [(11, 22, 1), (33, 44, 0)] {
            unsafe { SetLastError(incoming) };
            let result = timed(&stats, || {
                assert_eq!(unsafe { GetLastError() }, incoming);
                unsafe { SetLastError(outgoing) };
                expected
            });
            let observed = unsafe { GetLastError() };
            assert_eq!(result, expected);
            assert_eq!(observed, outgoing);
        }
        assert_eq!(stats.calls.load(Ordering::Relaxed), 2);
        assert!(stats.total_us.load(Ordering::Relaxed) >= stats.max_us.load(Ordering::Relaxed));
    }
}
