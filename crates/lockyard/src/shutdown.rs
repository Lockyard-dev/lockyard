// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Signal handling and final WAL maintenance for long-lived commands only.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(100);
static REQUESTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn requested() -> bool {
    REQUESTED.load(Ordering::Relaxed)
}

#[cfg(unix)]
extern "C" fn request(_signal: libc::c_int) {
    // The handler never touches SQLite, allocates, locks or writes a log.
    REQUESTED.store(true, Ordering::Relaxed);
}

#[cfg(windows)]
unsafe extern "system" fn console_request(event: u32) -> i32 {
    if matches!(event, 0 | 1 | 2 | 5 | 6) {
        REQUESTED.store(true, Ordering::Relaxed);
        1
    } else {
        0
    }
}

/// Declare before worker/runtime/store owners: they must stop before its final checkpoint.
pub(crate) struct Guard {
    cwd: PathBuf,
    #[cfg(unix)]
    previous: [(libc::c_int, libc::sigaction); 2],
}

impl Guard {
    pub(crate) fn new(cwd: &Path) -> io::Result<Self> {
        REQUESTED.store(false, Ordering::Relaxed);
        #[cfg(unix)]
        {
            // sigaction fully initializes the output structures on success. A zeroed input
            // with sigemptyset and no SA_RESTART is a plain, process-wide flag handler.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = request as *const () as libc::sighandler_t;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            let mut interrupt: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(libc::SIGINT, &action, &mut interrupt) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut terminate: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(libc::SIGTERM, &action, &mut terminate) } != 0 {
                let error = io::Error::last_os_error();
                unsafe { libc::sigaction(libc::SIGINT, &interrupt, std::ptr::null_mut()) };
                return Err(error);
            }
            Ok(Self {
                cwd: cwd.to_path_buf(),
                previous: [(libc::SIGINT, interrupt), (libc::SIGTERM, terminate)],
            })
        }
        #[cfg(windows)]
        {
            lockyard_core::windows::console_handler(console_request, true)?;
            Ok(Self {
                cwd: cwd.to_path_buf(),
            })
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(windows)]
        let _ = lockyard_core::windows::console_handler(console_request, false);
        if let Err(error) = lockyard_core::Store::checkpoint_on_shutdown(&self.cwd) {
            eprintln!(
                "lockyard shutdown: WAL checkpoint incomplete; retain database sidecars: {error}"
            );
        }
        #[cfg(unix)]
        for (signal, previous) in &self.previous {
            unsafe { libc::sigaction(*signal, previous, std::ptr::null_mut()) };
        }
    }
}
