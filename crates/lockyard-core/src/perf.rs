// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Opt-in, payload-free CLI profiling. Disabled unless `LOCKYARD_PERF_TRACE=1`.
use std::{sync::OnceLock, time::Instant};

/// A diagnostic wall-time span. Labels must never contain paths, identities or payloads.
pub struct Span {
    label: &'static str,
    started: Option<Instant>,
}

impl Span {
    pub fn new(label: &'static str) -> Self {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        let enabled =
            *ENABLED.get_or_init(|| std::env::var("LOCKYARD_PERF_TRACE").as_deref() == Ok("1"));
        Self {
            label,
            started: enabled.then(Instant::now),
        }
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            // Diagnostics must never turn a successful durable write into a failed command.
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr().lock(),
                "perf_span {} us={}",
                self.label,
                started.elapsed().as_micros()
            );
        }
    }
}
