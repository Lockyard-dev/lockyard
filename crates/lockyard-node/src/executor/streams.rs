// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

#[cfg(test)]
#[cfg(unix)]
pub(super) fn drain<W: Write>(
    reader: impl Read,
    spool: Arc<Mutex<Spool<W>>>,
    secrets: Vec<Vec<u8>>,
    stopped: Arc<AtomicBool>,
) -> std::result::Result<(), &'static str> {
    let matcher =
        Arc::new(CredentialMatcher::new(&secrets).map_err(|_| "credential_matcher_unavailable")?);
    drain_matched(reader, spool, matcher, stopped)
}
pub(super) fn drain_matched<W: Write>(
    mut reader: impl Read,
    spool: Arc<Mutex<Spool<W>>>,
    matcher: Arc<CredentialMatcher>,
    stopped: Arc<AtomicBool>,
) -> std::result::Result<(), &'static str> {
    let mut pending = Vec::new();
    let mut buf = [0u8; 4096];
    let mut failure = None;
    loop {
        let count = match reader.read(&mut buf) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if stopped.load(Ordering::SeqCst) {
                    0
                } else {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                failure = Some("stream_read_failed");
                0
            }
        };
        pending.extend_from_slice(&buf[..count]);
        let mut output = Vec::new();
        let safe = if count == 0 {
            pending.len()
        } else {
            pending
                .len()
                .saturating_sub(matcher.longest.saturating_sub(1))
        };
        let mut pos = 0;
        if let Some(automaton) = &matcher.automaton {
            for found in automaton.find_iter(&pending) {
                if found.start() >= safe {
                    break;
                }
                output.extend_from_slice(&pending[pos..found.start()]);
                output.extend_from_slice(b"[REDACTED]");
                pos = found.end();
            }
        }
        if pos < safe {
            output.extend_from_slice(&pending[pos..safe]);
            pos = safe;
        }
        pending.drain(..pos);
        match spool.lock() {
            Ok(mut spool) => {
                if let Some(code) = failure {
                    spool.mark_error(code);
                }
                if spool.append(&output, &matcher).is_err() {
                    failure.get_or_insert("spool_write_failed");
                }
            }
            Err(poisoned) => {
                poisoned.into_inner().mark_error("spool_lock_poisoned");
                failure.get_or_insert("spool_lock_poisoned");
            }
        }
        // A sink failure never stops draining the process pipe. EOF/read failure still ends it.
        if count == 0 {
            break;
        }
    }
    match failure {
        Some(code) => Err(code),
        None => Ok(()),
    }
}

pub(super) fn join_stream(
    handle: thread::JoinHandle<std::result::Result<(), &'static str>>,
) -> Option<&'static str> {
    match handle.join() {
        Ok(Ok(())) => None,
        Ok(Err(code)) => Some(code),
        Err(_) => Some("stream_thread_failed"),
    }
}
