// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Bound synchronous libc DNS latency and abandoned resolver workers.
use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Instant,
};

const MAX_IN_FLIGHT: usize = 16;
static IN_FLIGHT: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

pub(crate) fn resolve(netloc: &str, deadline: Instant) -> io::Result<Vec<SocketAddr>> {
    if let Ok(address) = netloc.parse::<SocketAddr>() {
        if Instant::now() >= deadline {
            return Err(timeout());
        }
        return Ok(vec![address]);
    }
    let name = netloc.to_owned();
    resolve_with(
        IN_FLIGHT
            .get_or_init(|| Arc::new(AtomicUsize::new(0)))
            .clone(),
        deadline,
        move || {
            name.to_socket_addrs()
                .map(|addresses| addresses.take(64).collect())
        },
    )
}

fn timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "node DNS deadline elapsed")
}
fn resolve_with(
    pool: Arc<AtomicUsize>,
    deadline: Instant,
    lookup: impl FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
) -> io::Result<Vec<SocketAddr>> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(timeout)?;
    let mut count = pool.load(Ordering::Acquire);
    loop {
        if count >= MAX_IN_FLIGHT {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "node DNS capacity unavailable",
            ));
        }
        match pool.compare_exchange_weak(count, count + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(current) => count = current,
        }
    }
    struct Reservation(Arc<AtomicUsize>);
    impl Drop for Reservation {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }
    let reservation = Reservation(pool);
    let (sender, receiver) = mpsc::sync_channel(1);
    // A timed-out libc call cannot be cancelled safely. Its reservation stays held
    // until that call exits; repeated requests cannot create unbounded threads.
    std::thread::Builder::new()
        .name("node-dns".into())
        .spawn(move || {
            let _reservation = reservation;
            let _ = sender.send(lookup());
        })
        .map_err(|_| io::Error::other("node DNS worker unavailable"))?;
    receiver
        .recv_timeout(remaining)
        .map_err(|_| timeout())?
        .map_err(|_| io::Error::other("node DNS resolution failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn stalled_dns_times_out_and_keeps_its_capacity_reserved_until_exit() {
        let pool = Arc::new(AtomicUsize::new(0));
        let (release_sender, release_receiver) = mpsc::channel();
        let result = resolve_with(
            pool.clone(),
            Instant::now() + Duration::from_millis(20),
            move || {
                release_receiver.recv().unwrap();
                Ok(vec![])
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(pool.load(Ordering::Acquire), 1);
        release_sender.send(()).unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        while pool.load(Ordering::Acquire) != 0 && Instant::now() < until {
            std::thread::yield_now();
        }
        assert_eq!(pool.load(Ordering::Acquire), 0);
    }
    #[test]
    fn exhausted_pool_rejects_before_starting_a_lookup_and_expired_deadline_rejects_ip() {
        let pool = Arc::new(AtomicUsize::new(MAX_IN_FLIGHT));
        assert_eq!(
            resolve_with(pool, Instant::now() + Duration::from_secs(1), || panic!(
                "must not start"
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            resolve("127.0.0.1:443", Instant::now()).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            resolve("[::1]:443", Instant::now() + Duration::from_secs(1))
                .unwrap()
                .len(),
            1
        );
    }
}
