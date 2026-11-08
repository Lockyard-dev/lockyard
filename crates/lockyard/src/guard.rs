// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Heavy command admission and the standalone machine report.

use lockyard_core::machine::{Level, Levels, MachineConfig, Sample, Sampler, SystemSampler};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Write};
#[cfg(not(windows))]
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Command, ExitStatus};
#[cfg(not(windows))]
use std::thread;
use std::time::Duration;

#[derive(Serialize)]
pub struct MachineReport {
    pub level: Level,
    pub sample: Sample,
    pub thresholds: lockyard_core::machine::Thresholds,
    pub queue: Vec<i32>,
    pub running_heavy_jobs: Vec<i32>,
    pub paused_jobs: Vec<i32>,
    pub top_consumers: Vec<Consumer>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Consumer {
    pub pid: i32,
    pub memory_bytes: u64,
    pub name: String,
}

#[derive(Default, Serialize, Deserialize)]
struct SharedState {
    sampled_at_ms: i64,
    sample: Sample,
    levels: Levels,
    previous_swap: Option<u64>,
}

#[cfg(unix)]
fn shared_dir() -> std::path::PathBuf {
    crate::agent::state_root()
        .unwrap_or_else(|_| std::path::PathBuf::from("/dev/null/lockyard"))
        .join("machine")
}

#[cfg(not(unix))]
fn shared_dir() -> std::path::PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            lockyard_core::paths::home_dir()
                .map(|home| std::path::PathBuf::from(home).join(".local/state"))
        })
        .unwrap_or_else(|| std::path::PathBuf::from("/dev/null"))
        .join("lockyard/machine")
}

fn ensure_shared_dir() -> io::Result<std::path::PathBuf> {
    let dir = shared_dir();
    #[cfg(unix)]
    crate::agent::private_dir(&dir)?;
    #[cfg(windows)]
    lockyard_core::windows::private_dir(&dir)?;
    Ok(dir)
}

fn acquire_state_lock(lock: &File, hook: bool, has_stale: bool) -> io::Result<bool> {
    #[cfg(unix)]
    {
        let flags = libc::LOCK_EX | if hook { libc::LOCK_NB } else { 0 };
        if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(lock), flags) } == 0 {
            return Ok(true);
        }
        if hook && has_stale {
            return Ok(false);
        }
        if hook {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "machine state unavailable",
            ));
        }
        Err(io::Error::last_os_error())
    }
    #[cfg(not(unix))]
    {
        if !hook {
            lock.lock()?;
            return Ok(true);
        }
        match lock.try_lock() {
            Ok(()) => Ok(true),
            Err(_) if has_stale => Ok(false),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "machine state unavailable",
            )),
        }
    }
}

#[cfg(any(test, not(windows)))]
fn wait_remaining(elapsed: Duration, limit: Duration) -> Option<Duration> {
    limit
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
}

fn with_state(config: &MachineConfig, details: bool) -> io::Result<MachineReport> {
    with_state_mode(config, details, false)
}

fn with_state_mode(config: &MachineConfig, details: bool, hook: bool) -> io::Result<MachineReport> {
    let dir = ensure_shared_dir()?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join("state.lock"))?;
    let path = dir.join("state.json");
    let mut state = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<SharedState>(&bytes).ok())
        .unwrap_or_default();
    let now = now_ms();
    if now.saturating_sub(state.sampled_at_ms) >= 5_000 || state.sampled_at_ms == 0 {
        let owns_lock = acquire_state_lock(&lock, hook, state.sampled_at_ms > 0)?;
        if !owns_lock {
            // The lock holder is refreshing. Hooks use the stale sample and never wait.
        } else {
            let old_at = state.sampled_at_ms;
            let mut sampler = SystemSampler;
            let sample = sampler.sample()?;
            let elapsed = Duration::from_millis(now.saturating_sub(old_at).max(0) as u64);
            state.levels.update(
                sample,
                lockyard_core::machine::previous_swap_if_fresh(state.previous_swap, old_at, now),
                config.thresholds(sample),
                elapsed,
            );
            state.previous_swap = Some(sample.swap_used);
            state.sample = sample;
            state.sampled_at_ms = now;
            let temp = dir.join(format!("state-{}.tmp", std::process::id()));
            let mut file = File::create(&temp)?;
            file.write_all(&serde_json::to_vec(&state).map_err(io::Error::other)?)?;
            lockyard_core::fsio::rename(temp, path)?;
        }
    }
    #[cfg(windows)]
    let level = Level::Warn;
    #[cfg(not(windows))]
    let level = state.levels.level();
    let (queue, running_heavy_jobs, paused_jobs, top_consumers) = if details {
        let queue = queue_records()
            .into_iter()
            .map(|record| record.pid)
            .collect();
        let runners = runner_records();
        let running = runners.iter().map(|record| record.pgid).collect();
        let _ = runners;
        let consumers = top_processes();
        (
            queue,
            running,
            pause_records()
                .into_iter()
                .map(|record| record.pgid)
                .collect(),
            consumers,
        )
    } else {
        (Vec::new(), Vec::new(), Vec::new(), Vec::new())
    };
    let report = MachineReport {
        level,
        thresholds: config.thresholds(state.sample),
        sample: state.sample,
        queue,
        running_heavy_jobs,
        paused_jobs,
        top_consumers,
    };
    let critical_disk = report
        .sample
        .lowest_known_disk_free()
        .is_some_and(|free| free < report.thresholds.critical_disk_bytes);
    if !hook || critical_disk {
        maintain_reserve(config, &report);
    }
    #[cfg(unix)]
    unsafe {
        libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_UN);
    }
    Ok(report)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

pub fn report(config: MachineConfig) -> io::Result<MachineReport> {
    with_state(&config, true)
}

pub fn snapshot(config: &MachineConfig) -> io::Result<MachineReport> {
    with_state(config, false)
}

pub fn tick() {
    let config = MachineConfig::load_user();
    recover_paused_groups();
    if let Ok(report) = with_state(&config, false) {
        maintain_reserve(&config, &report);
    }
}

pub fn recover() {
    recover_paused_groups();
}

pub fn cached_level(config: &MachineConfig) -> io::Result<Level> {
    with_state_mode(config, false, true).map(|report| report.level)
}

pub fn maintain_reserve(config: &MachineConfig, report: &MachineReport) {
    let Ok(dir) = ensure_shared_dir() else { return };
    let path = dir.join("reserve.bin");
    let critical_disk = report
        .sample
        .lowest_known_disk_free()
        .is_some_and(|free| free < report.thresholds.critical_disk_bytes);
    if critical_disk {
        let _ = fs::remove_file(path);
        return;
    }
    if report.level != Level::Ok {
        return;
    }
    if path.exists() {
        return;
    }
    let bytes = config.reserve_bytes.unwrap_or(512 * 1024 * 1024);
    if report
        .sample
        .temp_free
        .is_none_or(|free| free < bytes.saturating_add(report.thresholds.warn_disk_bytes))
    {
        return;
    }
    if let Ok(file) = OpenOptions::new().write(true).create_new(true).open(&path) {
        #[cfg(target_os = "macos")]
        let allocated = unsafe {
            #[repr(C)]
            struct FStore {
                flags: libc::c_int,
                position: libc::c_int,
                offset: libc::off_t,
                length: libc::off_t,
                allocated: libc::off_t,
            }
            let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
            let mut store = FStore {
                flags: 4,
                position: 3,
                offset: 0,
                length: bytes as libc::off_t,
                allocated: 0,
            };
            libc::fcntl(fd, 42, &mut store) == 0 && file.set_len(bytes).is_ok()
        };
        #[cfg(target_os = "linux")]
        let allocated = unsafe {
            unsafe extern "C" {
                fn posix_fallocate(
                    fd: libc::c_int,
                    offset: libc::off_t,
                    len: libc::off_t,
                ) -> libc::c_int;
            }
            posix_fallocate(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                0,
                bytes as libc::off_t,
            )
        } == 0;
        #[cfg(windows)]
        let allocated = {
            use std::io::Write;
            let result = (|| -> io::Result<()> {
                let mut remaining = bytes;
                let zeros = vec![0u8; 1024 * 1024];
                let mut sink = &file;
                while remaining > 0 {
                    let count = remaining.min(zeros.len() as u64) as usize;
                    sink.write_all(&zeros[..count])?;
                    remaining -= count as u64;
                }
                file.sync_all()
            })();
            result.is_ok()
        };
        if !allocated {
            let _ = fs::remove_file(path);
        }
    }
}

pub fn text(report: &MachineReport) -> String {
    let mut out = format!(
        "{}   memory pressure high ({:.0}% free) · swap {} · disk {} free of {}",
        level_text(report.level),
        if report.sample.memory_total == 0 {
            0.0
        } else {
            report.sample.memory_available as f64 * 100.0 / report.sample.memory_total as f64
        },
        human(report.sample.swap_used),
        report
            .sample
            .disk_free
            .map(human)
            .unwrap_or_else(|| "unknown".into()),
        human(report.sample.disk_total),
    );
    out = out.replace("   memory", "  memory");
    if !report.top_consumers.is_empty() {
        out.push_str("\n\ntop memory");
        for job in &report.top_consumers {
            out.push_str(&format!(
                "\n  {}  {} ({})",
                human(job.memory_bytes),
                job.name,
                job.pid
            ));
        }
    }
    out.push_str(&format!(
        "\n\nheavy jobs: {} running, {} queued, {} paused",
        report.running_heavy_jobs.len(),
        report.queue.len(),
        report.paused_jobs.len()
    ));
    if report.sample.swap_used as f64 > report.sample.disk_free.unwrap_or(u64::MAX) as f64 * 0.25 {
        out.push_str("\nhint: swap files live on your disk. Freeing memory frees disk.");
    } else if report
        .sample
        .disk_free
        .is_some_and(|free| free < report.thresholds.warn_disk_bytes)
    {
        out.push_str("\nhint: disk space is below the warning threshold.");
    } else if report.top_consumers.first().is_some_and(|job| {
        report.sample.memory_total > 0
            && job.memory_bytes as f64 > report.sample.memory_total as f64 * 0.4
    }) {
        out.push_str("\nhint: one process is using more than 40% of memory.");
    }
    out
}

#[cfg(target_os = "linux")]
fn top_processes() -> Vec<Consumer> {
    let mut values = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return values;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|v| v.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let mut name = String::new();
        let mut rss = 0u64;
        let mut swap = 0u64;
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("Name:") {
                name = v.trim().to_string();
            }
            if let Some(v) = line
                .strip_prefix("VmRSS:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
            {
                rss = v.saturating_mul(1024);
            }
            if let Some(v) = line
                .strip_prefix("VmSwap:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
            {
                swap = v.saturating_mul(1024);
            }
        }
        if rss + swap > 0 {
            values.push(Consumer {
                pid,
                memory_bytes: rss.saturating_add(swap),
                name,
            });
        }
    }
    values.sort_by_key(|p| std::cmp::Reverse(p.memory_bytes));
    values.truncate(5);
    values
}

#[cfg(target_os = "macos")]
fn top_processes() -> Vec<Consumer> {
    #[repr(C)]
    struct Usage {
        uuid: [u8; 16],
        user: u64,
        system: u64,
        pkg: u64,
        interrupt: u64,
        pageins: u64,
        wired: u64,
        resident: u64,
        footprint: u64,
        rest: [u64; 24],
    }
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_listallpids(buffer: *mut libc::c_void, buffersize: libc::c_int) -> libc::c_int;
        fn proc_pid_rusage(
            pid: libc::c_int,
            flavor: libc::c_int,
            buffer: *mut libc::c_void,
        ) -> libc::c_int;
        fn proc_name(pid: libc::c_int, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
    }
    let n = unsafe { proc_listallpids(std::ptr::null_mut(), 0) }.max(0) as usize;
    let mut pids = vec![0i32; n.saturating_add(128)];
    let count = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), (pids.len() * 4) as i32) }
        .max(0) as usize;
    pids.truncate(count.min(pids.len()));
    let mut values = Vec::new();
    for pid in pids.into_iter().filter(|pid| *pid > 0) {
        let mut usage = std::mem::MaybeUninit::<Usage>::zeroed();
        if unsafe { proc_pid_rusage(pid, 2, usage.as_mut_ptr().cast()) } != 0 {
            continue;
        }
        let memory_bytes = unsafe { usage.assume_init() }.footprint;
        let mut name = [0u8; 256];
        let len =
            unsafe { proc_name(pid, name.as_mut_ptr().cast(), name.len() as u32) }.max(0) as usize;
        if memory_bytes > 0 {
            values.push(Consumer {
                pid,
                memory_bytes,
                name: String::from_utf8_lossy(&name[..len.min(name.len())]).into_owned(),
            });
        }
    }
    values.sort_by_key(|p| std::cmp::Reverse(p.memory_bytes));
    values.truncate(5);
    values
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn top_processes() -> Vec<Consumer> {
    Vec::new()
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn level_text(level: Level) -> &'static str {
    match level {
        Level::Ok => "ok",
        Level::Warn => "warn",
        Level::Hold => "hold",
        Level::Critical => "critical",
    }
}

/// Runs one heavy command. At hold it waits; at critical it refuses admission. A child is paused only
/// through its own process group, which is created immediately before spawning it.
#[cfg(not(windows))]
pub fn run_heavy(
    config: MachineConfig,
    command: &[std::ffi::OsString],
    max_wait: u64,
) -> io::Result<ExitStatus> {
    if command.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a command after --",
        ));
    }
    recover_paused_groups();
    let lock = match acquire_slot(&config, Duration::from_secs(max_wait))? {
        Some(slot) => slot,
        None => {
            eprintln!("lockyard: waited {max_wait} seconds for heavy work; giving up.");
            use std::os::unix::process::ExitStatusExt;
            return Ok(ExitStatus::from_raw(75 << 8));
        }
    };
    let executable = &command[0];
    let mut child_cmd = Command::new(executable);
    child_cmd.args(&command[1..]);
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        child_cmd.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            // If the runner dies while the job is stopped, the kernel sends the orphaned group SIGHUP and
            // SIGCONT. Ignoring SIGHUP lets the job carry on: Lockyard pauses work, it never loses it.
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            Ok(())
        });
    }
    let mut child = child_cmd.spawn()?;
    let pid = child.id() as i32;
    register_runner(pid, &config)?;
    loop {
        if let Some(status) = child.try_wait()? {
            let _ = resume_group(pid);
            remove_pause_record(pid);
            unregister_runner(pid);
            drop(lock);
            return Ok(status);
        }
        // The config is read on every tick, so a changed threshold needs no restart. A failed round must not
        // end supervision: the child would run on with nobody to resume it.
        let current = MachineConfig::load_user();
        match with_state(&current, false).and_then(|report| coordinate_groups(pid, &report)) {
            Ok(()) => {}
            Err(error) => eprintln!("lockyard: machine guard round failed ({error}); retrying."),
        }
        thread::sleep(Duration::from_secs(5));
    }
}

#[derive(Serialize, Deserialize)]
struct PauseRecord {
    owner_pid: i32,
    owner_start: String,
    pgid: i32,
    group_start: String,
    paused_at_ms: i64,
}

#[derive(Serialize, Deserialize)]
struct RunnerRecord {
    owner_pid: i32,
    owner_start: String,
    pgid: i32,
    group_start: String,
    memory_bytes: u64,
}

#[derive(Default, Serialize, Deserialize)]
#[cfg(not(windows))]
struct CoordinationState {
    last_pause_ms: i64,
}

fn pause_dir() -> std::path::PathBuf {
    shared_dir().join("paused")
}

#[cfg(target_os = "macos")]
fn process_bsd_info(pid: i32) -> Option<(u32, u64, u64)> {
    #[repr(C)]
    struct BsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        rfu: u32,
        comm: [u8; 16],
        name: [u8; 32],
        nfiles: u32,
        pgid: u32,
        pjobc: u32,
        tdev: u32,
        tpgid: u32,
        nice: i32,
        start_sec: u64,
        start_usec: u64,
    }
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }
    let mut info = std::mem::MaybeUninit::<BsdInfo>::uninit();
    let size = std::mem::size_of::<BsdInfo>() as libc::c_int;
    let bytes = unsafe { proc_pidinfo(pid, 3, 0, info.as_mut_ptr().cast(), size) };
    if bytes < size {
        return None;
    }
    let info = unsafe { info.assume_init() };
    Some((info.status, info.start_sec, info.start_usec))
}

fn process_start_time(pid: i32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.rsplit_once(") ")?
            .1
            .split_whitespace()
            .nth(19)
            .map(str::to_owned)
    }
    #[cfg(target_os = "macos")]
    {
        process_bsd_info(pid).map(|(_, seconds, micros)| format!("{seconds}.{micros}"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(not(windows))]
fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = File::create(&temp)?;
    file.write_all(&serde_json::to_vec(value).map_err(io::Error::other)?)?;
    file.sync_all()?;
    lockyard_core::fsio::rename(temp, path)
}

#[cfg(not(windows))]
fn register_runner(pgid: i32, _config: &MachineConfig) -> io::Result<()> {
    let Some(owner_start) = process_start_time(std::process::id() as i32) else {
        return Err(io::Error::other("cannot verify runner process identity"));
    };
    let Some(group_start) = process_start_time(pgid) else {
        return Err(io::Error::other("cannot verify child process identity"));
    };
    let dir = shared_dir().join("runners");
    fs::create_dir_all(&dir)?;
    let record = RunnerRecord {
        owner_pid: std::process::id() as i32,
        owner_start,
        pgid,
        group_start,
        memory_bytes: process_memory(pgid).unwrap_or(0),
    };
    write_json_atomic(&dir.join(format!("{}.json", pgid)), &record)
}

#[cfg(not(windows))]
fn update_runner(pgid: i32) -> io::Result<()> {
    let dir = shared_dir().join("runners");
    let path = dir.join(format!("{}.json", pgid));
    let bytes = fs::read(&path)?;
    let mut record: RunnerRecord = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    record.memory_bytes = process_memory(pgid).unwrap_or(record.memory_bytes);
    write_json_atomic(&path, &record)
}

#[cfg(not(windows))]
fn unregister_runner(pgid: i32) {
    let _ = fs::remove_file(shared_dir().join("runners").join(format!("{pgid}.json")));
}

#[cfg(not(windows))]
fn process_memory(pid: i32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let mut total = 0u64;
        let mut found = false;
        for entry in fs::read_dir("/proc").ok()?.flatten() {
            let Some(member) = entry
                .file_name()
                .to_str()
                .and_then(|v| v.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let Some(fields) = stat
                .rsplit_once(") ")
                .map(|(_, rest)| rest.split_whitespace().collect::<Vec<_>>())
            else {
                continue;
            };
            if fields.get(2).and_then(|v| v.parse::<i32>().ok()) != Some(pid) {
                continue;
            }
            let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
                continue;
            };
            let (mut rss, mut swap) = (0, 0);
            for line in status.lines() {
                if let Some(v) = line
                    .strip_prefix("VmRSS:")
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|v| v.parse::<u64>().ok())
                {
                    rss = v;
                }
                if let Some(v) = line
                    .strip_prefix("VmSwap:")
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|v| v.parse::<u64>().ok())
                {
                    swap = v;
                }
            }
            total = total.saturating_add(rss.saturating_add(swap).saturating_mul(1024));
            found = true;
            let _ = member;
        }
        found.then_some(total.max(page))
    }
    #[cfg(target_os = "macos")]
    {
        #[link(name = "proc")]
        unsafe extern "C" {
            fn proc_listpgrppids(
                pgid: libc::c_int,
                buffer: *mut libc::c_int,
                buffersize: libc::c_int,
            ) -> libc::c_int;
            fn proc_pid_rusage(
                pid: libc::c_int,
                flavor: libc::c_int,
                buffer: *mut libc::c_void,
            ) -> libc::c_int;
        }
        let count = unsafe { proc_listpgrppids(pid, std::ptr::null_mut(), 0) }.max(0) as usize;
        let mut pids = vec![0i32; count.saturating_add(32)];
        let got = unsafe { proc_listpgrppids(pid, pids.as_mut_ptr(), (pids.len() * 4) as i32) }
            .max(0) as usize;
        pids.truncate(got.min(pids.len()));
        let mut total = 0u64;
        for member in pids {
            let mut bytes = [0u64; 64];
            if unsafe { proc_pid_rusage(member, 2, bytes.as_mut_ptr().cast()) } == 0 {
                total = total.saturating_add(bytes[8]);
            }
        }
        (total > 0).then_some(total)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(not(windows))]
fn coordinate_groups(own_group: i32, report: &MachineReport) -> io::Result<()> {
    update_runner(own_group)?;
    let dir = shared_dir();
    fs::create_dir_all(&dir)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join("coordinator.lock"))?;
    #[cfg(unix)]
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } == -1 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(windows)]
    lock.lock()?;
    let runner_dir = dir.join("runners");
    let paused_dir = pause_dir();
    fs::create_dir_all(&paused_dir)?;
    let mut runners = Vec::new();
    if let Ok(entries) = fs::read_dir(&runner_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(record) = serde_json::from_slice::<RunnerRecord>(&bytes) else {
                continue;
            };
            if process_start_time(record.owner_pid).as_deref() != Some(record.owner_start.as_str())
                || process_start_time(record.pgid).as_deref() != Some(record.group_start.as_str())
            {
                let _ = fs::remove_file(path);
                continue;
            }
            runners.push(record);
        }
    }
    let mut paused = Vec::new();
    if let Ok(entries) = fs::read_dir(&paused_dir) {
        for entry in entries.flatten() {
            if let Ok(bytes) = fs::read(entry.path())
                && let Ok(record) = serde_json::from_slice::<PauseRecord>(&bytes)
            {
                paused.push(record);
            }
        }
    }
    paused.sort_by_key(|record| record.paused_at_ms);
    if matches!(report.level, Level::Ok | Level::Warn) {
        if let Some(record) = paused.first()
            && process_start_time(record.pgid).as_deref() == Some(record.group_start.as_str())
        {
            resume_group(record.pgid)?;
            remove_pause_record(record.pgid);
            eprintln!("lockyard: pressure eased; resumed the oldest paused heavy job.");
        }
    } else if report.level == Level::Critical {
        let state_path = dir.join("coordinator.json");
        let mut state = fs::read(&state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CoordinationState>(&bytes).ok())
            .unwrap_or_default();
        let now = now_ms();
        if now.saturating_sub(state.last_pause_ms) >= 15_000 {
            runners.sort_by_key(|runner| std::cmp::Reverse(runner.memory_bytes));
            if let Some(runner) = runners
                .iter()
                .find(|runner| !paused.iter().any(|p| p.pgid == runner.pgid))
            {
                let record = PauseRecord {
                    owner_pid: runner.owner_pid,
                    owner_start: runner.owner_start.clone(),
                    pgid: runner.pgid,
                    group_start: runner.group_start.clone(),
                    paused_at_ms: now,
                };
                write_json_atomic(&paused_dir.join(format!("{}.json", runner.pgid)), &record)?;
                if let Err(error) = pause_group(runner.pgid) {
                    remove_pause_record(runner.pgid);
                    return Err(error);
                }
                state.last_pause_ms = now;
                write_json_atomic(&state_path, &state)?;
                eprintln!("lockyard: critical pressure; paused the largest Lockyard heavy job.");
            }
        }
    }
    #[cfg(unix)]
    unsafe {
        libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_UN);
    }
    Ok(())
}

#[cfg(not(windows))]
fn remove_pause_record(pgid: i32) {
    let _ = fs::remove_file(pause_dir().join(format!("{pgid}.json")));
}

fn recover_paused_groups() {
    recover_paused_groups_in(&pause_dir());
}

fn recover_paused_groups_in(dir: &Path) {
    recover_paused_groups_from(dir);
}

fn recover_paused_groups_from(directory: &Path) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(record) = fs::read(&path).and_then(|bytes| {
            serde_json::from_slice::<PauseRecord>(&bytes).map_err(io::Error::other)
        }) else {
            continue;
        };
        let owner_alive =
            process_start_time(record.owner_pid).is_some_and(|start| start == record.owner_start);
        if owner_alive {
            continue;
        }
        if process_start_time(record.pgid).is_some_and(|start| start == record.group_start) {
            let _ = resume_group(record.pgid);
        }
        let _ = fs::remove_file(path);
    }
}

#[cfg(windows)]
pub fn run_heavy(
    _: MachineConfig,
    command: &[std::ffi::OsString],
    _: u64,
) -> io::Result<ExitStatus> {
    let (program, args) = command.split_first().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "expected a command after --")
    })?;
    Command::new(program).args(args).status()
}

#[cfg(unix)]
#[cfg(not(windows))]
fn pause_group(pid: i32) -> io::Result<()> {
    signal_group(pid, libc::SIGSTOP)
}
#[cfg(unix)]
fn resume_group(pid: i32) -> io::Result<()> {
    signal_group(pid, libc::SIGCONT)
}
#[cfg(unix)]
fn signal_group(pid: i32, signal: i32) -> io::Result<()> {
    if unsafe { libc::kill(-pid, signal) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[cfg(not(unix))]
#[cfg(not(windows))]
fn pause_group(_: i32) -> io::Result<()> {
    Ok(())
}
#[cfg(not(unix))]
fn resume_group(_: i32) -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
struct Slot {
    _file: File,
}
#[cfg(not(windows))]
struct QueueTicket {
    path: std::path::PathBuf,
    id: u64,
}
#[cfg(not(windows))]
impl Drop for QueueTicket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
#[derive(Serialize, Deserialize)]
struct QueueRecord {
    id: u64,
    pid: i32,
    start: String,
}

fn heavy_dir() -> std::path::PathBuf {
    shared_dir()
}

fn queue_records() -> Vec<QueueRecord> {
    let mut records = Vec::new();
    if let Ok(entries) = fs::read_dir(heavy_dir()) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(bytes) = fs::read(&path)
                && let Ok(record) = serde_json::from_slice::<QueueRecord>(&bytes)
            {
                if process_start_time(record.pid).as_deref() == Some(record.start.as_str()) {
                    records.push(record);
                } else {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }
    records.sort_by_key(|record| record.id);
    records
}

fn runner_records() -> Vec<RunnerRecord> {
    let mut records = Vec::new();
    if let Ok(entries) = fs::read_dir(shared_dir().join("runners")) {
        for entry in entries.flatten() {
            if let Ok(bytes) = fs::read(entry.path())
                && let Ok(record) = serde_json::from_slice::<RunnerRecord>(&bytes)
                && process_start_time(record.owner_pid).as_deref()
                    == Some(record.owner_start.as_str())
                && process_start_time(record.pgid).as_deref() == Some(record.group_start.as_str())
            {
                records.push(record);
            }
        }
    }
    records.sort_by_key(|record| record.pgid);
    records
}

fn pause_records() -> Vec<PauseRecord> {
    let mut records = Vec::new();
    if let Ok(entries) = fs::read_dir(pause_dir()) {
        for entry in entries.flatten() {
            if let Ok(bytes) = fs::read(entry.path())
                && let Ok(record) = serde_json::from_slice::<PauseRecord>(&bytes)
                && process_start_time(record.pgid).as_deref() == Some(record.group_start.as_str())
            {
                records.push(record);
            }
        }
    }
    records.sort_by_key(|record| record.paused_at_ms);
    records
}

#[cfg(not(windows))]
fn acquire_slot(config: &MachineConfig, max_wait: Duration) -> io::Result<Option<Slot>> {
    let limit = config.slots(with_state(config, false)?.sample);
    let base = heavy_dir();
    std::fs::create_dir_all(&base)?;
    let ticket = make_ticket(&base)?;
    let began = std::time::Instant::now();
    let mut last_message = String::new();
    loop {
        let current = with_state(config, false)?;
        let critical_disk = current
            .sample
            .lowest_known_disk_free()
            .is_some_and(|free| free < current.thresholds.critical_disk_bytes);
        if current.level == Level::Critical && critical_disk {
            drop(ticket);
            eprintln!(
                "lockyard: critical pressure; heavy work is refused. See `lockyard machine`."
            );
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "critical machine pressure",
            ));
        }
        let held = matches!(current.level, Level::Hold | Level::Critical);
        if !held && ticket_is_first(&base, ticket.id) {
            for n in 0..limit {
                let path = base.join(format!("slot-{n}"));
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&path)?;
                #[cfg(unix)]
                if unsafe {
                    libc::flock(
                        std::os::fd::AsRawFd::as_raw_fd(&file),
                        libc::LOCK_EX | libc::LOCK_NB,
                    )
                } == 0
                {
                    drop(ticket);
                    return Ok(Some(Slot { _file: file }));
                }
                #[cfg(not(unix))]
                {
                    drop(ticket);
                    return Ok(Some(Slot { _file: file }));
                }
            }
        }
        let message = format!(
            "lockyard: heavy work waiting at {} pressure; retrying in 5 seconds",
            if held {
                level_text(current.level)
            } else {
                "slot limit"
            }
        );
        if message != last_message {
            eprintln!("{message}");
            last_message = message;
        }
        let Some(remaining) = wait_remaining(began.elapsed(), max_wait) else {
            drop(ticket);
            return Ok(None);
        };
        thread::sleep(Duration::from_secs(5).min(remaining));
    }
}

#[cfg(not(windows))]
fn make_ticket(base: &Path) -> io::Result<QueueTicket> {
    let counter_path = base.join("queue-counter");
    let mut counter = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&counter_path)?;
    #[cfg(unix)]
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&counter), libc::LOCK_EX) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut old = String::new();
    counter.read_to_string(&mut old)?;
    let id = old.trim().parse::<u64>().unwrap_or(0).saturating_add(1);
    counter.seek(SeekFrom::Start(0))?;
    counter.set_len(0)?;
    write!(counter, "{id}")?;
    counter.sync_all()?;
    #[cfg(unix)]
    unsafe {
        libc::flock(std::os::fd::AsRawFd::as_raw_fd(&counter), libc::LOCK_UN);
    }
    let start = process_start_time(std::process::id() as i32)
        .ok_or_else(|| io::Error::other("cannot verify runner process identity"))?;
    let path = base.join(format!("queue-{id:020}.json"));
    let bytes = serde_json::to_vec(&QueueRecord {
        id,
        pid: std::process::id() as i32,
        start,
    })
    .map_err(io::Error::other)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(QueueTicket { path, id })
}

#[cfg(not(windows))]
fn ticket_is_first(base: &Path, id: u64) -> bool {
    let Ok(entries) = fs::read_dir(base) else {
        return true;
    };
    let mut ids = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("queue-") || !name.ends_with(".json") {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<QueueRecord>(&bytes) else {
            let _ = fs::remove_file(path);
            continue;
        };
        if process_start_time(record.pid).as_deref() != Some(record.start.as_str()) {
            let _ = fs::remove_file(path);
        } else {
            ids.push(record.id);
        }
    }
    ids.sort_unstable();
    ids.first() == Some(&id)
}
pub fn project_config(cwd: &Path) -> MachineConfig {
    let _ = cwd;
    MachineConfig::load_user()
}

#[cfg(windows)]
use lockyard_core::windows::OpenOptions;
#[cfg(unix)]
use std::fs::OpenOptions;

#[cfg(test)]
mod format_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn hook_lock_is_nonblocking_and_uses_stale_state_when_busy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let holder = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&holder), libc::LOCK_EX) },
            0
        );
        assert!(!acquire_state_lock(&contender, true, true).unwrap());
        assert_eq!(
            acquire_state_lock(&contender, true, false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn heavy_wait_deadline_has_no_remaining_wait_after_limit() {
        assert_eq!(
            wait_remaining(Duration::from_secs(5), Duration::from_secs(10)),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            wait_remaining(Duration::from_secs(10), Duration::from_secs(10)),
            None
        );
        assert_eq!(wait_remaining(Duration::ZERO, Duration::ZERO), None);
    }

    #[test]
    fn machine_text_formats_fixed_sample_and_omits_empty_queue() {
        let sample = Sample {
            memory_total: 100_000_000_000,
            memory_available: 41_000_000_000,
            swap_used: 8_700_000_000,
            disk_free: Some(5_000_000_000),
            disk_total: 245_000_000_000,
            temp_free: Some(5_000_000_000),
            cpus: 8,
            ..Sample::default()
        };
        let report = MachineReport {
            level: Level::Hold,
            thresholds: MachineConfig::default().thresholds(sample),
            sample,
            queue: vec![],
            running_heavy_jobs: vec![7],
            paused_jobs: vec![],
            top_consumers: vec![Consumer {
                pid: 7,
                memory_bytes: 12_900_000_000,
                name: "com.apple.Virtualization.VirtualMachine".into(),
            }],
        };
        let output = text(&report);
        assert!(output.contains("hold  memory pressure high (41% free)"));
        assert!(output.contains("swap 8.7 GB · disk 5.0 GB free of 245.0 GB"));
        assert!(
            output.contains("top memory\n  12.9 GB  com.apple.Virtualization.VirtualMachine (7)")
        );
        assert!(output.contains("heavy jobs: 1 running, 0 queued, 0 paused"));
        assert!(!output.contains("queue:"));
    }
}

#[cfg(all(test, unix))]
mod recovery_tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    fn child_group() -> std::process::Child {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        command.spawn().unwrap()
    }

    fn is_stopped(pid: i32) -> bool {
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED) };
        result == pid && status & 0xff == 0x7f
    }

    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let pid = self.0.id() as i32;
            let _ = resume_group(pid);
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn process_state(pid: i32) -> Option<char> {
        #[cfg(target_os = "linux")]
        {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            stat.rsplit_once(") ")?.1.chars().next()
        }
        #[cfg(target_os = "macos")]
        {
            // libproc remains available when the process sandbox disallows invoking ps.
            // Darwin sys/proc.h defines SSTOP=4 and SZOMB=5.
            process_bsd_info(pid).map(|(status, _, _)| match status {
                4 => 'T',
                5 => 'Z',
                _ => 'R',
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let output = Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            String::from_utf8(output.stdout).ok()?.trim().chars().next()
        }
    }

    fn wait_for_state(pid: i32, stopped: bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let state = process_state(pid).expect("the owned test child must remain alive");
            assert!(
                !matches!(state, 'Z' | 'X'),
                "the owned test child must not exit"
            );
            if matches!(state, 'T' | 't') == stopped {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the owned child did not reach the expected state"
            );
            thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn recovery_resumes_a_group_only_when_its_start_time_matches() {
        let child = OwnedChild(child_group());
        let pid = child.0.id() as i32;
        let Some(group_start) = process_start_time(pid) else {
            // Process metadata can be hidden by sandbox policies; this test needs it to
            // distinguish a live group from a reused pid. OwnedChild always cleans up.
            return;
        };
        if pause_group(pid).is_err() {
            return;
        }
        wait_for_state(pid, true);
        // Reap the stop notification before checking that recovery resumes the child.
        assert!(is_stopped(pid));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{pid}.json"));
        let record = PauseRecord {
            owner_pid: i32::MAX,
            owner_start: "gone".into(),
            pgid: pid,
            group_start: group_start.clone(),
            paused_at_ms: now_ms(),
        };
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        recover_paused_groups_in(dir.path());
        wait_for_state(pid, false);
        assert!(!is_stopped(pid));
        assert!(!path.exists());

        if pause_group(pid).is_err() {
            return;
        }
        wait_for_state(pid, true);
        let reused = PauseRecord {
            owner_pid: i32::MAX,
            owner_start: "gone".into(),
            pgid: pid,
            group_start: "different-process".into(),
            paused_at_ms: now_ms(),
        };
        fs::write(&path, serde_json::to_vec(&reused).unwrap()).unwrap();
        recover_paused_groups_from(dir.path());
        assert!(
            is_stopped(pid),
            "a mismatched process start time must never be signalled"
        );
        let until = std::time::Instant::now() + Duration::from_millis(100);
        while std::time::Instant::now() < until {
            assert!(
                matches!(process_state(pid), Some('T' | 't')),
                "a mismatched process start time must never be signalled"
            );
            thread::sleep(Duration::from_millis(2));
        }
        assert!(!path.exists());
    }

    #[test]
    fn machine_tickets_are_first_come_first_served() {
        let dir = tempfile::tempdir().unwrap();
        let first = make_ticket(dir.path()).unwrap();
        let second = make_ticket(dir.path()).unwrap();
        assert!(ticket_is_first(dir.path(), first.id));
        assert!(!ticket_is_first(dir.path(), second.id));
        drop(first);
        assert!(ticket_is_first(dir.path(), second.id));
    }
}
