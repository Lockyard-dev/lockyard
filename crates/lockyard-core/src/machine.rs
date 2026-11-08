// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Local machine measurements and the guard's level state machine.

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    #[default]
    Ok,
    Warn,
    Hold,
    Critical,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MachineConfig {
    pub warn_memory_percent: Option<f64>,
    pub hold_memory_percent: Option<f64>,
    pub critical_memory_percent: Option<f64>,
    pub warn_disk_bytes: Option<u64>,
    pub hold_disk_bytes: Option<u64>,
    pub critical_disk_bytes: Option<u64>,
    pub warn_load_per_cpu: Option<f64>,
    pub hold_load_per_cpu: Option<f64>,
    pub swap_growth_bytes: Option<u64>,
    /// macOS only: whether the kernel's own pressure signal raises the level. On by default.
    pub use_kernel_pressure: Option<bool>,
    pub slots: Option<usize>,
    pub reserve_bytes: Option<u64>,
    pub heavy_commands: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct Sample {
    pub memory_total: u64,
    pub memory_available: u64,
    pub swap_used: u64,
    pub pressure: Option<Level>,
    pub disk_free: Option<u64>,
    pub disk_total: u64,
    pub temp_free: Option<u64>,
    pub temp_total: u64,
    pub load: f64,
    pub cpus: usize,
}

impl Sample {
    pub fn lowest_known_disk_free(self) -> Option<u64> {
        match (self.disk_free, self.temp_free) {
            (Some(root), Some(temp)) => Some(root.min(temp)),
            (Some(root), None) => Some(root),
            (None, Some(temp)) => Some(temp),
            (None, None) => None,
        }
    }
}

pub fn macos_pressure(level: i32) -> Option<Level> {
    match level {
        4.. => Some(Level::Critical),
        2..=3 => Some(Level::Hold),
        _ => None,
    }
}

pub fn macos_available(total: u64, percent: i32) -> u64 {
    total.saturating_mul(percent.clamp(0, 100) as u64) / 100
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Thresholds {
    pub warn_memory_percent: f64,
    pub hold_memory_percent: f64,
    pub critical_memory_percent: f64,
    pub warn_disk_bytes: u64,
    pub hold_disk_bytes: u64,
    pub critical_disk_bytes: u64,
    pub warn_load_per_cpu: f64,
    pub hold_load_per_cpu: f64,
    pub swap_growth_bytes: u64,
    pub use_kernel_pressure: bool,
}

impl MachineConfig {
    pub fn config_path(
        xdg: Option<&std::path::Path>,
        home: Option<&std::path::Path>,
    ) -> Option<std::path::PathBuf> {
        xdg.map(|path| path.join("lockyard/machine.toml"))
            .or_else(|| home.map(|path| path.join(".config/lockyard/machine.toml")))
    }

    pub fn user_config_path() -> std::io::Result<std::path::PathBuf> {
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from);
        let home = crate::paths::home_dir()
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from);
        Self::config_path(xdg.as_deref(), home.as_deref())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "HOME is not set"))
    }

    pub fn load_user() -> Self {
        Self::user_config_path()
            .ok()
            .and_then(|path| {
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|text| toml::from_str(&text).ok())
            })
            .unwrap_or_default()
    }

    pub fn thresholds(&self, sample: Sample) -> Thresholds {
        let gb = 1_000_000_000;
        let capacity = sample.disk_total.min(sample.temp_total);
        let disk_limit = |per_mille: u64, floor: u64, fallback: u64| {
            if capacity == 0 {
                fallback
            } else {
                ((capacity as u128 * per_mille as u128 / 1000) as u64).max(floor)
            }
        };
        Thresholds {
            warn_memory_percent: self.warn_memory_percent.unwrap_or(15.0),
            hold_memory_percent: self.hold_memory_percent.unwrap_or(8.0),
            critical_memory_percent: self.critical_memory_percent.unwrap_or(4.0),
            warn_disk_bytes: self
                .warn_disk_bytes
                .unwrap_or(disk_limit(70, 3 * gb, 7 * gb)),
            hold_disk_bytes: self
                .hold_disk_bytes
                .unwrap_or(disk_limit(40, 2 * gb, 4 * gb)),
            critical_disk_bytes: self
                .critical_disk_bytes
                .unwrap_or(disk_limit(15, gb, 2 * gb)),
            warn_load_per_cpu: self.warn_load_per_cpu.unwrap_or(1.5),
            hold_load_per_cpu: self.hold_load_per_cpu.unwrap_or(2.5),
            swap_growth_bytes: self
                .swap_growth_bytes
                .unwrap_or((sample.memory_total / 100).max(64 * 1024 * 1024)),
            use_kernel_pressure: self.use_kernel_pressure.unwrap_or(true),
        }
    }
    pub fn slots(&self, sample: Sample) -> usize {
        self.slots
            .unwrap_or((sample.cpus / 4).max(1))
            .min((sample.memory_total / (2 * 1024 * 1024 * 1024)).max(1) as usize)
            .max(1)
    }
    pub fn heavy_commands(&self) -> Vec<String> {
        self.heavy_commands.clone().unwrap_or_else(|| {
            [
                "cargo build",
                "cargo test",
                "dotnet build",
                "dotnet test",
                "pnpm build",
                "npm run build",
                "pnpm test",
                "pnpm run build",
                "make",
                "gradle",
                "mvn",
                "go build",
                "go test",
                "next build",
                "playwright",
                "docker build",
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        })
    }
}

pub fn previous_swap_if_fresh(
    previous: Option<u64>,
    sampled_at_ms: i64,
    now_ms: i64,
) -> Option<u64> {
    (sampled_at_ms > 0 && now_ms.saturating_sub(sampled_at_ms) < 60_000)
        .then_some(previous)
        .flatten()
}

pub trait Sampler {
    fn sample(&mut self) -> std::io::Result<Sample>;
}

#[derive(Default)]
pub struct SystemSampler;
impl Sampler for SystemSampler {
    fn sample(&mut self) -> std::io::Result<Sample> {
        system_sample()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Levels {
    level: Level,
    lower_for_ms: u64,
}
impl Default for Levels {
    fn default() -> Self {
        Self {
            level: Level::Ok,
            lower_for_ms: 0,
        }
    }
}
impl Levels {
    pub fn level(&self) -> Level {
        self.level
    }
    pub fn classify(
        &mut self,
        sample: Sample,
        previous_swap: Option<u64>,
        thresholds: Thresholds,
        elapsed: Duration,
    ) -> Level {
        self.update(sample, previous_swap, thresholds, elapsed)
    }
    pub fn update(
        &mut self,
        sample: Sample,
        previous_swap: Option<u64>,
        thresholds: Thresholds,
        elapsed: Duration,
    ) -> Level {
        let available = if sample.memory_total == 0 {
            100.0
        } else {
            sample.memory_available as f64 * 100.0 / sample.memory_total as f64
        };
        let low_disk = sample.lowest_known_disk_free();
        let disk_level = low_disk
            .map(|free| {
                if free < thresholds.critical_disk_bytes {
                    Level::Critical
                } else if free < thresholds.hold_disk_bytes {
                    Level::Hold
                } else if free < thresholds.warn_disk_bytes {
                    Level::Warn
                } else {
                    Level::Ok
                }
            })
            .unwrap_or(Level::Ok);
        let memory_level = if available < thresholds.critical_memory_percent {
            Level::Critical
        } else if available < thresholds.hold_memory_percent {
            Level::Hold
        } else if available < thresholds.warn_memory_percent {
            Level::Warn
        } else {
            Level::Ok
        };
        let load_level = if sample.load > thresholds.hold_load_per_cpu * sample.cpus.max(1) as f64 {
            Level::Hold
        } else if sample.load > thresholds.warn_load_per_cpu * sample.cpus.max(1) as f64 {
            Level::Warn
        } else {
            Level::Ok
        };
        let swap_level = if previous_swap
            .is_some_and(|p| sample.swap_used.saturating_sub(p) >= thresholds.swap_growth_bytes)
        {
            Level::Hold
        } else {
            Level::Ok
        };
        let desired = [
            memory_level,
            disk_level,
            load_level,
            swap_level,
            sample
                .pressure
                .filter(|_| thresholds.use_kernel_pressure)
                .unwrap_or(Level::Ok),
        ]
        .into_iter()
        .max_by_key(|level| *level as u8)
        .unwrap_or(Level::Ok);
        if desired as u8 >= self.level as u8 {
            self.level = desired;
            self.lower_for_ms = 0;
        } else if desired != self.level {
            self.lower_for_ms = self.lower_for_ms.saturating_add(elapsed.as_millis() as u64);
            if self.lower_for_ms >= 30_000 {
                self.level = desired;
                self.lower_for_ms = 0;
            }
        }
        self.level
    }
}

#[cfg(target_os = "linux")]
fn system_sample() -> std::io::Result<Sample> {
    use std::{fs, path::Path};
    let mem = fs::read_to_string("/proc/meminfo")?;
    let val = |name: &str| {
        mem.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            * 1024
    };
    let (memory_total, memory_available) = (val("MemTotal:"), val("MemAvailable:"));
    let swap_used = val("SwapTotal:").saturating_sub(val("SwapFree:"));
    let stat = |path: &Path| -> (Option<u64>, u64) {
        let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe {
            libc::statvfs(
                std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
                    .ok()
                    .as_ref()
                    .map_or(std::ptr::null(), |p| p.as_ptr()),
                s.as_mut_ptr(),
            )
        } == 0
        {
            let s = unsafe { s.assume_init() };
            // libc's statvfs field widths vary by target. Keep the calculation in u64 even
            // where a conversion is currently redundant (as on 64-bit Linux).
            #[allow(clippy::unnecessary_cast)]
            let available = s.f_bavail as u64;
            #[allow(clippy::unnecessary_cast)]
            let blocks = s.f_blocks as u64;
            #[allow(clippy::unnecessary_cast)]
            let fragment_size = s.f_frsize as u64;
            (
                Some(available.saturating_mul(fragment_size)),
                blocks.saturating_mul(fragment_size),
            )
        } else {
            (None, 0)
        }
    };
    let (root, root_total) = stat(Path::new("/"));
    let (temp, temp_total) = stat(Path::new(std::env::temp_dir().to_str().unwrap_or("/tmp")));
    let mut load = [0.0; 3];
    unsafe {
        libc::getloadavg(load.as_mut_ptr(), 3);
    }
    Ok(Sample {
        memory_total,
        memory_available,
        swap_used,
        pressure: None,
        disk_free: root,
        disk_total: root_total,
        temp_free: temp,
        temp_total,
        load: load[0],
        cpus: std::thread::available_parallelism().map_or(1, usize::from),
    })
}

#[cfg(target_os = "macos")]
fn system_sample() -> std::io::Result<Sample> {
    use std::{ffi::CString, mem::MaybeUninit, path::Path};
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Swap {
        total: u64,
        avail: u64,
        used: u64,
        pagesize: i32,
        encrypted: i32,
    }
    unsafe extern "C" {
        fn sysctlbyname(
            name: *const libc::c_char,
            oldp: *mut libc::c_void,
            oldlenp: *mut usize,
            newp: *mut libc::c_void,
            newlen: usize,
        ) -> libc::c_int;
    }
    fn sysval<T: Copy>(name: &str) -> Option<T> {
        let n = CString::new(name).ok()?;
        let mut v = MaybeUninit::<T>::uninit();
        let mut len = std::mem::size_of::<T>();
        (unsafe {
            sysctlbyname(
                n.as_ptr(),
                v.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } == 0)
            .then(|| unsafe { v.assume_init() })
    }
    let total = sysval::<u64>("hw.memsize").unwrap_or(0);
    // Darwin exports these counters as sysctl values and avoids spawning vm_stat.
    let pressure = sysval::<i32>("kern.memorystatus_vm_pressure_level").and_then(macos_pressure);
    let swap = sysval::<Swap>("vm.swapusage").unwrap_or(Swap {
        total: 0,
        avail: 0,
        used: 0,
        pagesize: 0,
        encrypted: 0,
    });
    let disk = |path: &Path| {
        let name = CString::new(path.as_os_str().as_encoded_bytes()).ok();
        let mut s = MaybeUninit::<libc::statvfs>::uninit();
        if unsafe {
            libc::statvfs(
                name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr()),
                s.as_mut_ptr(),
            )
        } == 0
        {
            let s = unsafe { s.assume_init() };
            (
                Some((s.f_bavail as u64).saturating_mul(s.f_frsize)),
                (s.f_blocks as u64).saturating_mul(s.f_frsize),
            )
        } else {
            (None, 0)
        }
    };
    let (disk_free, disk_total) = disk(Path::new("/System/Volumes/Data"));
    let (temp_free, temp_total) = disk(&std::env::temp_dir());
    let mut load = [0.0; 3];
    unsafe {
        libc::getloadavg(load.as_mut_ptr(), 3);
    }
    Ok(Sample {
        memory_total: total,
        memory_available: macos_available(
            total,
            sysval::<i32>("kern.memorystatus_level").unwrap_or(0),
        ),
        swap_used: swap.used,
        pressure,
        disk_free,
        disk_total,
        temp_free,
        temp_total,
        load: load[0],
        cpus: std::thread::available_parallelism().map_or(1, usize::from),
    })
}

#[cfg(windows)]
fn system_sample() -> std::io::Result<Sample> {
    Ok(Sample {
        pressure: None,
        cpus: std::thread::available_parallelism().map_or(1, usize::from),
        ..Sample::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake(Sample);
    impl Sampler for Fake {
        fn sample(&mut self) -> std::io::Result<Sample> {
            Ok(self.0)
        }
    }

    #[test]
    fn macos_fake_kernel_values_drive_memory_and_pressure() {
        assert_eq!(macos_available(1000, 41), 410);
        assert_eq!(macos_pressure(1), None);
        assert_eq!(macos_pressure(2), Some(Level::Hold));
        assert_eq!(macos_pressure(4), Some(Level::Critical));
        let sample = Sample {
            memory_total: 1000,
            memory_available: 410,
            pressure: macos_pressure(2),
            ..Sample::default()
        };
        let mut levels = Levels::default();
        assert_eq!(
            levels.update(
                sample,
                None,
                MachineConfig::default().thresholds(sample),
                Duration::ZERO
            ),
            Level::Hold
        );
        let off = MachineConfig {
            use_kernel_pressure: Some(false),
            ..MachineConfig::default()
        };
        assert_eq!(
            Levels::default().update(sample, None, off.thresholds(sample), Duration::ZERO),
            Level::Ok,
            "the kernel signal can be turned off"
        );
    }

    #[test]
    fn unknown_disk_free_does_not_raise_pressure() {
        let sample = Sample {
            memory_total: 100,
            memory_available: 80,
            disk_free: None,
            temp_free: None,
            cpus: 4,
            ..Sample::default()
        };
        let mut levels = Levels::default();
        assert_eq!(
            levels.update(
                sample,
                None,
                MachineConfig::default().thresholds(sample),
                Duration::ZERO
            ),
            Level::Ok
        );
    }

    #[test]
    fn machine_policy_path_is_shared_user_config() {
        assert_eq!(
            MachineConfig::config_path(
                Some(std::path::Path::new("/xdg")),
                Some(std::path::Path::new("/home/u"))
            ),
            Some(std::path::PathBuf::from("/xdg/lockyard/machine.toml"))
        );
        assert_eq!(
            MachineConfig::config_path(None, Some(std::path::Path::new("/home/u"))),
            Some(std::path::PathBuf::from(
                "/home/u/.config/lockyard/machine.toml"
            ))
        );
    }

    #[test]
    fn swap_baseline_is_discarded_after_a_sixty_second_gap() {
        assert_eq!(previous_swap_if_fresh(Some(10), 1_000, 60_999), Some(10));
        assert_eq!(previous_swap_if_fresh(Some(10), 1_000, 61_000), None);
    }
    #[test]
    fn fake_sampler_drives_levels_and_config_overrides_defaults() {
        let s = Sample {
            memory_total: 100,
            memory_available: 2,
            disk_free: Some(20_000_000_000),
            temp_free: Some(20_000_000_000),
            cpus: 4,
            ..Sample::default()
        };
        let mut fake = Fake(s);
        let got = fake.sample().unwrap();
        let mut levels = Levels::default();
        assert_eq!(
            levels.update(
                got,
                None,
                MachineConfig::default().thresholds(got),
                Duration::ZERO
            ),
            Level::Critical
        );
        assert_eq!(
            MachineConfig {
                critical_memory_percent: Some(1.0),
                ..Default::default()
            }
            .thresholds(got)
            .critical_memory_percent,
            1.0
        );
    }
    #[test]
    fn levels_rise_immediately_and_fall_after_thirty_seconds() {
        let base = Sample {
            memory_total: 100,
            memory_available: 50,
            disk_free: Some(30_000_000_000),
            temp_free: Some(30_000_000_000),
            cpus: 4,
            ..Sample::default()
        };
        let thresholds = MachineConfig::default().thresholds(base);
        let mut levels = Levels::default();
        assert_eq!(
            levels.update(base, None, thresholds, Duration::from_secs(5)),
            Level::Ok
        );
        let warn = Sample {
            memory_available: 14,
            ..base
        };
        assert_eq!(
            levels.update(warn, None, thresholds, Duration::from_secs(5)),
            Level::Warn
        );
        assert_eq!(
            levels.update(base, None, thresholds, Duration::from_secs(5)),
            Level::Warn
        );
        assert_eq!(
            levels.update(base, None, thresholds, Duration::from_secs(25)),
            Level::Ok
        );
    }

    #[test]
    fn swap_growth_holds_once_and_recovers_without_flapping() {
        let sample = Sample {
            memory_total: 100 * 1_000_000_000,
            memory_available: 50 * 1_000_000_000,
            disk_free: Some(100 * 1_000_000_000),
            temp_free: Some(100 * 1_000_000_000),
            disk_total: 500 * 1_000_000_000,
            temp_total: 500 * 1_000_000_000,
            cpus: 4,
            ..Sample::default()
        };
        let config = MachineConfig::default();
        let mut levels = Levels::default();
        let thresholds = config.thresholds(sample);
        assert_eq!(thresholds.warn_disk_bytes, 35 * 1_000_000_000);
        assert_eq!(thresholds.hold_disk_bytes, 20 * 1_000_000_000);
        assert_eq!(thresholds.critical_disk_bytes, 7_500_000_000);
        assert_eq!(
            levels.update(sample, Some(0), thresholds, Duration::from_secs(5)),
            Level::Ok
        );
        assert_eq!(
            levels.update(
                Sample {
                    swap_used: thresholds.swap_growth_bytes,
                    ..sample
                },
                Some(0),
                thresholds,
                Duration::from_secs(5)
            ),
            Level::Hold
        );
        assert_eq!(
            levels.update(sample, Some(0), thresholds, Duration::from_secs(5)),
            Level::Hold
        );
        assert_eq!(
            levels.update(sample, Some(0), thresholds, Duration::from_secs(25)),
            Level::Ok
        );
    }
    #[test]
    fn fake_samples_cover_warn_hold_critical_and_recovery() {
        let safe = Sample {
            memory_total: 100,
            disk_free: Some(30_000_000_000),
            temp_free: Some(30_000_000_000),
            cpus: 4,
            ..Sample::default()
        };
        let mut fake = Fake(Sample {
            memory_available: 50,
            ..safe
        });
        let config = MachineConfig::default();
        let mut levels = Levels::default();
        let mut tick = |sample: Sample, seconds| {
            fake.0 = sample;
            let observed = fake.sample().unwrap();
            levels.update(
                observed,
                None,
                config.thresholds(observed),
                Duration::from_secs(seconds),
            )
        };
        assert_eq!(
            tick(
                Sample {
                    memory_available: 14,
                    ..safe
                },
                5
            ),
            Level::Warn
        );
        assert_eq!(
            tick(
                Sample {
                    memory_available: 7,
                    ..safe
                },
                5
            ),
            Level::Hold
        );
        assert_eq!(
            tick(
                Sample {
                    memory_available: 3,
                    ..safe
                },
                5
            ),
            Level::Critical
        );
        assert_eq!(
            tick(
                Sample {
                    memory_available: 50,
                    ..safe
                },
                29
            ),
            Level::Critical
        );
        assert_eq!(
            tick(
                Sample {
                    memory_available: 50,
                    ..safe
                },
                1
            ),
            Level::Ok
        );
    }
}
