// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! `lockyard agent install|uninstall|status`: a launchd or systemd user unit.
//!
//! The unit names a token file, never a token: a unit file is not a place for a secret.
//!
//! WorkingDirectory is deliberately outside TCC-protected folders (Desktop/Documents). A
//! launchd job whose cwd is `~/Desktop/...` can block forever in `getcwd` waiting for Full
//! Disk Access; the socket never appears (LY-0007). `agent install` copies url / workspace /
//! repository into `~/.local/state/lockyard/agent-config.toml`; the running service reads
//! only that file and never opens the project tree before the socket. Encryption cache stays
//! under the state root (`encryption.json`). After changing `.lockyard/config.toml`, run
//! `lockyard agent install` again.

use lockyard_core::config::Config;
use lockyard_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

const LABEL: &str = "dev.lockyard.agent";
const UNIT: &str = "lockyard-agent.service";
const AGENT_CONFIG_NAME: &str = "agent-config.toml";
/// How long a live service may take to open its socket before status warns about macOS TCC.
pub const SOCKET_WAIT_HINT_AFTER: Duration = Duration::from_secs(5);

/// What a unit needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSpec {
    pub executable: PathBuf,
    /// Safe cwd for the service (home or `~/.local/state/lockyard`).
    pub work_dir: PathBuf,
    pub token_file: PathBuf,
}

/// Snapshot of the project cloud settings the service needs (LY-0007).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentServiceConfig {
    pub url: String,
    pub workspace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    pub project_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_config_mtime: Option<u64>,
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Path of the service settings copy under the state root.
pub fn agent_config_path() -> Result<PathBuf> {
    Ok(super::state_root()
        .map_err(Error::Io)?
        .join(AGENT_CONFIG_NAME))
}

/// Writes url/workspace/repository from the project so the unit never opens Desktop.
pub fn write_agent_config(root: &Path, config: &Config) -> Result<PathBuf> {
    let (url, workspace) = (
        config
            .url
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::Invalid("cloud mode requires url".into()))?,
        config
            .workspace
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::Invalid("cloud mode requires workspace".into()))?,
    );
    let project_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let config_path = project_root.join(".lockyard").join("config.toml");
    let project_config_mtime = fs::metadata(&config_path)
        .ok()
        .and_then(|meta| meta.modified().ok())
        .and_then(|stamp| stamp.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|elapsed| elapsed.as_secs());
    let snapshot = AgentServiceConfig {
        url: url.trim_end_matches('/').to_string(),
        workspace: workspace.to_string(),
        repository: config.repository.clone(),
        project_root: project_root.display().to_string(),
        project_config_mtime,
    };
    let state = super::state_root().map_err(Error::Io)?;
    super::private_dir(&state).map_err(Error::Io)?;
    let path = state.join(AGENT_CONFIG_NAME);
    let text = toml::to_string_pretty(&snapshot)
        .map_err(|error| Error::Invalid(format!("cannot encode agent-config.toml: {error}")))?;
    fs::write(&path, text)?;
    Ok(path)
}

/// Settings the running service uses — never the live project tree.
pub fn load_agent_config() -> Result<AgentServiceConfig> {
    let path = agent_config_path()?;
    let text = fs::read_to_string(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::Invalid(
                "agent-config.toml missing: run `lockyard agent install` from the project".into(),
            )
        } else {
            Error::Io(error)
        }
    })?;
    toml::from_str(&text)
        .map_err(|error| Error::Invalid(format!("invalid agent-config.toml: {error}")))
}

/// True when the copied settings look older than the project's `.lockyard/config.toml`.
pub fn agent_config_stale(snapshot: &AgentServiceConfig) -> bool {
    let project = Path::new(&snapshot.project_root)
        .join(".lockyard")
        .join("config.toml");
    let Ok(meta) = fs::metadata(project) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let Some(current) = modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
    else {
        return false;
    };
    snapshot
        .project_config_mtime
        .is_none_or(|copied| current > copied)
}

/// Text of the launchd property list.
pub fn launchd_plist(spec: &UnitSpec) -> String {
    let (exe, work, token) = (
        xml(&spec.executable.display().to_string()),
        xml(&spec.work_dir.display().to_string()),
        xml(&spec.token_file.display().to_string()),
    );
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>agent</string>
  </array>
  <key>WorkingDirectory</key><string>{work}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>LOCKYARD_TOKEN_FILE</key><string>{token}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
"#
    )
}

fn unit_quote(text: &str) -> String {
    format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}

/// Text of the systemd user unit.
pub fn systemd_unit(spec: &UnitSpec) -> String {
    format!(
        "[Unit]\nDescription=Lockyard agent\n\n[Service]\nExecStart={} agent\nWorkingDirectory={}\nEnvironment={}\nRestart=always\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n",
        unit_quote(&spec.executable.display().to_string()),
        spec.work_dir.display().to_string().replace('%', "%%"),
        unit_quote(&format!(
            "LOCKYARD_TOKEN_FILE={}",
            spec.token_file.display()
        )),
    )
}

/// The file the unit lives in, under `home`.
pub fn unit_path(home: &Path, launchd: bool) -> PathBuf {
    if launchd {
        home.join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist"))
    } else {
        home.join(".config/systemd/user").join(UNIT)
    }
}

fn home() -> Result<PathBuf> {
    lockyard_core::paths::home_dir()
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| Error::Invalid("HOME is not set".into()))
}

fn launchd() -> bool {
    cfg!(target_os = "macos")
}

/// Cwd for the service: state root when available, otherwise `$HOME`.
pub fn service_work_dir() -> Result<PathBuf> {
    match super::state_root() {
        Ok(dir) => {
            super::private_dir(&dir).map_err(Error::Io)?;
            Ok(dir)
        }
        Err(_) => home(),
    }
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "{program} {} failed with {status}",
            args.join(" ")
        )))
    }
}

fn gui_domain() -> String {
    format!("gui/{}", super::uid())
}

/// Writes the unit and, unless `start` is false, starts it.
pub fn install(root: &Path, config: &Config, start: bool) -> Result<PathBuf> {
    let token_file = std::env::var_os("LOCKYARD_TOKEN_FILE").filter(|path| !path.is_empty()).ok_or_else(|| {
        Error::Invalid("agent install needs LOCKYARD_TOKEN_FILE: a token is never written into a unit file".into())
    })?;
    let token_file = PathBuf::from(token_file);
    let token_file = token_file
        .canonicalize()
        .map_err(|error| Error::Invalid(format!("cannot read LOCKYARD_TOKEN_FILE: {error}")))?;
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    write_agent_config(&root, config)?;
    let spec = UnitSpec {
        executable: std::env::current_exe()?,
        work_dir: service_work_dir()?,
        token_file,
    };
    let path = unit_path(&home()?, launchd());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = if launchd() {
        launchd_plist(&spec)
    } else {
        systemd_unit(&spec)
    };
    fs::write(&path, text)?;
    if start {
        if launchd() {
            // Replacing a loaded service fails, and removing one that is absent fails too.
            let _ = run(
                "launchctl",
                &["bootout", &gui_domain(), &path.display().to_string()],
            );
            run(
                "launchctl",
                &["bootstrap", &gui_domain(), &path.display().to_string()],
            )?;
        } else {
            run("systemctl", &["--user", "daemon-reload"])?;
            run("systemctl", &["--user", "enable", "--now", UNIT])?;
        }
    }
    Ok(path)
}

/// Stops the service and removes its unit.
pub fn uninstall(start: bool) -> Result<PathBuf> {
    let path = unit_path(&home()?, launchd());
    if start {
        if launchd() {
            let _ = run(
                "launchctl",
                &["bootout", &gui_domain(), &path.display().to_string()],
            );
        } else {
            let _ = run("systemctl", &["--user", "disable", "--now", UNIT]);
        }
    }
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if start && !launchd() {
        let _ = run("systemctl", &["--user", "daemon-reload"]);
    }
    Ok(path)
}

/// True when the unit file exists.
pub fn installed() -> Result<bool> {
    Ok(unit_path(&home()?, launchd()).is_file())
}

/// Best-effort PID of the installed user service, when the manager reports one.
pub fn service_pid() -> Option<u32> {
    if launchd() {
        let output = Command::new("launchctl")
            .args(["print", &format!("{}/{}", gui_domain(), LABEL)])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("pid = ") {
                return rest.trim().parse().ok().filter(|pid| *pid > 0);
            }
        }
        None
    } else {
        let output = Command::new("systemctl")
            .args(["--user", "show", "-p", "MainPID", "--value", UNIT])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .ok()
            .filter(|pid| *pid > 0)
    }
}

/// Elapsed time since a live process started (`ps etime`), when available.
pub fn process_age(pid: u32) -> Option<Duration> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "etime="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_etime(String::from_utf8_lossy(&output.stdout).trim())
}

/// Parses `ps` elapsed-time forms: `SS`, `MM:SS`, `HH:MM:SS`, `DD-HH:MM:SS`.
pub fn parse_etime(text: &str) -> Option<Duration> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let (days, rest) = match text.split_once('-') {
        Some((days, rest)) => (days.parse::<u64>().ok()?, rest),
        None => (0, text),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    let (hours, minutes, seconds) = match parts.as_slice() {
        [seconds] => (0, 0, seconds.parse::<u64>().ok()?),
        [minutes, seconds] => (
            0,
            minutes.parse::<u64>().ok()?,
            seconds.parse::<u64>().ok()?,
        ),
        [hours, minutes, seconds] => (
            hours.parse::<u64>().ok()?,
            minutes.parse::<u64>().ok()?,
            seconds.parse::<u64>().ok()?,
        ),
        _ => return None,
    };
    Some(Duration::from_secs(
        days * 86_400 + hours * 3_600 + minutes * 60 + seconds,
    ))
}

/// Hint when a managed process is alive but the socket file never appeared (macOS TCC stall).
pub fn socket_missing_hint(socket: &Path) -> Option<&'static str> {
    if socket.exists() {
        return None;
    }
    let pid = service_pid()?;
    let age = process_age(pid).unwrap_or(Duration::ZERO);
    if age < SOCKET_WAIT_HINT_AFTER {
        return None;
    }
    Some(
        "служба не открыла сокет: возможно, ждёт разрешения macOS на папку; \
         Системные настройки → Конфиденциальность → Полный доступ к диску",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> UnitSpec {
        UnitSpec {
            executable: "/opt/a b/lockyard".into(),
            work_dir: "/Users/me/.local/state/lockyard".into(),
            token_file: "/home/me/.config/lockyard/token".into(),
        }
    }

    #[test]
    fn the_launchd_unit_uses_safe_cwd_without_project_root() {
        let text = launchd_plist(&spec());
        assert!(text.contains("<string>/opt/a b/lockyard</string>"));
        assert!(text.contains("<string>agent</string>"));
        assert!(!text.contains("--root"));
        assert!(!text.contains("LOCKYARD_AGENT_ROOT"));
        assert!(!text.contains("/Users/me/Desktop/flexgaming"));
        assert!(text.contains(
            "<key>WorkingDirectory</key><string>/Users/me/.local/state/lockyard</string>"
        ));
        assert!(text.contains(
            "<key>LOCKYARD_TOKEN_FILE</key><string>/home/me/.config/lockyard/token</string>"
        ));
        assert!(!text.contains("LOCKYARD_TOKEN<"));
    }

    #[test]
    fn the_systemd_unit_quotes_its_values_and_keeps_cwd_safe() {
        let text = systemd_unit(&spec());
        assert!(text.contains("ExecStart=\"/opt/a b/lockyard\" agent\n"));
        assert!(
            text.contains("Environment=\"LOCKYARD_TOKEN_FILE=/home/me/.config/lockyard/token\"\n")
        );
        assert!(!text.contains("LOCKYARD_AGENT_ROOT"));
        assert!(text.contains("Restart=always"));
        assert!(!text.contains("LOCKYARD_TOKEN="));
        assert!(text.contains("WorkingDirectory=/Users/me/.local/state/lockyard\n"));
        assert!(!text.contains("WorkingDirectory=/Users/me/Desktop/flexgaming"));
        assert!(!text.contains("WorkingDirectory=\""));
    }

    #[test]
    fn units_land_in_the_folders_their_managers_read() {
        let home = Path::new("/home/me");
        assert!(unit_path(home, true).ends_with("Library/LaunchAgents/dev.lockyard.agent.plist"));
        assert!(unit_path(home, false).ends_with(".config/systemd/user/lockyard-agent.service"));
    }

    #[test]
    fn socket_missing_hint_stays_quiet_when_the_socket_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        fs::write(&socket, b"").unwrap();
        assert!(socket_missing_hint(&socket).is_none());
        assert!(SOCKET_WAIT_HINT_AFTER >= Duration::from_secs(5));
    }

    #[test]
    fn parse_etime_accepts_common_ps_forms() {
        assert_eq!(parse_etime("05"), Some(Duration::from_secs(5)));
        assert_eq!(parse_etime("01:02"), Some(Duration::from_secs(62)));
        assert_eq!(parse_etime("1:02:03"), Some(Duration::from_secs(3723)));
        assert_eq!(
            parse_etime("2-01:02:03"),
            Some(Duration::from_secs(2 * 86_400 + 3723))
        );
    }

    #[test]
    fn process_age_tracks_a_live_child() {
        let mut child = Command::new("sleep").arg("8").spawn().unwrap();
        // `ps etime` is second-resolution; wait past one tick.
        std::thread::sleep(Duration::from_secs(2));
        let age = process_age(child.id()).expect("etime");
        assert!(age >= Duration::from_secs(1), "{age:?}");
        let _ = child.kill();
        let _ = child.wait();
    }
}
