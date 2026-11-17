// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Per-user scheduled task executing the native agent with a private token-file reference.
use lockyard_core::config::Config;
use lockyard_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime},
};

const AGENT_CONFIG_NAME: &str = "agent-config.toml";
/// Kept for parity with the Unix service hint; unused on Windows path checks today.
#[allow(dead_code)]
pub const SOCKET_WAIT_HINT_AFTER: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
struct ServiceSpec {
    executable: PathBuf,
    /// Safe cwd; cloud settings live in agent-config.toml (LY-0007).
    #[serde(default)]
    work_dir: PathBuf,
    token_file: PathBuf,
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
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn path() -> Result<PathBuf> {
    Ok(super::state_root()?.join("agent-service.json"))
}
fn legacy_path() -> Result<PathBuf> {
    Ok(super::state_root()?.join("agent-service.ps1"))
}
fn name() -> String {
    format!("Lockyard-Agent-{}", super::uid())
}
fn powershell(script: &str) -> Result<()> {
    let status = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .status()?;
    if !status.success() {
        return Err(Error::Invalid(format!(
            "user scheduled task update failed: {status}"
        )));
    }
    Ok(())
}
fn task_registration(spec: &ServiceSpec, start: bool) -> String {
    // A real token-file path cannot contain a quote or end with a separator.
    // Quoting it once preserves spaces in the native executable's argv.
    let work = &spec.work_dir;
    let argument = format!(
        "agent --service-token-file \"{}\"",
        spec.token_file.display()
    );
    let start_command = if start {
        format!("; Start-ScheduledTask -TaskName {}", quote(&name()))
    } else {
        String::new()
    };
    format!(
        "$ErrorActionPreference='Stop'; $user=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $a=New-ScheduledTaskAction -Execute {} -Argument {} -WorkingDirectory {}; $p=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited; $t=New-ScheduledTaskTrigger -AtLogOn -User $user; $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable; Register-ScheduledTask -TaskName {} -Action $a -Principal $p -Trigger $t -Settings $settings -Force | Out-Null{}",
        quote(&spec.executable.to_string_lossy()),
        quote(&argument),
        quote(&work.to_string_lossy()),
        quote(&name()),
        start_command,
    )
}
pub fn read_service_token(path: &Path) -> Result<String> {
    let bytes = lockyard_core::windows::read_private(path, 1024 * 1024)?;
    let token = String::from_utf8(bytes)
        .map_err(|_| Error::Invalid("agent service token file is not UTF-8".into()))?;
    let token = token.trim();
    if token.is_empty() {
        return Err(Error::Invalid("agent service token file is empty".into()));
    }
    Ok(token.to_owned())
}
fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
pub fn agent_config_path() -> Result<PathBuf> {
    Ok(super::state_root()?.join(AGENT_CONFIG_NAME))
}

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
    let state = super::state_root()?;
    super::private_dir(&state)?;
    let path = state.join(AGENT_CONFIG_NAME);
    write_agent_snapshot(&path, &snapshot)?;
    Ok(path)
}

fn write_agent_snapshot(path: &Path, snapshot: &AgentServiceConfig) -> Result<()> {
    let text = toml::to_string_pretty(snapshot)
        .map_err(|error| Error::Invalid(format!("cannot encode agent-config.toml: {error}")))?;
    lockyard_core::fsio::replace(path, text.as_bytes(), 0o600)?;
    Ok(())
}

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

pub fn socket_missing_hint(socket: &Path) -> Option<&'static str> {
    if socket.exists() {
        return None;
    }
    None
}

pub fn install(root: &Path, config: &Config, start: bool) -> Result<PathBuf> {
    let token = std::env::var_os("LOCKYARD_TOKEN_FILE")
        .filter(|p| !p.is_empty())
        .ok_or_else(|| Error::Invalid("agent install needs LOCKYARD_TOKEN_FILE".into()))?;
    let token_file = PathBuf::from(token).canonicalize()?;
    // Validate the credential now and again at every scheduled start.
    read_service_token(&token_file)?;
    write_agent_config(root, config)?;
    let work_dir = super::state_root().unwrap_or_else(|_| root.to_path_buf());
    let _ = super::private_dir(&work_dir);
    let spec = ServiceSpec {
        executable: std::env::current_exe()?,
        work_dir,
        token_file,
    };
    let path = path()?;
    super::private_dir(path.parent().expect("service parent"))?;
    let receipt = serde_json::to_vec(&spec).map_err(|error| {
        Error::Invalid(format!(
            "cannot encode agent service configuration: {error}"
        ))
    })?;
    lockyard_core::fsio::replace(&path, &receipt, 0o600)?;
    powershell(&task_registration(&spec, start))?;
    remove_if_present(&legacy_path()?)?;
    Ok(path)
}
pub fn uninstall(start: bool) -> Result<PathBuf> {
    let path = path()?;
    powershell(&format!(
        "$ErrorActionPreference='Stop'; $t=Get-ScheduledTask -TaskName {} -ErrorAction SilentlyContinue; if ($t) {{ {}; Unregister-ScheduledTask -InputObject $t -Confirm:$false }}",
        quote(&name()),
        if start {
            "Stop-ScheduledTask -InputObject $t"
        } else {
            "$null=$t"
        }
    ))?;
    remove_if_present(&path)?;
    remove_if_present(&legacy_path()?)?;
    Ok(path)
}
pub fn installed() -> Result<bool> {
    // The task registry is authoritative, including installations from the old script launcher.
    let status = Command::new("powershell.exe").args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", &format!(
        "$ErrorActionPreference='Stop'; if (Get-ScheduledTask -TaskName {} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 3 }}", quote(&name()))]).status()?;
    match status.code() {
        Some(0) => Ok(true),
        Some(3) => Ok(false),
        _ => Err(Error::Invalid(format!(
            "cannot query user scheduled task: {status}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduled_task_starts_the_native_agent_with_only_a_token_file_reference() {
        let spec = ServiceSpec {
            executable: r"C:\Program Files\Lockyard\lockyard.exe".into(),
            work_dir: r"C:\Users\me\AppData\Local\lockyard".into(),
            token_file: r"C:\Private O'Brien\token".into(),
        };
        let command = task_registration(&spec, false);
        assert!(command.contains("-Execute 'C:\\Program Files\\Lockyard\\lockyard.exe'"));
        assert!(command.contains("-WorkingDirectory 'C:\\Users\\me\\AppData\\Local\\lockyard'"));
        assert!(!command.contains("--root"));
        assert!(command.contains("agent --service-token-file \"C:\\Private O''Brien\\token\""));
        assert!(!command.contains("-ExecutionPolicy"));
        assert!(!command.contains("-File "));
        assert!(!command.contains("powershell.exe"));
        assert!(!command.contains(".ps1"));
        assert!(!command.contains("Start-ScheduledTask"));
        assert!(task_registration(&spec, true).contains("Start-ScheduledTask"));
    }

    #[test]
    fn service_token_is_read_from_a_private_regular_file_and_must_be_nonempty() {
        let root = tempfile::tempdir().unwrap();
        lockyard_core::windows::private_dir(root.path()).unwrap();
        let token = root.path().join("token");
        lockyard_core::fsio::replace(&token, b"  private-value\n", 0o600).unwrap();
        assert_eq!(read_service_token(&token).unwrap(), "private-value");
        lockyard_core::fsio::replace(&token, b" \n", 0o600).unwrap();
        assert!(read_service_token(&token).is_err());
        lockyard_core::fsio::replace(&token, b"private-value", 0o600).unwrap();
        let grant = std::process::Command::new("icacls.exe")
            .arg(&token)
            .args(["/grant", "*S-1-1-0:R"])
            .status()
            .unwrap();
        assert!(grant.success(), "cannot expose fixture token");
        assert!(read_service_token(&token).is_err());
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn snapshot_replaces_complete_file_and_preserves_old_reader() {
        let dir = tempfile::tempdir().unwrap();
        super::super::private_dir(dir.path()).unwrap();
        let path = dir.path().join("agent-config.toml");
        let mut snapshot = AgentServiceConfig {
            url: "http://127.0.0.1:1".into(),
            workspace: "old".into(),
            repository: None,
            project_root: dir.path().display().to_string(),
            project_config_mtime: None,
        };
        write_agent_snapshot(&path, &snapshot).unwrap();
        #[cfg(unix)]
        let mut old_reader = fs::File::open(&path).unwrap();
        snapshot.workspace = "new".into();
        write_agent_snapshot(&path, &snapshot).unwrap();
        let current: AgentServiceConfig =
            toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(current, snapshot);
        #[cfg(unix)]
        {
            use std::io::Read;
            use std::os::unix::fs::PermissionsExt;
            let mut old = String::new();
            old_reader.read_to_string(&mut old).unwrap();
            let old: AgentServiceConfig = toml::from_str(&old).unwrap();
            assert_eq!(
                old.workspace, "old",
                "an open reader must retain the old inode"
            );
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
