// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Per-user scheduled task executing the native agent with a private token-file reference.
use lockyard_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Serialize, Deserialize)]
struct ServiceSpec {
    executable: PathBuf,
    root: PathBuf,
    token_file: PathBuf,
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
        quote(&spec.root.to_string_lossy()),
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
pub fn install(root: &Path, start: bool) -> Result<PathBuf> {
    let token = std::env::var_os("LOCKYARD_TOKEN_FILE")
        .filter(|p| !p.is_empty())
        .ok_or_else(|| Error::Invalid("agent install needs LOCKYARD_TOKEN_FILE".into()))?;
    let token_file = PathBuf::from(token).canonicalize()?;
    // Validate the credential now and again at every scheduled start.
    read_service_token(&token_file)?;
    let spec = ServiceSpec {
        executable: std::env::current_exe()?,
        root: root.canonicalize()?,
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
            root: r"C:\Проект O'Brien".into(),
            token_file: r"C:\Private O'Brien\token".into(),
        };
        let command = task_registration(&spec, false);
        assert!(command.contains("-Execute 'C:\\Program Files\\Lockyard\\lockyard.exe'"));
        assert!(command.contains("-WorkingDirectory 'C:\\Проект O''Brien'"));
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
