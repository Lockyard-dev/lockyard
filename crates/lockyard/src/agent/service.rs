// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! `lockyard agent install|uninstall|status`: a launchd or systemd user unit.
//!
//! The unit names a token file, never a token: a unit file is not a place for a secret.

use lockyard_core::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const LABEL: &str = "dev.lockyard.agent";
const UNIT: &str = "lockyard-agent.service";

/// What a unit needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSpec {
    pub executable: PathBuf,
    pub root: PathBuf,
    pub token_file: PathBuf,
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Text of the launchd property list.
pub fn launchd_plist(spec: &UnitSpec) -> String {
    let (exe, root, token) = (
        xml(&spec.executable.display().to_string()),
        xml(&spec.root.display().to_string()),
        xml(&spec.token_file.display().to_string()),
    );
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{exe}</string><string>agent</string></array>
  <key>WorkingDirectory</key><string>{root}</string>
  <key>EnvironmentVariables</key><dict><key>LOCKYARD_TOKEN_FILE</key><string>{token}</string></dict>
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
        unit_quote(&spec.root.display().to_string()),
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
    std::env::var_os("HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| Error::Invalid("HOME is not set".into()))
}

fn launchd() -> bool {
    cfg!(target_os = "macos")
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
pub fn install(root: &Path, start: bool) -> Result<PathBuf> {
    let token_file = std::env::var_os("LOCKYARD_TOKEN_FILE").filter(|path| !path.is_empty()).ok_or_else(|| {
        Error::Invalid("agent install needs LOCKYARD_TOKEN_FILE: a token is never written into a unit file".into())
    })?;
    let token_file = PathBuf::from(token_file);
    let token_file = token_file
        .canonicalize()
        .map_err(|error| Error::Invalid(format!("cannot read LOCKYARD_TOKEN_FILE: {error}")))?;
    let spec = UnitSpec {
        executable: std::env::current_exe()?,
        root: root.to_path_buf(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> UnitSpec {
        UnitSpec {
            executable: "/opt/a b/lockyard".into(),
            root: "/work/R&D".into(),
            token_file: "/home/me/.config/lockyard/token".into(),
        }
    }

    #[test]
    fn the_launchd_unit_names_the_token_file_and_escapes_xml() {
        let text = launchd_plist(&spec());
        assert!(text.contains("<string>/opt/a b/lockyard</string><string>agent</string>"));
        assert!(text.contains("/work/R&amp;D"));
        assert!(text.contains(
            "<key>LOCKYARD_TOKEN_FILE</key><string>/home/me/.config/lockyard/token</string>"
        ));
        assert!(!text.contains("LOCKYARD_TOKEN<"));
    }

    #[test]
    fn the_systemd_unit_quotes_its_values() {
        let text = systemd_unit(&spec());
        assert!(text.contains("ExecStart=\"/opt/a b/lockyard\" agent\n"));
        assert!(
            text.contains("Environment=\"LOCKYARD_TOKEN_FILE=/home/me/.config/lockyard/token\"\n")
        );
        assert!(text.contains("Restart=always"));
        assert!(!text.contains("LOCKYARD_TOKEN="));
    }

    #[test]
    fn units_land_in_the_folders_their_managers_read() {
        let home = Path::new("/home/me");
        assert!(unit_path(home, true).ends_with("Library/LaunchAgents/dev.lockyard.agent.plist"));
        assert!(unit_path(home, false).ends_with(".config/systemd/user/lockyard-agent.service"));
    }
}
