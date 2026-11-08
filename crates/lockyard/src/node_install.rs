// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Root-only AppArmor setup. Does not load node configuration, credentials, or workspace state.
use lockyard_core::{Error, Result};
use serde_json::Value;
use std::path::Path;

pub(super) fn apparmor(explicit: bool, sandbox: &Path, lockyard: Option<&Path>) -> Result<Value> {
    if !explicit {
        return Err(Error::Invalid(
            "apparmor_install_explicit_flag_required".into(),
        ));
    }
    #[cfg(target_os = "linux")]
    {
        linux::install(sandbox, lockyard)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (sandbox, lockyard);
        Err(Error::Invalid("apparmor_install_requires_linux".into()))
    }
}

#[cfg(any(target_os = "linux", test))]
fn render(lockyard: &Path, sandbox: &Path) -> Result<String> {
    fn literal(path: &Path) -> Result<&str> {
        let value = path
            .to_str()
            .ok_or_else(|| Error::Invalid("invalid_apparmor_binary_path".into()))?;
        // AppArmor attachment paths are globs even inside quotes. Restrict them to literals.
        if !path.is_absolute()
            || value == "/"
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-.+".contains(&b))
        {
            return Err(Error::Invalid("invalid_apparmor_binary_path".into()));
        }
        Ok(value)
    }
    let rendered = include_str!("../../../packaging/apparmor/lockyard")
        .replace("@LOCKYARD_BINARY@", literal(lockyard)?)
        .replace("@SANDBOX_BINARY@", literal(sandbox)?);
    if lockyard == sandbox {
        Ok(rendered
            .split("\nprofile lockyard-sandbox")
            .next()
            .unwrap_or(&rendered)
            .to_owned())
    } else {
        Ok(rendered)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use serde_json::json;
    use std::{
        fs,
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::PathBuf,
        process::{Command, Stdio},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn invalid(code: &str) -> Error {
        Error::Invalid(code.into())
    }

    fn root_directory(path: &Path) -> Result<()> {
        for parent in path.ancestors() {
            let metadata = fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(invalid("apparmor_install_unsafe_directory"));
            }
        }
        Ok(())
    }

    fn binary(path: &Path) -> Result<PathBuf> {
        if !path.is_absolute() {
            return Err(invalid("invalid_apparmor_binary_path"));
        }
        let path = fs::canonicalize(path)?;
        root_directory(
            path.parent()
                .ok_or_else(|| invalid("invalid_apparmor_binary_path"))?,
        )?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
            || metadata.mode() & 0o6000 != 0
        {
            return Err(invalid("apparmor_install_unsafe_binary"));
        }
        Ok(path)
    }

    fn existing(path: &Path, expected: &[u8]) -> Result<bool> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(Error::Io(error)),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
            || metadata.len() > 65536
        {
            return Err(invalid("apparmor_profile_conflict"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(65537)
            .read_to_end(&mut bytes)?;
        if bytes != expected {
            return Err(invalid("apparmor_profile_conflict"));
        }
        Ok(true)
    }

    fn parser(parser: &Path, profile: &Path, syntax_only: bool) -> Result<()> {
        let mut command = Command::new(parser);
        command
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        command.arg("--skip-cache");
        command.arg(if syntax_only {
            "--skip-kernel-load"
        } else {
            "--replace"
        });
        if !command.arg(profile).status()?.success() {
            return Err(invalid(if syntax_only {
                "apparmor_profile_parse_failed"
            } else {
                "apparmor_profile_load_failed"
            }));
        }
        Ok(())
    }

    struct Temporary(PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    pub(super) fn install(sandbox: &Path, lockyard: Option<&Path>) -> Result<Value> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(invalid("apparmor_install_requires_root"));
        }
        let current = std::env::current_exe()?;
        let lockyard = binary(lockyard.unwrap_or(&current))?;
        let sandbox = binary(sandbox)?;
        let content = render(&lockyard, &sandbox)?;
        let directory = Path::new("/etc/apparmor.d");
        root_directory(directory)?;
        let target = directory.join("lockyard");
        // Never overwrite an administrator's profile, a symlink, or a changed prior installation.
        let already_present = existing(&target, content.as_bytes())?;
        let parser_path = ["/usr/sbin/apparmor_parser", "/sbin/apparmor_parser"]
            .into_iter()
            .find_map(|path| binary(Path::new(path)).ok())
            .ok_or_else(|| invalid("apparmor_parser_unavailable"))?;
        if !already_present {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| invalid("apparmor_install_clock_invalid"))?
                .as_nanos();
            let temporary_path =
                directory.join(format!(".lockyard.{}.{nonce}.tmp", std::process::id()));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary_path)?;
            let temporary = Temporary(temporary_path);
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
            parser(&parser_path, &temporary.0, true)?;
            match fs::hard_link(&temporary.0, &target) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !existing(&target, content.as_bytes())? {
                        return Err(invalid("apparmor_profile_conflict"));
                    }
                }
                Err(error) => return Err(Error::Io(error)),
            }
            fs::remove_file(&temporary.0)?;
            lockyard_core::fsio::sync_path(directory)?;
        }
        parser(&parser_path, &target, false)?;
        Ok(
            json!({"installed":true,"apparmor_profile":target,"lockyard_binary":lockyard,"sandbox_binary":sandbox,
            "restart_required":true,"note":"Restart both binaries so the exact AppArmor attachments take effect; re-run doctor afterward."}),
        )
    }
}

#[cfg(target_os = "linux")]
use std::fs::OpenOptions;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profiles_bind_both_literal_binaries_and_reject_injection() {
        let profile = render(
            Path::new("/opt/lockyard/bin/lockyard"),
            Path::new("/opt/lockyard/bin/lockyard-sandbox"),
        )
        .unwrap();
        assert!(
            profile
                .contains("profile lockyard \"/opt/lockyard/bin/lockyard\" flags=(default_allow)")
        );
        assert!(profile.contains(
            "profile lockyard-sandbox \"/opt/lockyard/bin/lockyard-sandbox\" flags=(default_allow)"
        ));
        assert_eq!(profile.matches("userns,").count(), 2);
        let single = render(Path::new("/opt/lockyard"), Path::new("/opt/lockyard")).unwrap();
        assert_eq!(single.matches("userns,").count(), 1);
        assert_eq!(single.matches("profile lockyard ").count(), 1);
        assert!(!single.contains("profile lockyard-sandbox"));
        assert!(!profile.contains("@LOCKYARD_BINARY@"));
        for invalid in [
            "relative",
            "/opt/*",
            "/opt/a\"b",
            "/opt/a b",
            "/opt/{a,b}",
            "/",
        ] {
            assert!(render(Path::new(invalid), Path::new("/opt/lockyard-sandbox")).is_err());
        }
    }
}
