// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Managed client integration and read-only diagnostics. Configuration writes are opt-in;
//! manifests own individual entries, never a user's whole configuration file.

use lockyard_core::config::{Config, Mode};
use lockyard_core::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupAction {
    Preview,
    Apply,
    Check,
    Remove,
}

impl SetupAction {
    fn name(self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Apply => "apply",
            Self::Check => "check",
            Self::Remove => "remove",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct Entry {
    path: Vec<String>,
    value: Value,
    #[serde(default)]
    append: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct Manifest {
    schema: u32,
    owner: String,
    version: String,
    entries: Vec<Entry>,
    #[serde(default)]
    toml_block: Option<String>,
}

impl Manifest {
    fn empty() -> Self {
        Self {
            schema: 1,
            owner: "lockyard".into(),
            version: lockyard_core::VERSION.into(),
            entries: Vec::new(),
            toml_block: None,
        }
    }
}

#[derive(Debug)]
struct Spec {
    path: PathBuf,
    entries: Vec<Entry>,
    toml: bool,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| invalid("HOME is not set"))
}

fn entry(path: &[&str], value: Value) -> Entry {
    Entry {
        path: path.iter().map(|part| (*part).to_string()).collect(),
        value,
        append: false,
    }
}

// Resolve only the selected base. Managed components appended below must remain visible
// to the symlink checks, including when a selected CODEX_HOME does not exist yet.
fn canonical_base(path: &Path) -> Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let name = path.file_name().ok_or(error)?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            Ok(canonical_base(parent)?.join(name))
        }
        Err(error) => Err(error.into()),
    }
}

fn specs(root: &Path, client: &str, home: &Path, codex_home: Option<&Path>) -> Result<Vec<Spec>> {
    let root = if matches!(client, "claude" | "cursor") {
        canonical_base(root)?
    } else {
        root.to_path_buf()
    };
    let server = json!({"command":"lockyard", "args":["mcp"]});
    match client {
        "claude" => {
            let hooks: Value = serde_json::from_str(crate::hook::SETTINGS)
                .map_err(|_| invalid("built-in Claude configuration is invalid"))?;
            let mut entries = Vec::new();
            for (event, definitions) in hooks["hooks"].as_object().expect("built-in hooks object") {
                for definition in definitions.as_array().expect("built-in hooks array") {
                    entries.push(Entry {
                        path: vec!["hooks".into(), event.clone()],
                        value: definition.clone(),
                        append: true,
                    });
                }
            }
            Ok(vec![
                Spec {
                    path: root.join(".mcp.json"),
                    entries: vec![entry(&["mcpServers", "lockyard"], server)],
                    toml: false,
                },
                Spec {
                    path: root.join(".claude/settings.json"),
                    entries,
                    toml: false,
                },
            ])
        }
        "cursor" => Ok(vec![Spec {
            path: root.join(".cursor/mcp.json"),
            entries: vec![entry(&["mcpServers", "lockyard"], server)],
            toml: false,
        }]),
        "codex" => Ok(vec![Spec {
            path: match codex_home {
                Some(base) => canonical_base(base)?,
                None => canonical_base(home)?.join(".codex"),
            }
            .join("config.toml"),
            entries: vec![entry(
                &["mcp_servers", "lockyard"],
                json!({"command":"lockyard", "args":["mcp"], "env_vars":["LOCKYARD_AGENT", "LOCKYARD_URL", "LOCKYARD_TOKEN_FILE", "LOCKYARD_TOKEN", "LOCKYARD_NODE_CONFIG", "XDG_CONFIG_HOME", "LOCKYARD_REQUIRE_E2EE", "LOCKYARD_E2EE_WORKSPACE_ID"]}),
            )],
            toml: true,
        }]),
        _ => Err(invalid("client must be claude, codex or cursor")),
    }
}

fn sidecar(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.lockyard-setup.json",
        path.file_name().unwrap_or_default().to_string_lossy()
    ))
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(invalid(
            format!("{} must be a regular file", path.display()),
        )),
        Ok(_) => Ok(Some(fs::read(path)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn manifest(path: &Path) -> Result<Option<Manifest>> {
    read_optional(&sidecar(path))?
        .map(|bytes| {
            let value: Manifest = serde_json::from_slice(&bytes)
                .map_err(|_| invalid("invalid setup ownership manifest; no changes made"))?;
            if value.owner != "lockyard" || value.schema != 1 {
                return Err(invalid(
                    "unsupported setup ownership manifest; no changes made",
                ));
            }
            Ok(value)
        })
        .transpose()
}

fn locate<'a>(value: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut current = value;
    for part in path {
        current = current.get(part)?;
    }
    Some(current)
}

fn parent<'a>(value: &'a mut Value, path: &[String]) -> Result<&'a mut Value> {
    let mut current = value;
    for part in path.iter().take(path.len().saturating_sub(1)) {
        if !current.is_object() {
            return Err(invalid(
                "configuration section is not an object; no changes made",
            ));
        }
        current = current
            .as_object_mut()
            .expect("checked object")
            .entry(part.clone())
            .or_insert_with(|| json!({}));
    }
    if !current.is_object() {
        return Err(invalid(
            "configuration section is not an object; no changes made",
        ));
    }
    Ok(current)
}

fn contains(value: &Value, item: &Entry) -> bool {
    match locate(value, &item.path) {
        Some(Value::Array(array)) if item.append => array.contains(&item.value),
        Some(found) if !item.append => found == &item.value,
        _ => false,
    }
}

fn remove_entry(value: &mut Value, item: &Entry) -> Result<()> {
    let Some(current) = locate(value, &item.path) else {
        return Ok(());
    };
    if item.append {
        let Some(array) = current.as_array() else {
            return Err(invalid("managed hook section was changed; preserving it"));
        };
        if !array.contains(&item.value) {
            return Err(invalid(
                "managed hook was changed or removed; preserving configuration",
            ));
        }
        let current = parent(value, &item.path)?;
        let key = item.path.last().expect("entry path");
        current[key]
            .as_array_mut()
            .expect("checked array")
            .retain(|found| found != &item.value);
    } else {
        if current != &item.value {
            return Err(invalid(
                "managed server entry was changed; preserving configuration",
            ));
        }
        parent(value, &item.path)?
            .as_object_mut()
            .expect("checked object")
            .remove(item.path.last().expect("entry path"));
    }
    Ok(())
}

fn insert_entry(value: &mut Value, item: &Entry) -> Result<bool> {
    if contains(value, item) {
        return Ok(false);
    }
    let current = parent(value, &item.path)?;
    let key = item.path.last().expect("entry path");
    if item.append {
        let array = current
            .as_object_mut()
            .expect("checked object")
            .entry(key.clone())
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| invalid("hook section is not an array; preserving configuration"))?;
        if array.iter().any(|found| {
            found["hooks"].as_array().is_some_and(|hooks| {
                hooks
                    .iter()
                    .any(|hook| hook["command"].as_str() == Some("lockyard hook claude"))
            })
        }) {
            return Err(invalid(
                "a customized Lockyard hook already exists; preserving it",
            ));
        }
        array.push(item.value.clone());
    } else {
        if current.get(key).is_some() {
            return Err(invalid(
                "a different lockyard server entry exists; preserving it",
            ));
        }
        current
            .as_object_mut()
            .expect("checked object")
            .insert(key.clone(), item.value.clone());
    }
    Ok(true)
}

const LEGACY_TOML_BLOCK: &str = "# BEGIN LOCKYARD MANAGED MCP\n[mcp_servers.lockyard]\ncommand = \"lockyard\"\nargs = [\"mcp\"]\n# END LOCKYARD MANAGED MCP\n";
const AGENT_ONLY_TOML_BLOCK: &str = "# BEGIN LOCKYARD MANAGED MCP\n[mcp_servers.lockyard]\ncommand = \"lockyard\"\nargs = [\"mcp\"]\nenv_vars = [\"LOCKYARD_AGENT\"]\n# END LOCKYARD MANAGED MCP\n";
const CLOUD_TOML_BLOCK: &str = "# BEGIN LOCKYARD MANAGED MCP\n[mcp_servers.lockyard]\ncommand = \"lockyard\"\nargs = [\"mcp\"]\nenv_vars = [\"LOCKYARD_AGENT\", \"LOCKYARD_URL\", \"LOCKYARD_TOKEN_FILE\", \"LOCKYARD_TOKEN\"]\n# END LOCKYARD MANAGED MCP\n";
const TOML_BLOCK: &str = "# BEGIN LOCKYARD MANAGED MCP\n[mcp_servers.lockyard]\ncommand = \"lockyard\"\nargs = [\"mcp\"]\nenv_vars = [\"LOCKYARD_AGENT\", \"LOCKYARD_URL\", \"LOCKYARD_TOKEN_FILE\", \"LOCKYARD_TOKEN\", \"LOCKYARD_NODE_CONFIG\", \"XDG_CONFIG_HOME\", \"LOCKYARD_REQUIRE_E2EE\", \"LOCKYARD_E2EE_WORKSPACE_ID\"]\n# END LOCKYARD MANAGED MCP\n";

fn legacy_codex_entry() -> Entry {
    entry(
        &["mcp_servers", "lockyard"],
        json!({"command":"lockyard", "args":["mcp"]}),
    )
}

fn legacy_codex_versions() -> [(&'static str, Entry); 3] {
    [
        (LEGACY_TOML_BLOCK, legacy_codex_entry()),
        (
            CLOUD_TOML_BLOCK,
            entry(
                &["mcp_servers", "lockyard"],
                json!({"command":"lockyard", "args":["mcp"], "env_vars":["LOCKYARD_AGENT", "LOCKYARD_URL", "LOCKYARD_TOKEN_FILE", "LOCKYARD_TOKEN"]}),
            ),
        ),
        (
            AGENT_ONLY_TOML_BLOCK,
            entry(
                &["mcp_servers", "lockyard"],
                json!({"command":"lockyard", "args":["mcp"], "env_vars":["LOCKYARD_AGENT"]}),
            ),
        ),
    ]
}

fn supported_ownership(spec: &Spec, owned: &Manifest) -> bool {
    if spec.toml {
        (owned.entries == spec.entries && owned.toml_block.as_deref() == Some(TOML_BLOCK))
            || legacy_codex_versions().iter().any(|(block, entry)| {
                owned.entries.as_slice() == std::slice::from_ref(entry)
                    && owned.toml_block.as_deref() == Some(*block)
            })
    } else {
        owned.toml_block.is_none()
            && owned
                .entries
                .iter()
                .all(|entry| spec.entries.contains(entry))
    }
}

struct Planned {
    bytes: Vec<u8>,
    ownership: Manifest,
    present: bool,
    changed: bool,
}

fn plan(
    spec: &Spec,
    previous: Option<&[u8]>,
    owned: Option<&Manifest>,
    action: SetupAction,
) -> Result<Planned> {
    let mut ownership = Manifest::empty();
    if owned.is_some_and(|owned| !supported_ownership(spec, owned)) {
        return Err(invalid(
            "ownership manifest contains unsupported entries; preserving configuration",
        ));
    }
    if spec.toml {
        let source = std::str::from_utf8(previous.unwrap_or_default())
            .map_err(|_| invalid("configuration is not UTF-8; preserving it"))?;
        let parsed: toml::Value = source
            .parse()
            .map_err(|_| invalid("configuration is not valid TOML; preserving it"))?;
        let value = serde_json::to_value(parsed).map_err(|_| invalid("cannot inspect TOML"))?;
        let present = spec.entries.iter().all(|item| contains(&value, item));
        if action == SetupAction::Check {
            return Ok(Planned {
                bytes: source.as_bytes().to_vec(),
                ownership,
                present,
                changed: false,
            });
        }
        let mut next = source.to_string();
        let legacy_versions = legacy_codex_versions();
        if let Some(block) = owned.and_then(|owned| owned.toml_block.as_ref()) {
            // The receipt is persisted before the configuration. A process interrupted during
            // an upgrade can therefore leave a current receipt beside the exact legacy block.
            let block = if block == TOML_BLOCK && !next.contains(TOML_BLOCK) {
                legacy_versions
                    .iter()
                    .find(|(block, entry)| {
                        next.matches(block).count() == 1 && contains(&value, entry)
                    })
                    .map_or(block.as_str(), |(block, _)| *block)
            } else {
                block.as_str()
            };
            if !next.contains(block)
                && !next.contains("# BEGIN LOCKYARD MANAGED MCP")
                && locate(&value, &spec.entries[0].path).is_none()
            {
                // An interrupted initial install may have persisted the ownership receipt
                // before the configuration. Reapplying can safely finish that exact plan.
                if action != SetupAction::Remove {
                    if !next.is_empty() && !next.ends_with('\n') {
                        next.push('\n');
                    }
                    next.push_str(TOML_BLOCK);
                    ownership.toml_block = Some(TOML_BLOCK.into());
                    ownership.entries = spec.entries.clone();
                }
            } else if next.matches(block).count() != 1
                || !contains(
                    &value,
                    legacy_versions
                        .iter()
                        .find(|(legacy, _)| *legacy == block)
                        .map_or(&spec.entries[0], |(_, entry)| entry),
                )
            {
                return Err(invalid(
                    "managed TOML block changed; preserving configuration",
                ));
            } else if action == SetupAction::Remove {
                next = next.replacen(block, "", 1);
            } else {
                next = next.replacen(block, TOML_BLOCK, 1);
                ownership.toml_block = Some(TOML_BLOCK.into());
                ownership.entries = spec.entries.clone();
            }
        } else if action != SetupAction::Remove && !present {
            if locate(&value, &spec.entries[0].path).is_some() {
                return Err(invalid(
                    "a different lockyard server entry exists; preserving it",
                ));
            }
            if next.contains("# BEGIN LOCKYARD MANAGED MCP") {
                return Err(invalid(
                    "unowned Lockyard marker exists; preserving configuration",
                ));
            }
            if !next.is_empty() && !next.ends_with('\n') {
                next.push('\n');
            }
            next.push_str(TOML_BLOCK);
            ownership.toml_block = Some(TOML_BLOCK.into());
            ownership.entries = spec.entries.clone();
        }
        let _: toml::Value = next
            .parse()
            .map_err(|_| invalid("merge would produce invalid TOML; no changes made"))?;
        return Ok(Planned {
            changed: next.as_bytes() != source.as_bytes(),
            bytes: next.into_bytes(),
            ownership,
            present,
        });
    }
    let mut value: Value = previous
        .map(|bytes| {
            serde_json::from_slice(bytes)
                .map_err(|_| invalid("configuration is not valid JSON; preserving it"))
        })
        .transpose()?
        .unwrap_or_else(|| json!({}));
    if !value.is_object() {
        return Err(invalid(
            "configuration must be a JSON object; preserving it",
        ));
    }
    let present = spec.entries.iter().all(|item| contains(&value, item));
    if action == SetupAction::Check {
        return Ok(Planned {
            bytes: previous.unwrap_or_default().to_vec(),
            ownership,
            present,
            changed: false,
        });
    }
    let before = value.clone();
    if let Some(owned) = owned {
        for item in &owned.entries {
            remove_entry(&mut value, item)?;
        }
    }
    if action != SetupAction::Remove {
        for item in &spec.entries {
            if insert_entry(&mut value, item)? {
                ownership.entries.push(item.clone());
            }
        }
    }
    let changed = before != value;
    let bytes = if changed {
        let mut bytes = serde_json::to_vec_pretty(&value)
            .map_err(|_| invalid("cannot encode configuration"))?;
        bytes.push(b'\n');
        bytes
    } else {
        previous.unwrap_or_default().to_vec()
    };
    Ok(Planned {
        bytes,
        ownership,
        present,
        changed,
    })
}

fn nonce() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("configuration has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".lockyard-{}.tmp", nonce()));
    write_private(&temporary, bytes)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(())
}

fn execute(spec: &Spec, action: SetupAction) -> Result<Value> {
    for ancestor in spec.path.ancestors().skip(1) {
        if fs::symlink_metadata(ancestor).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(invalid(
                "configuration parent is a symbolic link; preserving it",
            ));
        }
    }
    let previous = read_optional(&spec.path)?;
    let owned = manifest(&spec.path)?;
    let planned = plan(spec, previous.as_deref(), owned.as_ref(), action)?;
    if action == SetupAction::Check {
        return Ok(
            json!({"path":spec.path,"status":if planned.present {"present"} else {"missing"},"ok":planned.present,"managed":owned.is_some()}),
        );
    }
    let mut backup = None;
    if matches!(action, SetupAction::Apply | SetupAction::Remove) {
        if read_optional(&spec.path)? != previous {
            return Err(invalid(
                "configuration changed during setup; retry after inspecting it",
            ));
        }
        if planned.changed {
            if let Some(previous) = &previous {
                let name = format!(
                    "{}.lockyard-backup-{}",
                    spec.path.file_name().unwrap_or_default().to_string_lossy(),
                    nonce()
                );
                let path = spec.path.with_file_name(name);
                write_private(&path, previous)?;
                backup = Some(path);
            }
            // Save intended ownership first: an interrupted file write is safely recoverable by
            // reapplying; ownership never grants permission to overwrite a modified user entry.
            if !planned.ownership.entries.is_empty() {
                atomic_write(
                    &sidecar(&spec.path),
                    &serde_json::to_vec_pretty(&planned.ownership)
                        .map_err(|_| invalid("cannot encode ownership"))?,
                )?;
            }
            atomic_write(&spec.path, &planned.bytes)?;
        }
        if planned.ownership.entries.is_empty() {
            if owned.is_some() {
                fs::remove_file(sidecar(&spec.path))?;
            }
        } else if !planned.changed && owned.is_some() {
            // Preserve the existing ownership receipt on a repeated installation.
        }
    }
    let status = if !planned.changed {
        "unchanged"
    } else if action == SetupAction::Preview {
        if previous.is_none() {
            "would_create"
        } else {
            "would_update"
        }
    } else if action == SetupAction::Remove {
        "removed"
    } else if previous.is_none() {
        "created"
    } else {
        "updated"
    };
    Ok(
        json!({"path":spec.path,"status":status,"ok":true,"would_change":planned.changed,"backup":backup,
        "managed_entries":spec.entries.iter().map(|item|json!({"path":item.path,"operation":if item.append {"append hook if missing"} else {"install server if absent"},"value":item.value})).collect::<Vec<_>>() }),
    )
}

/// Plans or applies only the selected integration. Each file has an explicit result; a failure in
/// one file does not pretend that preceding file writes were rolled back.
pub fn setup(cwd: &Path, client: &str, action: SetupAction) -> Result<Value> {
    let root = lockyard_core::paths::find_root(cwd).unwrap_or_else(|| cwd.to_path_buf());
    let codex_home = std::env::var_os("CODEX_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);
    setup_selected(&root, client, action, &home()?, codex_home.as_deref())
}

#[cfg(test)]
fn setup_at(root: &Path, client: &str, action: SetupAction, home: &Path) -> Result<Value> {
    setup_selected(root, client, action, home, None)
}

fn setup_selected(
    root: &Path,
    client: &str,
    action: SetupAction,
    home: &Path,
    codex_home: Option<&Path>,
) -> Result<Value> {
    let files: Vec<Value> = specs(root, client, home, codex_home)?.iter().map(|spec| {
        execute(spec, action).unwrap_or_else(|error| json!({"path":spec.path,"status":"failed","ok":false,"message":error.to_string()}))
    }).collect();
    Ok(
        json!({"client":client,"action":action.name(),"ok":files.iter().all(|file|file["ok"]==true),"files":files,"enforcement":if client=="claude" {"edit tools and heavy-command hooks; unknown state refuses edits"} else {"MCP only; edit enforcement is not installed"},"note":"Configuration presence does not prove the client loaded it. Run doctor --smoke and restart or reload the client."}),
    )
}

fn check(checks: &mut Vec<Value>, name: &str, state: &str, message: &str) {
    checks.push(json!({"name":name,"state":state,"message":message}));
}

/// Diagnostics do not send credentials to a network endpoint or change project/client settings.
/// `smoke` creates and removes a separate temporary local project, leaving the current project alone.
pub fn doctor(cwd: &Path, agent: Option<&str>, client: Option<&str>, smoke: bool) -> Result<Value> {
    let mut checks = Vec::new();
    let executable = std::env::current_exe().is_ok_and(|path| path.is_file());
    check(
        &mut checks,
        "executable",
        if executable { "ok" } else { "failed" },
        "Current Lockyard executable is available.",
    );
    let identity = agent
        .map(str::to_string)
        .or_else(|| std::env::var("LOCKYARD_AGENT").ok())
        .or_else(|| std::env::var("CLAUDE_CODE_SESSION_ID").ok());
    check(
        &mut checks,
        "identity",
        if identity
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            "ok"
        } else {
            "warning"
        },
        "Use a distinct agent name per concurrent session; local uniqueness cannot be proven by configuration alone.",
    );
    let root = lockyard_core::paths::find_root(cwd);
    match root.as_ref() {
        None => check(
            &mut checks,
            "project",
            "failed",
            "No project found. Run lockyard init in the project root.",
        ),
        Some(root) => {
            check(&mut checks, "project", "ok", "A project root was found.");
            match Config::load(root) {
                Err(_) => check(
                    &mut checks,
                    "configuration",
                    "failed",
                    "Project configuration is invalid; inspect .lockyard/config.toml. Contents are not included in diagnostics.",
                ),
                Ok(config) => {
                    check(
                        &mut checks,
                        "configuration",
                        "ok",
                        if config.mode == Mode::Local {
                            "Local mode."
                        } else {
                            "Cloud mode."
                        },
                    );
                    if config.mode == Mode::Local {
                        check(
                            &mut checks,
                            "local_store",
                            if root.join(".lockyard/lockyard.db").is_file() {
                                "ok"
                            } else {
                                "failed"
                            },
                            "The local database must exist. No migration or repair is performed by doctor.",
                        );
                    } else {
                        cloud_checks(&mut checks, &config);
                    }
                }
            }
        }
    }
    if let Some(client) = client {
        let report = setup(cwd, client, SetupAction::Check)?;
        check(
            &mut checks,
            "client_configuration",
            if report["ok"] == true { "ok" } else { "failed" },
            if report["ok"] == true {
                "Expected MCP configuration is present; reload the client to activate changes."
            } else {
                "Client configuration is missing, incompatible, or modified. Inspect lockyard setup CLIENT --preview."
            },
        );
        check(
            &mut checks,
            "edit_enforcement",
            if client == "claude" { "ok" } else { "warning" },
            if client == "claude" {
                "Claude hook definitions are checked alongside MCP configuration; runtime activation still requires a real edit check."
            } else {
                "This integration installs MCP only, not edit enforcement."
            },
        );
    }
    let smoke_report = if smoke { Some(local_smoke()?) } else { None };
    if let Some(report) = &smoke_report {
        check(
            &mut checks,
            "two_agent_smoke",
            if report["ok"] == true { "ok" } else { "failed" },
            "Separate local CLI processes must claim, conflict, release and claim successfully.",
        );
    }
    let ok = checks.iter().all(|item| item["state"] != "failed");
    Ok(json!({"ok":ok,"checks":checks,"smoke":smoke_report,"network_authorization_verified":false}))
}

fn cloud_checks(checks: &mut Vec<Value>, config: &Config) {
    let (Some(url), Some(workspace)) = (config.url.as_deref(), config.workspace.as_deref()) else {
        return;
    };
    check(
        checks,
        "server_trust",
        if crate::open::trusted_url(url).is_ok() {
            "ok"
        } else {
            "failed"
        },
        "The configured URL must be explicitly trusted before credentials are sent.",
    );
    let token = Config::token().ok();
    check(
        checks,
        "credential_binding",
        if token.is_some() { "ok" } else { "failed" },
        "A non-empty credential binding or private token file is required. Values are never printed; remote authorization is not tested by doctor.",
    );
    #[cfg(unix)]
    {
        match crate::agent::socket::AgentSocket::status(
            &crate::agent::socket_path(),
            std::time::Duration::from_millis(800),
        ) {
            Err(_) => check(
                checks,
                "daemon",
                "warning",
                "No reachable private daemon. Direct CLI calls may work, but cloud hooks need lockyard agent.",
            ),
            Ok(status) => {
                let aligned = status.url.trim_end_matches('/') == url.trim_end_matches('/')
                    && status.workspace == workspace
                    && token.as_ref().is_some_and(|token| {
                        status.token_id == lockyard_cloud_client::token_id(token)
                    });
                check(
                    checks,
                    "daemon_alignment",
                    if aligned { "ok" } else { "failed" },
                    "Daemon URL, workspace and token must match this project; credential fingerprints are not printed.",
                );
                check(
                    checks,
                    "daemon_freshness",
                    if status.view_fresh { "ok" } else { "warning" },
                    "An old daemon view must not be treated as a confirmed free path.",
                );
                check(
                    checks,
                    "daemon_delivery",
                    if status.rejected == 0 {
                        "ok"
                    } else {
                        "warning"
                    },
                    "Inspect agent status if rejected outbox entries require attention.",
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = workspace;
        check(
            checks,
            "daemon",
            "warning",
            "The background agent and its edit hooks require Unix; direct CLI calls are available.",
        );
    }
}

struct SmokeDirectory(PathBuf);
impl Drop for SmokeDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn local_smoke() -> Result<Value> {
    let directory =
        SmokeDirectory(std::env::temp_dir().join(format!("lockyard-doctor-{}", nonce())));
    fs::create_dir(&directory.0)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700))?;
    }
    let executable = std::env::current_exe()?;
    let run = |agent: &str, args: &[&str]| -> Result<i32> {
        let output = Command::new(&executable)
            .current_dir(&directory.0)
            .arg("--agent")
            .arg(agent)
            .args(args)
            .env_remove("LOCKYARD_AGENT")
            .env_remove("CLAUDE_CODE_SESSION_ID")
            .output()?;
        Ok(output.status.code().unwrap_or(-1))
    };
    let mut steps = Vec::new();
    for (name, agent, args, expected) in [
        ("init", "doctor-a", vec!["init"], 0),
        ("claim_a", "doctor-a", vec!["zone", "claim", "src"], 0),
        (
            "conflict_b",
            "doctor-b",
            vec!["zone", "claim", "src/file.rs"],
            3,
        ),
        ("release_a", "doctor-a", vec!["zone", "release"], 0),
        (
            "claim_b",
            "doctor-b",
            vec!["zone", "claim", "src/file.rs"],
            0,
        ),
    ] {
        let code = run(agent, &args)?;
        steps.push(
            json!({"step":name,"exit_code":code,"expected_exit_code":expected,"ok":code==expected}),
        );
        if code != expected {
            break;
        }
    }
    Ok(
        json!({"scope":"temporary local project; not a cloud authorization or live-client activation test","ok":steps.len()==5 && steps.iter().all(|step|step["ok"]==true),"steps":steps}),
    )
}

pub fn text(report: &Value) -> String {
    let mut lines = vec![if report["ok"] == true {
        "ok".to_string()
    } else {
        "needs attention".to_string()
    }];
    if let Some(checks) = report["checks"].as_array() {
        for item in checks {
            lines.push(format!(
                "{}: {} — {}",
                item["name"].as_str().unwrap_or_default(),
                item["state"].as_str().unwrap_or_default(),
                item["message"].as_str().unwrap_or_default()
            ));
        }
    }
    if let Some(files) = report["files"].as_array() {
        for file in files {
            lines.push(format!(
                "{}: {}{}",
                file["path"].as_str().unwrap_or_default(),
                file["status"].as_str().unwrap_or_default(),
                file["message"]
                    .as_str()
                    .map(|message| format!(" — {message}"))
                    .unwrap_or_default()
            ));
        }
        if let Some(note) = report["note"].as_str() {
            lines.push(note.into());
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_merge_is_repeatable_and_remove_preserves_user_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".mcp.json");
        fs::write(
            &path,
            b"{\"mcpServers\":{\"other\":{\"command\":\"other\"}},\"custom\":true}",
        )
        .unwrap();
        assert_eq!(
            setup_at(dir.path(), "claude", SetupAction::Preview, dir.path()).unwrap()["ok"],
            true
        );
        assert!(!sidecar(&path).exists());
        assert_eq!(
            setup_at(dir.path(), "claude", SetupAction::Apply, dir.path()).unwrap()["ok"],
            true
        );
        let first = fs::read(&path).unwrap();
        assert_eq!(
            setup_at(dir.path(), "claude", SetupAction::Apply, dir.path()).unwrap()["ok"],
            true
        );
        assert_eq!(first, fs::read(&path).unwrap());
        assert_eq!(
            setup_at(dir.path(), "claude", SetupAction::Check, dir.path()).unwrap()["ok"],
            true
        );
        assert_eq!(
            setup_at(dir.path(), "claude", SetupAction::Remove, dir.path()).unwrap()["ok"],
            true
        );
        let found: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(found["custom"], true);
        assert_eq!(found["mcpServers"]["other"]["command"], "other");
        assert!(found["mcpServers"].get("lockyard").is_none());
    }

    #[test]
    fn modified_owned_entries_are_never_overwritten_or_removed() {
        let dir = tempfile::tempdir().unwrap();
        setup_at(dir.path(), "cursor", SetupAction::Apply, dir.path()).unwrap();
        let path = dir.path().join(".cursor/mcp.json");
        fs::write(
            &path,
            b"{\"mcpServers\":{\"lockyard\":{\"command\":\"custom\"}}}",
        )
        .unwrap();
        let changed = fs::read(&path).unwrap();
        for action in [SetupAction::Apply, SetupAction::Remove] {
            assert_eq!(
                setup_at(dir.path(), "cursor", action, dir.path()).unwrap()["ok"],
                false
            );
            assert_eq!(changed, fs::read(&path).unwrap());
        }
    }

    #[test]
    fn codex_preserves_comments_and_removes_only_its_managed_block() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".codex")).unwrap();
        let path = dir.path().join(".codex/config.toml");
        let user =
            "# Keep this comment\nmodel = 'my-model'\n[mcp_servers.other]\ncommand = 'other'\n";
        fs::write(&path, user).unwrap();
        assert_eq!(
            setup_at(dir.path(), "codex", SetupAction::Apply, dir.path()).unwrap()["ok"],
            true
        );
        assert!(fs::read_to_string(&path).unwrap().starts_with(user));
        assert_eq!(
            setup_at(dir.path(), "codex", SetupAction::Apply, dir.path()).unwrap()["ok"],
            true
        );
        assert_eq!(
            setup_at(dir.path(), "codex", SetupAction::Check, dir.path()).unwrap()["ok"],
            true
        );
        assert_eq!(
            setup_at(dir.path(), "codex", SetupAction::Remove, dir.path()).unwrap()["ok"],
            true
        );
        assert_eq!(fs::read_to_string(path).unwrap(), user);
    }

    #[test]
    fn legacy_codex_receipt_upgrades_without_claiming_other_configuration() {
        for (legacy_block, legacy_entry) in legacy_codex_versions() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(".codex/config.toml");
            fs::create_dir(path.parent().unwrap()).unwrap();
            let user =
                "# Keep this comment\nmodel = 'my-model'\n[mcp_servers.other]\ncommand = 'other'\n";
            let original = format!("{user}{legacy_block}");
            fs::write(&path, &original).unwrap();
            let mut receipt = Manifest::empty();
            receipt.entries = vec![legacy_entry];
            receipt.toml_block = Some(legacy_block.into());
            let original_receipt = serde_json::to_vec(&receipt).unwrap();
            fs::write(sidecar(&path), &original_receipt).unwrap();

            assert_eq!(
                setup_at(dir.path(), "codex", SetupAction::Check, dir.path()).unwrap()["ok"],
                false
            );
            let preview = setup_at(dir.path(), "codex", SetupAction::Preview, dir.path()).unwrap();
            assert_eq!(preview["ok"], true);
            assert_eq!(preview["files"][0]["would_change"], true);
            assert_eq!(fs::read_to_string(&path).unwrap(), original);
            assert_eq!(fs::read(sidecar(&path)).unwrap(), original_receipt);

            assert_eq!(
                setup_at(dir.path(), "codex", SetupAction::Apply, dir.path()).unwrap()["ok"],
                true
            );
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                format!("{user}{TOML_BLOCK}")
            );
            let upgraded = manifest(&path).unwrap().unwrap();
            assert_eq!(upgraded.toml_block.as_deref(), Some(TOML_BLOCK));
            assert_eq!(
                upgraded.entries[0].value["env_vars"],
                json!([
                    "LOCKYARD_AGENT",
                    "LOCKYARD_URL",
                    "LOCKYARD_TOKEN_FILE",
                    "LOCKYARD_TOKEN",
                    "LOCKYARD_NODE_CONFIG",
                    "XDG_CONFIG_HOME",
                    "LOCKYARD_REQUIRE_E2EE",
                    "LOCKYARD_E2EE_WORKSPACE_ID"
                ])
            );
            assert_eq!(
                setup_at(dir.path(), "codex", SetupAction::Check, dir.path()).unwrap()["ok"],
                true
            );
            let repeated = setup_at(dir.path(), "codex", SetupAction::Apply, dir.path()).unwrap();
            assert_eq!(repeated["files"][0]["would_change"], false);
            assert_eq!(
                setup_at(dir.path(), "codex", SetupAction::Remove, dir.path()).unwrap()["ok"],
                true
            );
            assert_eq!(fs::read_to_string(path).unwrap(), user);
        }
    }

    #[test]
    fn interrupted_codex_upgrade_can_resume_from_the_exact_legacy_block() {
        for (legacy_block, _) in legacy_codex_versions() {
            let dir = tempfile::tempdir().unwrap();
            let spec = specs(dir.path(), "codex", dir.path(), None)
                .unwrap()
                .remove(0);
            fs::create_dir(spec.path.parent().unwrap()).unwrap();
            fs::write(&spec.path, legacy_block).unwrap();
            let mut receipt = Manifest::empty();
            receipt.entries = spec.entries.clone();
            receipt.toml_block = Some(TOML_BLOCK.into());
            fs::write(sidecar(&spec.path), serde_json::to_vec(&receipt).unwrap()).unwrap();

            let report = setup_at(dir.path(), "codex", SetupAction::Apply, dir.path()).unwrap();
            assert_eq!(report["ok"], true);
            assert_eq!(fs::read_to_string(spec.path).unwrap(), TOML_BLOCK);
        }
    }

    #[test]
    fn codex_upgrade_refuses_modified_entries_and_receipts() {
        for (legacy_block, legacy_entry) in legacy_codex_versions() {
            for current_receipt in [false, true] {
                for change in ["command", "outside_block", "receipt"] {
                    let dir = tempfile::tempdir().unwrap();
                    let path = dir.path().join(".codex/config.toml");
                    fs::create_dir(path.parent().unwrap()).unwrap();
                    let original = match change {
                        "command" => {
                            legacy_block.replace("command = \"lockyard\"", "command = \"custom\"")
                        }
                        "outside_block" => {
                            format!("{legacy_block}env = {{ CUSTOM_AGENT = \"custom\" }}\n")
                        }
                        _ => legacy_block.to_string(),
                    };
                    fs::write(&path, &original).unwrap();
                    let mut receipt = Manifest::empty();
                    receipt.entries = if current_receipt {
                        specs(dir.path(), "codex", dir.path(), None)
                            .unwrap()
                            .remove(0)
                            .entries
                    } else {
                        vec![legacy_entry.clone()]
                    };
                    receipt.toml_block = Some(
                        if current_receipt {
                            TOML_BLOCK
                        } else {
                            legacy_block
                        }
                        .into(),
                    );
                    if change == "receipt" {
                        receipt.entries[0].value["command"] = json!("custom");
                    }
                    let original_receipt = serde_json::to_vec(&receipt).unwrap();
                    fs::write(sidecar(&path), &original_receipt).unwrap();
                    for action in [
                        SetupAction::Preview,
                        SetupAction::Apply,
                        SetupAction::Remove,
                    ] {
                        let report = setup_at(dir.path(), "codex", action, dir.path()).unwrap();
                        assert_eq!(report["ok"], false, "{current_receipt} {change} {action:?}");
                        assert_eq!(fs::read_to_string(&path).unwrap(), original);
                        assert_eq!(fs::read(sidecar(&path)).unwrap(), original_receipt);
                    }
                }
            }
        }
    }

    #[test]
    fn identical_preexisting_entries_are_not_claimed_or_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".cursor/mcp.json");
        fs::create_dir(path.parent().unwrap()).unwrap();
        let original =
            b"{\"mcpServers\":{\"lockyard\":{\"command\":\"lockyard\",\"args\":[\"mcp\"]}}}";
        fs::write(&path, original).unwrap();
        setup_at(dir.path(), "cursor", SetupAction::Apply, dir.path()).unwrap();
        assert!(!sidecar(&path).exists());
        setup_at(dir.path(), "cursor", SetupAction::Remove, dir.path()).unwrap();
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn receipt_cannot_claim_unrelated_user_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".cursor/mcp.json");
        fs::create_dir(path.parent().unwrap()).unwrap();
        fs::write(&path, "{\"personal\":true}").unwrap();
        let mut receipt = Manifest::empty();
        receipt.entries.push(entry(&["personal"], json!(true)));
        fs::write(sidecar(&path), serde_json::to_vec(&receipt).unwrap()).unwrap();
        let report = setup_at(dir.path(), "cursor", SetupAction::Remove, dir.path()).unwrap();
        assert_eq!(report["ok"], false);
        assert_eq!(fs::read_to_string(path).unwrap(), "{\"personal\":true}");
    }

    #[test]
    fn an_interrupted_codex_initial_install_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let spec = specs(dir.path(), "codex", dir.path(), None)
            .unwrap()
            .remove(0);
        fs::create_dir(spec.path.parent().unwrap()).unwrap();
        let mut receipt = Manifest::empty();
        receipt.entries = spec.entries.clone();
        receipt.toml_block = Some(TOML_BLOCK.into());
        fs::write(sidecar(&spec.path), serde_json::to_vec(&receipt).unwrap()).unwrap();
        let report = setup_at(dir.path(), "codex", SetupAction::Apply, dir.path()).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(
            setup_at(dir.path(), "codex", SetupAction::Check, dir.path()).unwrap()["ok"],
            true
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_inside_symlink_directory_supports_setup_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("projects");
        fs::create_dir(&base).unwrap();
        let project = base.join("project");
        fs::create_dir(&project).unwrap();
        let alias = dir.path().join("projects-alias");
        std::os::unix::fs::symlink(&base, &alias).unwrap();
        let selected = alias.join("project");
        let path = project.join(".cursor/mcp.json");
        for action in [
            SetupAction::Preview,
            SetupAction::Apply,
            SetupAction::Check,
            SetupAction::Remove,
        ] {
            let report = setup_at(&selected, "cursor", action, dir.path()).unwrap();
            assert_eq!(report["ok"], true, "{action:?}: {report}");
            if action == SetupAction::Preview {
                assert!(!path.exists());
            }
        }
        let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(value["mcpServers"].get("lockyard").is_none());
        assert!(!sidecar(&path).exists());
    }

    #[cfg(unix)]
    #[test]
    fn selected_codex_base_alias_is_resolved_before_managed_components() {
        let dir = tempfile::tempdir().unwrap();
        let selected = dir.path().join("home-alias");
        let base = dir.path().join("home");
        fs::create_dir(&base).unwrap();
        std::os::unix::fs::symlink(&base, &selected).unwrap();
        for custom in [false, true] {
            for action in [
                SetupAction::Preview,
                SetupAction::Apply,
                SetupAction::Check,
                SetupAction::Remove,
            ] {
                let report = setup_selected(
                    dir.path(),
                    "codex",
                    action,
                    &selected,
                    custom.then_some(selected.as_path()),
                )
                .unwrap();
                assert_eq!(report["ok"], true, "{custom} {action:?}: {report}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn managed_codex_directory_and_ownership_symlinks_remain_refused() {
        let dir = tempfile::tempdir().unwrap();
        let external = dir.path().join("external");
        fs::create_dir(&external).unwrap();
        let managed = dir.path().join(".codex");
        std::os::unix::fs::symlink(&external, &managed).unwrap();
        for action in [
            SetupAction::Preview,
            SetupAction::Apply,
            SetupAction::Check,
            SetupAction::Remove,
        ] {
            let report = setup_at(dir.path(), "codex", action, dir.path()).unwrap();
            assert_eq!(report["ok"], false, "{action:?}: {report}");
            assert_eq!(fs::read_dir(&external).unwrap().count(), 0);
        }
        let path = dir.path().join(".cursor/mcp.json");
        fs::create_dir(path.parent().unwrap()).unwrap();
        fs::write(&path, "{}").unwrap();
        let receipt = external.join("receipt");
        fs::write(&receipt, "{}").unwrap();
        std::os::unix::fs::symlink(&receipt, sidecar(&path)).unwrap();
        for action in [
            SetupAction::Preview,
            SetupAction::Apply,
            SetupAction::Check,
            SetupAction::Remove,
        ] {
            let report = setup_at(dir.path(), "cursor", action, dir.path()).unwrap();
            assert_eq!(report["ok"], false, "{action:?}: {report}");
            assert_eq!(fs::read_to_string(&path).unwrap(), "{}");
            assert_eq!(fs::read_to_string(&receipt).unwrap(), "{}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn user_symlink_parent_is_refused_without_writing_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let external = dir.path().join("external");
        fs::create_dir(&external).unwrap();
        // EP-14 permits aliases in the selected base; managed directories inside it
        // must still be refused rather than redirected into another directory.
        let alias = dir.path().join(".cursor");
        std::os::unix::fs::symlink(&external, &alias).unwrap();
        let report = setup_at(dir.path(), "cursor", SetupAction::Apply, dir.path()).unwrap();
        assert_eq!(report["ok"], false);
        assert!(
            report["files"][0]["message"]
                .as_str()
                .unwrap()
                .contains("parent is a symbolic link")
        );
        assert_eq!(fs::read_dir(&external).unwrap().count(), 0);
        assert!(
            fs::symlink_metadata(alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_configs_are_refused_and_backups_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".cursor/mcp.json");
        fs::create_dir(path.parent().unwrap()).unwrap();
        let external = dir.path().join("external");
        fs::write(&external, "{}").unwrap();
        std::os::unix::fs::symlink(&external, &path).unwrap();
        assert_eq!(
            setup_at(dir.path(), "cursor", SetupAction::Apply, dir.path()).unwrap()["ok"],
            false
        );
        assert_eq!(fs::read_to_string(&external).unwrap(), "{}");
        fs::remove_file(&path).unwrap();
        fs::write(&path, "{}").unwrap();
        let report = setup_at(dir.path(), "cursor", SetupAction::Apply, dir.path()).unwrap();
        let backup = PathBuf::from(report["files"][0]["backup"].as_str().unwrap());
        assert_eq!(
            fs::metadata(backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
