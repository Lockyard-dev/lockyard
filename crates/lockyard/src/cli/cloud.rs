// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn read_json(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text)
        .map_err(|error| Error::Invalid(format!("{}: {error}", path.display())))
}

pub(super) fn run_cloud(
    mut opened: Opened,
    command: CloudCommand,
    agent: Option<&String>,
) -> Result<Output> {
    let backend = opened.backend.as_mut();
    if !backend.is_cloud() {
        return Err(Error::needs_cloud("this command"));
    }
    let agent = agent
        .cloned()
        .or_else(env_agent)
        .unwrap_or_else(|| "lockyard-cli".to_string());
    let answer = match command {
        CloudCommand::Trust { .. } | CloudCommand::Login { .. } | CloudCommand::Logout { .. } => {
            unreachable!("these are handled before opening the project")
        }
        CloudCommand::Export => backend.export()?,
        CloudCommand::Freeze { state, reason } => {
            backend.freeze(&agent, &Freeze { on: state, reason })?
        }
        CloudCommand::ReleaseSession { session } => backend.release_session(&agent, &session)?,
        CloudCommand::ImportZones { file } => backend.import_zones(&agent, &read_json(&file)?)?,
        CloudCommand::ImportBus { file } => backend.import_bus(&agent, &read_json(&file)?)?,
        CloudCommand::ImportRegistry { file } => {
            backend.registry_import(&agent, &read_json(&file)?)?
        }
        CloudCommand::Area(CloudAreaCommand::List) => backend.area_list(&agent)?,
        CloudCommand::Area(CloudAreaCommand::Create {
            key,
            name,
            prefix,
            pad,
        }) => backend.area_create(
            &agent,
            &json!({"key": key, "name": name, "prefix": prefix, "pad": pad}),
        )?,
        CloudCommand::Area(CloudAreaCommand::Update {
            key,
            name,
            prefix,
            pad,
        }) => {
            let mut request = json!({});
            if let Some(name) = name {
                request["name"] = json!(name);
            }
            if let Some(prefix) = prefix {
                request["prefix"] = json!(prefix);
            }
            if let Some(pad) = pad {
                request["pad"] = json!(pad);
            }
            backend.area_update(&agent, &key, &request)?
        }
        CloudCommand::Token(command) => return run_token(backend, command, &agent),
        CloudCommand::Key(_) => {
            unreachable!("local key commands are handled before opening the cloud backend")
        }
        CloudCommand::Encryption(_) => {
            unreachable!("workspace encryption commands use the direct client")
        }
    };
    let text = answer.to_string();
    output(&answer, text)
}

/// The agent must start while the server is away, so the encryption setting it last saw is kept
/// in its state folder and used until the server answers again. A setting the server sends wins.
#[cfg(unix)]
pub(super) fn agent_client(
    client: lockyard_cloud_client::Client,
) -> Result<lockyard_cloud_client::Client> {
    use lockyard_cloud_client::{ClientError, WorkspaceEncryption};
    let cache = agent::state_root()?.join("encryption.json");
    let session = client.service_session(&format!("lockyard-agent-{}", agent::uid()));
    match client.workspace_encryption(&session) {
        Ok(setting) => {
            if let Ok(text) = serde_json::to_string(&setting) {
                let _ = std::fs::create_dir_all(cache.parent().unwrap_or(&cache));
                let _ = std::fs::write(&cache, text);
            }
            Ok(client.apply_content_encryption(setting)?)
        }
        Err(ClientError::NotFound(_)) => Ok(client),
        Err(
            error @ (ClientError::Transport(_)
            | ClientError::Frozen(_)
            | ClientError::RateLimited(_)
            | ClientError::Http(_)),
        ) => {
            match std::fs::read_to_string(&cache)
                .ok()
                .and_then(|text| serde_json::from_str::<WorkspaceEncryption>(&text).ok())
            {
                Some(setting) => Ok(client.apply_content_encryption(setting)?),
                None => {
                    eprintln!(
                        "lockyard agent: encryption setting unavailable ({error}); starting without it until the server answers"
                    );
                    Ok(client)
                }
            }
        }
        Err(error) => Err(error.into()),
    }
}

/// The server a cloud command works on: the one asked for, or this project's.
///
/// A URL typed on the command line is an explicit decision and is trusted once the login
/// succeeds. A URL that only came out of a project file is not: that file can arrive with a
/// clone, so it still has to be named in `lockyard cloud trust` first.
pub(super) fn cloud_server(cwd: &Path, asked: Option<String>) -> Result<(String, bool)> {
    if let Some(url) = asked {
        return Ok((url.trim_end_matches('/').to_string(), true));
    }
    let root = lockyard_core::paths::find_root(cwd).ok_or(Error::NoProject)?;
    let config = lockyard_core::config::Config::load(&root)?;
    let (url, _) = open::endpoint(&config)?;
    open::trusted_url(&url)?;
    Ok((url.trim_end_matches('/').to_string(), false))
}

pub(super) fn run_cloud_login(cwd: &Path, url: Option<String>, no_browser: bool) -> Result<Output> {
    use lockyard_cloud_client::device;
    let (url, typed) = cloud_server(cwd, url)?;
    let machine = machine_name();
    let post = device::HttpDevice::new(&url)?;
    let mut announce = |start: &device::Start| {
        let link = start
            .verification_uri_complete
            .as_deref()
            .unwrap_or(&start.verification_uri);
        // Printed to stderr so `--json` output stays one JSON document on stdout.
        eprintln!("code {}\nopen {link}", start.user_code);
        if !no_browser && !open_browser(link) {
            eprintln!("open that page in a browser to finish signing in");
        }
    };
    let granted = device::login(&post, &machine, &url, &mut announce, &mut |wait| {
        std::thread::sleep(wait);
    })?;
    if typed {
        open::trust_url(&granted.server_url)?;
    }
    lockyard_core::credentials::save_in(
        &lockyard_core::credentials::path()?,
        &lockyard_core::credentials::Entry {
            url: granted.server_url.clone(),
            token: granted.token.clone(),
            workspace_id: granted.workspace_id.clone(),
            workspace_name: granted.workspace_name.clone(),
            role: granted.role.clone(),
        },
    )?;
    // The token itself is never printed: it is in a 0600 file and nowhere else.
    output(
        &json!({
            "server": granted.server_url,
            "workspace": granted.workspace_name,
            "workspace_id": granted.workspace_id,
            "role": granted.role,
        }),
        format!(
            "signed in to {} as {} on {}",
            granted.workspace_name, granted.role, granted.server_url
        ),
    )
}

pub(super) fn run_cloud_logout(cwd: &Path, url: Option<String>) -> Result<Output> {
    let (url, _) = cloud_server(cwd, url)?;
    let path = lockyard_core::credentials::path()?;
    let had = lockyard_core::credentials::forget_in(&path, &url)?;
    let text = if had {
        format!("signed out of {url}")
    } else {
        format!("no token was stored for {url}")
    };
    output(&json!({"server": url, "removed": had}), text)
}

/// What the panel calls this machine in the token list. Only a label.
pub(super) fn machine_name() -> String {
    if let Ok(name) = std::env::var("LOCKYARD_MACHINE")
        && !name.trim().is_empty()
    {
        return name.trim().to_string();
    }
    #[cfg(unix)]
    {
        let mut buffer = [0_i8; 256];
        // SAFETY: the buffer and its length are handed over together and the result is only
        // read up to the first NUL that gethostname wrote.
        if unsafe { libc::gethostname(buffer.as_mut_ptr(), buffer.len() - 1) } == 0 {
            let bytes: Vec<u8> = buffer
                .iter()
                .take_while(|byte| **byte != 0)
                .map(|byte| *byte as u8)
                .collect();
            if let Ok(name) = String::from_utf8(bytes)
                && !name.is_empty()
            {
                return name;
            }
        }
    }
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
}

/// Asks the desktop to open a link. Answers whether the request could be handed over at all.
pub(super) fn open_browser(link: &str) -> bool {
    let (program, first) = if cfg!(target_os = "macos") {
        ("open", None)
    } else if cfg!(target_os = "windows") {
        ("cmd", Some("/c"))
    } else {
        ("xdg-open", None)
    };
    let mut command = std::process::Command::new(program);
    if let Some(first) = first {
        command.arg(first).arg("start").arg("");
    }
    command
        .arg(link)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

pub(super) fn run_cloud_key(cwd: &Path, command: KeyCommand) -> Result<Output> {
    use lockyard_cloud_client::WorkspaceKey;
    let root = lockyard_core::paths::find_root(cwd).ok_or(Error::NoProject)?;
    let config = lockyard_core::config::Config::load(&root)?;
    let (url, _) = open::endpoint(&config)?;
    let client = open::direct_client(&url)?;
    let setting = client.workspace_encryption("lockyard-cli")?;
    let workspace = setting.workspace_id;
    match command {
        KeyCommand::Create => {
            let (key, _phrase) = WorkspaceKey::generate().map_err(Error::Invalid)?;
            key.store_for_workspace(&workspace)
                .map_err(Error::Invalid)?;
            output(
                &json!({"created":true,"key_id":key.key_id()}),
                format!("created local key {}", key.key_id()),
            )
        }
        KeyCommand::ShowPhrase => {
            eprint!("Type SHOW to display this workspace recovery phrase: ");
            std::io::stderr().flush()?;
            let mut confirmation = String::new();
            std::io::stdin().read_line(&mut confirmation)?;
            if confirmation.trim() != "SHOW" {
                return Err(Error::Invalid(
                    "recovery phrase display was not confirmed".into(),
                ));
            }
            let key = WorkspaceKey::load_for_workspace(&workspace)
                .map_err(Error::Invalid)?
                .ok_or_else(|| Error::Invalid("no local key exists for this workspace".into()))?;
            let phrase = key.phrase();
            output(&json!({"recovery_phrase":phrase}), phrase)
        }
        KeyCommand::Import => {
            let mut phrase = String::new();
            std::io::stdin().read_to_string(&mut phrase)?;
            let key = WorkspaceKey::from_phrase(&phrase).map_err(Error::Invalid)?;
            key.store_for_workspace(&workspace)
                .map_err(Error::Invalid)?;
            output(
                &json!({"imported":true,"key_id":key.key_id()}),
                format!("imported local key {}", key.key_id()),
            )
        }
    }
}

pub(super) fn run_cloud_encryption(cwd: &Path, command: EncryptionCommand) -> Result<Output> {
    use lockyard_cloud_client::WorkspaceKey;
    let root = lockyard_core::paths::find_root(cwd).ok_or(Error::NoProject)?;
    let config = lockyard_core::config::Config::load(&root)?;
    let (url, _) = open::endpoint(&config)?;
    let client = open::direct_client(&url)?;
    let setting = client.workspace_encryption("lockyard-cli")?;
    let key = WorkspaceKey::load_for_workspace(&setting.workspace_id).map_err(Error::Invalid)?;
    match command {
        EncryptionCommand::Status => {
            let local_id = key.as_ref().map(WorkspaceKey::key_id);
            let matches = match (&local_id, &setting.key_id) {
                (Some(local), Some(server)) => local == server,
                _ => false,
            };
            let text = format!(
                "encryption {}, key id {}, local key {}",
                setting.encryption,
                setting.key_id.as_deref().unwrap_or("none"),
                if matches {
                    "matches"
                } else if local_id.is_some() {
                    "does not match"
                } else {
                    "missing"
                }
            );
            output(
                &json!({"encryption":setting.encryption,"key_id":setting.key_id,"local_key_matches":matches}),
                text,
            )
        }
        EncryptionCommand::Require => {
            let key = key.ok_or_else(|| Error::Invalid(
                "no local workspace key exists; create one with `lockyard cloud key create` or import it with `lockyard cloud key import`".into(),
            ))?;
            let id = key.key_id();
            client.set_workspace_encryption("lockyard-cli", "required", Some(&id))?;
            output(
                &json!({"encryption":"required","key_id":id}),
                format!("encryption required with key {id}"),
            )
        }
        EncryptionCommand::Off => {
            client.set_workspace_encryption("lockyard-cli", "off", None)?;
            output(&json!({"encryption":"off"}), "encryption off")
        }
    }
}

pub(super) fn run_token(
    backend: &mut dyn Backend,
    command: TokenCommand,
    agent: &str,
) -> Result<Output> {
    let line = |token: &Value| {
        let field = |name: &str| token[name].as_str().unwrap_or("-").to_string();
        let revoked = if token["revoked_at"].is_string() {
            "  revoked"
        } else {
            ""
        };
        format!(
            "{}  {}  {}  until {}{revoked}",
            field("id"),
            field("role"),
            field("name"),
            field("expires_at")
        )
    };
    match command {
        TokenCommand::Create { name, role, days } => {
            let request = TokenRequest {
                name,
                role,
                expires_at: rfc3339(now_ms().saturating_add(days.saturating_mul(DAY_MS))),
            };
            let answer = backend.token_create(agent, &request)?;
            let raw = answer["raw"].as_str().unwrap_or_default();
            let text = format!(
                "{}\nThis token is shown once:\n{raw}",
                line(&answer["token"])
            );
            output(&answer, text)
        }
        TokenCommand::List => {
            let answer = backend.tokens()?;
            let rows = answer.as_array().map_or(&[][..], Vec::as_slice);
            let text = join(rows, line, "no tokens");
            output(&answer, text)
        }
        TokenCommand::Revoke { id } => {
            let answer = backend.token_revoke(agent, &id)?;
            let text = line(&answer);
            output(&answer, text)
        }
    }
}
