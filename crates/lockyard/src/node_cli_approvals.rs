// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Offline customer-owner approval. These commands never send requests or execute jobs.
use super::{absolute, invalid, write_new};
use clap::{Args, Subcommand};
use lockyard_core::Result;
use lockyard_node::{
    approvals::{self, ApprovalExpectation, OwnerApproval},
    executor::{RepositoryConfig, RunnerProfile},
    provenance::{self, SigningKey, TrustedSigningKey},
    wire::{self, JobSpec},
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Args)]
pub struct ContextArgs {
    /// Exact typed job request; includes its stable ID, arguments, priority and workflow inputs.
    #[arg(long)]
    request: PathBuf,
    /// Independently reviewed JSON RunnerProfile, including pinned customer-owner public keys.
    #[arg(long)]
    runner_config: PathBuf,
    /// Reviewed repository configuration when the executor injects cloud credentials.
    #[arg(long)]
    repository_config: Option<PathBuf>,
    #[arg(long)]
    workspace: String,
    #[arg(long)]
    node: String,
    #[arg(long)]
    certificate_sha256: String,
    /// Independently resolved immutable Git commit, not a mutable branch name.
    #[arg(long)]
    revision: String,
}

#[derive(Subcommand)]
pub enum ApprovalCommand {
    /// Sign a reviewed frozen DAG request exported by node workflow approval-request.
    SignMaterialized {
        /// Independently authenticated destination context, not values inferred from the bundle.
        #[arg(long)]
        workspace: String,
        #[arg(long)]
        node: String,
        #[arg(long)]
        certificate_sha256: String,
        #[arg(long)]
        input: PathBuf,
        /// Independently reviewed target profile; its exact hash must match the frozen request.
        #[arg(long)]
        runner_config: PathBuf,
        /// Reviewed repository configuration when the executor injects cloud credentials.
        #[arg(long)]
        repository_config: Option<PathBuf>,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        not_before_ms: u64,
        #[arg(long)]
        expires_at_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Create a private owner key below the global protected Lockyard keys directory.
    Key {
        #[arg(long)]
        name: String,
    },
    /// Prepare a content-free exact approval claim for local owner review.
    Prepare {
        #[command(flatten)]
        context: ContextArgs,
        #[arg(long)]
        not_before_ms: u64,
        #[arg(long)]
        expires_at_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign a reviewed claim only when its request and runner bytes match the provided files.
    Sign {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        runner_config: PathBuf,
        /// Reviewed repository configuration when the executor injects cloud credentials.
        #[arg(long)]
        repository_config: Option<PathBuf>,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify against an independent owner pin and exact context; optionally attach to a request.
    Verify {
        #[command(flatten)]
        context: ContextArgs,
        #[arg(long)]
        approval: PathBuf,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        output_request: Option<PathBuf>,
    },
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("approval input must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(128 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 128 * 1024 {
        return Err(invalid("approval input is too large"));
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid("invalid typed approval input"))
}
pub(super) fn load_request(path: &Path) -> Result<JobSpec> {
    read_json(path)
}

fn expectation<'a>(
    context: &'a ContextArgs,
    spec: &'a JobSpec,
    runner: &'a RunnerProfile,
    repository: Option<&'a RepositoryConfig>,
) -> ApprovalExpectation<'a> {
    ApprovalExpectation {
        workspace: &context.workspace,
        node_id: &context.node,
        node_certificate_sha256: &context.certificate_sha256,
        spec,
        resolved_revision: &context.revision,
        runner,
        repository_cloud: repository.and_then(|repository| repository.cloud.as_ref()),
    }
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

/// Reject an owner-selected config root already inside a Git checkout. The
/// daemon cannot discover another machine's XDG path, so enforce this at custody.
fn reject_checkout_key_directory(path: &Path) -> Result<()> {
    let mut existing = path;
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing = existing
                    .parent()
                    .ok_or_else(|| invalid("cannot validate owner key custody directory"))?;
            }
            Err(_) => return Err(invalid("cannot validate owner key custody directory")),
        }
    }
    let canonical = existing.canonicalize()?;
    fn git_metadata(directory: &Path) -> bool {
        directory.join("HEAD").is_file()
            && ((directory.join("config").is_file() && directory.join("objects").is_dir())
                || directory.join("commondir").is_file())
    }
    for ancestor in canonical.ancestors() {
        let marker = ancestor.join(".git");
        let in_worktree = match fs::symlink_metadata(&marker) {
            Ok(metadata) if metadata.is_dir() || metadata.file_type().is_symlink() => {
                git_metadata(&marker)
            }
            Ok(metadata) if metadata.is_file() && metadata.len() <= 4096 => {
                use std::os::unix::fs::OpenOptionsExt;
                let mut text = String::new();
                let file = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&marker)?;
                file.take(4097).read_to_string(&mut text)?;
                text.trim().strip_prefix("gitdir:").is_some_and(|target| {
                    let target = Path::new(target.trim());
                    git_metadata(&if target.is_absolute() {
                        target.into()
                    } else {
                        ancestor.join(target)
                    })
                })
            }
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(invalid("cannot validate owner key custody directory")),
        };
        if in_worktree || git_metadata(ancestor) {
            return Err(invalid(
                "owner private key directory must be outside Git checkouts and repository metadata",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn owner_key_directory(create: bool) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(
            std::env::var_os("HOME").ok_or_else(|| invalid("owner key directory unavailable"))?,
        )
        .join(".config"),
    };
    if !base.is_absolute() {
        return Err(invalid(
            "owner key configuration directory must be absolute",
        ));
    }
    reject_checkout_key_directory(&base)?;
    // The standard config base may be shared-readable. Every Lockyard/key directory below it
    // must be owned, private and a real directory. Never follow a redirected key directory.
    if create {
        fs::create_dir_all(&base)?;
    }
    let mut current = base;
    for name in ["lockyard", "keys", "owner-approvals"] {
        current.push(name);
        if create {
            match fs::DirBuilder::new().mode(0o700).create(&current) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error.into()),
            }
        }
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(invalid(
                "owner key directories must be private, owned and not symlinks",
            ));
        }
        if create {
            fs::File::open(
                current
                    .parent()
                    .ok_or_else(|| invalid("invalid owner key directory"))?,
            )?
            .sync_all()?;
        }
    }
    Ok(current)
}
#[cfg(not(unix))]
fn owner_key_directory(_: bool) -> Result<PathBuf> {
    Err(invalid("owner key custody requires Unix file permissions"))
}

fn load_owner_key(path: &Path) -> Result<SigningKey> {
    let path = absolute(path)?;
    let directory = owner_key_directory(false)?;
    if path.parent() != Some(directory.as_path()) {
        return Err(invalid(
            "owner private key must remain in the global protected owner-approvals directory",
        ));
    }
    SigningKey::load(&path).map_err(|_| invalid("cannot load protected owner key"))
}

pub fn run(command: ApprovalCommand) -> Result<Value> {
    match command {
        ApprovalCommand::SignMaterialized {
            workspace,
            node,
            certificate_sha256,
            input,
            runner_config,
            repository_config,
            key_file,
            not_before_ms,
            expires_at_ms,
            output,
        } => {
            let bundle: approvals::MaterializedApproval = read_json(&input)?;
            if bundle.workspace != workspace
                || bundle.node_id != node
                || bundle.node_certificate_sha256 != certificate_sha256
            {
                return Err(invalid(
                    "frozen request differs from independently authenticated workspace or destination certificate",
                ));
            }
            let runner: RunnerProfile = read_json(&runner_config)?;
            let repository: Option<RepositoryConfig> =
                repository_config.as_deref().map(read_json).transpose()?;
            if approvals::repository_cloud_sha256(
                repository
                    .as_ref()
                    .and_then(|repository| repository.cloud.as_ref()),
            )
            .map_err(|error| invalid(error.0))?
                != bundle.repository_cloud_sha256
            {
                return Err(invalid(
                    "frozen request differs from independently reviewed repository credentials",
                ));
            }
            if lockyard_node::executor::runner_config_digest(&runner)
                .map_err(|error| invalid(error.0))?
                != bundle.runner_configuration_sha256
                || runner.action != bundle.action
                || (!runner.action.requires_owner()
                    && runner.requires_external_approval() != bundle.external_spec)
                || runner.container.image != bundle.image_reference
                || runner.owner_approval_authorities != bundle.owner_approval_authorities
            {
                return Err(invalid(
                    "frozen request differs from the independently reviewed runner profile",
                ));
            }
            let claim = bundle
                .prepare(not_before_ms, expires_at_ms)
                .map_err(|error| invalid(error.0))?;
            let now = now_ms();
            if now < claim.not_before_ms || now >= claim.expires_at_ms {
                return Err(invalid("owner approval is outside its signing window"));
            }
            let key = load_owner_key(&key_file)?;
            if !bundle
                .owner_approval_authorities
                .contains(&key.trusted_key())
            {
                return Err(invalid(
                    "owner key is not pinned by the frozen target runner profile",
                ));
            }
            let document = claim.sign(&key).map_err(|error| invalid(error.0))?;
            write_new(
                &output,
                &serde_json::to_vec_pretty(&document)
                    .map_err(|_| invalid("cannot encode signed owner approval"))?,
            )?;
            Ok(
                json!({"output":output,"job_id":claim.job_id,"key_id":document.key_id,"request_sha256":claim.request_sha256}),
            )
        }
        ApprovalCommand::Key { name } => {
            if !wire::valid_name(&name) {
                return Err(invalid("invalid owner key name"));
            }
            let path = owner_key_directory(true)?.join(format!("{name}.pk8"));
            let key = SigningKey::generate(&path)
                .map_err(|_| invalid("cannot create protected owner key"))?;
            Ok(
                json!({"key_file":path,"public_key":key.trusted_key().public_key,"key_id":key.trusted_key().key_id().map_err(|_|invalid("invalid owner key"))?}),
            )
        }
        ApprovalCommand::Prepare {
            context,
            not_before_ms,
            expires_at_ms,
            output,
        } => {
            let spec: JobSpec = read_json(&context.request)?;
            if spec.owner_approval.is_some() {
                return Err(invalid(
                    "prepare requires a request without an attached approval",
                ));
            }
            let runner: RunnerProfile = read_json(&context.runner_config)?;
            let repository: Option<RepositoryConfig> = context
                .repository_config
                .as_deref()
                .map(read_json)
                .transpose()?;
            let claim = approvals::prepare(
                &expectation(&context, &spec, &runner, repository.as_ref()),
                not_before_ms,
                expires_at_ms,
            )
            .map_err(|error| invalid(error.0))?;
            write_new(
                &output,
                &serde_json::to_vec_pretty(&claim)
                    .map_err(|_| invalid("cannot encode owner approval"))?,
            )?;
            Ok(
                json!({"output":output,"job_id":claim.job_id,"action":claim.action,"request_sha256":claim.request_sha256}),
            )
        }
        ApprovalCommand::Sign {
            input,
            request,
            runner_config,
            repository_config,
            key_file,
            output,
        } => {
            let claim = OwnerApproval::load(&input).map_err(|error| invalid(error.0))?;
            let spec: JobSpec = read_json(&request)?;
            let runner: RunnerProfile = read_json(&runner_config)?;
            let repository: Option<RepositoryConfig> =
                repository_config.as_deref().map(read_json).transpose()?;
            if spec.owner_approval.is_some() {
                return Err(invalid("sign requires the original unapproved request"));
            }
            let expected = ApprovalExpectation {
                workspace: &claim.workspace,
                node_id: &claim.node_id,
                node_certificate_sha256: &claim.node_certificate_sha256,
                spec: &spec,
                resolved_revision: &claim.resolved_revision,
                runner: &runner,
                repository_cloud: repository
                    .as_ref()
                    .and_then(|repository| repository.cloud.as_ref()),
            };
            if approvals::prepare(&expected, claim.not_before_ms, claim.expires_at_ms)
                .map_err(|error| invalid(error.0))?
                != claim
            {
                return Err(invalid(
                    "owner approval does not match reviewed request and runner",
                ));
            }
            if now_ms() < claim.not_before_ms || now_ms() >= claim.expires_at_ms {
                return Err(invalid("owner approval is outside its validity window"));
            }
            let key = load_owner_key(&key_file)?;
            if !runner
                .owner_approval_authorities
                .contains(&key.trusted_key())
            {
                return Err(invalid(
                    "owner key is not independently pinned by this runner profile",
                ));
            }
            let document = claim.sign(&key).map_err(|error| invalid(error.0))?;
            write_new(
                &output,
                &serde_json::to_vec_pretty(&document)
                    .map_err(|_| invalid("cannot encode signed owner approval"))?,
            )?;
            Ok(json!({"output":output,"job_id":claim.job_id,"key_id":document.key_id}))
        }
        ApprovalCommand::Verify {
            context,
            approval,
            public_key,
            output_request,
        } => {
            let mut spec: JobSpec = read_json(&context.request)?;
            let runner: RunnerProfile = read_json(&context.runner_config)?;
            let repository: Option<RepositoryConfig> = context
                .repository_config
                .as_deref()
                .map(read_json)
                .transpose()?;
            let document =
                provenance::load_document(&approval).map_err(|error| invalid(error.0))?;
            let key = TrustedSigningKey { public_key };
            if !runner.owner_approval_authorities.contains(&key) {
                return Err(invalid(
                    "owner key is absent from independently configured runner authorities",
                ));
            }
            let claim = approvals::verify(
                &document,
                &[key],
                &expectation(&context, &spec, &runner, repository.as_ref()),
                now_ms(),
            )
            .map_err(|error| invalid(error.0))?;
            if let Some(path) = &output_request {
                spec.owner_approval = Some(document);
                write_new(
                    path,
                    &serde_json::to_vec_pretty(&spec)
                        .map_err(|_| invalid("cannot encode approved request"))?,
                )?;
            }
            Ok(json!({"verified":true,"claim":claim,"output_request":output_request}))
        }
    }
}
