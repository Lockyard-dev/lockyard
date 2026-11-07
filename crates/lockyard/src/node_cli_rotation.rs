// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Customer-local rotation commands. Only public plan/receipt metadata reaches stdout.
use super::{absolute, config_path, invalid};
use clap::{Subcommand, ValueEnum};
use lockyard_core::Result;
use lockyard_node::rotation;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Clone, Copy, ValueEnum)]
pub enum RotationCause {
    MemberRevocation,
    Compromise,
}
#[derive(Clone, Copy, ValueEnum)]
pub enum RotationHistory {
    RetainPrivateHistory,
    Discard,
}

#[derive(Subcommand)]
pub enum KeyRotationCommand {
    /// Display the current local workspace phrase after typing SHOW; never contacts the cloud.
    ShowPhrase {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Create a customer-local authority key; its private bytes never leave this file.
    AuthorityGenerate {
        #[arg(long)]
        output: PathBuf,
    },
    /// Pin the independently verified customer authority; refuses replacement.
    AuthorityPin {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        public_key: String,
    },
    /// Seal a fresh workspace key only to an explicit remaining-node roster.
    Prepare {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        roster: PathBuf,
        #[arg(long, value_enum)]
        reason: RotationCause,
        #[arg(long, value_enum)]
        history: RotationHistory,
        #[arg(long)]
        epoch: u64,
        #[arg(long)]
        expires_at_ms: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign the exact reviewed plan digest; all key capsules stay customer encrypted.
    Commit {
        #[arg(long)]
        draft: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        approve_plan: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Apply a signed capsule offline to a stopped, drained node and save its receipt.
    Apply {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Recover an interrupted install using the same signed bundle and a fresh receipt path.
    Recover {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify installation receipts against the approved roster and new local key.
    Status {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long = "receipt")]
        receipts: Vec<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn failure(error: impl std::fmt::Display) -> lockyard_core::Error {
    invalid(&format!("workspace-key rotation failed: {error}"))
}
fn config(value: Option<PathBuf>) -> Result<PathBuf> {
    absolute(&config_path(value)?)
}

pub fn run(command: KeyRotationCommand) -> Result<Value> {
    match command {
        KeyRotationCommand::ShowPhrase {
            config: node_config,
        } => {
            use std::io::{BufRead, Read, Write};
            let node_config = config(node_config)?;
            eprint!("Type SHOW to display the locally configured workspace recovery phrase: ");
            std::io::stderr().flush()?;
            let mut confirmation = Vec::new();
            std::io::stdin()
                .lock()
                .take(8)
                .read_until(b'\n', &mut confirmation)?;
            let (workspace, phrase) = rotation::local_recovery_phrase(
                &node_config,
                std::str::from_utf8(&confirmation).unwrap_or(""),
            )
            .map_err(failure)?;
            Ok(json!({"workspace_id":workspace,"recovery_phrase":phrase}))
        }
        KeyRotationCommand::AuthorityGenerate { output } => {
            let output = absolute(&output)?;
            let key = rotation::authority_generate(&output).map_err(failure)?;
            let key_id = key.key_id().map_err(failure)?;
            Ok(json!({"key_file":output,"public_key":key.public_key,"authority_key_id":key_id}))
        }
        KeyRotationCommand::AuthorityPin {
            config: node_config,
            public_key,
        } => {
            let node_config = config(node_config)?;
            rotation::authority_pin(&node_config, &public_key).map_err(failure)?;
            Ok(json!({"config":node_config,"authority_pinned":true,"public_key":public_key}))
        }
        KeyRotationCommand::Prepare {
            config: node_config,
            roster,
            reason,
            history,
            epoch,
            expires_at_ms,
            output,
        } => {
            let node_config = config(node_config)?;
            let roster = absolute(&roster)?;
            let output = absolute(&output)?;
            let reason = match reason {
                RotationCause::MemberRevocation => rotation::RotationReason::MemberRevocation,
                RotationCause::Compromise => rotation::RotationReason::Compromise,
            };
            let history = match history {
                RotationHistory::RetainPrivateHistory => {
                    rotation::HistoryPolicy::RetainPrivateHistory
                }
                RotationHistory::Discard => rotation::HistoryPolicy::Discard,
            };
            let draft =
                rotation::prepare(&node_config, &roster, reason, history, epoch, expires_at_ms)
                    .map_err(failure)?;
            let digest = draft.plan_sha256().map_err(failure)?;
            rotation::write_private_json(&output, &draft).map_err(failure)?;
            let header = &draft.plan.header;
            Ok(
                json!({"draft":output,"plan_sha256":digest,"workspace":header.workspace,"epoch":header.epoch,
                "old_key_id":header.old_key_id,"new_key_id":header.new_key_id,"reason":header.reason,
                "history_policy":header.history_policy,"authority_key_id":header.authority_key_id,
                "expires_at_ms":header.expires_at_ms,"recipients":draft.plan.recipients.iter().map(|recipient|
                    json!({"node_id":recipient.node_id,"certificate_sha256":recipient.certificate_sha256})).collect::<Vec<_>>()}),
            )
        }
        KeyRotationCommand::Commit {
            draft,
            signing_key,
            approve_plan,
            output,
        } => {
            let draft = absolute(&draft)?;
            let signing_key = absolute(&signing_key)?;
            let output = absolute(&output)?;
            let bundle = rotation::commit(&draft, &signing_key, &approve_plan).map_err(failure)?;
            let digest = bundle.draft.plan_sha256().map_err(failure)?;
            rotation::write_private_json(&output, &bundle).map_err(failure)?;
            Ok(
                json!({"bundle":output,"plan_sha256":digest,"workspace":bundle.draft.plan.header.workspace,
                "epoch":bundle.draft.plan.header.epoch,"new_key_id":bundle.draft.plan.header.new_key_id,
                "recipient_count":bundle.draft.plan.recipients.len()}),
            )
        }
        KeyRotationCommand::Apply {
            config: node_config,
            bundle,
            output,
        } => install(
            config(node_config)?,
            absolute(&bundle)?,
            absolute(&output)?,
            false,
        ),
        KeyRotationCommand::Recover {
            config: node_config,
            bundle,
            output,
        } => install(
            config(node_config)?,
            absolute(&bundle)?,
            absolute(&output)?,
            true,
        ),
        KeyRotationCommand::Status {
            config: node_config,
            bundle,
            receipts,
            output,
        } => {
            let node_config = config(node_config)?;
            let bundle = absolute(&bundle)?;
            let receipts = receipts
                .iter()
                .map(|path| absolute(path))
                .collect::<Result<Vec<_>>>()?;
            let status = rotation::status(&node_config, &bundle, &receipts).map_err(failure)?;
            if let Some(output) = output {
                rotation::write_private_json(&absolute(&output)?, &status).map_err(failure)?;
            }
            serde_json::to_value(status).map_err(|_| invalid("cannot encode rotation status"))
        }
    }
}

fn install(config: PathBuf, bundle: PathBuf, output: PathBuf, recover: bool) -> Result<Value> {
    use std::os::unix::fs::MetadataExt;
    // Avoid a known destination conflict before the irreversible install. An I/O failure
    // afterward is reported as a receipt failure, never as proof the key did not change.
    if std::fs::symlink_metadata(&output).is_ok() {
        return Err(invalid(
            "receipt output already exists; choose a fresh path before applying or recovering rotation",
        ));
    }
    let parent = output
        .parent()
        .ok_or_else(|| invalid("rotation receipt needs an existing private parent directory"))?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o200 == 0
    {
        return Err(invalid(
            "rotation receipt parent must be private, owned and writable before installation",
        ));
    }
    let receipt = if recover {
        rotation::recover(&config, &bundle)
    } else {
        rotation::apply(&config, &bundle)
    }
    .map_err(failure)?;
    rotation::write_private_json(&output,&receipt).map_err(|_|invalid("rotation installed but receipt could not be saved; recover the same signed bundle to a fresh private output path"))?;
    Ok(
        json!({"receipt":output,"workspace":receipt.payload.workspace,"node_id":receipt.payload.node_id,
        "epoch":receipt.payload.epoch,"new_key_id":receipt.payload.new_key_id,"plan_sha256":receipt.payload.plan_sha256,
        "installed_at_ms":receipt.payload.installed_at_ms,"direct_trust_reconciled":receipt.payload.direct_trust_reconciled}),
    )
}
