// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Explicit local signed update management. These commands never start the downloaded executable.
use clap::Subcommand;
use lockyard_core::{Error, Result};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum UpdateCommand {
    /// Sign a customer-controlled release statement; this is not permission to publish it.
    Sign {
        #[arg(long)]
        statement: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Opt a dedicated private executable into management with an independently pinned signed baseline.
    Init {
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Inspect a signed local candidate and return its exact approval digest, without installing it.
    Prepare {
        #[arg(long)]
        release: PathBuf,
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Install the exact reviewed candidate while drained, stopped and fully reconciled; never restarts it.
    Apply {
        #[arg(long)]
        prepared: PathBuf,
        #[arg(long)]
        approval_sha256: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Finish a previously approved interrupted transaction; never guesses an execution outcome.
    Recover {
        #[arg(long)]
        approval_sha256: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Explicitly restore only the previous independently verified installation, retaining the high-water sequence.
    Rollback {
        #[arg(long)]
        approval_sha256: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Inspect installed and pending signed release metadata and the rollback approval digest.
    Status {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}
fn config(value: Option<PathBuf>) -> Result<PathBuf> {
    value
        .or_else(|| std::env::var_os("LOCKYARD_NODE_CONFIG").map(PathBuf::from))
        .ok_or_else(|| Error::Invalid("set --config or LOCKYARD_NODE_CONFIG".into()))
}
fn absolute(value: PathBuf) -> Result<PathBuf> {
    if value.is_absolute() {
        Ok(value)
    } else {
        Ok(std::env::current_dir()?.join(value))
    }
}
fn failure(error: lockyard_node::updates::UpdateError) -> Error {
    Error::Invalid(error.0.into())
}
pub fn run(command: UpdateCommand) -> Result<Value> {
    use lockyard_node::updates;
    match command {
        UpdateCommand::Sign {
            statement,
            key_file,
            output,
        } => {
            let release: updates::Release =
                lockyard_node::rotation::read_private_json(&absolute(statement)?)
                    .map_err(|_| Error::Invalid("invalid private release statement".into()))?;
            let signed = updates::sign_release(&release, &absolute(key_file)?).map_err(failure)?;
            let output = absolute(output)?;
            lockyard_node::rotation::write_private_json(&output, &signed)
                .map_err(|_| Error::Invalid("cannot write new private signed release".into()))?;
            Ok(
                serde_json::json!({"output":output,"release_sha256":lockyard_node::provenance::sha256(&serde_json::to_vec(&signed).map_err(|_|Error::Invalid("cannot encode signed release".into()))?),"published":false}),
            )
        }
        UpdateCommand::Init {
            binary,
            public_key,
            baseline,
            config: input,
        } => updates::initialize(
            &config(input)?,
            &absolute(binary)?,
            &public_key,
            &absolute(baseline)?,
        )
        .map_err(failure),
        UpdateCommand::Prepare {
            release,
            binary,
            config: input,
        } => updates::prepare(&config(input)?, &absolute(release)?, &absolute(binary)?)
            .map_err(failure),
        UpdateCommand::Apply {
            prepared,
            approval_sha256,
            config: input,
        } => {
            updates::apply(&config(input)?, &absolute(prepared)?, &approval_sha256).map_err(failure)
        }
        UpdateCommand::Recover {
            approval_sha256,
            config: input,
        } => updates::recover(&config(input)?, &approval_sha256).map_err(failure),
        UpdateCommand::Rollback {
            approval_sha256,
            config: input,
        } => updates::rollback(&config(input)?, &approval_sha256).map_err(failure),
        UpdateCommand::Status { config: input } => {
            updates::status(&config(input)?).map_err(failure)
        }
    }
}
