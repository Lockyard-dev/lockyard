// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Local operator interface to the persistent node service.
use clap::Subcommand;
use lockyard_core::{Error, Result};
use lockyard_node::{
    host, quic,
    wire::{self, JobSpec, LogChunk, Operation},
};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[path = "node_cli_approvals.rs"]
mod approvals;
#[path = "node_cli_rotation.rs"]
mod key_rotation;

#[path = "node_download.rs"]
mod download;

#[path = "node_install.rs"]
mod install;
#[path = "node_update_cli.rs"]
mod node_update_cli;

#[derive(Subcommand)]
#[command(defer = true)]
pub enum NodeCommand {
    /// Explicitly install and load AppArmor user-namespace permission for the exact binaries; root only.
    Install {
        #[arg(long, required = true)]
        apparmor: bool,
        #[arg(long)]
        sandbox_binary: PathBuf,
        /// Defaults to this executable; use the installed root-owned path.
        #[arg(long)]
        lockyard_binary: Option<PathBuf>,
    },
    /// Measure the provisioned native rootfs for its offline signed attestation.
    NativeImageDigest {
        #[arg(long)]
        rootfs: PathBuf,
    },
    /// Explicit local offline signed executable maintenance; never restarts a daemon.
    Update {
        #[command(subcommand)]
        command: node_update_cli::UpdateCommand,
    },
    /// Inspect or explicitly review unresolved outbound executions before maintenance.
    Dispatch {
        #[command(subcommand)]
        command: DispatchCommand,
    },
    /// Prepare, sign and verify exact owner authorization entirely offline.
    Approval {
        #[command(subcommand)]
        command: approvals::ApprovalCommand,
    },
    /// Operate durable distributed DAGs in the local daemon.
    Workflow {
        #[command(subcommand)]
        command: DistributedWorkflowCommand,
    },
    /// Rotate workspace keys only for member revocation or compromise.
    KeyRotation {
        #[command(subcommand)]
        command: key_rotation::KeyRotationCommand,
    },
    /// Inspect an exact active or inactive node credential generation; owner only.
    Binding {
        node_id: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Revoke and retire one dedicated machine generation before explicit re-enrollment.
    Retire {
        node_id: String,
        #[arg(long)]
        credential_id: String,
        #[arg(long)]
        certificate_sha256: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Create a recipient certificate and public request without a workspace key.
    PrepareJoin {
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        tls_name: String,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    /// Create an expiring one-use invitation, or resume its durable private receipt.
    Invite {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, conflicts_with = "resume", requires = "output")]
        request: Option<PathBuf>,
        #[arg(long, conflicts_with = "resume", requires = "request")]
        output: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["request", "output"])]
        resume: Option<PathBuf>,
        #[arg(long, default_value_t = 900)]
        expires_seconds: u64,
        #[arg(long, default_value_t = 30)]
        credential_days: u64,
    },
    /// Redeem an invitation for this prepared recipient and save a private configuration.
    Join {
        #[arg(long)]
        invite: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        config: PathBuf,
    },
    /// Revoke an invitation and its granted machine credential, if already redeemed.
    InviteRevoke {
        id: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Create an Ed25519 result or customer-attester key in an existing private directory.
    SigningKey {
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign an explicit local image statement after a customer scanner produced its evidence.
    SignImageAttestation {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Create a private configuration and identity. Import the workspace key first.
    Init {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        workspace: String,
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        tls_name: String,
    },
    /// Explicitly pin the server revocation key through the configured authenticated HTTPS origin.
    RevocationTrust {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Write a new private config; review it and restart the daemon with this path.
        #[arg(long)]
        output: PathBuf,
    },
    /// Run the node service in the foreground.
    Serve {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Inspect the local node service.
    Status {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Persistently stop admitting new job IDs while existing work finishes.
    Drain {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Resume new job admission after operator review.
    Resume {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Inspect local drain state and outstanding work, without changing it.
    DrainStatus {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// List configured peers.
    List {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Inspect encrypted scheduling capabilities of a node.
    Describe {
        target: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Test a configured peer.
    Ping {
        target: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
#[command(defer = true)]
pub enum DispatchCommand {
    Pending {
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Use only after independently verifying or stopping the exact old remote execution.
    /// This clears a maintenance fence; it does not verify success or retry the job.
    Review {
        target: String,
        job_id: String,
        #[arg(long)]
        certificate_sha256: String,
        #[arg(long)]
        source_certificate_sha256: Option<String>,
        #[arg(long)]
        binding: String,
        #[arg(long)]
        confirm_no_active_execution: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
#[command(defer = true)]
pub enum DistributedWorkflowCommand {
    /// Validate and durably enqueue an explicit workflow definition. Retain its ID for retries.
    Submit {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    ApprovalRequest {
        id: String,
        step: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    ApprovalAttach {
        id: String,
        step: String,
        #[arg(long)]
        definition_sha256: String,
        #[arg(long)]
        approval: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Status {
        id: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    List {
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Cancel {
        id: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// After drain, independent stop checks and separate outbound reviews, abandon an uncertain DAG without success or replay.
    Abandon {
        id: String,
        #[arg(long)]
        definition_sha256: String,
        #[arg(long)]
        controller_certificate_sha256: String,
        #[arg(long)]
        confirm_no_active_execution: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
#[command(defer = true)]
pub enum JobCommand {
    /// Download an authenticated signed result statement using the node key pinned in config.
    Manifest {
        target: String,
        job_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Verify a saved result against an independently pinned key and exact expected context.
    VerifyManifest {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        node: String,
        #[arg(long)]
        workspace: String,
        #[arg(long)]
        job: String,
        #[arg(long)]
        revision: String,
        #[arg(long)]
        image_digest: String,
        #[arg(long)]
        request_sha256: Option<String>,
        #[arg(long)]
        patch: Option<PathBuf>,
        #[arg(long)]
        log: Option<PathBuf>,
    },
    /// List durable local submission receipts for recovery.
    Receipts {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Inspect one durable local submission receipt.
    Receipt {
        job_id: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Submit a job. Save the ID and reuse it to reconcile uncertain outcomes.
    Submit {
        target: String,
        #[arg(long)]
        repository: String,
        #[arg(long, default_value = "HEAD")]
        revision: String,
        #[arg(long)]
        runner: String,
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        timeout_seconds: Option<u64>,
        #[arg(long,default_value_t=0,value_parser=clap::value_parser!(i16).range(-20..=20))]
        priority: i16,
        #[arg(long)]
        prompt_file: Option<PathBuf>,
        /// Offline owner signature required by a managed git_push/publish/deploy profile.
        #[arg(long)]
        owner_approval: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(last = true)]
        arguments: Vec<String>,
    },
    /// Submit an exact typed JSON request, including a previously verified owner approval.
    SubmitSpec {
        target: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Status {
        target: String,
        job_id: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Logs {
        target: String,
        job_id: String,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value_t=wire::DEFAULT_LOG_BYTES)]
        limit: u32,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Cancel {
        target: String,
        job_id: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Download the retained Git patch to a new private file; never applies it.
    Patch {
        target: String,
        job_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Explicitly download a node-signed encrypted portable archive; never applies it.
    Archive {
        target: String,
        job_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Verify and decrypt an archive into a new offline review directory; never runs jobs.
    RestoreArchive {
        target: String,
        /// Explicit retained-history key; never installs or replaces the active workspace key.
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Resolve an interrupted-unknown job after operator review.
    ResolveUnknown {
        target: String,
        job_id: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}
fn invalid(message: &str) -> Error {
    Error::Invalid(message.into())
}
fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new().map_err(|_| invalid("cannot start node runtime"))
}
fn config_path(config: Option<PathBuf>) -> Result<PathBuf> {
    config
        .or_else(|| std::env::var_os("LOCKYARD_NODE_CONFIG").map(PathBuf::from))
        .ok_or_else(|| invalid("set --config or LOCKYARD_NODE_CONFIG"))
}
fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn node(command: NodeCommand) -> Result<Value> {
    match command {
        NodeCommand::Install {
            apparmor,
            sandbox_binary,
            lockyard_binary,
        } => install::apparmor(apparmor, &sandbox_binary, lockyard_binary.as_deref()),
        NodeCommand::NativeImageDigest { rootfs } => {
            let digest = lockyard_node::native::rootfs_digest(&rootfs)
                .map_err(|error| Error::Invalid(error.to_string()))?;
            Ok(
                json!({"image": format!("native@{digest}"), "image_digest": digest, "image_config_digest": digest}),
            )
        }
        NodeCommand::Update { command } => node_update_cli::run(command),
        NodeCommand::Approval { command } => approvals::run(command),
        NodeCommand::KeyRotation { command } => key_rotation::run(command),
        NodeCommand::Binding { node_id, config } => {
            let config = config_path(config)?;
            lockyard_node::invites::binding(&config, &node_id)
                .map_err(|error| invalid(&error.to_string()))
        }
        NodeCommand::Retire {
            node_id,
            credential_id,
            certificate_sha256,
            config,
        } => {
            let config = config_path(config)?;
            lockyard_node::invites::retire_node(
                &config,
                &node_id,
                &credential_id,
                &certificate_sha256,
            )
            .map_err(|error| invalid(&error.to_string()))
        }
        NodeCommand::PrepareJoin {
            node_id,
            tls_name,
            state_dir,
            request,
        } => lockyard_node::invites::prepare(node_id, tls_name, &state_dir, &request)
            .map_err(|error| invalid(&error.to_string())),
        NodeCommand::Invite {
            config,
            request,
            output,
            resume,
            expires_seconds,
            credential_days,
        } => {
            let config = config_path(config)?;
            let result = match (request, output, resume) {
                (Some(request), Some(output), None) => lockyard_node::invites::create(
                    &config,
                    &request,
                    &output,
                    expires_seconds,
                    credential_days,
                ),
                (None, None, Some(receipt)) => lockyard_node::invites::resume(&config, &receipt),
                _ => return Err(invalid("provide --request and --output, or --resume")),
            };
            result.map_err(|error| invalid(&error.to_string()))
        }
        NodeCommand::Join {
            invite,
            state_dir,
            config,
        } => lockyard_node::invites::join(&invite, &state_dir, &config)
            .map_err(|error| invalid(&error.to_string())),
        NodeCommand::InviteRevoke { id, config } => {
            let config = config_path(config)?;
            lockyard_node::invites::revoke(&config, &id)
                .map_err(|error| invalid(&error.to_string()))
        }
        NodeCommand::SigningKey { output } => {
            let path = absolute(&output)?;
            let key = lockyard_node::provenance::SigningKey::generate(&path)
                .map_err(|_| invalid("cannot create a private signing key"))?;
            Ok(
                json!({"key_file":path,"public_key":key.trusted_key().public_key,"key_id":key.trusted_key().key_id().map_err(|_| invalid("invalid signing key"))?}),
            )
        }
        NodeCommand::SignImageAttestation {
            input,
            key_file,
            output,
        } => {
            let key = lockyard_node::provenance::SigningKey::load(&absolute(&key_file)?)
                .map_err(|_| invalid("cannot load private attester key"))?;
            let statement = lockyard_node::supply_chain::ImageAttestation::load(&input)
                .map_err(|_| invalid("invalid image attestation statement"))?;
            let signed = statement
                .sign(&key)
                .map_err(|_| invalid("cannot sign image attestation"))?;
            write_new(
                &output,
                &serde_json::to_vec_pretty(&signed)
                    .map_err(|_| invalid("cannot encode attestation"))?,
            )?;
            Ok(json!({"output":output,"key_id":signed.key_id}))
        }
        NodeCommand::Init {
            config,
            node_id,
            workspace,
            state_dir,
            tls_name,
        } => {
            if !wire::valid_name(&workspace) {
                return Err(invalid("invalid workspace ID"));
            }
            if !wire::valid_name(&node_id) {
                return Err(invalid("invalid node ID"));
            }
            lockyard_cloud_client::WorkspaceKey::load_for_workspace(&workspace)
                .map_err(|_| invalid("cannot load workspace key"))?
                .ok_or_else(|| invalid("import the workspace key before initializing a node"))?;
            let config = absolute(&config)?;
            let state_dir = absolute(&state_dir)?;
            if config.exists() || state_dir.exists() {
                return Err(invalid(
                    "configuration and state directory must not already exist",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&state_dir)?;
            }
            #[cfg(not(unix))]
            {
                fs::create_dir(&state_dir)?;
            }
            let identity = quic::generate_identity(&state_dir, vec![tls_name])
                .map_err(|_| invalid("cannot create node identity"))?;
            let signing_file = state_dir.join("result-signing.pk8");
            let signer = lockyard_node::provenance::SigningKey::generate(&signing_file)
                .map_err(|_| invalid("cannot create result signing identity"))?;
            let own_trust =
                std::collections::BTreeMap::from([(node_id.clone(), signer.trusted_key())]);
            let value = json!({"node_id":node_id,"workspace":workspace,"state_dir":state_dir,"certificate":identity.certificate,"private_key":identity.private_key,"trust_anchors":[],"peers":[],"rpc_timeout_seconds":60,"result_trust":own_trust});
            let text = toml::to_string_pretty(&value)
                .map_err(|_| invalid("cannot encode node configuration"))?;
            write_new(&config, text.as_bytes())?;
            Ok(
                json!({"config":config,"certificate":identity.certificate,"certificate_sha256":identity.certificate_sha256,"result_signing":{"workspace":workspace,"key_file":signing_file,"public_key":signer.trusted_key().public_key}}),
            )
        }
        NodeCommand::RevocationTrust { config, output } => {
            let source = config_path(config)?;
            let mut configuration =
                host::NodeConfig::load(&source).map_err(|error| invalid(&error.to_string()))?;
            let client = lockyard_node::cloud::NodeCloudClient::from_config(&configuration)
                .map_err(|error| invalid(&error.to_string()))?;
            let trust = client
                .bootstrap_revocation_trust(&configuration.workspace)
                .map_err(|error| invalid(&error.to_string()))?;
            let key_id = trust.key_id.clone();
            configuration.revocations = Some(lockyard_node::revocations::RevocationConfig {
                required: true,
                poll_seconds: 30,
                max_offline_seconds: 600,
                trust,
            });
            let destination = absolute(&output)?;
            let bytes = toml::to_string_pretty(&configuration)
                .map_err(|_| invalid("cannot encode node configuration"))?;
            write_new(&destination, bytes.as_bytes())?;
            Ok(json!({"config":destination,"key_id":key_id,"restart_required":true}))
        }
        NodeCommand::Serve { config } => {
            let _shutdown = crate::shutdown::Guard::new(&std::env::current_dir()?)?;
            let config = config_path(config)?;
            let config = host::NodeConfig::load(&config)
                .map_err(|_| invalid("invalid node configuration"))?;
            // Cancellation drops the host future and aborts its background tasks. Runtime
            // shutdown then joins runtime workers before the outer checkpoint guard drops.
            let runtime = runtime()?;
            let outcome = runtime.block_on(async {
                tokio::select! {
                    outcome = host::serve(config) => outcome,
                    _ = async {
                        while !crate::shutdown::requested() {
                            tokio::time::sleep(crate::shutdown::POLL_INTERVAL).await;
                        }
                    } => Ok(()),
                }
            });
            drop(runtime);
            outcome.map_err(|_| invalid("node service failed"))?;
            Ok(json!({"stopped":true}))
        }
        NodeCommand::Status { config } => {
            let path = config_path(config)?;
            let status = runtime()?
                .block_on(host::status(&path))
                .map_err(|_| invalid("node service unavailable"))?;
            serde_json::to_value(status).map_err(|_| invalid("cannot encode node status"))
        }
        NodeCommand::Drain { config } => local_drain(config, Some(true)),
        NodeCommand::Resume { config } => local_drain(config, Some(false)),
        NodeCommand::DrainStatus { config } => local_drain(config, None),
        NodeCommand::List { config } => {
            let path = config_path(config)?;
            let config =
                host::NodeConfig::load(&path).map_err(|_| invalid("invalid node configuration"))?;
            if config.delegation_socket.is_some() {
                return rpc(
                    Some(path),
                    &config.node_id,
                    Operation::NodePing,
                    json!({"discover":true}),
                );
            }
            if config.relay.is_some() {
                let client = lockyard_node::cloud::NodeCloudClient::from_config(&config)
                    .map_err(|_| invalid("cannot configure node directory"))?;
                let entries = runtime()?
                    .block_on(client.directory())
                    .map_err(|_| invalid("node directory unavailable"))?;
                Ok(json!({"source":"cloud", "nodes":entries}))
            } else {
                Ok(json!({"source":"configured_peers", "peers":config.peers}))
            }
        }
        NodeCommand::Dispatch { command } => {
            use lockyard_node::incarnation::DispatchControl;
            let (config, request) = match command {
                DispatchCommand::Pending {
                    offset,
                    limit,
                    config,
                } => (config, DispatchControl::List { offset, limit }),
                DispatchCommand::Review {
                    target,
                    job_id,
                    certificate_sha256,
                    source_certificate_sha256,
                    binding,
                    confirm_no_active_execution,
                    config,
                } => {
                    if !confirm_no_active_execution {
                        return Err(invalid(
                            "independently stop or verify the exact remote execution, then supply --confirm-no-active-execution; this only clears the maintenance fence",
                        ));
                    }
                    (
                        config,
                        DispatchControl::Review {
                            job_id,
                            target,
                            certificate_sha256,
                            source_certificate_sha256,
                            binding,
                            confirm_no_active_execution,
                        },
                    )
                }
            };
            runtime()?.block_on(host::local_dispatch(&config_path(config)?,request))
                .map_err(|_|invalid("outbound dispatch review failed; check the exact pending identity and binding"))
        }
        NodeCommand::Workflow { command } => {
            use lockyard_node::workflow::WorkflowControl;
            match command {
                DistributedWorkflowCommand::Submit { file, config } => {
                    let mut bytes = Vec::new();
                    OpenOptions::new()
                        .read(true)
                        .open(&file)?
                        .take(131073)
                        .read_to_end(&mut bytes)?;
                    if bytes.len() > 131072 {
                        return Err(invalid("workflow definition exceeds 128 KiB"));
                    }
                    let definition = if file
                        .extension()
                        .is_some_and(|extension| extension == "toml")
                    {
                        toml::from_str(
                            std::str::from_utf8(&bytes)
                                .map_err(|_| invalid("invalid workflow definition"))?,
                        )
                        .map_err(|_| invalid("invalid workflow definition"))?
                    } else {
                        serde_json::from_slice(&bytes)
                            .map_err(|_| invalid("invalid workflow definition"))?
                    };
                    workflow_control(config, WorkflowControl::Submit { definition })
                }
                DistributedWorkflowCommand::ApprovalRequest {
                    id,
                    step,
                    output,
                    config,
                } => {
                    let request = workflow_control(
                        config,
                        WorkflowControl::ApprovalRequest {
                            id: id.clone(),
                            step: step.clone(),
                        },
                    )?;
                    write_new(
                        &output,
                        &serde_json::to_vec_pretty(&request).map_err(|_| {
                            invalid("cannot encode materialized owner approval request")
                        })?,
                    )?;
                    Ok(json!({"workflow_id":id,"step":step,"output":output}))
                }
                DistributedWorkflowCommand::ApprovalAttach {
                    id,
                    step,
                    definition_sha256,
                    approval,
                    config,
                } => {
                    let approval = lockyard_node::provenance::load_document(&approval)
                        .map_err(|error| invalid(error.0))?;
                    workflow_control(
                        config,
                        WorkflowControl::ApprovalAttach {
                            id,
                            step,
                            definition_sha256,
                            approval,
                        },
                    )
                }
                DistributedWorkflowCommand::Status { id, config } => {
                    workflow_control(config, WorkflowControl::Status { id })
                }
                DistributedWorkflowCommand::List {
                    offset,
                    limit,
                    config,
                } => workflow_control(config, WorkflowControl::List { offset, limit }),
                DistributedWorkflowCommand::Cancel { id, config } => {
                    workflow_control(config, WorkflowControl::Cancel { id })
                }
                DistributedWorkflowCommand::Abandon {
                    id,
                    definition_sha256,
                    controller_certificate_sha256,
                    confirm_no_active_execution,
                    config,
                } => {
                    if !confirm_no_active_execution {
                        return Err(invalid(
                            "drain the controller, independently stop/check each execution and separately review expired outbound admissions before --confirm-no-active-execution; abandonment never verifies success or retries work",
                        ));
                    }
                    workflow_control(
                        config,
                        WorkflowControl::Abandon {
                            review: lockyard_node::workflow::WorkflowAbandonRequest {
                                id,
                                definition_sha256,
                                controller_certificate_sha256,
                                expected_local_certificate_sha256: String::new(),
                                confirm_no_active_execution,
                            },
                        },
                    )
                }
            }
        }
        NodeCommand::Describe { target, config } => rpc(
            config,
            &target,
            Operation::NodePing,
            json!({"describe":true}),
        ),
        NodeCommand::Ping { target, config } => {
            rpc(config, &target, Operation::NodePing, Value::Null)
        }
    }
}
fn local_drain(config: Option<PathBuf>, enabled: Option<bool>) -> Result<Value> {
    let path = config_path(config)?;
    runtime()?
        .block_on(host::drain(&path, enabled))
        .map_err(|_| invalid("local node drain control unavailable"))
}
pub fn workflow_control(
    config: Option<PathBuf>,
    request: lockyard_node::workflow::WorkflowControl,
) -> Result<Value> {
    let path = config_path(config)?;
    runtime()?
        .block_on(host::local_workflow(&path, request))
        .map_err(|_| {
            invalid("workflow control failed; inspect the same workflow ID before retrying")
        })
}
pub fn rpc(config: Option<PathBuf>, target: &str, op: Operation, payload: Value) -> Result<Value> {
    let path = config_path(config)?;
    let reply = runtime()?
        .block_on(host::local_rpc(&path, target, op, payload))
        .map_err(|_| invalid("node request failed or outcome is unknown; query the same job ID"))?;
    serde_json::to_value(reply).map_err(|_| invalid("cannot encode node reply"))
}
fn read_prompt(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    if path.as_os_str() == "-" {
        std::io::stdin().take(131073).read_to_end(&mut bytes)?;
    } else {
        fs::File::open(path)?.take(131073).read_to_end(&mut bytes)?;
    }
    if bytes.len() > 131072 {
        return Err(invalid("prompt exceeds 131072 bytes"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("prompt must be UTF-8"))
}
// The private receipt is durable before the control socket sees the request. Its keyed
// fingerprint binds all fields including the prompt without storing the prompt itself.
fn secure_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if !path.exists() {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(invalid(
            "submission directory must be private and owned by this user",
        ));
    }
    Ok(())
}
fn read_private(path: &Path, max: u64) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.len() > max
    {
        return Err(invalid("invalid private submission file"));
    }
    let mut b = Vec::new();
    f.take(max + 1).read_to_end(&mut b)?;
    if b.len() as u64 > max {
        return Err(invalid("submission file too large"));
    }
    Ok(b)
}
fn receipt_dir(config: Option<PathBuf>) -> Result<PathBuf> {
    let path = config_path(config)?;
    let config =
        host::NodeConfig::load(&path).map_err(|_| invalid("invalid node configuration"))?;
    secure_dir(&config.state_dir)?;
    let dir = config.state_dir.join("submissions");
    secure_dir(&dir)?;
    fs::File::open(&config.state_dir)?.sync_all()?;
    Ok(dir)
}
fn fingerprint_key(dir: &Path) -> Result<Vec<u8>> {
    use ring::rand::SecureRandom;
    let path = dir.join(".fingerprint-key");
    match read_private(&path, 32) {
        Ok(key) if key.len() == 32 => return Ok(key),
        Ok(_) => return Err(invalid("invalid submission fingerprint key")),
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut key = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| invalid("cannot generate submission key"))?;
    let tmp = dir.join(format!(
        ".key-{}",
        wire::new_id().map_err(|_| invalid("cannot generate submission key"))?
    ));
    write_new(&tmp, &key)?;
    let link = fs::hard_link(&tmp, &path);
    let _ = fs::remove_file(&tmp);
    if let Err(e) = link
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(e.into());
    }
    fs::File::open(dir)?.sync_all()?;
    let key = read_private(&path, 32)?;
    if key.len() != 32 {
        return Err(invalid("invalid submission fingerprint key"));
    }
    Ok(key)
}
fn fingerprint(dir: &Path, target: &str, spec: &JobSpec) -> Result<String> {
    let key = fingerprint_key(dir)?;
    let bytes = serde_json::to_vec(&json!({"target":target,"spec":spec}))
        .map_err(|_| invalid("cannot encode submission"))?;
    let tag = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key), &bytes);
    Ok(tag.as_ref().iter().map(|b| format!("{b:02x}")).collect())
}
fn receipt_value(path: &Path) -> Result<Value> {
    serde_json::from_slice(&read_private(path, 8192)?)
        .map_err(|_| invalid("invalid submission receipt"))
}
fn prepare_receipt(config: Option<PathBuf>, target: &str, spec: &JobSpec) -> Result<PathBuf> {
    if !wire::valid_ulid(&spec.id) || !wire::valid_name(target) {
        return Err(invalid("invalid submission identity"));
    }
    let dir = receipt_dir(config)?;
    let digest = fingerprint(&dir, target, spec)?;
    let path = dir.join(format!("{}.json", spec.id));
    let receipt =
        json!({"job_id":spec.id,"target":target,"spec_fingerprint":digest,"status":"dispatching"});
    let bytes =
        serde_json::to_vec(&receipt).map_err(|_| invalid("cannot encode submission receipt"))?;
    // Never expose a partially written final receipt. Linking is create-only, so
    // concurrent clients either install a complete receipt or validate the winner.
    let tmp = dir.join(format!(
        ".receipt-{}.tmp",
        wire::new_id().map_err(|_| invalid("cannot generate receipt temporary name"))?
    ));
    if let Err(error) = write_new(&tmp, &bytes) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    let linked = fs::hard_link(&tmp, &path);
    let _ = fs::remove_file(&tmp);
    if let Err(error) = linked
        && error.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(error.into());
    }
    // Every client, including one observing a concurrent install, must sync the
    // directory before it can dispatch. The installer may have crashed meanwhile.
    let prior = receipt_value(&path)?;
    if prior["job_id"] != spec.id
        || prior["target"] != target
        || prior["spec_fingerprint"] != digest
    {
        return Err(invalid("job ID already belongs to a different submission"));
    }
    fs::File::open(&dir)?.sync_all()?;
    Ok(path)
}
pub fn receipts(config: Option<PathBuf>, id: Option<&str>) -> Result<Value> {
    let dir = receipt_dir(config)?;
    if let Some(id) = id {
        if !wire::valid_ulid(id) {
            return Err(invalid("job ID must be a ULID"));
        }
        let path = dir.join(format!("{id}.json"));
        return Ok(json!({"path":path,"receipt":receipt_value(&path)?}));
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        if !wire::valid_ulid(id) {
            continue;
        }
        let path = entry.path();
        match receipt_value(&path) {
            Ok(receipt) => entries.push(json!({"job_id":id,"path":path,"receipt":receipt})),
            Err(_) => entries.push(
                json!({"job_id":id,"path":path,"error":"invalid or unreadable submission receipt"}),
            ),
        }
    }
    entries.sort_by(|a, b| a["job_id"].as_str().cmp(&b["job_id"].as_str()));
    Ok(json!({"receipts":entries}))
}
pub fn submit(config: Option<PathBuf>, target: &str, spec: JobSpec) -> Value {
    let id = spec.id.clone();
    let receipt = match prepare_receipt(config.clone(), target, &spec) {
        Ok(path) => path,
        Err(_) => {
            return json!({"job_id":id,"ok":false,"error":{"code":"receipt_unavailable_or_conflict","message":"Submission was not sent: cannot persist a receipt, or this job ID belongs to a different specification."}});
        }
    };
    match rpc(
        config,
        target,
        Operation::JobSubmit,
        serde_json::to_value(spec).unwrap(),
    ) {
        Ok(reply) => json!({"job_id":id,"receipt":receipt,"reply":reply}),
        Err(_) => {
            json!({"job_id":id,"receipt":receipt,"ok":false,"error":{"code":"outcome_unknown","message":"Submission outcome is unknown; query or retry with the same job ID and identical specification."}})
        }
    }
}

pub fn job(command: JobCommand) -> Result<Value> {
    match command {
        JobCommand::Manifest {
            target,
            job_id,
            output,
            config,
        } => {
            let (signed, manifest) = authenticated_manifest(config, &target, &job_id)?;
            write_new(
                &output,
                &serde_json::to_vec_pretty(&signed)
                    .map_err(|_| invalid("cannot encode result manifest"))?,
            )?;
            Ok(
                json!({"output":output,"job_id":manifest.job_id,"node_id":manifest.node_id,"verified":true}),
            )
        }
        JobCommand::VerifyManifest {
            manifest,
            public_key,
            node,
            workspace,
            job,
            revision,
            image_digest,
            request_sha256,
            patch,
            log,
        } => {
            use lockyard_node::provenance::{self, ResultExpectation, TrustedSigningKey};
            let signed = provenance::load_document(&manifest)
                .map_err(|_| invalid("invalid result manifest file"))?;
            let expected = ResultExpectation {
                node_id: &node,
                workspace: &workspace,
                job_id: &job,
                resolved_revision: &revision,
                image_digest: &image_digest,
                request_sha256: request_sha256.as_deref(),
            };
            let verified =
                provenance::verify_result(&signed, &TrustedSigningKey { public_key }, &expected)
                    .map_err(|_| {
                        invalid("result signature or expected execution context did not verify")
                    })?;
            for (name, path) in [("result.patch", patch), ("output.log", log)] {
                if let Some(path) = path {
                    let artifact = verified
                        .artifacts
                        .get(name)
                        .ok_or_else(|| invalid("artifact is absent from signed result"))?;
                    if artifact.truncated || artifact.error_code.is_some() {
                        return Err(invalid(
                            "signed artifact is incomplete or has a collection error",
                        ));
                    }
                    provenance::verify_artifact(&verified, name, &path)
                        .map_err(|_| invalid("artifact bytes do not match signed result"))?;
                }
            }
            Ok(json!({"verified":true,"manifest":verified}))
        }
        JobCommand::Receipts { config } => receipts(config, None),
        JobCommand::Receipt { config, job_id } => receipts(config, Some(&job_id)),
        JobCommand::Submit {
            target,
            repository,
            revision,
            runner,
            id,
            timeout_seconds,
            priority,
            prompt_file,
            owner_approval,
            config,
            arguments,
        } => {
            let id = match id {
                Some(id) if wire::valid_ulid(&id) => id,
                Some(_) => return Err(invalid("job ID must be a ULID")),
                None => wire::new_id().map_err(|_| invalid("cannot create job ID"))?,
            };
            let prompt = prompt_file.as_deref().map(read_prompt).transpose()?;
            Ok(submit(
                config,
                &target,
                JobSpec {
                    id,
                    repository,
                    revision,
                    runner,
                    arguments,
                    prompt,
                    timeout_seconds,
                    priority,
                    workflow_inputs: Vec::new(),
                    expected_runner_sha256: None,
                    owner_approval: owner_approval
                        .as_deref()
                        .map(lockyard_node::provenance::load_document)
                        .transpose()
                        .map_err(|_| invalid("invalid owner approval file"))?,
                },
            ))
        }
        JobCommand::SubmitSpec {
            target,
            input,
            config,
        } => Ok(submit(config, &target, approvals::load_request(&input)?)),
        JobCommand::Status {
            target,
            job_id,
            config,
        } => rpc(
            config,
            &target,
            Operation::JobStatus,
            json!({"job_id":job_id}),
        ),
        JobCommand::Cancel {
            target,
            job_id,
            config,
        } => rpc(
            config,
            &target,
            Operation::JobCancel,
            json!({"job_id":job_id}),
        ),
        JobCommand::ResolveUnknown {
            target,
            job_id,
            config,
        } => rpc(
            config,
            &target,
            Operation::JobResolveUnknown,
            json!({"job_id":job_id}),
        ),
        JobCommand::Logs {
            target,
            job_id,
            offset,
            limit,
            config,
        } => {
            if limit == 0 || limit > wire::MAX_LOG_BYTES {
                return Err(invalid("log limit must be between 1 and 65536"));
            }
            rpc(
                config,
                &target,
                Operation::JobLog,
                json!({"job_id":job_id,"offset":offset,"limit":limit}),
            )
        }
        JobCommand::Patch {
            target,
            job_id,
            output,
            config,
        } => patch(config, &target, &job_id, &output),
        JobCommand::Archive {
            target,
            job_id,
            output,
            config,
        } => download_archive(config, &target, &job_id, &output),
        JobCommand::RestoreArchive {
            target,
            archive,
            output,
            config,
            key_file,
        } => {
            let path = config_path(config)?;
            let configuration =
                host::NodeConfig::load(&path).map_err(|_| invalid("invalid node configuration"))?;
            let trusted = configuration.result_trust.get(&target).ok_or_else(|| {
                invalid("pin the source node result signing key in result_trust before restoring")
            })?;
            let key = match key_file {
                Some(path) => lockyard_cloud_client::WorkspaceKey::load_private(&absolute(&path)?),
                None => lockyard_cloud_client::WorkspaceKey::load_for_workspace(
                    &configuration.workspace,
                ),
            }
            .map_err(|_| invalid("workspace key unavailable or not a private regular file"))?
            .ok_or_else(|| invalid("workspace key unavailable"))?;
            let destination = absolute(&output)?;
            let report = lockyard_node::archive::restore_job_offline(
                &absolute(&archive)?,
                &destination,
                &configuration.workspace,
                &key,
                &target,
                trusted,
            )
            .map_err(|_| {
                invalid("archive signature, encryption, paths or content did not verify")
            })?;
            Ok(json!({"output":destination,"verified":true,"offline_only":true,"report":report}))
        }
    }
}
fn download_archive(
    config: Option<PathBuf>,
    target: &str,
    job_id: &str,
    destination: &Path,
) -> Result<Value> {
    // Confirm independent signing-key trust before downloading private content.
    authenticated_manifest(config.clone(), target, job_id)?;
    let mut download = download::Download::new(destination, "archive")?;
    (|| -> Result<Value> {
        let mut offset = 0u64;
        loop {
            let reply = rpc(
                config.clone(),
                target,
                Operation::JobArchive,
                json!({"job_id":job_id,"offset":offset,"limit":wire::MAX_TRANSFER_BYTES}),
            )?;
            if reply["ok"] != true {
                return Err(invalid("archive request failed or content expired"));
            }
            let chunk: LogChunk = serde_json::from_value(reply["result"].clone())
                .map_err(|_| invalid("invalid archive chunk"))?;
            if chunk.offset != offset
                || chunk.bytes.len() > wire::MAX_LOG_BYTES as usize
                || chunk.next_offset
                    != offset
                        .checked_add(chunk.bytes.len() as u64)
                        .ok_or_else(|| invalid("invalid archive offset"))?
                || (!chunk.eof && chunk.bytes.is_empty())
                || chunk.truncated
                || chunk.next_offset > 1024 * 1024 * 1024
            {
                return Err(invalid("invalid, truncated or oversized archive"));
            }
            download.file().write_all(&chunk.bytes)?;
            offset = chunk.next_offset;
            if chunk.eof {
                break;
            }
        }
        download.file().sync_all()?;
        let configuration = host::NodeConfig::load(&config_path(config.clone())?)
            .map_err(|_| invalid("invalid node configuration"))?;
        let trusted = configuration
            .result_trust
            .get(target)
            .ok_or_else(|| invalid("archive signing key is not pinned"))?;
        let key = lockyard_cloud_client::WorkspaceKey::load_for_workspace(&configuration.workspace)
            .map_err(|_| invalid("workspace key unavailable"))?
            .ok_or_else(|| invalid("workspace key unavailable"))?;
        let manifest = lockyard_node::archive::inspect_file(
            download.file(),
            &configuration.workspace,
            &key,
            target,
            trusted,
        )
        .map_err(|_| invalid("archive manifest signature or encryption did not verify"))?;
        if manifest.job_id != job_id {
            return Err(invalid("archive belongs to a different job"));
        }
        download.publish()?;
        Ok(
            json!({"output":destination,"bytes":offset,"encrypted":true,"scope":manifest.scope,
            "manifest_verified":true,"body_verification":"on_restore","automatic_execution":false}),
        )
    })()
}
pub fn patch(
    config: Option<PathBuf>,
    target: &str,
    job_id: &str,
    destination: &Path,
) -> Result<Value> {
    let (_, manifest) = authenticated_manifest(config.clone(), target, job_id)?;
    let patch_artifact = manifest
        .artifacts
        .get("result.patch")
        .ok_or_else(|| invalid("signed patch metadata is unavailable"))?;
    if patch_artifact.truncated || patch_artifact.error_code.is_some() {
        return Err(invalid("signed patch is incomplete or unavailable"));
    }
    let expected_bytes = patch_artifact.size_bytes;
    let mut download = download::Download::new(destination, "patch")?;
    (|| -> Result<Value> {
        let mut offset = 0u64;
        loop {
            let reply = rpc(
                config.clone(),
                target,
                Operation::JobPatch,
                json!({"job_id":job_id,"offset":offset,"limit":wire::MAX_TRANSFER_BYTES}),
            )?;
            if reply["ok"] != true {
                return Err(invalid("patch request failed"));
            }
            let chunk: LogChunk = serde_json::from_value(reply["result"].clone())
                .map_err(|_| invalid("invalid patch chunk"))?;
            if chunk.offset != offset
                || chunk.bytes.len() > wire::MAX_LOG_BYTES as usize
                || chunk.next_offset
                    != offset
                        .checked_add(chunk.bytes.len() as u64)
                        .ok_or_else(|| invalid("invalid patch offset"))?
                || (!chunk.eof && chunk.bytes.is_empty())
                || chunk.truncated
            {
                return Err(invalid("invalid or truncated patch"));
            }
            if chunk.next_offset > 128 * 1024 * 1024 || chunk.next_offset > expected_bytes {
                return Err(invalid("patch exceeds signed length or download limit"));
            }
            download.file().write_all(&chunk.bytes)?;
            offset = chunk.next_offset;
            if chunk.eof {
                break;
            }
        }
        download.file().sync_all()?;
        lockyard_node::provenance::verify_artifact_file(&manifest, "result.patch", download.file())
            .map_err(|_| invalid("downloaded patch does not match signed result"))?;
        download.publish()?;
        Ok(json!({"output":destination,"bytes":offset}))
    })()
}

fn authenticated_manifest(
    config: Option<PathBuf>,
    target: &str,
    job_id: &str,
) -> Result<(
    lockyard_node::provenance::SignedDocument,
    lockyard_node::provenance::ResultManifest,
)> {
    let path = config_path(config)?;
    let configuration =
        host::NodeConfig::load(&path).map_err(|_| invalid("invalid node configuration"))?;
    let key = configuration.result_trust.get(target).ok_or_else(|| invalid("pin the target node result signing public key in result_trust before downloading results"))?;
    let reply = rpc(
        Some(path),
        target,
        Operation::JobStatus,
        json!({"job_id":job_id}),
    )?;
    if reply["ok"] != true {
        return Err(invalid("result status is unavailable"));
    }
    let record: wire::JobRecord = serde_json::from_value(reply["result"].clone())
        .map_err(|_| invalid("invalid result status"))?;
    if record.provenance_error.is_some() {
        return Err(invalid("node could not durably sign this result"));
    }
    let signed = record
        .result_manifest
        .ok_or_else(|| invalid("signed result is not available yet"))?;
    let manifest = lockyard_node::provenance::verify_result_identity(
        &signed,
        key,
        target,
        &configuration.workspace,
        job_id,
    )
    .map_err(|_| invalid("result signature or node identity did not verify"))?;
    let request_hash = lockyard_node::provenance::sha256(
        &serde_json::to_vec(&record.spec).map_err(|_| invalid("invalid result request"))?,
    );
    if record.spec.id != job_id
        || request_hash != manifest.request_sha256
        || record.resolved_revision.as_deref() != Some(manifest.resolved_revision.as_str())
        || record.state != manifest.state
        || record.exit_code != manifest.exit_code
        || record.error_code != manifest.error_code
    {
        return Err(invalid("signed result differs from returned job metadata"));
    }
    Ok((signed, manifest))
}

pub fn native_doctor(path: &Path) -> Result<Value> {
    let config = host::NodeConfig::load(path).map_err(|error| Error::Invalid(error.to_string()))?;
    let mut runners = serde_json::Map::new();
    let mut healthy = true;
    if let Some(executor) = config.executor {
        for (name, runner) in executor.runners {
            if matches!(
                runner.container.runtime,
                lockyard_node::executor::ContainerRuntime::Native
            ) {
                let mut report = lockyard_node::native::capabilities(
                    runner.container.cgroup_root.as_deref(),
                    &runner.container.runtime_program,
                );
                if !runner.container.native_rootfs.as_ref().is_some_and(|path| {
                    path.is_absolute() && path.is_dir() && path != Path::new("/")
                }) {
                    report.reasons.push(
                        "native_rootfs must name a provisioned immutable private image directory"
                            .into(),
                    );
                }
                if matches!(
                    runner.container.network,
                    lockyard_node::executor::ContainerNetwork::Bridge
                ) && !runner
                    .container
                    .native_network_program
                    .as_ref()
                    .is_some_and(|path| path.is_absolute() && path.is_file())
                {
                    report.reasons.push("bridge requires native_network_program=/usr/bin/slirp4netns; host networking is never inherited".into());
                }
                report.available &= report.reasons.is_empty();
                healthy &= report.available;
                runners.insert(
                    name,
                    serde_json::to_value(report)
                        .map_err(|error| Error::Invalid(error.to_string()))?,
                );
            }
        }
    }
    Ok(
        json!({"healthy": healthy, "native_executor": runners, "build": lockyard_core::build_info()}),
    )
}
