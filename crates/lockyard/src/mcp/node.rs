// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::*;

pub(super) fn node_tool(name: &str, args: Args<'_>) -> Result<Value> {
    use lockyard_node::wire::{self, JobSpec, Operation};
    use std::path::PathBuf;
    let config = args.some_text("config")?.map(PathBuf::from);
    if name == "workflow_inputs" {
        let path = std::env::var_os("LOCKYARD_WORKFLOW_INPUTS_FILE")
            .ok_or_else(|| Error::Invalid("this job has no workflow input context".into()))?;
        return encode(
            &lockyard_node::workflow::read_context(std::path::Path::new(&path)).map_err(|_| {
                Error::Invalid("workflow input context is unavailable or invalid".into())
            })?,
        );
    }
    if name.starts_with("flow_") {
        use lockyard_node::workflow::WorkflowControl;
        let request = match name {
            "flow_submit" => WorkflowControl::Submit {
                definition: serde_json::from_value(
                    args.get("definition")
                        .cloned()
                        .ok_or_else(|| wrong_type("definition", "an object"))?,
                )
                .map_err(|_| Error::Invalid("invalid distributed workflow definition".into()))?,
            },
            "flow_status" => WorkflowControl::Status {
                id: args.text("id")?.into(),
            },
            "flow_list" => WorkflowControl::List {
                offset: usize::try_from(args.some_int("offset")?.unwrap_or(0))
                    .map_err(|_| Error::Invalid("offset must be nonnegative".into()))?,
                limit: usize::try_from(args.some_int("limit")?.unwrap_or(100))
                    .ok()
                    .filter(|limit| (1..=100).contains(limit))
                    .ok_or_else(|| Error::Invalid("limit must be 1..100".into()))?,
            },
            "flow_cancel" => WorkflowControl::Cancel {
                id: args.text("id")?.into(),
            },
            "flow_approval_request" => WorkflowControl::ApprovalRequest {
                id: args.text("id")?.into(),
                step: args.text("step")?.into(),
            },
            "flow_approval_attach" => WorkflowControl::ApprovalAttach {
                id: args.text("id")?.into(),
                step: args.text("step")?.into(),
                definition_sha256: args.text("definition_sha256")?.into(),
                approval: serde_json::from_value(
                    args.get("approval")
                        .cloned()
                        .ok_or_else(|| wrong_type("approval", "an object"))?,
                )
                .map_err(|_| Error::Invalid("invalid signed owner approval".into()))?,
            },
            _ => {
                return Err(Error::Invalid(
                    "unknown distributed workflow operation".into(),
                ));
            }
        };
        return crate::node_cli::workflow_control(config, request);
    }
    if name == "node_status" {
        return crate::node_cli::node(crate::node_cli::NodeCommand::Status { config });
    }
    if name == "node_list" {
        return crate::node_cli::node(crate::node_cli::NodeCommand::List { config });
    }
    if name == "job_receipts" {
        return crate::node_cli::receipts(config, None);
    }
    if name == "job_receipt" {
        return crate::node_cli::receipts(config, Some(args.text("job_id")?));
    }
    let target = args.text("target")?;
    if name == "node_ping" {
        return crate::node_cli::rpc(config, target, Operation::NodePing, Value::Null);
    }
    if name == "node_describe" {
        return crate::node_cli::rpc(
            config,
            target,
            Operation::NodePing,
            json!({"describe":true}),
        );
    }
    if name == "job_submit" {
        let id = args.text("id")?.to_string();
        if !wire::valid_ulid(&id) {
            return Err(Error::Invalid("job ID must be a ULID".into()));
        }
        let arguments = match args.get("arguments") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| Error::Invalid("arguments must contain strings".into()))
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(Error::Invalid("arguments must be an array".into())),
        };
        let timeout_seconds = args
            .some_int("timeout_seconds")?
            .map(|n| {
                u64::try_from(n)
                    .map_err(|_| Error::Invalid("timeout_seconds must be positive".into()))
            })
            .transpose()?;
        let spec = JobSpec {
            id,
            repository: args.text("repository")?.into(),
            revision: args.some_text("revision")?.unwrap_or_else(|| "HEAD".into()),
            runner: args.text("runner")?.into(),
            arguments,
            prompt: args.some_text("prompt")?,
            timeout_seconds,
            priority: i16::try_from(args.some_int("priority")?.unwrap_or(0))
                .ok()
                .filter(|priority| lockyard_node::scheduler::valid_priority(*priority))
                .ok_or_else(|| Error::Invalid("priority must be between -20 and 20".into()))?,
            workflow_inputs: Vec::new(),
            expected_runner_sha256: None,
            owner_approval: args
                .get("owner_approval")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| Error::Invalid("invalid owner approval document".into()))?,
        };
        return Ok(crate::node_cli::submit(config, target, spec));
    }
    let job_id = args.text("job_id")?;
    if name == "job_patch" {
        return crate::node_cli::patch(
            config,
            target,
            job_id,
            std::path::Path::new(args.text("output")?),
        );
    }
    let operation = match name {
        "job_status" => Operation::JobStatus,
        "job_cancel" => Operation::JobCancel,
        "job_logs" => Operation::JobLog,
        "job_resolve_unknown" => Operation::JobResolveUnknown,
        _ => return Err(Error::Invalid("unknown tool".into())),
    };
    let payload = if name == "job_logs" {
        let offset = u64::try_from(args.some_int("offset")?.unwrap_or(0))
            .map_err(|_| Error::Invalid("invalid log offset".into()))?;
        let limit = u32::try_from(
            args.some_int("limit")?
                .unwrap_or(i64::from(wire::DEFAULT_LOG_BYTES)),
        )
        .map_err(|_| Error::Invalid("invalid log limit".into()))?;
        if limit == 0 || limit > wire::MAX_LOG_BYTES {
            return Err(Error::Invalid("invalid log limit".into()));
        }
        json!({"job_id":job_id,"offset":offset,"limit":limit})
    } else {
        json!({"job_id":job_id})
    };
    crate::node_cli::rpc(config, target, operation, payload)
}

pub(super) fn uses_node_transport(name: &str) -> bool {
    matches!(
        name,
        "node_status" | "node_list" | "node_ping" | "node_describe" | "workflow_inputs"
    ) || name.starts_with("flow_")
        || name.starts_with("job_")
}
