// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Adapter between the local durable controller and authenticated node transport.
use super::*;
use crate::workflow::{WorkflowController, WorkflowDriver, WorkflowError};
use futures_util::{
    future::BoxFuture,
    stream::{self, StreamExt},
};
use std::sync::Weak;

pub(super) struct Driver {
    host: Weak<Host>,
    cursor: std::sync::atomic::AtomicUsize,
}
impl Driver {
    pub(super) fn new(host: Weak<Host>) -> Self {
        Self {
            host,
            cursor: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}
impl WorkflowDriver for Driver {
    fn describe_nodes(
        &self,
    ) -> BoxFuture<'_, crate::workflow::Result<Vec<crate::scheduler::NodeCapabilities>>> {
        Box::pin(async move {
            let host = self
                .host
                .upgrade()
                .ok_or(WorkflowError("workflow_host_stopped"))?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
            let mut candidates = BTreeMap::new();
            candidates.insert(host.config.node_id.clone(), host.certificate_sha256.clone());
            for peer in &host.config.peers {
                candidates.insert(
                    peer.node_id.clone(),
                    PeerPin::from_hex(&peer.certificate_sha256)
                        .map_err(|_| WorkflowError("workflow_peer_identity_invalid"))?
                        .to_hex(),
                );
            }
            if host.config.relay.is_some() {
                let client = crate::cloud::NodeCloudClient::from_config(&host.config)
                    .map_err(|_| WorkflowError("workflow_directory_unavailable"))?;
                // Independent peer pins remain authoritative if a directory entry differs.
                if let Ok(Ok(entries)) =
                    tokio::time::timeout(Duration::from_secs(2), client.directory()).await
                {
                    let key = WorkspaceKey::load_for_workspace(&host.config.workspace)
                        .map_err(|_| WorkflowError("workflow_workspace_key_unavailable"))?
                        .ok_or(WorkflowError("workflow_workspace_key_unavailable"))?;
                    let mut advertised = HashSet::new();
                    let mut ambiguous = HashSet::new();
                    for entry in entries {
                        if entry.controller_only || entry.node_id.starts_with("web_") {
                            continue;
                        }
                        if !advertised.insert(entry.node_id.clone()) {
                            ambiguous.insert(entry.node_id.clone());
                        }
                        if candidates.contains_key(&entry.node_id) {
                            continue;
                        }
                        let Some(proof) = entry.identity_proof else {
                            continue;
                        };
                        if crate::incarnation::verify_identity(
                            &host.config.workspace,
                            &entry.node_id,
                            &entry.certificate_sha256,
                            &proof,
                            &key,
                        )
                        .is_ok()
                        {
                            candidates.insert(entry.node_id, entry.certificate_sha256);
                        }
                    }
                    for node in ambiguous {
                        if !host.config.peers.iter().any(|peer| peer.node_id == node)
                            && node != host.config.node_id
                        {
                            candidates.remove(&node);
                        }
                    }
                }
            }
            if candidates.len() > 4096 {
                return Err(WorkflowError("workflow_directory_too_large"));
            }
            let mut candidates: Vec<_> = candidates.into_iter().collect();
            let count = candidates.len();
            if count == 0 {
                return Ok(Vec::new());
            }
            candidates.rotate_left(self.cursor.load(Ordering::Relaxed) % count);
            // Advance only by completed probes. Timed-out unfinished entries become
            // early candidates next round instead of starving at the global deadline.
            let mut responses =
                stream::iter(candidates.into_iter().take(128).map(|(node, pin)| {
                    let host = host.clone();
                    async move {
                        let reply = if node == host.config.node_id {
                            Ok(host
                                .dispatch(
                                    Operation::NodePing,
                                    json!({"describe":true}),
                                    Caller {
                                        node_id: host.config.node_id.clone(),
                                        local_operator: false,
                                        certificate_sha256: Some(host.certificate_sha256.clone()),
                                    },
                                    None,
                                )
                                .await)
                        } else {
                            // pin was authenticated above; this read-only RPC creates no sticky route.
                            match tokio::time::timeout_at(
                                deadline.min(tokio::time::Instant::now() + Duration::from_secs(2)),
                                host.rpc_once(
                                    &node,
                                    Operation::NodePing,
                                    json!({"describe":true}),
                                    None,
                                    Some(pin.clone()),
                                ),
                            )
                            .await
                            {
                                Ok(reply) => reply,
                                Err(_) => return None,
                            }
                        };
                        let reply = reply.ok()?;
                        if !reply.ok {
                            return None;
                        }
                        let value = reply.result?;
                        if value.get("node_id").and_then(Value::as_str) != Some(node.as_str()) {
                            return None;
                        }
                        let caps: crate::scheduler::NodeCapabilities =
                            serde_json::from_value(value.get("capabilities")?.clone()).ok()?;
                        if caps.node_id != node
                            || caps.certificate_sha256 != pin
                            || caps.validate().is_err()
                        {
                            return None;
                        }
                        Some(caps)
                    }
                }))
                .buffer_unordered(16);
            let (capabilities, completed) = collect_bounded(&mut responses, deadline).await;
            self.cursor.fetch_add(completed.max(1), Ordering::Relaxed);
            Ok(capabilities)
        })
    }
    fn rpc<'a>(
        &'a self,
        flow: &'a str,
        node: &'a str,
        pin: &'a str,
        operation: Operation,
        payload: Value,
    ) -> BoxFuture<'a, crate::workflow::Result<RpcReply<Value>>> {
        Box::pin(async move {
            let host = self
                .host
                .upgrade()
                .ok_or(WorkflowError("workflow_host_stopped"))?;
            tokio::time::timeout(
                Duration::from_secs(5),
                host.rpc_bound(
                    node,
                    operation,
                    payload,
                    Some(pin),
                    crate::incarnation::DispatchOrigin::Workflow(flow.into()),
                ),
            )
            .await
            .map_err(|_| WorkflowError("workflow_transport_uncertain"))?
            .map_err(|_| WorkflowError("workflow_transport_uncertain"))
        })
    }
}

pub(super) fn open(config: &NodeConfig, pin: &str) -> Result<Option<Arc<WorkflowController>>> {
    let Some(policy) = config.workflow.clone() else {
        return Ok(None);
    };
    let mut trust = config.result_trust.clone();
    let mut retention = config.project_retention.clone();
    if let Some(executor) = &config.executor {
        for (project, repository) in &executor.repositories {
            if let Some(policy) = &repository.retention {
                let policy = match retention.get(project) {
                    Some(sender) => policy.effective(sender)?,
                    None => policy.clone(),
                };
                retention.insert(project.clone(), policy);
            }
        }
        if let Some(signing) = &executor.provenance {
            let local = crate::provenance::TrustedSigningKey {
                public_key: signing.public_key.clone(),
            };
            local.validate()?;
            if trust
                .get(&config.node_id)
                .is_some_and(|existing| existing != &local)
            {
                return Err(
                    "controller local result-signing trust differs from executor configuration"
                        .into(),
                );
            }
            trust.insert(config.node_id.clone(), local);
        }
    }
    Ok(Some(Arc::new(WorkflowController::open(
        &config.state_dir,
        policy,
        config.workspace.clone(),
        config.node_id.clone(),
        pin.into(),
        trust,
        retention,
        wall_ms()?,
    )?)))
}

async fn collect_bounded<S>(
    responses: &mut S,
    deadline: tokio::time::Instant,
) -> (Vec<crate::scheduler::NodeCapabilities>, usize)
where
    S: futures_util::Stream<Item = Option<crate::scheduler::NodeCapabilities>> + Unpin,
{
    let mut capabilities = Vec::new();
    let mut completed = 0usize;
    while let Ok(Some(response)) = tokio::time::timeout_at(deadline, responses.next()).await {
        completed += 1;
        if let Some(capability) = response {
            capabilities.push(capability);
        }
    }
    (capabilities, completed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn hung_discovery_does_not_withhold_fast_authenticated_candidate_past_global_budget() {
        let capability:crate::scheduler::NodeCapabilities=serde_json::from_value(json!({
            "version":1,"node_id":"fast","certificate_sha256":"a".repeat(64),"labels":{},
            "capacity":null,"reserved":{"cpu_millis":0,"memory_mb":0},"runners":{},"projects":[],
            "max_concurrency":1,"max_pending_jobs":32,"running":0,"queued":0,"unknown":0,"draining":false})).unwrap();
        let mut responses = stream::iter(vec![
            Box::pin(std::future::pending())
                as BoxFuture<'static, Option<crate::scheduler::NodeCapabilities>>,
            Box::pin(async move { Some(capability) }),
        ])
        .buffer_unordered(2);
        let (found, completed) = tokio::time::timeout(
            Duration::from_secs(1),
            collect_bounded(
                &mut responses,
                tokio::time::Instant::now() + Duration::from_millis(30),
            ),
        )
        .await
        .unwrap();
        assert_eq!(completed, 1);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].node_id, "fast");
    }
}
