// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Placement and admission policies. Capability values travel only inside node E2EE RPCs.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpu_millis: u32,
    pub memory_mb: u64,
}
impl Resources {
    pub fn validate(self) -> Result<(), &'static str> {
        if self.cpu_millis == 0
            || self.cpu_millis > 16_384_000
            || self.memory_mb == 0
            || self.memory_mb > 1_073_741_824
        {
            return Err("invalid_node_resource_budget");
        }
        Ok(())
    }
    pub fn fits(self, available: Self) -> bool {
        self.cpu_millis <= available.cpu_millis && self.memory_mb <= available.memory_mb
    }
    pub fn saturating_sub(self, used: Self) -> Self {
        Self {
            cpu_millis: self.cpu_millis.saturating_sub(used.cpu_millis),
            memory_mb: self.memory_mb.saturating_sub(used.memory_mb),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeScheduling {
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Explicit administrator-reserved budget. Auto placement requires this value.
    pub capacity: Option<Resources>,
    #[serde(default)]
    pub queue: QueuePolicy,
}
impl NodeScheduling {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_labels(&self.labels)?;
        if let Some(capacity) = self.capacity {
            capacity.validate()?;
        }
        self.queue.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerCapability {
    /// Declared runner network/credentials require approval independently of its action label.
    #[serde(default, skip_serializing_if = "is_false")]
    pub external_approval_required: bool,
    #[serde(default)]
    pub action: crate::approvals::ManagedAction,
    #[serde(default)]
    pub owner_approval_authorities: Vec<crate::provenance::TrustedSigningKey>,
    pub image_reference: String,
    pub resources: Resources,
    pub pids_limit: u32,
    pub image_digest: String,
    pub configuration_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCapabilities {
    /// Content-free bindings for repositories that inject cloud credentials.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub repository_cloud_sha256: BTreeMap<String, String>,
    pub version: u8,
    pub node_id: String,
    pub certificate_sha256: String,
    pub labels: BTreeMap<String, String>,
    pub capacity: Option<Resources>,
    pub reserved: Resources,
    pub runners: BTreeMap<String, RunnerCapability>,
    pub projects: Vec<String>,
    pub max_concurrency: usize,
    pub max_pending_jobs: usize,
    pub running: usize,
    pub queued: usize,
    pub unknown: usize,
    pub draining: bool,
}
fn is_false(value: &bool) -> bool {
    !value
}

impl NodeCapabilities {
    pub fn requires_owner_approval(&self, repository: &str, runner: &str) -> bool {
        self.runners[runner].action.requires_owner()
            || self.runners[runner].external_approval_required
            || self.repository_cloud_sha256.contains_key(repository)
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != 1
            || !crate::wire::valid_name(&self.node_id)
            || !sha256(&self.certificate_sha256)
            || self.runners.len() > 256
            || self.repository_cloud_sha256.len() > 4096
            || self
                .repository_cloud_sha256
                .iter()
                .any(|(repository, digest)| !self.projects.contains(repository) || !sha256(digest))
            || self.projects.len() > 4096
            || self
                .projects
                .iter()
                .any(|project| !crate::wire::valid_name(project))
            || self.runners.iter().any(|(name, capability)| {
                !crate::wire::valid_name(name)
                    || capability.resources.validate().is_err()
                    || capability.pids_limit == 0
                    || !image_digest(&capability.image_digest)
                    || crate::supply_chain::immutable_image_digest(&capability.image_reference)
                        .ok()
                        .as_deref()
                        != Some(capability.image_digest.as_str())
                    || capability.image_reference.len() > 1024
                    || capability.owner_approval_authorities.len() > 32
                    || capability
                        .owner_approval_authorities
                        .iter()
                        .any(|key| key.validate().is_err())
                    || (capability.action.requires_owner()
                        && capability.owner_approval_authorities.is_empty())
                    || !sha256(&capability.configuration_sha256)
            })
            || self.max_concurrency > 4096
            || self.max_pending_jobs > 100_000
            || self.running > self.max_concurrency
            || self.queued > self.max_pending_jobs
        {
            return Err("invalid_node_capabilities");
        }
        validate_labels(&self.labels)?;
        if let Some(capacity) = self.capacity {
            capacity.validate()?;
            if !self.reserved.fits(capacity) {
                return Err("invalid_node_resource_reservation");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionCapability {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_cloud_sha256: Option<String>,
    pub node_id: String,
    pub certificate_sha256: String,
    pub repository: String,
    pub requested_revision: String,
    pub resolved_revision: String,
    pub runner: String,
    pub profile: RunnerCapability,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    /// A configured node always wins over automatic matching; requirements still apply.
    pub node: Option<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub minimum: Option<Resources>,
    /// Optional independently approved image digest. Otherwise snapshot the chosen profile digest.
    pub image_digest: Option<String>,
}
impl Placement {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self
            .node
            .as_ref()
            .is_some_and(|node| !crate::wire::valid_name(node))
        {
            return Err("invalid_placement_node");
        }
        validate_labels(&self.labels)?;
        if let Some(minimum) = self.minimum {
            minimum.validate()?;
        }
        if self
            .image_digest
            .as_ref()
            .is_some_and(|digest| !image_digest(digest))
        {
            return Err("invalid_placement_image");
        }
        Ok(())
    }
}

/// Candidates must already be authenticated and have independently pinned result keys.
/// Placement is advisory; the destination performs atomic quota/resource admission again.
pub fn select_node<'a>(
    nodes: &'a [NodeCapabilities],
    placement: &Placement,
    project: &str,
    runner: &str,
) -> Result<&'a NodeCapabilities, &'static str> {
    placement.validate()?;
    let mut candidates = Vec::new();
    for node in nodes {
        if let Err(error) = node.validate() {
            if placement.node.as_deref() == Some(&node.node_id) {
                return Err(error);
            }
            continue;
        }
        if placement
            .node
            .as_ref()
            .is_some_and(|id| *id != node.node_id)
            || node.draining
            || node.unknown != 0
            || node.max_concurrency == 0
            || node.running.saturating_add(node.queued) >= node.max_pending_jobs
            || !node.projects.iter().any(|name| name == project)
            || placement
                .labels
                .iter()
                .any(|(key, value)| node.labels.get(key) != Some(value))
        {
            continue;
        }
        let Some(profile) = node.runners.get(runner) else {
            continue;
        };
        if node.requires_owner_approval(project, runner)
            && profile.owner_approval_authorities.is_empty()
        {
            continue;
        }
        if placement
            .image_digest
            .as_ref()
            .is_some_and(|digest| *digest != profile.image_digest)
        {
            continue;
        }
        if placement
            .minimum
            .is_some_and(|minimum| !minimum.fits(profile.resources))
        {
            continue;
        }
        if let Some(capacity) = node.capacity {
            if !profile.resources.fits(capacity) {
                continue;
            }
        } else if placement.node.is_none() {
            // Do not invent physical capacity from an arbitrary per-container limit.
            continue;
        }
        candidates.push(node);
    }
    candidates.sort_by(|a, b| {
        // Compare rational load without floats or division and break ties deterministically.
        let a_load = a.running.saturating_add(a.queued) as u128;
        let b_load = b.running.saturating_add(b.queued) as u128;
        let slots = |node: &NodeCapabilities| {
            node.capacity
                .map_or(node.max_concurrency, |capacity| {
                    let profile = node.runners[runner].resources;
                    node.max_concurrency
                        .min((capacity.cpu_millis / profile.cpu_millis) as usize)
                        .min((capacity.memory_mb / profile.memory_mb) as usize)
                })
                .max(1) as u128
        };
        let ready = |node: &NodeCapabilities| {
            node.running < node.max_concurrency
                && node.capacity.is_none_or(|capacity| {
                    node.runners[runner]
                        .resources
                        .fits(capacity.saturating_sub(node.reserved))
                })
        };
        ready(b)
            .cmp(&ready(a))
            .then_with(|| (a_load * slots(b)).cmp(&(b_load * slots(a))))
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
    candidates.first().copied().ok_or("no_compatible_node")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QueuePolicy {
    pub max_pending_per_submitter: usize,
    pub max_pending_per_project: usize,
    pub max_running_per_submitter: usize,
    pub max_running_per_project: usize,
    /// Every interval adds one priority point; a bounded base priority cannot starve an old job.
    pub aging_interval_ms: u64,
    #[serde(default)]
    pub projects: BTreeMap<String, ProjectQuota>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectQuota {
    pub max_pending: usize,
    pub max_running: usize,
}
impl Default for QueuePolicy {
    fn default() -> Self {
        Self {
            max_pending_per_submitter: 32,
            max_pending_per_project: 128,
            max_running_per_submitter: 1,
            max_running_per_project: 16,
            aging_interval_ms: 1000,
            projects: BTreeMap::new(),
        }
    }
}
impl QueuePolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if [
            self.max_pending_per_submitter,
            self.max_pending_per_project,
            self.max_running_per_submitter,
            self.max_running_per_project,
        ]
        .iter()
        .any(|limit| !(1..=100_000).contains(limit))
            || !(100..=60_000).contains(&self.aging_interval_ms)
            || self.projects.len() > 4096
            || self.projects.iter().any(|(name, quota)| {
                !crate::wire::valid_name(name)
                    || !(1..=100_000).contains(&quota.max_pending)
                    || !(1..=100_000).contains(&quota.max_running)
            })
        {
            return Err("invalid_queue_policy");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueuePhase {
    Queued,
    Active,
    Unknown,
    Done,
}
#[derive(Debug, Clone, Copy)]
pub struct QueueItem<'a> {
    pub id: &'a str,
    pub submitter: &'a str,
    pub submitter_certificate_sha256: Option<&'a str>,
    pub project: &'a str,
    pub enqueued_at_ms: u64,
    pub priority: i16,
    pub phase: QueuePhase,
}
pub fn valid_priority(priority: i16) -> bool {
    (-20..=20).contains(&priority)
}

pub fn admit(
    items: &[QueueItem<'_>],
    submitter: &str,
    submitter_certificate_sha256: Option<&str>,
    project: &str,
    policy: &QueuePolicy,
    max_pending: usize,
) -> Result<(), &'static str> {
    policy.validate()?;
    let pending: Vec<_> = items
        .iter()
        .filter(|item| item.phase != QueuePhase::Done)
        .collect();
    if pending.len() >= max_pending {
        return Err("job_queue_full");
    }
    if pending
        .iter()
        .filter(|item| {
            item.submitter == submitter
                && item.submitter_certificate_sha256 == submitter_certificate_sha256
        })
        .count()
        >= policy.max_pending_per_submitter
    {
        return Err("submitter_queue_full");
    }
    if pending
        .iter()
        .filter(|item| item.project == project)
        .count()
        >= policy
            .projects
            .get(project)
            .map_or(policy.max_pending_per_project, |quota| quota.max_pending)
    {
        return Err("project_queue_full");
    }
    Ok(())
}

/// Invoke under the executor's existing job mutex. Persist Starting before releasing it.
pub fn next_job<'a>(
    items: &[QueueItem<'a>],
    policy: &QueuePolicy,
    concurrency: usize,
    capacity: Option<Resources>,
    resources: &BTreeMap<&str, Resources>,
    now_ms: u64,
) -> Option<&'a str> {
    if policy.validate().is_err() || items.iter().any(|item| item.phase == QueuePhase::Unknown) {
        return None;
    }
    let active: Vec<_> = items
        .iter()
        .filter(|item| item.phase == QueuePhase::Active)
        .collect();
    if active.len() >= concurrency
        || (capacity.is_some() && active.iter().any(|item| !resources.contains_key(item.id)))
    {
        return None;
    }
    let used = active
        .iter()
        .filter_map(|item| resources.get(item.id))
        .fold(
            Resources {
                cpu_millis: 0,
                memory_mb: 0,
            },
            |sum, item| Resources {
                cpu_millis: sum.cpu_millis.saturating_add(item.cpu_millis),
                memory_mb: sum.memory_mb.saturating_add(item.memory_mb),
            },
        );
    items
        .iter()
        .filter(|item| item.phase == QueuePhase::Queued && valid_priority(item.priority))
        .filter(|item| {
            active
                .iter()
                .filter(|running| {
                    running.submitter == item.submitter
                        && running.submitter_certificate_sha256 == item.submitter_certificate_sha256
                })
                .count()
                < policy.max_running_per_submitter
        })
        .filter(|item| {
            active
                .iter()
                .filter(|running| running.project == item.project)
                .count()
                < policy
                    .projects
                    .get(item.project)
                    .map_or(policy.max_running_per_project, |quota| quota.max_running)
        })
        .filter(|item| {
            capacity.is_none_or(|total| {
                resources
                    .get(item.id)
                    .is_some_and(|required| required.fits(total))
            })
        })
        .max_by(|a, b| {
            let score = |item: &QueueItem<'_>| {
                i128::from(item.priority)
                    + i128::from(
                        now_ms.saturating_sub(item.enqueued_at_ms) / policy.aging_interval_ms,
                    )
            };
            score(a)
                .cmp(&score(b))
                .then_with(|| b.enqueued_at_ms.cmp(&a.enqueued_at_ms))
                .then_with(|| b.id.cmp(a.id))
        })
        // Reserve resources for the best eligible waiter. Continuously refilling
        // smaller jobs would otherwise starve an older large job forever.
        .filter(|item| {
            capacity.is_none_or(|total| {
                resources
                    .get(item.id)
                    .is_some_and(|required| required.fits(total.saturating_sub(used)))
            })
        })
        .map(|item| item.id)
}

fn validate_labels(labels: &BTreeMap<String, String>) -> Result<(), &'static str> {
    if labels.len() > 64
        || labels
            .iter()
            .any(|(key, value)| !crate::wire::valid_name(key) || !crate::wire::valid_name(value))
    {
        return Err("invalid_node_labels");
    }
    Ok(())
}
fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn image_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(id: &str, queued: usize) -> NodeCapabilities {
        NodeCapabilities {
            repository_cloud_sha256: BTreeMap::new(),
            version: 1,
            node_id: id.into(),
            certificate_sha256: "a".repeat(64),
            labels: BTreeMap::from([("os".into(), "linux".into())]),
            capacity: Some(Resources {
                cpu_millis: 4000,
                memory_mb: 8192,
            }),
            reserved: Resources {
                cpu_millis: 0,
                memory_mb: 0,
            },
            runners: BTreeMap::from([(
                "build".into(),
                RunnerCapability {
                    external_approval_required: false,
                    action: Default::default(),
                    owner_approval_authorities: vec![],
                    image_reference: format!("sha256:{}", "b".repeat(64)),
                    resources: Resources {
                        cpu_millis: 1000,
                        memory_mb: 1024,
                    },
                    pids_limit: 64,
                    image_digest: format!("sha256:{}", "b".repeat(64)),
                    configuration_sha256: "f".repeat(64),
                },
            )]),
            projects: vec!["repo".into()],
            max_concurrency: 4,
            max_pending_jobs: 128,
            running: 0,
            queued,
            unknown: 0,
            draining: false,
        }
    }
    #[test]
    fn placement_matches_resources_labels_and_least_load_without_inventing_capacity() {
        let mut nodes = vec![node("b", 2), node("a", 0)];
        let placement = Placement {
            node: None,
            labels: BTreeMap::from([("os".into(), "linux".into())]),
            minimum: Some(Resources {
                cpu_millis: 1000,
                memory_mb: 512,
            }),
            image_digest: None,
        };
        assert_eq!(
            select_node(&nodes, &placement, "repo", "build")
                .unwrap()
                .node_id,
            "a"
        );
        nodes[1].capacity = None;
        assert_eq!(
            select_node(&nodes, &placement, "repo", "build")
                .unwrap()
                .node_id,
            "b"
        );
        let explicit = Placement {
            node: Some("a".into()),
            ..placement.clone()
        };
        assert_eq!(
            select_node(&nodes, &explicit, "repo", "build")
                .unwrap()
                .node_id,
            "a"
        );
        nodes[0].draining = true;
        assert!(select_node(&nodes, &placement, "repo", "build").is_err());
        assert!(select_node(&nodes, &explicit, "other-project", "build").is_err());
    }
    fn queued<'a>(id: &'a str, caller: &'a str, at: u64, priority: i16) -> QueueItem<'a> {
        QueueItem {
            id,
            submitter: caller,
            submitter_certificate_sha256: None,
            project: "repo",
            enqueued_at_ms: at,
            priority,
            phase: QueuePhase::Queued,
        }
    }
    #[test]
    fn bounded_priority_aging_prevents_new_high_priority_jobs_starving_old_low_job() {
        let policy = QueuePolicy::default();
        let jobs = [
            queued("old", "a", 1000, -20),
            queued("new", "b", 42_000, 20),
        ];
        assert_eq!(
            next_job(&jobs, &policy, 1, None, &BTreeMap::new(), 42_000),
            Some("old")
        );
        assert_eq!(
            next_job(&jobs, &policy, 1, None, &BTreeMap::new(), 1000),
            Some("new")
        );
    }
    #[test]
    fn running_and_pending_quotas_are_independent_and_unknown_blocks_new_execution() {
        let policy = QueuePolicy {
            max_pending_per_submitter: 2,
            ..Default::default()
        };
        let mut jobs = [
            queued("active", "a", 1, 0),
            queued("same", "a", 2, 20),
            queued("other", "b", 3, -20),
        ];
        jobs[0].phase = QueuePhase::Active;
        assert_eq!(
            admit(&jobs, "a", None, "repo", &policy, 128),
            Err("submitter_queue_full")
        );
        assert_eq!(
            next_job(&jobs, &policy, 2, None, &BTreeMap::new(), 3),
            Some("other")
        );
        jobs[0].phase = QueuePhase::Unknown;
        assert_eq!(next_job(&jobs, &policy, 2, None, &BTreeMap::new(), 3), None);
    }
    #[test]
    fn resource_reservations_and_deterministic_fifo_ties_are_enforced() {
        let policy = QueuePolicy::default();
        let jobs = [queued("b", "b", 1, 0), queued("a", "a", 1, 0)];
        let resources = BTreeMap::from([
            (
                "a",
                Resources {
                    cpu_millis: 2000,
                    memory_mb: 1024,
                },
            ),
            (
                "b",
                Resources {
                    cpu_millis: 1000,
                    memory_mb: 1024,
                },
            ),
        ]);
        assert_eq!(
            next_job(
                &jobs,
                &policy,
                2,
                Some(Resources {
                    cpu_millis: 1000,
                    memory_mb: 2048
                }),
                &resources,
                1
            ),
            Some("b")
        );
        assert_eq!(next_job(&jobs, &policy, 2, None, &resources, 1), Some("a"));
    }
    #[test]
    fn large_eligible_waiter_reserves_capacity_instead_of_starving_on_small_refills() {
        let policy = QueuePolicy::default();
        let mut jobs = [
            queued("active", "a", 1, 0),
            queued("large", "b", 1, -20),
            queued("new-small", "c", 42000, 20),
        ];
        jobs[0].phase = QueuePhase::Active;
        let small = Resources {
            cpu_millis: 1000,
            memory_mb: 1024,
        };
        let total = Resources {
            cpu_millis: 2000,
            memory_mb: 2048,
        };
        let resources = BTreeMap::from([("active", small), ("large", total), ("new-small", small)]);
        assert_eq!(
            next_job(&jobs, &policy, 2, Some(total), &resources, 42000),
            None
        );
        jobs[0].phase = QueuePhase::Done;
        assert_eq!(
            next_job(&jobs, &policy, 2, Some(total), &resources, 42000),
            Some("large")
        );
    }
    #[test]
    fn ep06_unapprovable_external_compute_is_not_a_placement_candidate() {
        for repository_credentials in [false, true] {
            let mut unavailable = serde_json::to_value(node("a", 0)).unwrap();
            if repository_credentials {
                unavailable["repository_cloud_sha256"] = serde_json::json!({"repo":"e".repeat(64)});
            } else {
                unavailable["runners"]["build"]["external_approval_required"] =
                    serde_json::json!(true);
            }
            unavailable["projects"] = serde_json::json!(["repo", "offline"]);
            unavailable["runners"]["offline"] =
                serde_json::to_value(&node("offline", 0).runners["build"]).unwrap();
            let mut approved = unavailable.clone();
            approved["node_id"] = serde_json::json!("b");
            approved["runners"]["build"]["owner_approval_authorities"] =
                serde_json::json!([{"public_key":"a".repeat(64)}]);
            let unavailable: NodeCapabilities = serde_json::from_value(unavailable).unwrap();
            let approved: NodeCapabilities = serde_json::from_value(approved).unwrap();
            let nodes = [unavailable, approved];
            assert_eq!(
                select_node(&nodes[..1], &Placement::default(), "offline", "offline")
                    .unwrap()
                    .node_id,
                "a"
            );
            if repository_credentials {
                assert_eq!(
                    select_node(&nodes[..1], &Placement::default(), "offline", "build")
                        .unwrap()
                        .node_id,
                    "a"
                );
            }
            let selected = select_node(&nodes, &Placement::default(), "repo", "build").unwrap();
            assert_eq!(selected.node_id, "b");
            assert_eq!(
                select_node(&nodes[..1], &Placement::default(), "repo", "build").unwrap_err(),
                "no_compatible_node"
            );
            let explicit = Placement {
                node: Some("a".into()),
                ..Placement::default()
            };
            assert_eq!(
                select_node(&nodes, &explicit, "repo", "build").unwrap_err(),
                "no_compatible_node"
            );
        }
    }
}
