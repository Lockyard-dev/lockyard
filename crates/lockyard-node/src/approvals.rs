// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Offline owner authorization for declared external workload specifications.
//!
//! Signatures bind configuration and destination references, not every dynamic shell/network
//! operation. Execution hosts and their administrators are trusted.
use crate::{
    executor::{CloudConfig, RunnerProfile, runner_config_digest},
    provenance::{self, ProvenanceError, SignedDocument, SigningKey, TrustedSigningKey},
    wire::{self, JobSpec},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub type Result<T> = std::result::Result<T, ProvenanceError>;
const APPROVAL_DOMAIN: &[u8] = b"lockyard-owner-external-action-v1\0";
/// An offline owner approval is intentionally short lived. This is an admission/start deadline;
/// an already running authorized job is not stopped merely because this window ends.
pub const MAX_APPROVAL_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedAction {
    #[default]
    Compute,
    GitPush,
    Publish,
    Deploy,
}
impl ManagedAction {
    pub fn requires_owner(self) -> bool {
        self != Self::Compute
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerApproval {
    pub version: u8,
    pub workspace: String,
    pub node_id: String,
    pub node_certificate_sha256: String,
    /// Stable one-use identity. The executor's durable job journal/tombstone consumes this ID.
    pub job_id: String,
    pub repository: String,
    pub runner: String,
    /// Canonical complete JobSpec with only owner_approval omitted, avoiding circular hashing.
    pub request_sha256: String,
    pub resolved_revision: String,
    pub runner_configuration_sha256: String,
    /// Configured broker destinations and credential references, never resolved values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_cloud_sha256: Option<String>,
    pub image_reference: String,
    pub image_digest: String,
    pub action: ManagedAction,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
}
impl OwnerApproval {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || !wire::valid_name(&self.workspace)
            || !wire::valid_name(&self.node_id)
            || !wire::valid_certificate_pin(&self.node_certificate_sha256)
            || !wire::valid_ulid(&self.job_id)
            || !wire::valid_name(&self.repository)
            || !wire::valid_name(&self.runner)
            || !provenance::valid_sha256(&self.request_sha256)
            || !provenance::valid_sha256(&self.runner_configuration_sha256)
            || ![40, 64].contains(&self.resolved_revision.len())
            || !self
                .resolved_revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self
                .repository_cloud_sha256
                .as_ref()
                .is_some_and(|hash| !provenance::valid_sha256(hash))
            || self.not_before_ms == 0
            || self.expires_at_ms <= self.not_before_ms
            || self.expires_at_ms - self.not_before_ms > MAX_APPROVAL_WINDOW_MS
        {
            return Err(ProvenanceError("invalid_owner_approval"));
        }
        let digest = crate::supply_chain::immutable_image_digest(&self.image_reference)
            .map_err(|_| ProvenanceError("invalid_owner_approval_image"))?;
        if self.image_digest != digest {
            return Err(ProvenanceError("invalid_owner_approval_image"));
        }
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = provenance::read_bounded(path, provenance::MAX_SIGNED_DOCUMENT_BYTES / 2)?;
        let value: Self = serde_json::from_slice(&bytes)
            .map_err(|_| ProvenanceError("invalid_owner_approval"))?;
        value.validate()?;
        Ok(value)
    }
    pub fn sign(&self, key: &SigningKey) -> Result<SignedDocument> {
        self.validate()?;
        key.sign_document(APPROVAL_DOMAIN, self)
    }
}

/// Every expected field comes from trusted local configuration or the authenticated request.
/// In particular, neither a document's key ID nor its embedded claim selects a trust anchor.
pub struct ApprovalExpectation<'a> {
    pub workspace: &'a str,
    pub node_id: &'a str,
    pub node_certificate_sha256: &'a str,
    pub spec: &'a JobSpec,
    pub resolved_revision: &'a str,
    pub runner: &'a RunnerProfile,
    pub repository_cloud: Option<&'a CloudConfig>,
}

pub fn request_sha256(spec: &JobSpec) -> Result<String> {
    let mut unapproved = spec.clone();
    unapproved.owner_approval = None;
    let bytes = serde_json::to_vec(&unapproved)
        .map_err(|_| ProvenanceError("owner_approval_request_encoding_failed"))?;
    if bytes.len() > 128 * 1024 {
        return Err(ProvenanceError("owner_approval_request_too_large"));
    }
    Ok(provenance::sha256(&bytes))
}

pub fn prepare(
    expected: &ApprovalExpectation<'_>,
    not_before_ms: u64,
    expires_at_ms: u64,
) -> Result<OwnerApproval> {
    if !expected.runner.action.requires_owner()
        && (!requires_owner_approval(expected)
            || expected.runner.owner_approval_authorities.is_empty())
    {
        return Err(ProvenanceError("owner_approval_required"));
    }
    let claim = OwnerApproval {
        version: 1,
        workspace: expected.workspace.into(),
        node_id: expected.node_id.into(),
        node_certificate_sha256: expected.node_certificate_sha256.into(),
        job_id: expected.spec.id.clone(),
        repository: expected.spec.repository.clone(),
        runner: expected.spec.runner.clone(),
        request_sha256: request_sha256(expected.spec)?,
        resolved_revision: expected.resolved_revision.into(),
        runner_configuration_sha256: runner_config_digest(expected.runner)
            .map_err(|_| ProvenanceError("owner_approval_runner_encoding_failed"))?,
        repository_cloud_sha256: repository_cloud_sha256(expected.repository_cloud)?,
        image_reference: expected.runner.container.image.clone(),
        image_digest: crate::supply_chain::immutable_image_digest(&expected.runner.container.image)
            .map_err(|_| ProvenanceError("invalid_owner_approval_image"))?,
        action: expected.runner.action,
        not_before_ms,
        expires_at_ms,
    };
    claim.validate()?;
    Ok(claim)
}

pub fn verify(
    document: &SignedDocument,
    authorities: &[TrustedSigningKey],
    expected: &ApprovalExpectation<'_>,
    now_ms: u64,
) -> Result<OwnerApproval> {
    // Compare against independent configured pins before parsing an attacker-selected payload.
    if authorities.is_empty() || authorities.len() > 32 {
        return Err(ProvenanceError("owner_approval_authority_required"));
    }
    let authority = authorities
        .iter()
        .find(|key| key.key_id().ok().as_deref() == Some(&document.key_id))
        .ok_or(ProvenanceError("untrusted_owner_approval_signer"))?;
    let claim: OwnerApproval = provenance::verify_document(document, APPROVAL_DOMAIN, authority)
        .map_err(|_| ProvenanceError("owner_approval_signature_invalid"))?;
    claim.validate()?;
    if now_ms < claim.not_before_ms || now_ms >= claim.expires_at_ms {
        return Err(ProvenanceError("owner_approval_outside_window"));
    }
    let actual = prepare(expected, claim.not_before_ms, claim.expires_at_ms)?;
    if claim != actual {
        return Err(ProvenanceError("owner_approval_context_mismatch"));
    }
    Ok(claim)
}

pub fn repository_cloud_sha256(cloud: Option<&CloudConfig>) -> Result<Option<String>> {
    cloud
        .map(|cloud| {
            serde_json::to_vec(cloud)
                .map(|bytes| provenance::sha256(&bytes))
                .map_err(|_| ProvenanceError("owner_approval_request_encoding_failed"))
        })
        .transpose()
}

pub fn requires_owner_approval(expected: &ApprovalExpectation<'_>) -> bool {
    expected.runner.action.requires_owner()
        || expected.runner.requires_external_approval()
        || expected.repository_cloud.is_some()
}

/// Offline compute without credentials retains all-member dispatch; all declared external
/// specifications and explicitly managed profiles require independently pinned owner authority.
pub fn enforce(expected: &ApprovalExpectation<'_>, now_ms: u64) -> Result<()> {
    if requires_owner_approval(expected) {
        let document = expected
            .spec
            .owner_approval
            .as_ref()
            .ok_or(ProvenanceError("owner_approval_required"))?;
        verify(
            document,
            &expected.runner.owner_approval_authorities,
            expected,
            now_ms,
        )?;
    } else if expected.spec.owner_approval.is_some() {
        return Err(ProvenanceError("owner_approval_action_mismatch"));
    }
    Ok(())
}

/// Safe public profile binding for a materialized DAG approval. No executable,
/// secret reference, checkout path, or broker credential is included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedApproval {
    #[serde(default, skip_serializing_if = "is_false")]
    pub external_spec: bool,
    pub workspace: String,
    pub node_id: String,
    pub node_certificate_sha256: String,
    pub spec: JobSpec,
    pub resolved_revision: String,
    pub runner_configuration_sha256: String,
    /// Configured broker destinations and credential references, never resolved values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_cloud_sha256: Option<String>,
    pub image_reference: String,
    pub image_digest: String,
    pub action: ManagedAction,
    pub owner_approval_authorities: Vec<TrustedSigningKey>,
}
fn is_false(value: &bool) -> bool {
    !value
}

impl MaterializedApproval {
    pub fn prepare(&self, not_before_ms: u64, expires_at_ms: u64) -> Result<OwnerApproval> {
        if (!self.action.requires_owner()
            && !self.external_spec
            && self.repository_cloud_sha256.is_none())
            || self.spec.revision != self.resolved_revision
            || self.spec.expected_runner_sha256.as_deref()
                != Some(self.runner_configuration_sha256.as_str())
            || self.owner_approval_authorities.is_empty()
            || self.owner_approval_authorities.len() > 32
            || self
                .owner_approval_authorities
                .iter()
                .any(|key| key.validate().is_err())
        {
            return Err(ProvenanceError("invalid_materialized_owner_approval"));
        }
        let claim = OwnerApproval {
            version: 1,
            workspace: self.workspace.clone(),
            node_id: self.node_id.clone(),
            node_certificate_sha256: self.node_certificate_sha256.clone(),
            job_id: self.spec.id.clone(),
            repository: self.spec.repository.clone(),
            runner: self.spec.runner.clone(),
            request_sha256: request_sha256(&self.spec)?,
            resolved_revision: self.resolved_revision.clone(),
            runner_configuration_sha256: self.runner_configuration_sha256.clone(),
            repository_cloud_sha256: self.repository_cloud_sha256.clone(),
            image_reference: self.image_reference.clone(),
            image_digest: self.image_digest.clone(),
            action: self.action,
            not_before_ms,
            expires_at_ms,
        };
        claim.validate()?;
        Ok(claim)
    }
    pub fn verify_context(&self, document: &SignedDocument) -> Result<OwnerApproval> {
        let authority = self
            .owner_approval_authorities
            .iter()
            .find(|key| key.key_id().ok().as_deref() == Some(document.key_id.as_str()))
            .ok_or(ProvenanceError("untrusted_owner_approval_signer"))?;
        let claim: OwnerApproval =
            provenance::verify_document(document, APPROVAL_DOMAIN, authority)
                .map_err(|_| ProvenanceError("owner_approval_signature_invalid"))?;
        claim.validate()?;
        if claim != self.prepare(claim.not_before_ms, claim.expires_at_ms)? {
            return Err(ProvenanceError("owner_approval_context_mismatch"));
        }
        Ok(claim)
    }
    pub fn verify(&self, document: &SignedDocument, now_ms: u64) -> Result<OwnerApproval> {
        let claim = self.verify_context(document)?;
        if now_ms < claim.not_before_ms || now_ms >= claim.expires_at_ms {
            return Err(ProvenanceError("owner_approval_outside_window"));
        }
        Ok(claim)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{fs, os::unix::fs::PermissionsExt};

    fn fixture() -> (tempfile::TempDir, SigningKey, JobSpec, RunnerProfile) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key = SigningKey::generate(&root.path().join("owner.pk8")).unwrap();
        let spec = serde_json::from_value(json!({"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","repository":"repo",
            "revision":"HEAD","runner":"deploy","arguments":["destination"],"prompt":"private prompt",
            "timeout_seconds":30,"priority":5,"expected_runner_sha256":"e".repeat(64)})).unwrap();
        let runner = serde_json::from_value(json!({"action":"deploy","owner_approval_authorities":[key.trusted_key()],
            "container":{"runtime":"docker","runtime_program":"/usr/bin/docker","image":format!("sha256:{}","a".repeat(64)),
                "git_program":"/usr/bin/git","memory_mb":128,"cpu_millis":1000,"pids_limit":64,"network":"bridge"},
            "program":"/usr/bin/deploy","fixed_args":[],"env_passthrough":[]})).unwrap();
        (root, key, spec, runner)
    }
    fn expected<'a>(spec: &'a JobSpec, runner: &'a RunnerProfile) -> ApprovalExpectation<'a> {
        ApprovalExpectation {
            workspace: "workspace",
            node_id: "worker",
            node_certificate_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            spec,
            resolved_revision: "cccccccccccccccccccccccccccccccccccccccc",
            runner,
            repository_cloud: None,
        }
    }
    #[test]
    fn exact_external_action_authorization_roundtrips_without_content_in_claim() {
        let (_root, key, mut spec, runner) = fixture();
        let claim = prepare(&expected(&spec, &runner), 100, 200).unwrap();
        let document = claim.sign(&key).unwrap();
        assert_eq!(
            verify(
                &document,
                &[key.trusted_key()],
                &expected(&spec, &runner),
                100
            )
            .unwrap(),
            claim
        );
        let serialized = serde_json::to_string(&claim).unwrap();
        for content in ["private prompt", "destination", "/usr/bin/deploy"] {
            assert!(!serialized.contains(content));
        }
        let before = request_sha256(&spec).unwrap();
        spec.owner_approval = Some(document);
        assert_eq!(request_sha256(&spec).unwrap(), before);
        enforce(&expected(&spec, &runner), 199).unwrap();
    }
    #[test]
    fn every_independent_execution_binding_is_enforced() {
        let (_root, key, spec, runner) = fixture();
        let claim = prepare(&expected(&spec, &runner), 100, 200).unwrap();
        let document = claim.sign(&key).unwrap();
        for field in 0..7 {
            let mut changed = expected(&spec, &runner);
            match field {
                0 => changed.workspace = "other",
                1 => changed.node_id = "other",
                2 => {
                    changed.node_certificate_sha256 =
                        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
                3 => changed.resolved_revision = "dddddddddddddddddddddddddddddddddddddddd",
                _ => (),
            }
            let mut other_spec = spec.clone();
            let mut other_runner = runner.clone();
            if field == 4 {
                other_spec.id = "01ARZ3NDEKTSV4RRFFQ69G5FAW".into();
                changed.spec = &other_spec;
            }
            if field == 5 {
                other_runner.container.image = format!("sha256:{}", "d".repeat(64));
                changed.runner = &other_runner;
            } else if field == 6 {
                other_runner.action = ManagedAction::Publish;
                changed.runner = &other_runner;
            }
            assert_eq!(
                verify(&document, &[key.trusted_key()], &changed, 150)
                    .unwrap_err()
                    .0,
                "owner_approval_context_mismatch"
            );
        }
    }
    #[test]
    fn all_request_and_runner_changes_invalidate_the_owner_signature() {
        let (_root, key, spec, runner) = fixture();
        let document = prepare(&expected(&spec, &runner), 100, 200)
            .unwrap()
            .sign(&key)
            .unwrap();
        for field in 0..9 {
            let mut changed = spec.clone();
            match field {0=>changed.repository="other".into(),1=>changed.runner="other".into(),2=>changed.arguments.push("extra".into()),
                3=>changed.prompt=Some("changed".into()),4=>changed.timeout_seconds=Some(31),5=>changed.priority=6,
                6=>changed.expected_runner_sha256=Some("f".repeat(64)),7=>changed.revision="main".into(),
                _=>changed.workflow_inputs=serde_json::from_value(json!([{"step":"build","job_id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","node_id":"worker",
                    "certificate_sha256":"a".repeat(64),"manifest_sha256":"b".repeat(64),"resolved_revision":"c".repeat(40),
                    "image_digest":format!("sha256:{}","d".repeat(64)),"artifacts":{}}])).unwrap()}
            assert_eq!(
                verify(
                    &document,
                    &[key.trusted_key()],
                    &expected(&changed, &runner),
                    150
                )
                .unwrap_err()
                .0,
                "owner_approval_context_mismatch"
            );
        }
        for field in 0..5 {
            let mut changed = runner.clone();
            match field {
                0 => changed.program = "/usr/bin/other".into(),
                1 => changed.fixed_args.push("--force".into()),
                2 => changed.container.memory_mb += 1,
                3 => changed.credential_repositories.push("repo".into()),
                _ => changed.owner_approval_authorities.clear(),
            }
            assert_eq!(
                verify(
                    &document,
                    &[key.trusted_key()],
                    &expected(&spec, &changed),
                    150
                )
                .unwrap_err()
                .0,
                "owner_approval_context_mismatch"
            );
        }
    }
    #[test]
    fn windows_are_exact_and_bounded() {
        let (_root, key, spec, runner) = fixture();
        let context = expected(&spec, &runner);
        let document = prepare(&context, 100, 200).unwrap().sign(&key).unwrap();
        for now in [0, 99, 200, u64::MAX] {
            assert_eq!(
                verify(&document, &[key.trusted_key()], &context, now)
                    .unwrap_err()
                    .0,
                "owner_approval_outside_window"
            );
        }
        for (start, end) in [
            (0, 1),
            (100, 100),
            (200, 100),
            (1, MAX_APPROVAL_WINDOW_MS + 2),
            (u64::MAX, u64::MAX),
        ] {
            assert!(prepare(&context, start, end).is_err());
        }
    }
    #[test]
    fn owner_pins_are_independent_of_workspace_membership_and_machine_keys() {
        let (_root, key, spec, runner) = fixture();
        let context = expected(&spec, &runner);
        let document = prepare(&context, 100, 200).unwrap().sign(&key).unwrap();
        let (_other_root, other, _, _) = fixture();
        assert_eq!(
            verify(&document, &[other.trusted_key()], &context, 150)
                .unwrap_err()
                .0,
            "untrusted_owner_approval_signer"
        );
        assert_eq!(
            verify(&document, &[], &context, 150).unwrap_err().0,
            "owner_approval_authority_required"
        );
        let mut tampered = document.clone();
        tampered.signature = "A".repeat(88);
        assert_eq!(
            verify(&tampered, &[key.trusted_key()], &context, 150)
                .unwrap_err()
                .0,
            "owner_approval_signature_invalid"
        );
    }
    #[test]
    fn cross_purpose_signatures_and_ambiguous_claims_are_rejected() {
        let (_root, key, spec, runner) = fixture();
        let context = expected(&spec, &runner);
        let claim = prepare(&context, 100, 200).unwrap();
        let wrong_domain = key
            .sign_document(provenance::RESULT_DOMAIN, &claim)
            .unwrap();
        assert_eq!(
            verify(&wrong_domain, &[key.trusted_key()], &context, 150)
                .unwrap_err()
                .0,
            "owner_approval_signature_invalid"
        );
        let mut value = serde_json::to_value(&claim).unwrap();
        value["owner"] = json!(true);
        let unknown = key.sign_document(APPROVAL_DOMAIN, &value).unwrap();
        assert_eq!(
            verify(&unknown, &[key.trusted_key()], &context, 150)
                .unwrap_err()
                .0,
            "owner_approval_signature_invalid"
        );
        let noncanonical = key
            .sign_document(APPROVAL_DOMAIN, &serde_json::to_value(&claim).unwrap())
            .unwrap();
        assert_eq!(
            verify(&noncanonical, &[key.trusted_key()], &context, 150)
                .unwrap_err()
                .0,
            "owner_approval_signature_invalid"
        );
    }
    #[test]
    fn ordinary_member_compute_needs_no_owner_and_managed_actions_fail_closed() {
        let (_root, _key, spec, mut runner) = fixture();
        assert_eq!(
            enforce(&expected(&spec, &runner), 150).unwrap_err().0,
            "owner_approval_required"
        );
        runner.action = ManagedAction::Compute;
        runner.container.network = crate::executor::ContainerNetwork::None;
        runner.owner_approval_authorities.clear();
        enforce(&expected(&spec, &runner), 150).unwrap();
        assert!(prepare(&expected(&spec, &runner), 100, 200).is_err());
    }
}
