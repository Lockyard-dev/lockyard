// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Offline, customer-trusted image admission. A signed statement is not an independent scan.
use crate::provenance::{
    self, IMAGE_DOMAIN, ProvenanceError, SignedDocument, SigningKey, TrustedSigningKey,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};

const MAX_SBOM_BYTES: usize = 32 * 1024 * 1024;
const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_AGE_SECONDS: u64 = 30 * 24 * 3600;
const CLOCK_SKEW_MS: u64 = 60_000;

pub type Result<T> = std::result::Result<T, ProvenanceError>;

/// Required for every executable runner. File references never leave the trusted node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainPolicy {
    pub attestation_file: PathBuf,
    pub sbom_file: PathBuf,
    pub vulnerability_report_file: PathBuf,
    pub trusted_signers: Vec<TrustedSigningKey>,
    pub max_attestation_age_seconds: u64,
    pub max_report_age_seconds: u64,
    pub max_database_age_seconds: u64,
    pub max_critical: u32,
    pub max_high: u32,
    pub max_medium: u32,
    pub max_low: u32,
    pub max_unknown: u32,
    #[serde(default)]
    pub denied_vulnerability_ids: Vec<String>,
}
impl SupplyChainPolicy {
    pub fn validate(&self) -> Result<()> {
        if !self.attestation_file.is_absolute()
            || !self.sbom_file.is_absolute()
            || !self.vulnerability_report_file.is_absolute()
            || self.trusted_signers.is_empty()
            || self.trusted_signers.len() > 32
            || [
                self.max_attestation_age_seconds,
                self.max_report_age_seconds,
                self.max_database_age_seconds,
            ]
            .iter()
            .any(|age| *age == 0 || *age > MAX_AGE_SECONDS)
            || self.denied_vulnerability_ids.len() > 1024
            || self
                .denied_vulnerability_ids
                .iter()
                .any(|id| !valid_vulnerability_id(id))
        {
            return Err(ProvenanceError("invalid_supply_chain_policy"));
        }
        let mut keys = BTreeSet::new();
        for key in &self.trusted_signers {
            key.validate()?;
            if !keys.insert(key.key_id()?) {
                return Err(ProvenanceError("duplicate_attestation_signer"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SbomFormat {
    SpdxJson,
    CycloneDxJson,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobDescriptor {
    pub sha256: String,
    pub size_bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageAttestation {
    pub version: u8,
    pub image_reference: String,
    pub image_digest: String,
    pub image_config_digest: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub sbom_format: SbomFormat,
    pub sbom: BlobDescriptor,
    pub vulnerability_report: BlobDescriptor,
}
impl ImageAttestation {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = provenance::read_bounded(path, provenance::MAX_SIGNED_DOCUMENT_BYTES / 2)?;
        let statement: Self = serde_json::from_slice(&bytes)
            .map_err(|_| ProvenanceError("invalid_image_attestation"))?;
        statement.validate()?;
        Ok(statement)
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || immutable_image_digest(&self.image_reference)? != self.image_digest
            || !provenance::valid_digest(&self.image_config_digest)
            || self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
            || !provenance::valid_sha256(&self.sbom.sha256)
            || !provenance::valid_sha256(&self.vulnerability_report.sha256)
            || self.sbom.size_bytes == 0
            || self.sbom.size_bytes > MAX_SBOM_BYTES as u64
            || self.vulnerability_report.size_bytes == 0
            || self.vulnerability_report.size_bytes > MAX_REPORT_BYTES as u64
        {
            return Err(ProvenanceError("invalid_image_attestation"));
        }
        Ok(())
    }
    pub fn sign(&self, key: &SigningKey) -> Result<SignedDocument> {
        self.validate()?;
        key.sign_document(IMAGE_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Negligible,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnerabilityFinding {
    pub id: String,
    pub package: String,
    pub severity: Severity,
    pub fixed_version: Option<String>,
}
/// A trusted scanner adapter emits this strict report; arbitrary scanner JSON is never guessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnerabilityReport {
    pub version: u8,
    pub image_digest: String,
    pub generated_at_ms: u64,
    pub database_updated_at_ms: u64,
    pub scanner_name: String,
    pub scanner_version: String,
    pub findings: Vec<VulnerabilityFinding>,
}
impl VulnerabilityReport {
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || !provenance::valid_digest(&self.image_digest)
            || self.generated_at_ms == 0
            || self.database_updated_at_ms == 0
            || !safe_label(&self.scanner_name, 128)
            || !safe_label(&self.scanner_version, 128)
            || self.findings.len() > 50_000
        {
            return Err(ProvenanceError("invalid_vulnerability_report"));
        }
        let mut seen = BTreeSet::new();
        for finding in &self.findings {
            if !valid_vulnerability_id(&finding.id)
                || !safe_label(&finding.package, 512)
                || finding
                    .fixed_version
                    .as_ref()
                    .is_some_and(|value| !safe_label(value, 128))
                || !seen.insert((&finding.id, &finding.package))
            {
                return Err(ProvenanceError("invalid_vulnerability_report"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedImage {
    pub image_reference: String,
    pub image_digest: String,
    pub image_config_digest: String,
    pub attestation_sha256: String,
    pub attestation_key_id: String,
    pub sbom_sha256: String,
    pub report_sha256: String,
}
impl VerifiedImage {
    pub fn validate(&self) -> Result<()> {
        if immutable_image_digest(&self.image_reference)? != self.image_digest
            || !provenance::valid_digest(&self.image_config_digest)
            || [
                &self.attestation_sha256,
                &self.attestation_key_id,
                &self.sbom_sha256,
                &self.report_sha256,
            ]
            .iter()
            .any(|value| !provenance::valid_sha256(value))
        {
            return Err(ProvenanceError("invalid_image_admission"));
        }
        Ok(())
    }
}

pub fn verify_image(
    policy: &SupplyChainPolicy,
    image_reference: &str,
    now_ms: u64,
) -> Result<VerifiedImage> {
    policy.validate()?;
    let image_digest = immutable_image_digest(image_reference)?;
    let signed_bytes = provenance::read_bounded(
        &policy.attestation_file,
        provenance::MAX_SIGNED_DOCUMENT_BYTES,
    )?;
    let signed: SignedDocument = serde_json::from_slice(&signed_bytes)
        .map_err(|_| ProvenanceError("invalid_image_attestation"))?;
    let key = policy
        .trusted_signers
        .iter()
        .find(|key| key.key_id().ok().as_deref() == Some(&signed.key_id))
        .ok_or(ProvenanceError("untrusted_image_signer"))?;
    let attestation: ImageAttestation = provenance::verify_document(&signed, IMAGE_DOMAIN, key)?;
    attestation.validate()?;
    if attestation.image_reference != image_reference || attestation.image_digest != image_digest {
        return Err(ProvenanceError("image_attestation_subject_mismatch"));
    }
    if attestation.expires_at_ms <= now_ms
        || !fresh(
            attestation.issued_at_ms,
            now_ms,
            policy.max_attestation_age_seconds,
        )
    {
        return Err(ProvenanceError("image_attestation_expired"));
    }
    let sbom_bytes = provenance::read_bounded(&policy.sbom_file, MAX_SBOM_BYTES)?;
    let report_bytes =
        provenance::read_bounded(&policy.vulnerability_report_file, MAX_REPORT_BYTES)?;
    if !matches_blob(&sbom_bytes, &attestation.sbom)
        || !matches_blob(&report_bytes, &attestation.vulnerability_report)
    {
        return Err(ProvenanceError("image_evidence_digest_mismatch"));
    }
    validate_sbom(&sbom_bytes, attestation.sbom_format)?;
    let report: VulnerabilityReport = serde_json::from_slice(&report_bytes)
        .map_err(|_| ProvenanceError("invalid_vulnerability_report"))?;
    report.validate()?;
    if report.image_digest != image_digest {
        return Err(ProvenanceError("vulnerability_report_subject_mismatch"));
    }
    if !fresh(
        report.generated_at_ms,
        now_ms,
        policy.max_report_age_seconds,
    ) || !fresh(
        report.database_updated_at_ms,
        now_ms,
        policy.max_database_age_seconds,
    ) || report.generated_at_ms > attestation.issued_at_ms.saturating_add(CLOCK_SKEW_MS)
        || report.database_updated_at_ms > report.generated_at_ms.saturating_add(CLOCK_SKEW_MS)
    {
        return Err(ProvenanceError("vulnerability_report_stale"));
    }
    let mut counts = [0u32; 5];
    for finding in &report.findings {
        if policy
            .denied_vulnerability_ids
            .iter()
            .any(|denied| denied.eq_ignore_ascii_case(&finding.id))
        {
            return Err(ProvenanceError("vulnerability_policy_denied"));
        }
        let bucket = match finding.severity {
            Severity::Critical => Some(0),
            Severity::High => Some(1),
            Severity::Medium => Some(2),
            Severity::Low => Some(3),
            Severity::Unknown => Some(4),
            Severity::Negligible => None,
        };
        if let Some(bucket) = bucket {
            counts[bucket] = counts[bucket].saturating_add(1);
        }
    }
    let limits = [
        policy.max_critical,
        policy.max_high,
        policy.max_medium,
        policy.max_low,
        policy.max_unknown,
    ];
    if counts
        .iter()
        .zip(limits)
        .any(|(count, limit)| *count > limit)
    {
        return Err(ProvenanceError("vulnerability_policy_denied"));
    }
    Ok(VerifiedImage {
        image_reference: image_reference.into(),
        image_digest,
        image_config_digest: attestation.image_config_digest,
        attestation_sha256: provenance::sha256(&signed_bytes),
        attestation_key_id: signed.key_id,
        sbom_sha256: attestation.sbom.sha256,
        report_sha256: attestation.vulnerability_report.sha256,
    })
}

pub fn immutable_image_digest(reference: &str) -> Result<String> {
    if reference.len() > 512
        || reference
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(ProvenanceError("image_reference_must_be_immutable"));
    }
    if provenance::valid_digest(reference) {
        return Ok(reference.to_string());
    }
    let (repository, digest) = reference
        .rsplit_once('@')
        .ok_or(ProvenanceError("image_reference_must_be_immutable"))?;
    if !provenance::valid_digest(digest)
        || repository.is_empty()
        || repository.starts_with(['-', '/', '.'])
        || repository.contains("..")
        || repository.contains('@')
        || repository.contains("://")
        || !repository.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"/._-:".contains(&byte)
        })
    {
        return Err(ProvenanceError("image_reference_must_be_immutable"));
    }
    Ok(digest.into())
}
fn matches_blob(bytes: &[u8], descriptor: &BlobDescriptor) -> bool {
    bytes.len() as u64 == descriptor.size_bytes && provenance::sha256(bytes) == descriptor.sha256
}
fn fresh(timestamp: u64, now: u64, max_age: u64) -> bool {
    timestamp <= now.saturating_add(CLOCK_SKEW_MS)
        && now.saturating_sub(timestamp) <= max_age.saturating_mul(1000)
}
fn safe_label(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn valid_vulnerability_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_:./".contains(&byte))
}
fn validate_sbom(bytes: &[u8], format: SbomFormat) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ProvenanceError("invalid_sbom"))?;
    let valid = match format {
        SbomFormat::SpdxJson => {
            value["spdxVersion"]
                .as_str()
                .is_some_and(|version| matches!(version, "SPDX-2.2" | "SPDX-2.3"))
                && value["SPDXID"] == "SPDXRef-DOCUMENT"
                && value["dataLicense"] == "CC0-1.0"
                && value["name"]
                    .as_str()
                    .is_some_and(|name| safe_label(name, 512))
                && value["documentNamespace"]
                    .as_str()
                    .is_some_and(|namespace| url::Url::parse(namespace).is_ok())
                && value["creationInfo"]["created"].is_string()
                && value["creationInfo"]["creators"]
                    .as_array()
                    .is_some_and(|creators| {
                        !creators.is_empty() && creators.iter().all(serde_json::Value::is_string)
                    })
                && value["packages"].is_array()
        }
        SbomFormat::CycloneDxJson => {
            value["bomFormat"] == "CycloneDX"
                && value["specVersion"]
                    .as_str()
                    .is_some_and(|version| matches!(version, "1.4" | "1.5" | "1.6"))
                && value["version"].as_u64().is_some_and(|version| version > 0)
                && value["components"].is_array()
        }
    };
    if !valid {
        return Err(ProvenanceError("invalid_sbom"));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    const NOW: u64 = 1_800_000_000_000;
    #[test]
    fn supported_sbom_headers_require_real_versions_and_document_identity() {
        let spdx = br#"{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"fixture-image","documentNamespace":"urn:uuid:00000000-0000-4000-8000-000000000000","creationInfo":{"created":"2026-11-07T00:00:00Z","creators":["Tool: fixture"]},"packages":[]}"#;
        validate_sbom(spdx, SbomFormat::SpdxJson).unwrap();
        assert!(
            validate_sbom(
                br#"{"spdxVersion":"SPDX-2.invalid","SPDXID":"SPDXRef-DOCUMENT","packages":[]}"#,
                SbomFormat::SpdxJson
            )
            .is_err()
        );
        assert!(
            validate_sbom(
                br#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}"#,
                SbomFormat::CycloneDxJson
            )
            .is_err()
        );
    }
    struct Fixture {
        root: tempfile::TempDir,
        key: SigningKey,
        policy: SupplyChainPolicy,
        attestation: ImageAttestation,
        report: VulnerabilityReport,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let key = SigningKey::generate(&root.path().join("attester.pk8")).unwrap();
            let image = format!("registry.example/runner@sha256:{}", "a".repeat(64));
            let policy = SupplyChainPolicy {
                attestation_file: root.path().join("attestation.json"),
                sbom_file: root.path().join("sbom.json"),
                vulnerability_report_file: root.path().join("scan.json"),
                trusted_signers: vec![key.trusted_key()],
                max_attestation_age_seconds: 3600,
                max_report_age_seconds: 3600,
                max_database_age_seconds: 7200,
                max_critical: 0,
                max_high: 0,
                max_medium: 5,
                max_low: 100,
                max_unknown: 0,
                denied_vulnerability_ids: vec![],
            };
            let report = VulnerabilityReport {
                version: 1,
                image_digest: format!("sha256:{}", "a".repeat(64)),
                generated_at_ms: NOW - 1000,
                database_updated_at_ms: NOW - 2000,
                scanner_name: "synthetic-test-scanner".into(),
                scanner_version: "1".into(),
                findings: vec![],
            };
            let sbom =
                br#"{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}"#;
            fs::write(&policy.sbom_file, sbom).unwrap();
            let attestation = ImageAttestation {
                version: 1,
                image_reference: image,
                image_digest: report.image_digest.clone(),
                image_config_digest: format!("sha256:{}", "b".repeat(64)),
                issued_at_ms: NOW - 500,
                expires_at_ms: NOW + 60_000,
                sbom_format: SbomFormat::CycloneDxJson,
                sbom: BlobDescriptor {
                    sha256: provenance::sha256(sbom),
                    size_bytes: sbom.len() as u64,
                },
                vulnerability_report: BlobDescriptor {
                    sha256: String::new(),
                    size_bytes: 0,
                },
            };
            let mut fixture = Self {
                root,
                key,
                policy,
                attestation,
                report,
            };
            fixture.resign();
            fixture
        }
        fn resign(&mut self) {
            let report = serde_json::to_vec(&self.report).unwrap();
            fs::write(&self.policy.vulnerability_report_file, &report).unwrap();
            self.attestation.vulnerability_report = BlobDescriptor {
                sha256: provenance::sha256(&report),
                size_bytes: report.len() as u64,
            };
            fs::write(
                &self.policy.attestation_file,
                serde_json::to_vec(&self.attestation.sign(&self.key).unwrap()).unwrap(),
            )
            .unwrap();
        }
        fn verify(&self) -> Result<VerifiedImage> {
            verify_image(&self.policy, &self.attestation.image_reference, NOW)
        }
    }
    #[test]
    fn image_admission_requires_immutable_subject_pinned_signature_and_actual_evidence_bytes() {
        let fixture = Fixture::new();
        let verified = fixture.verify().unwrap();
        assert_eq!(verified.image_digest, fixture.attestation.image_digest);
        assert_eq!(
            verified.image_config_digest,
            fixture.attestation.image_config_digest
        );
        assert!(!verified.attestation_sha256.is_empty());
        for reference in [
            "runner:latest",
            "registry.example/runner:v1",
            "https://registry.example/image@sha256:abc",
            "-image",
            "sha256:ABC",
            "registry.example/../image@sha256:abc",
        ] {
            assert!(immutable_image_digest(reference).is_err(), "{reference}");
        }
        let other = Fixture::new();
        let mut policy = fixture.policy.clone();
        policy.trusted_signers = vec![other.key.trusted_key()];
        assert_eq!(
            verify_image(&policy, &fixture.attestation.image_reference, NOW)
                .unwrap_err()
                .0,
            "untrusted_image_signer"
        );
        fs::write(&fixture.policy.sbom_file, b"modified bytes").unwrap();
        assert_eq!(
            fixture.verify().unwrap_err().0,
            "image_evidence_digest_mismatch"
        );
    }
    #[test]
    fn signed_evidence_still_obeys_expiry_subject_report_and_database_freshness() {
        let mut fixture = Fixture::new();
        assert_eq!(
            verify_image(
                &fixture.policy,
                &fixture.attestation.image_reference,
                NOW + 60_001
            )
            .unwrap_err()
            .0,
            "image_attestation_expired"
        );
        let other = format!("registry.example/other@sha256:{}", "c".repeat(64));
        assert_eq!(
            verify_image(&fixture.policy, &other, NOW).unwrap_err().0,
            "image_attestation_subject_mismatch"
        );
        fixture.report.image_digest = format!("sha256:{}", "c".repeat(64));
        fixture.resign();
        assert_eq!(
            fixture.verify().unwrap_err().0,
            "vulnerability_report_subject_mismatch"
        );
        fixture.report.image_digest = fixture.attestation.image_digest.clone();
        fixture.report.database_updated_at_ms = NOW - 7_201_000;
        fixture.resign();
        assert_eq!(
            fixture.verify().unwrap_err().0,
            "vulnerability_report_stale"
        );
        fixture.report.database_updated_at_ms = NOW - 2000;
        fixture.report.generated_at_ms = NOW - 3_601_000;
        fixture.resign();
        assert_eq!(
            fixture.verify().unwrap_err().0,
            "vulnerability_report_stale"
        );
    }
    #[test]
    fn signed_report_cannot_override_configured_severity_or_explicit_vulnerability_denial() {
        let mut fixture = Fixture::new();
        fixture.report.findings.push(VulnerabilityFinding {
            id: "CVE-2026-12345".into(),
            package: "fixture-package".into(),
            severity: Severity::High,
            fixed_version: Some("2".into()),
        });
        fixture.resign();
        assert_eq!(
            fixture.verify().unwrap_err().0,
            "vulnerability_policy_denied"
        );
        fixture.policy.max_high = 1;
        fixture.verify().unwrap();
        fixture
            .policy
            .denied_vulnerability_ids
            .push("cve-2026-12345".into());
        assert_eq!(
            fixture.verify().unwrap_err().0,
            "vulnerability_policy_denied"
        );
        fixture.policy.denied_vulnerability_ids.clear();
        fixture.report.findings[0].severity = Severity::Unknown;
        fixture.resign();
        assert_eq!(
            fixture.verify().unwrap_err().0,
            "vulnerability_policy_denied"
        );
    }
    #[test]
    fn untrusted_evidence_paths_and_malformed_signed_sbom_are_rejected() {
        let mut fixture = Fixture::new();
        let _keep = &fixture.root;
        fs::remove_file(&fixture.policy.sbom_file).unwrap();
        std::os::unix::fs::symlink(
            &fixture.policy.vulnerability_report_file,
            &fixture.policy.sbom_file,
        )
        .unwrap();
        assert_eq!(fixture.verify().unwrap_err().0, "artifact_unavailable");
        fs::remove_file(&fixture.policy.sbom_file).unwrap();
        let bytes = b"{}";
        fs::write(&fixture.policy.sbom_file, bytes).unwrap();
        fixture.attestation.sbom = BlobDescriptor {
            size_bytes: bytes.len() as u64,
            sha256: provenance::sha256(bytes),
        };
        fixture.resign();
        assert_eq!(fixture.verify().unwrap_err().0, "invalid_sbom");
        fixture.policy.trusted_signers.clear();
        assert_eq!(
            fixture.verify().unwrap_err().0,
            "invalid_supply_chain_policy"
        );
    }
}
