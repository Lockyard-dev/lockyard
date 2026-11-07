// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Payload encryption authenticates all RPC routing metadata as associated data.
use crate::{Result, wire::RpcFrame};
use lockyard_cloud_client::WorkspaceKey;
use serde::{Serialize, de::DeserializeOwned};

pub struct PayloadCodec {
    workspace: String,
    key: WorkspaceKey,
}

impl PayloadCodec {
    pub fn identity_proof(&self, node_id: &str, certificate_sha256: &str) -> Result<String> {
        crate::incarnation::seal_identity(&self.workspace, node_id, certificate_sha256, &self.key)
    }
    pub fn new(workspace: String, key: WorkspaceKey) -> Result<Self> {
        if !crate::wire::valid_name(&workspace) {
            return Err("valid workspace identity is required for node encryption".into());
        }
        Ok(Self { workspace, key })
    }

    pub fn encode<T: Serialize>(&self, frame: &mut RpcFrame, payload: &T) -> Result<()> {
        let field = frame.authenticated_field()?;
        let plaintext =
            serde_json::to_string(payload).map_err(|_| "cannot encode node RPC payload")?;
        frame.payload = match self.record_key(frame, &field)? {
            Some(key) => key.encrypt(&self.workspace, &field, &plaintext)?,
            None => self.key.encrypt(&self.workspace, &field, &plaintext)?,
        };
        frame.validate()?;
        Ok(())
    }

    pub fn decode<T: DeserializeOwned>(&self, frame: &RpcFrame) -> Result<T> {
        frame.validate()?;
        let field = frame.authenticated_field()?;
        let plaintext = match self.record_key(frame, &field)? {
            Some(key) => key.decrypt(&self.workspace, &field, &frame.payload)?,
            None => self.key.decrypt(&self.workspace, &field, &frame.payload)?,
        };
        Ok(serde_json::from_str(&plaintext).map_err(|_| "cannot decode node RPC payload")?)
    }

    fn record_key(&self, frame: &RpcFrame, field: &str) -> Result<Option<WorkspaceKey>> {
        if frame.v == 1 {
            return Ok(None);
        }
        let context = serde_json::to_vec(&(self.workspace.as_str(), field))?;
        Ok(Some(
            self.key.derive_context(b"lockyard-node-rpc-v2", &context)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{FrameKind, Operation, PROTOCOL_VERSION};
    use serde_json::{Value, json};
    #[test]
    fn v2_matches_independent_hkdf_aes_gcm_vector_and_binds_context() {
        for encoded in [
            include_str!("../tests/fixtures/rpc-v2.json"),
            include_str!("../tests/fixtures/rpc-v2-pins-retention.json"),
        ] {
            let vector: Value = serde_json::from_str(encoded).unwrap();
            let frame: RpcFrame = serde_json::from_value(vector["frame"].clone()).unwrap();
            assert_eq!(
                frame.authenticated_field().unwrap(),
                vector["authenticated_field"]
            );
            let codec =
                PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([7; 32])).unwrap();
            assert_eq!(codec.decode::<Value>(&frame).unwrap(), vector["plaintext"]);
            let mut changed = frame.clone();
            changed.target = "another".into();
            assert!(codec.decode::<Value>(&changed).is_err());
            if changed.source_certificate_sha256.is_some() {
                let mut changed = frame.clone();
                changed.source_certificate_sha256 = Some("c".repeat(64));
                assert!(codec.decode::<Value>(&changed).is_err());
                let mut changed = frame.clone();
                changed.target_certificate_sha256 = Some("d".repeat(64));
                assert!(codec.decode::<Value>(&changed).is_err());
            }
            if frame.retention.is_some() {
                let mut changed = frame.clone();
                changed.retention.as_mut().unwrap().content_ttl_seconds += 1;
                assert!(codec.decode::<Value>(&changed).is_err());
            }
            assert!(
                PayloadCodec::new(
                    "other-workspace".into(),
                    WorkspaceKey::from_entropy([7; 32])
                )
                .unwrap()
                .decode::<Value>(&frame)
                .is_err()
            );
            let previous_child_id = frame.payload.split('.').nth(1).unwrap().to_owned();
            let mut another = frame;
            let fresh_id = crate::wire::new_id().unwrap();
            another.id = format!("{}{}", &another.id[..10], &fresh_id[10..]);
            codec
                .encode(&mut another, &json!({"probe":"vector"}))
                .unwrap();
            assert_ne!(
                another.payload.split('.').nth(1).unwrap(),
                previous_child_id
            );
        }
    }

    #[test]
    fn v1_read_compatibility_rejects_mutation_and_v2_crypto_downgrade() {
        let codec =
            PayloadCodec::new("workspace".into(), WorkspaceKey::from_entropy([8; 32])).unwrap();
        let mut frame = RpcFrame {
            v: 1,
            kind: FrameKind::Request,
            id: crate::wire::new_id().unwrap(),
            source: "source".into(),
            target: "target".into(),
            operation: Operation::NodePing,
            in_reply_to: None,
            source_certificate_sha256: None,
            target_certificate_sha256: None,
            retention: None,
            payload: String::new(),
        };
        codec.encode(&mut frame, &json!({"legacy":true})).unwrap();
        assert_eq!(codec.decode::<Value>(&frame).unwrap()["legacy"], true);
        frame.operation = Operation::JobSubmit;
        frame.source_certificate_sha256 = Some("a".repeat(64));
        frame.target_certificate_sha256 = Some("b".repeat(64));
        assert!(codec.encode(&mut frame, &json!({})).is_err());
        frame.v = PROTOCOL_VERSION;
        frame.operation = Operation::NodePing;
        codec.encode(&mut frame, &json!({})).unwrap();
        frame.v = 1;
        assert!(codec.decode::<Value>(&frame).is_err());
    }
}
