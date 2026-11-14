// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Shared presence + claim activity used by CLI `keepalive` and MCP `keepalive`.
//! Does not extend claim leases; callers that need more time must use `zone_renew`.

use lockyard_core::proto::{
    ActivityRequest, Claim, ClaimQuery, PresenceBeat, SessionActivity, SessionState,
};
use lockyard_core::{Backend, Error, Result};
use serde_json::{Value, json};

/// Refresh presence and touch activity on the selected claim(s). Does not renew TTL.
pub(crate) fn keepalive(
    backend: &mut dyn Backend,
    agent: &str,
    id: Option<i64>,
    all: bool,
    client: &str,
    now: i64,
) -> Result<Value> {
    let beat = PresenceBeat {
        client: client.into(),
        version: Some(lockyard_core::VERSION.to_string()),
        activity: Some(SessionActivity {
            tool_running: false,
            tool_started_at: None,
            state: Some(SessionState::Working),
            meta: None,
        }),
        ..PresenceBeat::default()
    };
    backend.heartbeat(agent, &beat, now)?;
    let claims = backend.claims(
        &ClaimQuery {
            session: Some(agent.to_string()),
            path: None,
        },
        now,
    )?;
    let selected = select_claims(claims, id, all)?;
    let mut touched = Vec::new();
    for claim in &selected {
        let request = ActivityRequest {
            write: false,
            paths: claim.paths.clone(),
            fence: Some(claim.fence),
        };
        backend.activity(agent, claim.id, &request)?;
        touched.push(claim.id);
    }
    Ok(json!({"presence": true, "activity": touched}))
}

fn select_claims(claims: Vec<Claim>, id: Option<i64>, all: bool) -> Result<Vec<Claim>> {
    let selected: Vec<_> = if let Some(id) = id {
        claims.into_iter().filter(|claim| claim.id == id).collect()
    } else if all {
        if claims.is_empty() {
            return Err(Error::Invalid("no claims of yours".into()));
        }
        claims
    } else if claims.len() == 1 {
        claims
    } else if claims.is_empty() {
        return Err(Error::Invalid("no claims of yours".into()));
    } else {
        return Err(Error::Invalid("multiple claims: pass an id or all".into()));
    };
    if selected.is_empty() {
        return Err(Error::NotFound(
            "claim is not yours or does not exist".into(),
        ));
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_with_zero_claims_says_none_of_yours() {
        let error = select_claims(Vec::new(), None, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no claims of yours"), "{error}");
    }
}
