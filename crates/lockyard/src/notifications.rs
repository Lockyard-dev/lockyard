// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Notification routes use the caller's credential, just like CLI and MCP calls.

use crate::agent::{
    self,
    socket::{AgentSocket, CallerCredential},
};
use lockyard_cloud_client::{Call, Client, ClientError, Transport, token_id};
use lockyard_core::Result;
use std::path::PathBuf;
use std::time::{Duration, Instant};

// A short-lived value on one call path; on Windows the named-pipe socket is larger than a
// boxed client, and boxing it would only add an allocation per notification wait.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Route {
    Agent(AgentSocket),
    Direct(Box<Client>),
}

pub(crate) fn route(
    url: &str,
    workspace: &str,
    session: &str,
    deadline: Instant,
    socket_timeout: Duration,
) -> Result<Route> {
    let left = || deadline.saturating_duration_since(Instant::now());
    let automatic_claude = lockyard_core::config::token_source_for(url, session)? == "claude";
    let token = lockyard_core::config::optional_session_token(url, session)?;
    let credential = token.as_deref().map(CallerCredential::from_token);
    if let Some(socket) = AgentSocket::connect_for_credential(
        &agent::socket_path_for(url, workspace),
        url,
        workspace,
        credential.as_ref(),
        left().min(socket_timeout),
    ) {
        // Cache requests need no network binding. Defer the sticky downgrade until
        // an authenticated cloud request proves that this name belongs to the agent key.
        return Ok(Route::Agent(socket.with_auto_claude_fallback(
            url,
            session,
            automatic_claude,
        )));
    }
    crate::open::trusted_url(url)?;
    let client = Client::for_session(url, session, Some(left()))?;
    // A proven session_name_bound may have changed the selected key. Reuse the
    // matching service's reservations and wake cursor after that downgrade too.
    let direct_credential = CallerCredential::from_client(&client);
    if credential
        .as_ref()
        .is_some_and(|key| key.id != direct_credential.id)
        && let Some(socket) = AgentSocket::connect_for_credential(
            &agent::socket_path_for(url, workspace),
            url,
            workspace,
            Some(&direct_credential),
            left().min(socket_timeout),
        )
    {
        return Ok(Route::Agent(socket));
    }
    let client = client.configure_content_encryption_with_deadline(session, left())?;
    Ok(Route::Direct(Box::new(client)))
}

/// No raw key is stored. Delivery throttles and wake cursors cannot cross credentials,
/// workspaces or servers, even when the session name and message IDs are identical.
pub(crate) fn state_dir(url: &str, workspace: &str, credential: &str) -> Result<PathBuf> {
    let identity = format!("{}\0{workspace}\0{credential}", url.trim_end_matches('/'));
    Ok(agent::state_root()?.join(format!("notifications-{}", token_id(&identity))))
}

/// A short-lived hook or mail wait owns one total budget, including retries.
pub(crate) struct DirectTransport {
    pub client: Client,
    pub deadline: Instant,
}

impl Transport for DirectTransport {
    fn call(&self, call: &Call) -> std::result::Result<serde_json::Value, ClientError> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ClientError::Transport(
                "notification deadline elapsed".into(),
            ));
        }
        let mut call = call.clone();
        let ms = left.as_millis().min(u128::from(u64::MAX)) as u64;
        call.deadline_ms = Some(call.deadline_ms.unwrap_or(ms).min(ms));
        call.attempt_timeout_ms = Some(call.attempt_timeout_ms.unwrap_or(ms).min(ms));
        self.client.call(&call)
    }
}
