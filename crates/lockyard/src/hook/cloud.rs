// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

use super::{Moment, Port, Tool, Verdict};
use crate::agent::socket::AgentSocket;
use crate::agent::wire::{Phase, Request};
use lockyard_cloud_client::Call;
use lockyard_core::proto::{CheckStatus, Event, Message};
use lockyard_core::{Error, Result};
use serde_json::json;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The agent's own limit is 800 ms. This one only catches a stuck process.
const SOCKET_TIMEOUT: Duration = Duration::from_millis(1200);

pub struct AgentPort {
    pub socket: AgentSocket,
    pub root: PathBuf,
    pub tool: Tool,
    pub repository: Option<String>,
    pub repository_confirmed: bool,
}

/// Connects to the agent. `None` when none is running for this workspace.
pub fn connect(url: &str, workspace: &str, root: PathBuf, tool: Tool) -> Option<AgentPort> {
    let socket =
        AgentSocket::connect(&crate::agent::socket_path(), url, workspace, SOCKET_TIMEOUT)?;
    let repository = lockyard_core::config::Config::load(&root).ok()?.repository;
    Some(AgentPort {
        socket,
        root,
        tool,
        repository,
        repository_confirmed: false,
    })
}

fn failed(error: io::Error) -> Error {
    Error::Unavailable(format!("agent socket: {error}"))
}

impl Port for AgentPort {
    fn root(&self) -> &Path {
        &self.root
    }

    fn check(&mut self, agent: &str, path: &str, _now: i64) -> Result<Verdict> {
        if let Some(repository) = self
            .repository
            .as_deref()
            .filter(|_| !self.repository_confirmed)
        {
            let root = lockyard_core::repository::qualify(Some(repository), ".")?;
            let mut call = Call::get(
                agent,
                format!(
                    "/api/v1/zones/claims?path={}&namespace_probe=1",
                    lockyard_cloud_client::encode(&root)
                ),
            );
            call.repository = Some(repository.to_string());
            call.deadline_ms = Some(800);
            let reply = self.socket.ask(&Request::Call { call }).map_err(failed)?;
            let confirmed = reply.error.is_none()
                && reply.value.as_ref().is_some_and(|value| {
                    value["repository_namespace_supported"] == true
                        && value["repository"] == repository
                });
            if !confirmed {
                return Ok(Verdict::Unknown);
            }
            self.repository_confirmed = true;
        }
        let request = Request::Check {
            session: agent.to_string(),
            paths: vec![lockyard_core::repository::qualify(
                self.repository.as_deref(),
                path,
            )?],
        };
        let reply = self.socket.ask(&request).map_err(failed)?;
        let found = reply
            .checks
            .and_then(|mut checks| (!checks.is_empty()).then(|| checks.remove(0)));
        Ok(match found {
            Some(check) if check.status == CheckStatus::Held => match check.holder {
                Some(mut holder) => {
                    holder.path = lockyard_core::repository::relative(
                        self.repository.as_deref(),
                        &holder.path,
                    )
                    .unwrap_or(&holder.path)
                    .to_string();
                    holder.held_path = lockyard_core::repository::relative(
                        self.repository.as_deref(),
                        &holder.held_path,
                    )
                    .unwrap_or(&holder.held_path)
                    .to_string();
                    Verdict::Held(Box::new(holder))
                }
                None => Verdict::Unknown,
            },
            Some(check) if check.status == CheckStatus::Unknown => Verdict::Unknown,
            Some(_) => Verdict::Free,
            None => Verdict::Unknown,
        })
    }

    fn unread(&mut self, agent: &str) -> Result<Option<i64>> {
        let reply = self
            .socket
            .ask(&Request::Unread {
                session: agent.to_string(),
            })
            .map_err(failed)?;
        Ok(reply.unread)
    }

    fn take_mail(&mut self, agent: &str, limit: usize, _now: i64) -> Result<Option<Vec<Message>>> {
        let request = Request::TakeMail {
            session: agent.to_string(),
            limit,
            lease_seconds: super::DELIVERY_LEASE_SECONDS,
        };
        Ok(self.socket.ask(&request).map_err(failed)?.messages)
    }

    fn mark_seen(&mut self, agent: &str, ids: &[i64], _now: i64) -> Result<()> {
        let call = Call::write(
            agent,
            "POST",
            "/api/v1/bus/inbox/seen".into(),
            json!({"ids": ids}),
        );
        let reply = self.socket.ask(&Request::Call { call }).map_err(failed)?;
        match reply.error {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    fn take_events(&mut self, agent: &str) -> Result<Option<Vec<Event>>> {
        let reply = self
            .socket
            .ask(&Request::TakeEvents {
                session: agent.to_string(),
            })
            .map_err(failed)?;
        match reply.error {
            Some(error) => Err(error.into()),
            None => Ok(reply.events),
        }
    }

    fn ack_events(&mut self, agent: &str, through: i64) -> Result<()> {
        let reply = self
            .socket
            .ask(&Request::AckEvents {
                session: agent.to_string(),
                through,
            })
            .map_err(failed)?;
        match reply.error {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    fn report(&mut self, agent: &str, moment: Moment, written: Vec<String>) {
        let phase = match moment {
            Moment::Before => Phase::Pre,
            Moment::After => Phase::Post,
            Moment::Prompt => Phase::Prompt,
            Moment::End => Phase::End,
        };
        let request = Request::Touch {
            session: agent.to_string(),
            client: self.tool.name().to_string(),
            phase,
            write_paths: written
                .into_iter()
                .filter_map(|path| {
                    lockyard_core::repository::qualify(self.repository.as_deref(), &path).ok()
                })
                .collect(),
        };
        // Told, not asked: the hook does not wait for the agent's disk.
        if let Err(error) = self.socket.tell(&request) {
            eprintln!("lockyard hook: {}", failed(error));
        }
    }
}
