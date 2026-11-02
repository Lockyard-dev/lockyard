// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Core of Lockyard: work zones, a message bus and tasks, all in one SQLite file under `.lockyard/`.
//!
//! Every write is one immediate transaction, so concurrent agents on one machine see a single order of
//! events. Time is passed in as milliseconds since the epoch, which keeps leases testable.

pub mod bus;
pub mod coordination;
pub mod config;
mod error;
pub mod paths;
mod store;
pub mod tasks;
pub mod zones;

pub use error::{Error, Result};
pub use paths::ZonePath;
pub use store::{Agent, DIR_NAME, Store, validate_agent};

/// Storage boundary used by command, hook, MCP and cloud adapters.
///
/// Keeping this interface in core lets callers select a backend without depending on SQLite.
pub trait Backend {
    fn touch_agent(&self, agent: &str, now: i64) -> Result<()>;
    fn agents(&self) -> Result<Vec<Agent>>;
    fn claim(&mut self, agent: &str, paths: &[ZonePath], note: &str, ttl: i64, now: i64) -> Result<zones::Claim>;
    fn renew(&mut self, agent: &str, id: Option<i64>, ttl: i64, now: i64) -> Result<usize>;
    fn release(&mut self, agent: &str, id: Option<i64>, now: i64) -> Result<usize>;
    fn claims(&self, now: i64) -> Result<Vec<zones::Claim>>;
    fn check(&self, agent: &str, path: &ZonePath, now: i64) -> Result<Option<zones::Conflict>>;
    fn send(&mut self, from: &str, to: &str, body: &str, now: i64) -> Result<bus::Message>;
    fn reply(&mut self, agent: &str, id: i64, body: &str, now: i64) -> Result<bus::Message>;
    fn inbox(&mut self, agent: &str, all: bool, mark_read: bool, limit: usize, now: i64) -> Result<Vec<bus::Message>>;
    fn unread(&self, agent: &str) -> Result<i64>;
    fn tasks(&self, status: Option<tasks::Status>, include_final: bool) -> Result<Vec<tasks::Task>>;
    fn task(&self, id: i64) -> Result<tasks::Task>;
    fn task_history(&self, id: i64) -> Result<Vec<tasks::TaskEvent>>;
    fn add_task(&mut self, author: &str, title: &str, body: &str, now: i64) -> Result<tasks::Task>;
    fn claim_task(&mut self, agent: &str, id: i64, ttl: i64, now: i64) -> Result<tasks::Task>;
    fn renew_task(&mut self, agent: &str, id: i64, ttl: i64, now: i64) -> Result<tasks::Task>;
    fn release_task(&mut self, agent: &str, id: i64, note: &str, now: i64) -> Result<tasks::Task>;
    fn submit_task(&mut self, agent: &str, id: i64, evidence: &str, now: i64) -> Result<tasks::Task>;
    fn accept_task(&mut self, agent: &str, id: i64, note: &str, now: i64) -> Result<tasks::Task>;
    fn reject_task(&mut self, agent: &str, id: i64, reason: &str, now: i64) -> Result<tasks::Task>;
    fn cancel_task(&mut self, agent: &str, id: i64, note: &str, now: i64) -> Result<tasks::Task>;
    fn board_set(&mut self, key: &str, value: &str, zone: Option<&str>, ttl_minutes: Option<i64>, now: i64) -> Result<coordination::BoardEntry>;
    fn board_get(&self, key: &str, now: i64) -> Result<Option<coordination::BoardEntry>>;
    fn board_remove(&mut self, key: &str) -> Result<bool>;
    fn board_list(&self, zone: Option<&str>, now: i64) -> Result<Vec<coordination::BoardEntry>>;
    fn heartbeat(&mut self, agent: &str, client: &str, update: coordination::PresenceUpdate<'_>, now: i64) -> Result<()>;
    fn presence(&self, active_within_seconds: i64, now: i64) -> Result<Vec<coordination::Presence>>;
}

impl Backend for Store {
    fn touch_agent(&self, agent: &str, now: i64) -> Result<()> { self.touch(agent, now) }
    fn agents(&self) -> Result<Vec<Agent>> { Store::agents(self) }
    fn claim(&mut self, agent: &str, paths: &[ZonePath], note: &str, ttl: i64, now: i64) -> Result<zones::Claim> { Store::claim(self, agent, paths, note, ttl, now) }
    fn renew(&mut self, agent: &str, id: Option<i64>, ttl: i64, now: i64) -> Result<usize> { Store::renew(self, agent, id, ttl, now) }
    fn release(&mut self, agent: &str, id: Option<i64>, now: i64) -> Result<usize> { Store::release(self, agent, id, now) }
    fn claims(&self, now: i64) -> Result<Vec<zones::Claim>> { Store::claims(self, now) }
    fn check(&self, agent: &str, path: &ZonePath, now: i64) -> Result<Option<zones::Conflict>> { Store::check(self, agent, path, now) }
    fn send(&mut self, from: &str, to: &str, body: &str, now: i64) -> Result<bus::Message> { Store::send(self, from, to, body, now) }
    fn reply(&mut self, agent: &str, id: i64, body: &str, now: i64) -> Result<bus::Message> { Store::reply(self, agent, id, body, now) }
    fn inbox(&mut self, agent: &str, all: bool, mark_read: bool, limit: usize, now: i64) -> Result<Vec<bus::Message>> { Store::inbox(self, agent, all, mark_read, limit, now) }
    fn unread(&self, agent: &str) -> Result<i64> { Store::unread(self, agent) }
    fn tasks(&self, status: Option<tasks::Status>, include_final: bool) -> Result<Vec<tasks::Task>> { Store::tasks(self, status, include_final) }
    fn task(&self, id: i64) -> Result<tasks::Task> { Store::task(self, id) }
    fn task_history(&self, id: i64) -> Result<Vec<tasks::TaskEvent>> { Store::task_history(self, id) }
    fn add_task(&mut self, author: &str, title: &str, body: &str, now: i64) -> Result<tasks::Task> { Store::add_task(self, author, title, body, now) }
    fn claim_task(&mut self, agent: &str, id: i64, ttl: i64, now: i64) -> Result<tasks::Task> { Store::claim_task(self, agent, id, ttl, now) }
    fn renew_task(&mut self, agent: &str, id: i64, ttl: i64, now: i64) -> Result<tasks::Task> { Store::renew_task(self, agent, id, ttl, now) }
    fn release_task(&mut self, agent: &str, id: i64, note: &str, now: i64) -> Result<tasks::Task> { Store::release_task(self, agent, id, note, now) }
    fn submit_task(&mut self, agent: &str, id: i64, evidence: &str, now: i64) -> Result<tasks::Task> { Store::submit_task(self, agent, id, evidence, now) }
    fn accept_task(&mut self, agent: &str, id: i64, note: &str, now: i64) -> Result<tasks::Task> { Store::accept_task(self, agent, id, note, now) }
    fn reject_task(&mut self, agent: &str, id: i64, reason: &str, now: i64) -> Result<tasks::Task> { Store::reject_task(self, agent, id, reason, now) }
    fn cancel_task(&mut self, agent: &str, id: i64, note: &str, now: i64) -> Result<tasks::Task> { Store::cancel_task(self, agent, id, note, now) }
    fn board_set(&mut self, key: &str, value: &str, zone: Option<&str>, ttl_minutes: Option<i64>, now: i64) -> Result<coordination::BoardEntry> { Store::board_set(self, key, value, zone, ttl_minutes, now) }
    fn board_get(&self, key: &str, now: i64) -> Result<Option<coordination::BoardEntry>> { Store::board_get(self, key, now) }
    fn board_remove(&mut self, key: &str) -> Result<bool> { Store::board_remove(self, key) }
    fn board_list(&self, zone: Option<&str>, now: i64) -> Result<Vec<coordination::BoardEntry>> { Store::board_list(self, zone, now) }
    fn heartbeat(&mut self, agent: &str, client: &str, update: coordination::PresenceUpdate<'_>, now: i64) -> Result<()> { Store::heartbeat(self, agent, client, update, now) }
    fn presence(&self, active_within_seconds: i64, now: i64) -> Result<Vec<coordination::Presence>> { Store::presence(self, active_within_seconds, now) }
}

/// Version of this build.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Home of the project.
pub const HOMEPAGE: &str = "https://lockyard.dev";

/// One line about the product.
pub const SUMMARY: &str = "Coordination for coding agents: a shared bus, work zones and tasks.";

/// Text of `lockyard about`.
pub fn about() -> String {
    format!("Lockyard {VERSION}\n{SUMMARY}\n{HOMEPAGE}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn about_names_the_version_and_the_homepage() {
        let text = about();
        assert!(text.contains(VERSION));
        assert!(text.contains(HOMEPAGE));
    }
}
