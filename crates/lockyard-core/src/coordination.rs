// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Local board and presence records.

use crate::{Error, Result, Store};
use rusqlite::{OptionalExtension, params};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoardEntry {
    pub key: String,
    pub value: String,
    pub zone: Option<String>,
    pub expires_at: Option<i64>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Presence {
    pub agent: String,
    pub client: String,
    pub role: Option<String>,
    pub version: Option<String>,
    pub cwd: Option<String>,
    pub last_seen: i64,
    pub dnd_until: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PresenceUpdate<'a> {
    pub role: Option<&'a str>,
    pub version: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub dnd_until: Option<i64>,
}

impl Store {
    pub fn board_set(
        &mut self,
        key: &str,
        value: &str,
        zone: Option<&str>,
        ttl_minutes: Option<i64>,
        now: i64,
    ) -> Result<BoardEntry> {
        if key.trim().is_empty() || value.len() > 8192 {
            return Err(Error::Invalid(
                "board key is required and value must be at most 8 KiB".into(),
            ));
        }
        let expires = ttl_minutes.map(|ttl| now.saturating_add(ttl.saturating_mul(60_000)));
        if ttl_minutes.is_some_and(|ttl| !(1..=43_200).contains(&ttl)) {
            return Err(Error::Invalid(
                "board TTL must be between 1 and 43200 minutes".into(),
            ));
        }
        self.conn.execute("INSERT INTO board(key,value,zone,expires_at,updated_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(key) DO UPDATE SET value=excluded.value,zone=excluded.zone,expires_at=excluded.expires_at,updated_at=excluded.updated_at", params![key, value, zone, expires, now])?;
        self.board_get(key, now)?
            .ok_or_else(|| Error::NotFound(format!("board key {key:?} not found")))
    }

    pub fn board_get(&self, key: &str, now: i64) -> Result<Option<BoardEntry>> {
        self.conn.query_row("SELECT key,value,zone,expires_at,updated_at FROM board WHERE key=?1 AND (expires_at IS NULL OR expires_at>?2)", params![key, now], read_board).optional().map_err(Into::into)
    }

    pub fn board_remove(&mut self, key: &str) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM board WHERE key=?1", [key])? > 0)
    }

    pub fn board_list(&self, zone: Option<&str>, now: i64) -> Result<Vec<BoardEntry>> {
        let mut statement = self.conn.prepare("SELECT key,value,zone,expires_at,updated_at FROM board WHERE (expires_at IS NULL OR expires_at>?1) AND (?2 IS NULL OR zone=?2) ORDER BY key")?;
        let rows = statement.query_map(params![now, zone], read_board)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn heartbeat(
        &mut self,
        agent: &str,
        client: &str,
        update: PresenceUpdate<'_>,
        now: i64,
    ) -> Result<()> {
        crate::validate_agent(agent)?;
        if client.trim().is_empty() {
            return Err(Error::Invalid("client name is required".into()));
        }
        self.conn.execute("INSERT INTO presence(agent,client,role,version,cwd,last_seen,dnd_until) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(agent) DO UPDATE SET client=excluded.client,role=excluded.role,version=excluded.version,cwd=excluded.cwd,last_seen=excluded.last_seen,dnd_until=excluded.dnd_until", params![agent, client, update.role, update.version, update.cwd, now, update.dnd_until])?;
        Ok(())
    }

    pub fn presence(&self, active_within_seconds: i64, now: i64) -> Result<Vec<Presence>> {
        if active_within_seconds < 0 {
            return Err(Error::Invalid("active_within must not be negative".into()));
        }
        let cutoff = now.saturating_sub(active_within_seconds.saturating_mul(1000));
        let mut statement = self.conn.prepare("SELECT agent,client,role,version,cwd,last_seen,dnd_until FROM presence WHERE last_seen>=?1 ORDER BY last_seen DESC,agent")?;
        let rows = statement.query_map([cutoff], |row| {
            Ok(Presence {
                agent: row.get(0)?,
                client: row.get(1)?,
                role: row.get(2)?,
                version: row.get(3)?,
                cwd: row.get(4)?,
                last_seen: row.get(5)?,
                dnd_until: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

fn read_board(row: &rusqlite::Row<'_>) -> rusqlite::Result<BoardEntry> {
    Ok(BoardEntry {
        key: row.get(0)?,
        value: row.get(1)?,
        zone: row.get(2)?,
        expires_at: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_store;

    #[test]
    fn board_values_update_filter_expire_and_delete() {
        let (_dir, mut store) = test_store();
        store
            .board_set("deploy", "ready", Some("src"), Some(1), 0)
            .unwrap();
        assert_eq!(
            store.board_get("deploy", 1).unwrap().unwrap().value,
            "ready"
        );
        assert_eq!(store.board_list(Some("docs"), 1).unwrap().len(), 0);
        assert_eq!(store.board_list(Some("src"), 1).unwrap().len(), 1);
        assert!(store.board_get("deploy", 60_000).unwrap().is_none());
        assert!(store.board_remove("deploy").unwrap());
    }

    #[test]
    fn presence_refreshes_session_and_filters_inactive_entries() {
        let (_dir, mut store) = test_store();
        store
            .heartbeat(
                "worker",
                "cli",
                PresenceUpdate {
                    role: Some("agent"),
                    cwd: Some("/repo"),
                    ..PresenceUpdate::default()
                },
                100,
            )
            .unwrap();
        store
            .heartbeat("worker", "mcp", PresenceUpdate::default(), 500)
            .unwrap();
        assert_eq!(store.presence(1, 1000).unwrap()[0].client, "mcp");
        assert!(store.presence(0, 1000).unwrap().is_empty());
    }
}
