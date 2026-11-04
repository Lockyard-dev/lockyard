// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Work zones. A claim is a lease on paths: nobody else can claim an overlapping path until it is
//! released or expires, so a crashed agent cannot hold a zone forever.

use crate::proto::Stamp;
use crate::{Error, Result, Store, ZonePath};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Lease of a claim unless the caller asks for another one.
pub const DEFAULT_TTL_MINUTES: i64 = 30;
/// Longest lease. A longer job renews.
pub const MAX_TTL_MINUTES: i64 = 240;

const MINUTE_MS: i64 = 60_000;

/// An active lease on paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Claim {
    pub id: i64,
    pub agent: String,
    pub note: String,
    pub paths: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

/// A requested path that another agent's claim covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub held_path: String,
    #[serde(default, alias = "claim_id", alias = "id")]
    pub claim: i64,
    #[serde(default, alias = "session", alias = "holder")]
    pub agent: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub expires_at: Stamp,
}

impl fmt::Display for Conflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is held by {}", self.path, self.agent)?;
        if !self.held_path.is_empty() {
            write!(f, " through {}", self.held_path)?;
        }
        if self.claim != 0 {
            write!(f, " (Z-{})", self.claim)?;
        }
        if !self.note.is_empty() {
            write!(f, ": {}", self.note)?;
        }
        Ok(())
    }
}

impl Store {
    /// Claims `paths` for `agent`, all of them or none.
    pub fn claim(
        &mut self,
        agent: &str,
        paths: &[ZonePath],
        note: &str,
        ttl_minutes: i64,
        now: i64,
    ) -> Result<Claim> {
        if paths.is_empty() {
            return Err(Error::Invalid("a claim needs at least one path".into()));
        }
        let lease = lease_ms(ttl_minutes)?;
        self.touch(agent, now)?;
        let transaction = self.write()?;
        transaction.execute("DELETE FROM claims WHERE expires_at <= ?1", [now])?;
        let conflicts = find_conflicts(&transaction, agent, paths, now)?;
        if !conflicts.is_empty() {
            return Err(Error::Conflict(conflicts));
        }
        let expires_at = now + lease;
        transaction.execute(
            "INSERT INTO claims (agent, note, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![agent, note, now, expires_at],
        )?;
        let id = transaction.last_insert_rowid();
        let mut unique: Vec<String> = paths.iter().map(|p| p.as_str().to_string()).collect();
        unique.sort();
        unique.dedup();
        for path in &unique {
            transaction.execute(
                "INSERT INTO claim_paths (claim_id, path) VALUES (?1, ?2)",
                params![id, path],
            )?;
        }
        transaction.commit()?;
        Ok(Claim {
            id,
            agent: agent.to_string(),
            note: note.to_string(),
            paths: unique,
            created_at: now,
            expires_at,
        })
    }

    /// Extends one active claim of `agent`, or all of them. Returns how many were extended.
    ///
    /// An expired claim stays expired: another agent may already hold those paths.
    pub fn renew(
        &mut self,
        agent: &str,
        id: Option<i64>,
        ttl_minutes: i64,
        now: i64,
    ) -> Result<usize> {
        let expires_at = now + lease_ms(ttl_minutes)?;
        self.touch(agent, now)?;
        let changed = self.conn.execute(
            "UPDATE claims SET expires_at = ?1
             WHERE agent = ?2 AND expires_at > ?3 AND (?4 IS NULL OR id = ?4)",
            params![expires_at, agent, now, id],
        )?;
        require_one(changed, id)
    }

    /// Releases one claim of `agent`, or all of them. Returns how many were released.
    pub fn release(&mut self, agent: &str, id: Option<i64>, now: i64) -> Result<usize> {
        self.touch(agent, now)?;
        let changed = self.conn.execute(
            "DELETE FROM claims WHERE agent = ?1 AND (?2 IS NULL OR id = ?2)",
            params![agent, id],
        )?;
        require_one(changed, id)
    }

    /// Every active claim, oldest first.
    pub fn claims(&self, now: i64) -> Result<Vec<Claim>> {
        let mut statement = self.conn.prepare(
            "SELECT id, agent, note, created_at, expires_at FROM claims
             WHERE expires_at > ?1 ORDER BY id",
        )?;
        let mut claims = statement
            .query_map([now], |row| {
                Ok(Claim {
                    id: row.get(0)?,
                    agent: row.get(1)?,
                    note: row.get(2)?,
                    paths: Vec::new(),
                    created_at: row.get(3)?,
                    expires_at: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut paths = self
            .conn
            .prepare("SELECT path FROM claim_paths WHERE claim_id = ?1 ORDER BY path")?;
        for claim in &mut claims {
            claim.paths = paths
                .query_map([claim.id], |row| row.get(0))?
                .collect::<rusqlite::Result<_>>()?;
        }
        Ok(claims)
    }

    /// Returns the claim that stops `agent` from touching `path`, if there is one.
    pub fn check(&self, agent: &str, path: &ZonePath, now: i64) -> Result<Option<Conflict>> {
        let mut conflicts = find_conflicts(&self.conn, agent, std::slice::from_ref(path), now)?;
        Ok((!conflicts.is_empty()).then(|| conflicts.remove(0)))
    }
}

fn find_conflicts(
    conn: &Connection,
    agent: &str,
    paths: &[ZonePath],
    now: i64,
) -> Result<Vec<Conflict>> {
    let mut statement = conn.prepare(
        "SELECT c.id, c.agent, c.note, c.expires_at, p.path
         FROM claims c JOIN claim_paths p ON p.claim_id = c.id
         WHERE c.expires_at > ?1 AND c.agent <> ?2 ORDER BY c.id, p.path",
    )?;
    let held = statement
        .query_map(params![now, agent], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut conflicts = Vec::new();
    for path in paths {
        for (claim, holder, note, expires_at, held_path) in &held {
            if path.overlaps(&ZonePath::stored(held_path.clone())) {
                conflicts.push(Conflict {
                    path: path.as_str().to_string(),
                    held_path: held_path.clone(),
                    claim: *claim,
                    agent: holder.clone(),
                    note: note.clone(),
                    expires_at: Stamp::Millis(*expires_at),
                });
            }
        }
    }
    Ok(conflicts)
}

fn lease_ms(ttl_minutes: i64) -> Result<i64> {
    if !(1..=MAX_TTL_MINUTES).contains(&ttl_minutes) {
        return Err(Error::Invalid(format!(
            "lease must be 1 to {MAX_TTL_MINUTES} minutes (got {ttl_minutes})"
        )));
    }
    Ok(ttl_minutes * MINUTE_MS)
}

fn require_one(changed: usize, id: Option<i64>) -> Result<usize> {
    match id {
        Some(id) if changed == 0 => Err(Error::NotFound(format!(
            "Z-{id} is not an active claim of this agent"
        ))),
        _ => Ok(changed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_store;

    fn path(text: &str) -> ZonePath {
        ZonePath::stored(text.into())
    }

    const TTL: i64 = 10;
    const TTL_MS: i64 = TTL * MINUTE_MS;

    #[test]
    fn an_overlapping_claim_is_refused_with_the_holder() {
        let (_dir, mut store) = test_store();
        store
            .claim("a", &[path("src")], "refactor", TTL, 0)
            .unwrap();
        let Err(Error::Conflict(conflicts)) = store.claim("b", &[path("src/x.rs")], "", TTL, 1)
        else {
            panic!("expected a conflict");
        };
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].agent, "a");
        assert_eq!(conflicts[0].held_path, "src");
        assert_eq!(conflicts[0].note, "refactor");
    }

    #[test]
    fn a_refused_claim_takes_nothing() {
        let (_dir, mut store) = test_store();
        store.claim("a", &[path("src")], "", TTL, 0).unwrap();
        let free_and_taken = [path("docs"), path("src")];
        assert!(store.claim("b", &free_and_taken, "", TTL, 1).is_err());
        assert_eq!(store.claims(1).unwrap().len(), 1);
        store.claim("c", &[path("docs")], "", TTL, 2).unwrap();
    }

    #[test]
    fn neighbours_do_not_collide_and_an_agent_never_collides_with_itself() {
        let (_dir, mut store) = test_store();
        store.claim("a", &[path("src/a")], "", TTL, 0).unwrap();
        store.claim("b", &[path("src/b")], "", TTL, 0).unwrap();
        store.claim("a", &[path("src/a/x")], "", TTL, 0).unwrap();
    }

    #[test]
    fn an_expired_claim_stops_blocking_at_its_exact_deadline() {
        let (_dir, mut store) = test_store();
        store.claim("a", &[path("src")], "", TTL, 0).unwrap();
        assert!(
            store
                .check("b", &path("src"), TTL_MS - 1)
                .unwrap()
                .is_some()
        );
        assert!(store.check("b", &path("src"), TTL_MS).unwrap().is_none());
        store.claim("b", &[path("src")], "", TTL, TTL_MS).unwrap();
    }

    #[test]
    fn renew_extends_only_a_living_claim_of_its_owner() {
        let (_dir, mut store) = test_store();
        let claim = store.claim("a", &[path("src")], "", TTL, 0).unwrap();
        assert!(matches!(
            store.renew("b", Some(claim.id), TTL, 1),
            Err(Error::NotFound(_))
        ));
        assert_eq!(store.renew("a", None, TTL, 5).unwrap(), 1);
        assert_eq!(store.claims(0).unwrap()[0].expires_at, 5 + TTL_MS);
        assert!(matches!(
            store.renew("a", Some(claim.id), TTL, 5 + TTL_MS),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn release_is_limited_to_the_owner() {
        let (_dir, mut store) = test_store();
        let claim = store.claim("a", &[path("src")], "", TTL, 0).unwrap();
        assert!(store.release("b", Some(claim.id), 1).is_err());
        assert_eq!(store.release("b", None, 1).unwrap(), 0);
        assert_eq!(store.claims(1).unwrap().len(), 1);
        assert_eq!(store.release("a", Some(claim.id), 1).unwrap(), 1);
        assert!(store.claims(1).unwrap().is_empty());
    }

    #[test]
    fn claim_paths_are_removed_with_the_claim() {
        let (_dir, mut store) = test_store();
        store.claim("a", &[path("src")], "", TTL, 0).unwrap();
        store.release("a", None, 1).unwrap();
        let left: i64 = store
            .conn
            .query_row("SELECT count(*) FROM claim_paths", [], |row| row.get(0))
            .unwrap();
        assert_eq!(left, 0);
    }

    #[test]
    fn repeated_paths_collapse() {
        let (_dir, mut store) = test_store();
        let claim = store
            .claim("a", &[path("src"), path("src")], "", TTL, 0)
            .unwrap();
        assert_eq!(claim.paths, ["src"]);
    }

    #[test]
    fn leases_are_bounded() {
        let (_dir, mut store) = test_store();
        assert!(store.claim("a", &[path("x")], "", 0, 0).is_err());
        assert!(store.claim("a", &[], "", TTL, 0).is_err());
        let longest = store.claim("a", &[path("x")], "", MAX_TTL_MINUTES, 0);
        assert!(longest.is_ok());
        assert!(
            store
                .claim("a", &[path("y")], "", MAX_TTL_MINUTES + 1, 0)
                .is_err()
        );
    }

    #[test]
    fn only_one_of_many_racing_connections_wins() {
        let (dir, _store) = test_store();
        let racers: Vec<_> = (0..16)
            .map(|index| {
                let root = dir.path().to_path_buf();
                std::thread::spawn(move || {
                    let mut store = Store::open(&root).unwrap();
                    store
                        .claim(&format!("agent-{index}"), &[path("src")], "", TTL, 0)
                        .is_ok()
                })
            })
            .collect();
        let wins = racers
            .into_iter()
            .map(|racer| racer.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(wins, 1);
    }
}
