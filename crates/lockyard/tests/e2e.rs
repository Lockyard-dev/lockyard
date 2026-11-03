// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Drives the real binary, as several agents, against a real server.
//!
//! It runs only with `LOCKYARD_E2E_URL`, and it fails rather than skips when
//! `LOCKYARD_E2E_REQUIRED=1`. Public CI has no server, so plain `CI=true` does not ask for it. It also needs
//! `LOCKYARD_E2E_OWNER_TOKEN`, the bootstrap token of that server, and `LOCKYARD_E2E_SERVER`, a shell
//! command that runs the server in the foreground on the same database: the suite starts and stops it
//! to make outages. Scenarios run one after another because a freeze and an outage reach everybody.

#![cfg(unix)]

use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BINARY: &str = env!("CARGO_BIN_EXE_lockyard");
/// A view older than this is not trusted by the agent process.
const VIEW_LIMIT: Duration = Duration::from_secs(30);

struct Out {
    code: i32,
    out: String,
    err: String,
}

impl Out {
    fn ok(self) -> Value {
        assert_eq!(self.code, 0, "stdout: {}\nstderr: {}", self.out, self.err);
        serde_json::from_str(&self.out).unwrap_or(Value::Null)
    }

    fn refused(self, code: i32, text: &str) {
        assert_eq!(
            self.code, code,
            "stdout: {}\nstderr: {}",
            self.out, self.err
        );
        let lower = self.err.to_lowercase();
        assert!(
            lower.contains(&text.to_lowercase()),
            "{text:?} not in {}",
            self.err
        );
    }
}

fn collect(output: std::process::Output) -> Out {
    Out {
        code: output.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&output.stdout).into_owned(),
        err: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[derive(Clone)]
struct Who {
    name: String,
    token: String,
}

/// One machine: a project folder, a home, and its own agent socket and state.
struct Machine {
    project: tempfile::TempDir,
    runtime: tempfile::TempDir,
    url: String,
    agent: Mutex<Option<Child>>,
}

impl Machine {
    fn new(url: &str) -> Self {
        // A socket path is limited to about 100 bytes, so this cannot sit in a long temp folder.
        let runtime = tempfile::Builder::new()
            .prefix("ly")
            .tempdir_in("/tmp")
            .unwrap();
        let project = tempfile::Builder::new()
            .prefix("ly")
            .tempdir_in("/tmp")
            .unwrap();
        fs::create_dir_all(project.path().join(".lockyard")).unwrap();
        fs::write(
            project.path().join(".lockyard/config.toml"),
            format!("mode = \"cloud\"\nurl = \"{url}\"\nworkspace = \"e2e\"\n"),
        )
        .unwrap();
        Self {
            project,
            runtime,
            url: url.to_string(),
            agent: Mutex::new(None),
        }
    }

    fn dir(&self) -> PathBuf {
        fs::canonicalize(self.project.path()).unwrap()
    }

    fn command(&self, token: Option<&str>) -> Command {
        let mut command = Command::new(BINARY);
        let run = self.runtime.path();
        command
            .current_dir(self.dir())
            .env_clear()
            .env("HOME", run)
            .env("PATH", "/usr/bin:/bin")
            .env("XDG_RUNTIME_DIR", run.join("run"))
            .env("XDG_STATE_HOME", run.join("state"))
            .env("LOCKYARD_URL", &self.url)
            .stdin(Stdio::null());
        if let Some(token) = token {
            command.env("LOCKYARD_TOKEN", token);
        }
        command
    }

    fn start_agent(&self, who: &Who) {
        fs::create_dir_all(self.runtime.path().join("run")).unwrap();
        let child = self
            .command(Some(&who.token))
            .arg("agent")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        *self.agent.lock().unwrap() = Some(child);
        wait_for("the agent socket", Duration::from_secs(5), || {
            self.agent_status(who).is_some()
        });
    }

    fn stop_agent(&self) {
        if let Some(mut child) = self.agent.lock().unwrap().take() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }

    fn agent_status(&self, who: &Who) -> Option<Value> {
        let output = self
            .command(Some(&who.token))
            .args(["--json", "agent", "status"])
            .output()
            .unwrap();
        let answer: Value = serde_json::from_slice(&output.stdout).ok()?;
        answer["running"]
            .as_bool()?
            .then(|| answer["status"].clone())
    }

    /// Runs one hook the way a tool runs it: no token, no agent name, only the socket.
    fn hook(&self, tool: &str, event: &Value) -> Out {
        let mut child = self
            .command(None)
            .args(["hook", tool])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(event.to_string().as_bytes()).unwrap();
        drop(stdin);
        collect(child.wait_with_output().unwrap())
    }

    /// A hook whose output goes nowhere: it reserves mail and dies before anyone reads it.
    fn hook_nobody_reads(&self, event: &Value) -> Out {
        let mut child = self
            .command(None)
            .args(["hook", "claude"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(event.to_string().as_bytes()).unwrap();
        drop(stdin);
        collect(child.wait_with_output().unwrap())
    }

    fn edit_event(&self, session: &str, path: &str) -> Value {
        json!({
            "hook_event_name": "PreToolUse", "session_id": session, "tool_name": "Edit",
            "cwd": self.dir(), "tool_input": {"file_path": self.dir().join(path)},
        })
    }

    fn prompt_event(&self, session: &str) -> Value {
        json!({"hook_event_name": "UserPromptSubmit", "session_id": session, "cwd": self.dir()})
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        self.stop_agent();
    }
}

fn wait_for(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < limit, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(100));
    }
}

struct Server {
    url: String,
    command: String,
    child: Mutex<Option<Child>>,
}

impl Server {
    fn healthy(&self) -> bool {
        let address = self.url.trim_start_matches("http://");
        let Some(found) = address
            .to_socket_addrs()
            .ok()
            .and_then(|mut all| all.next())
        else {
            return false;
        };
        let Ok(mut stream) = TcpStream::connect_timeout(&found, Duration::from_secs(1)) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        let asked = format!("GET /health HTTP/1.0\r\nHost: {address}\r\n\r\n");
        if stream.write_all(asked.as_bytes()).is_err() {
            return false;
        }
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        answer.starts_with("HTTP/1.1 200")
    }

    fn start(&self) {
        assert!(!self.healthy(), "stop the server first: the suite runs it");
        let child = Command::new("/bin/sh")
            .args(["-c", &format!("exec {}", self.command)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        *self.child.lock().unwrap() = Some(child);
        wait_for("the server", Duration::from_secs(60), || self.healthy());
    }

    fn stop(&self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        wait_for("the server to stop", Duration::from_secs(10), || {
            !self.healthy()
        });
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

type Scenario = (&'static str, fn(&World));

struct World {
    run: String,
    server: Server,
    box_a: Machine,
    box_b: Machine,
    owner: Who,
    lead: String,
    agent: String,
    exporter: String,
    importer: String,
    dispatcher: String,
    ran: Mutex<Vec<Vec<String>>>,
    tools: Mutex<HashSet<String>>,
}

impl World {
    /// A session or a path unique to this run, so a run can repeat on one database.
    fn name(&self, base: &str) -> String {
        format!("{base}-{}", self.run)
    }

    fn who(&self, base: &str, token: &str) -> Who {
        Who {
            name: self.name(base),
            token: token.to_string(),
        }
    }

    fn a(&self, base: &str) -> Who {
        self.who(base, &self.agent)
    }

    fn lead(&self, base: &str) -> Who {
        self.who(base, &self.lead)
    }

    fn on(&self, machine: &Machine, who: &Who, args: &[&str]) -> Out {
        self.ran
            .lock()
            .unwrap()
            .push(args.iter().map(|word| (*word).to_string()).collect());
        collect(
            machine
                .command(Some(&who.token))
                .arg("--json")
                .args(["--agent", &who.name])
                .args(args)
                .output()
                .unwrap(),
        )
    }

    fn ly(&self, who: &Who, args: &[&str]) -> Out {
        self.on(&self.box_a, who, args)
    }

    /// Like `on`, with text on standard input, for commands that read a confirmation or a phrase.
    fn on_input(&self, machine: &Machine, who: &Who, args: &[&str], input: &str) -> Out {
        self.ran
            .lock()
            .unwrap()
            .push(args.iter().map(|word| (*word).to_string()).collect());
        let mut child = machine
            .command(Some(&who.token))
            .arg("--json")
            .args(["--agent", &who.name])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        collect(child.wait_with_output().unwrap())
    }

    fn beat(&self, who: &Who) {
        self.ly(who, &["presence", "beat"]).ok();
    }

    fn id(&self, value: &Value) -> String {
        value["id"].as_i64().expect("an id").to_string()
    }

    fn claim(&self, who: &Who, path: &str) -> Value {
        self.ly(who, &["zone", "claim", path, "--note", "e2e"]).ok()
    }

    fn holders(&self, viewer: &Who, path: &str) -> Vec<String> {
        let found = self.ly(viewer, &["zone", "list", "--path", path]).ok();
        found
            .as_array()
            .unwrap()
            .iter()
            .map(|claim| claim["agent"].as_str().unwrap().to_string())
            .collect()
    }

    fn inbox_bodies(&self, who: &Who) -> Vec<String> {
        let mail = self.ly(who, &["msg", "inbox", "--peek"]).ok();
        mail.as_array()
            .unwrap()
            .iter()
            .map(|message| message["body"].as_str().unwrap().to_string())
            .filter(|body| !body.starts_with("to everyone"))
            .collect()
    }

    fn last_seq(&self, who: &Who, stream: &str) -> i64 {
        let mut after = 0;
        loop {
            let page = self
                .ly(
                    who,
                    &["events", "--stream", stream, "--after", &after.to_string()],
                )
                .ok();
            let rows = page.as_array().unwrap();
            match rows.last() {
                Some(last) => after = last["seq"].as_i64().unwrap(),
                None => return after,
            }
        }
    }
}

fn tokens(w: &mut World) {
    let root = w.owner.clone();
    let make = |role: &str| {
        let made = w
            .ly(
                &root,
                &[
                    "cloud", "token", "create", role, "--role", role, "--days", "1",
                ],
            )
            .ok();
        assert_eq!(made["token"]["role"], role);
        made["raw"].as_str().expect("the raw token").to_string()
    };
    let (lead, agent) = (make("lead"), make("agent"));
    let (exporter, importer, dispatcher) = (make("exporter"), make("importer"), make("dispatcher"));
    let doomed = make("agent");
    (w.lead, w.agent) = (lead, agent);
    (w.exporter, w.importer, w.dispatcher) = (exporter, importer, dispatcher);

    let listed = w.ly(&root, &["cloud", "token", "list"]).ok();
    let rows = listed.as_array().unwrap();
    assert!(rows.len() >= 6);
    assert!(rows.iter().all(|row| row.get("raw").is_none()), "{listed}");
    let lead = w.lead("lead");
    w.ly(&lead, &["cloud", "token", "list"]).refused(1, "");
    w.ly(&lead, &["cloud", "token", "create", "x", "--role", "agent"])
        .refused(1, "owner");

    let victim = Who {
        name: w.name("victim"),
        token: doomed,
    };
    w.ly(&victim, &["presence", "list"]).ok();
    let id = rows.last().unwrap()["id"].as_str().unwrap().to_string();
    let revoked = w.ly(&root, &["cloud", "token", "revoke", &id]).ok();
    assert!(revoked["revoked_at"].is_string());
    w.ly(&victim, &["presence", "list"]).refused(1, "token");
}

fn zones(w: &World) {
    let (one, two) = (w.a("one"), w.a("two"));
    w.beat(&one);
    w.beat(&two);
    let path = w.name("src");
    let file = format!("{path}/a.rs");
    let first = w.claim(&one, &path);
    let id = w.id(&first);
    let fence = first["fence"].as_i64().unwrap();
    assert!(fence > 0);

    // Conflict, with the holder named for the second agent.
    let out = w.ly(&two, &["zone", "claim", &file]);
    assert_eq!(out.code, 3, "{}", out.err);
    assert!(
        out.err.contains(&one.name) && out.err.contains(&file),
        "{}",
        out.err
    );
    assert!(out.err.contains(&format!("Z-{id}")), "{}", out.err);
    let held = w.ly(&two, &["zone", "check", &file]);
    assert_eq!(held.code, 3);
    assert!(held.err.contains(&one.name), "{}", held.err);
    assert_eq!(w.ly(&one, &["zone", "check", &file]).ok()["own"], true);
    assert_eq!(
        w.ly(&two, &["zone", "check", &w.name("elsewhere")]).ok()["free"],
        true
    );
    assert_eq!(w.holders(&two, &file), std::slice::from_ref(&one.name));

    // Growing, shrinking, renewing, and a fence that has gone stale.
    let extra = w.name("docs");
    let grown = w.ly(&one, &["zone", "add-path", &id, &extra]).ok();
    assert_eq!(grown["paths"].as_array().unwrap().len(), 2);
    let fence = grown["fence"].as_i64().unwrap();
    assert_eq!(w.holders(&two, &extra), std::slice::from_ref(&one.name));
    let narrowed = w.ly(&one, &["zone", "narrow", &id, &path]).ok();
    assert_eq!(narrowed["paths"], json!([path]));
    assert!(w.holders(&two, &extra).is_empty());
    w.ly(&one, &["zone", "renew", &id, "--fence", "999999"])
        .refused(1, "stale");
    let fence_text = fence.to_string();
    let renewed = w
        .ly(
            &one,
            &["zone", "renew", &id, "--ttl", "40", "--fence", &fence_text],
        )
        .ok();
    assert_eq!(renewed["renewed"], 1);
    w.ly(&one, &["zone", "activity", &id, &file, "--write"])
        .ok();
    let listed = w.ly(&two, &["zone", "list", "--session", &one.name]).ok();
    assert!(listed[0]["last_write_at"].is_string(), "{listed}");

    // Queue and grant: the second agent sees the claim become its own.
    let entry = w.ly(&two, &["zone", "queue", &path, "--note", "next"]).ok();
    assert_eq!(entry["granted"], Value::Null);
    let queued = w.ly(&two, &["zone", "queue"]).ok();
    let mine = queued.as_array().unwrap();
    assert!(
        mine.iter().any(|row| row["paths"] == json!([path])),
        "{queued}"
    );
    w.ly(&one, &["zone", "release", &id, "--note", "done"]).ok();
    assert_eq!(w.holders(&one, &path), std::slice::from_ref(&two.name));
    let granted = w.ly(&two, &["zone", "list", "--session", &two.name]).ok();
    assert!(granted[0]["fence"].as_i64().unwrap() > fence, "{granted}");
    let grant = w.id(&granted[0]);

    // A queue entry can be left.
    let third = w.a("three");
    w.beat(&third);
    let left = w.ly(&third, &["zone", "queue", &path]).ok();
    w.ly(&third, &["zone", "unwait", &w.id(&left)]).ok();
    assert_eq!(w.ly(&third, &["zone", "queue"]).ok(), json!([]));

    // A request reaches the holder, and the answer reaches the asker.
    let asked = w
        .ly(
            &third,
            &["zone", "request", &file, "--text", "may I", "--urgent"],
        )
        .ok();
    let seen = w.ly(&two, &["events", "--type", "zone.requested"]).ok();
    let rows = seen.as_array().unwrap();
    assert!(
        rows.iter().any(|row| row["payload"]["id"] == asked["id"]),
        "{seen}"
    );
    let waiting = w.ly(&third, &["zone", "requests"]).ok();
    assert!(
        waiting
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == asked["id"]),
        "{waiting}"
    );
    w.ly(&two, &["zone", "answer", &w.id(&asked), "--reply", "soon"])
        .ok();
    let told = w.ly(&third, &["events", "--type", "zone.answered"]).ok();
    let rows = told.as_array().unwrap();
    assert!(
        rows.iter().any(|row| row["payload"]["reply"] == "soon"),
        "{told}"
    );

    // A short wait is granted while it waits.
    thread::scope(|scope| {
        let waiter = scope.spawn(|| w.ly(&third, &["zone", "wait", &path, "--seconds", "20"]));
        thread::sleep(Duration::from_secs(2));
        w.ly(&two, &["zone", "release", &grant]).ok();
        let claim = waiter.join().unwrap().ok();
        assert_eq!(claim["agent"], json!(third.name));
        w.ly(&third, &["zone", "release", &w.id(&claim)]).ok();
    });

    handover_and_takeover(w, &one, &two);
    styles(w, &one, &two);
}

fn handover_and_takeover(w: &World, one: &Who, two: &Who) {
    let path = w.name("hand");
    let claim = w.claim(one, &path);
    let id = w.id(&claim);
    let old = claim["fence"].as_i64().unwrap().to_string();
    w.ly(
        one,
        &["zone", "handover", &id, "--to", &two.name, "--fence", &old],
    )
    .ok();
    let taken = w.ly(two, &["zone", "accept", &id]).ok();
    assert_eq!(taken["agent"], json!(two.name));
    assert_eq!(taken["return_to"], json!(one.name));
    assert!(taken["fence"].as_i64() > claim["fence"].as_i64());
    w.ly(one, &["zone", "renew", &id]).refused(1, "holder");
    w.ly(two, &["zone", "renew", &id, "--fence", &old])
        .refused(1, "stale");
    // Released, it returns to the live original owner.
    w.ly(two, &["zone", "release", &id]).ok();
    assert_eq!(w.holders(two, &path), std::slice::from_ref(&one.name));
    w.ly(one, &["zone", "release", &id]).ok();
    assert!(w.holders(two, &path).is_empty());

    let (lead, gone) = (w.lead("takeover-lead"), w.a("gone"));
    w.beat(&gone);
    let id = w.id(&w.claim(&gone, &path));
    w.ly(&lead, &["zone", "takeover", &id, "--reason", "stuck"])
        .refused(3, "heartbeat");
    w.ly(one, &["zone", "takeover", &id, "--reason", "stuck"])
        .refused(1, "role");
    w.ly(&gone, &["presence", "beat", "--state", "ended"]).ok();
    let taken = w
        .ly(&lead, &["zone", "takeover", &id, "--reason", "stuck"])
        .ok();
    assert_eq!(taken["agent"], json!(lead.name));
    let lost = w.ly(&gone, &["zone", "lost"]).ok();
    assert_eq!(lost[0]["claim_id"].to_string(), id);
    assert_eq!(lost[0]["reason"], "stuck");
    w.ly(&lead, &["zone", "release"]).ok();
}

fn styles(w: &World, one: &Who, two: &Who) {
    let path = w.name("shared");
    w.ly(one, &["zone", "claim", &path, "--shared"]).ok();
    w.ly(two, &["zone", "claim", &path, "--shared"]).ok();
    assert_eq!(w.holders(one, &path).len(), 2);
    w.ly(one, &["zone", "release"]).ok();
    w.ly(two, &["zone", "release"]).ok();
    let lazy = w
        .ly(
            one,
            &[
                "zone",
                "claim",
                "--lazy",
                "--deploy",
                "--meta",
                r#"{"change":"abc"}"#,
            ],
        )
        .ok();
    assert_eq!(lazy["purpose"], "deploy");
    assert_eq!(lazy["meta"]["change"], "abc");
    assert_eq!(lazy["paths"], json!([]));
    w.ly(one, &["zone", "add-path", &w.id(&lazy), &path]).ok();
    assert_eq!(w.holders(two, &path), std::slice::from_ref(&one.name));
    let queued = w.ly(
        two,
        &[
            "zone",
            "add-path",
            &w.id(&w.claim(two, &w.name("own"))),
            &path,
        ],
    );
    assert_eq!(queued.code, 3, "{}", queued.err);
    assert!(queued.err.contains(&one.name), "{}", queued.err);
    w.ly(one, &["zone", "release"]).ok();
    w.ly(two, &["zone", "release"]).ok();
}

fn dirty(w: &World) {
    let (one, two) = (w.a("dirty-one"), w.a("dirty-two"));
    w.beat(&one);
    w.beat(&two);
    let path = w.name("mess");
    let file = format!("{path}/left.rs");
    let id = w.id(&w.claim(&one, &path));
    w.ly(
        &one,
        &["zone", "dirty", "report", &file, "--reason", "half done"],
    )
    .ok();
    let listed = w.ly(&two, &["zone", "dirty", "list", &file]).ok();
    assert_eq!(listed[0]["owner_session"], json!(one.name));
    w.ly(&one, &["zone", "release", &id, "--leave-dirty"]).ok();

    // The next holder is told whose dirt lies in the zone.
    let next = w.claim(&two, &path);
    let foreign = next["foreign_dirty_paths"]
        .as_array()
        .expect("foreign paths");
    assert_eq!(foreign[0]["path"], json!(file));
    assert_eq!(foreign[0]["owner_session"], json!(one.name));
    w.ly(
        &two,
        &["zone", "dirty", "adopt", &file, "--reason", "mine now"],
    )
    .refused(3, "live owner");
    w.ly(&two, &["zone", "dirty", "disown", &file])
        .refused(1, "owner");
    w.ly(&one, &["presence", "beat", "--state", "ended"]).ok();
    w.ly(
        &two,
        &["zone", "dirty", "adopt", &file, "--reason", "mine now"],
    )
    .ok();
    let listed = w.ly(&one, &["zone", "dirty", "list", &file]).ok();
    assert_eq!(listed[0]["owner_session"], json!(two.name));
    w.ly(&two, &["zone", "dirty", "disown", &file]).ok();
    let listed = w.ly(&one, &["zone", "dirty", "list", &file]).ok();
    assert_eq!(listed[0]["owner_session"], Value::Null);
    w.ly(&two, &["zone", "release", &w.id(&next), "--leave-dirty"])
        .ok();
}

fn mail(w: &World) {
    let (one, two) = (w.a("mail-one"), w.a("mail-two"));
    w.beat(&one);
    w.beat(&two);
    w.ly(&one, &["msg", "send", &w.name("nobody"), "x"])
        .refused(1, "");
    let sent = w
        .ly(&one, &["msg", "send", &two.name, "hello", "--needs", "ack"])
        .ok();
    assert_eq!(w.ly(&two, &["msg", "unread"]).ok()["unread"], 1);
    assert_eq!(w.inbox_bodies(&two), ["hello"], "peek marks nothing");
    let read = w.ly(&two, &["msg", "inbox"]).ok();
    assert_eq!(read[0]["from"], json!(one.name));
    assert_eq!(read[0]["needs"], "ack");
    assert_eq!(w.ly(&two, &["msg", "unread"]).ok()["unread"], 0);
    assert!(w.inbox_bodies(&two).is_empty());
    let all = w.ly(&two, &["msg", "inbox", "--all", "--peek"]).ok();
    assert_eq!(all.as_array().unwrap().len(), 1);

    let id = w.id(&sent);
    let reply = w.ly(&two, &["msg", "reply", &id, "got it"]).ok();
    assert_eq!(reply["reply_to"].to_string(), id);
    assert_eq!(w.inbox_bodies(&one), ["got it"]);
    let thread = w.ly(&one, &["msg", "thread", &id]).ok();
    assert_eq!(thread.as_array().unwrap().len(), 2);
    w.ly(&two, &["msg", "ack", &id]).ok();
    let events = w.ly(&one, &["events", "--type", "bus.ack"]).ok();
    assert_eq!(events[0]["payload"]["id"].to_string(), id);
    assert_eq!(w.ly(&one, &["msg", "overdue"]).ok(), json!([]));

    let key = w.name("key");
    let first = w
        .ly(&one, &["msg", "send", &two.name, "keyed", "--key", &key])
        .ok();
    let again = w
        .ly(&one, &["msg", "send", &two.name, "keyed", "--key", &key])
        .ok();
    assert_eq!(again["id"], first["id"]);
    assert_eq!(again["deduplicated"], true);
    let other = w.ly(&one, &["msg", "send", &two.name, "changed", "--key", &key]);
    assert_eq!(other.code, 3, "{}", other.err);

    let everyone = w.name("to everyone");
    let others = w.a("mail-three");
    w.beat(&others);
    w.ly(
        &one,
        &[
            "msg", "send", "*", &everyone, "--kind", "notice", "--ttl", "30",
        ],
    )
    .ok();
    let broadcast = w.ly(&others, &["msg", "inbox", "--peek"]).ok();
    assert_eq!(broadcast[0]["body"], json!(everyone), "{broadcast}");
    let late = w.ly(&w.lead("mail-lead"), &["msg", "undelivered"]).ok();
    let rows = late.as_array().unwrap();
    assert!(
        rows.iter().any(|row| row["to"] == json!(two.name)),
        "{late}"
    );
    w.ly(&one, &["msg", "undelivered"]).refused(1, "role");
}

/// Real pressure on the machine running the suite decides the level, so only the shape is checked here.
/// The behaviour of the guard is proven with fake samples and real process groups in its own tests.
fn machine(w: &World) {
    let reader = w.a("machine-reader");
    let report = w.ly(&reader, &["machine"]).ok();
    assert!(report["level"].is_string(), "{report}");
    assert!(
        report["sample"]["memory_total"].as_u64().unwrap() > 0,
        "{report}"
    );
    w.ly(&reader, &["run", "--", "/bin/echo", "x"])
        .refused(1, "--heavy");
}

fn board(w: &World) {
    let (lead, reader) = (w.lead("board-lead"), w.a("board-reader"));
    let key = w.name("key");
    w.ly(&reader, &["board", "set", &key, "v"])
        .refused(1, "role");
    w.ly(&lead, &["board", "set", &key, "v1", "--zone", "api"])
        .ok();
    assert_eq!(w.ly(&reader, &["board", "get", &key]).ok()["value"], "v1");
    let listed = w.ly(&reader, &["board", "list", "--zone", "api"]).ok();
    let rows = listed.as_array().unwrap();
    assert!(rows.iter().any(|row| row["key"] == json!(key)), "{listed}");
    assert_eq!(w.ly(&lead, &["board", "rm", &key]).ok()["removed"], true);
    w.ly(&reader, &["board", "get", &key])
        .refused(1, "not found");
    assert_eq!(w.ly(&lead, &["board", "rm", &key]).ok()["removed"], false);
}

fn work(w: &World) {
    let (lead, one, two) = (w.lead("work-lead"), w.a("work-one"), w.a("work-two"));
    let offer = |to: &str| {
        w.ly(
            &lead,
            &[
                "work",
                "offer",
                "build it",
                "--to",
                to,
                "--accept",
                "tests pass",
            ],
        )
        .ok()
    };
    w.ly(&one, &["work", "offer", "t", "--to", "*", "--accept", "a"])
        .refused(1, "role");

    let task = offer(&one.name);
    let id = w.id(&task);
    assert_eq!(task["status"], "offered");
    assert_eq!(w.ly(&one, &["work", "show", &id]).ok()["title"], "build it");
    let listed = w.ly(&two, &["work", "list"]).ok();
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == task["id"])
    );
    w.ly(&two, &["work", "claim", &id]).refused(1, "addressee");
    let claimed = w.ly(&one, &["work", "claim", &id]).ok();
    assert_eq!(claimed["assignee"], json!(one.name));
    w.ly(&one, &["work", "beat", &id, "--if-version", "1"])
        .refused(3, "version");
    w.ly(&one, &["work", "beat", &id]).ok();
    let done = w
        .ly(
            &one,
            &[
                "work",
                "done",
                &id,
                "--report",
                "all green",
                "--commit",
                "abc",
            ],
        )
        .ok();
    assert_eq!(done["status"], "review");
    assert_eq!(done["commits"], json!(["abc"]));
    let back = w
        .ly(&lead, &["work", "reject", &id, "--reason", "no tests"])
        .ok();
    assert_eq!(
        (back["status"].as_str(), back["reason"].as_str()),
        (Some("claimed"), Some("no tests"))
    );
    w.ly(&one, &["work", "handoff", &id, "--to", &two.name])
        .ok();
    let seen = w.ly(&two, &["work", "show", &id]).ok();
    assert_eq!(seen["status"], "offered");
    let version = seen["version"].to_string();
    assert_eq!(
        w.ly(&two, &["work", "take", &id, "--if-version", &version])
            .ok()["assignee"],
        json!(two.name)
    );
    w.ly(&two, &["work", "done", &id]).ok();
    assert_eq!(
        w.ly(&lead, &["work", "accept", &id]).ok()["status"],
        "accepted"
    );
    assert_eq!(
        w.ly(&one, &["work", "show", &id]).ok()["status"],
        "accepted"
    );

    let refused = w.id(&offer(&one.name));
    let declined = w
        .ly(&one, &["work", "decline", &refused, "--reason", "busy"])
        .ok();
    assert_eq!(declined["status"], "cancelled");
    assert!(declined["declined_at"].is_string());
    assert_eq!(declined["reason"], "busy");
    let failed = w.id(&offer(&one.name));
    w.ly(&one, &["work", "claim", &failed]).ok();
    assert_eq!(
        w.ly(&one, &["work", "fail", &failed, "--reason", "broken"])
            .ok()["status"],
        "failed"
    );
    let cancelled = w.id(&offer("*"));
    assert_eq!(
        w.ly(&lead, &["work", "cancel", &cancelled]).ok()["status"],
        "cancelled"
    );

    // The lead vanishes during a review: the owner or a dispatcher finishes it, not anyone else.
    w.beat(&lead);
    let stranded = w.id(&offer(&one.name));
    w.ly(&one, &["work", "claim", &stranded]).ok();
    w.ly(&one, &["work", "done", &stranded]).ok();
    let boss = Who {
        name: w.name("boss"),
        token: w.owner.token.clone(),
    };
    let router = w.who("router", &w.dispatcher);
    w.ly(&boss, &["work", "accept", &stranded])
        .refused(1, "live");
    w.ly(&lead, &["presence", "beat", "--state", "ended"]).ok();
    w.ly(&one, &["work", "accept", &stranded])
        .refused(1, "role");
    let back = w
        .ly(&router, &["work", "reject", &stranded, "--reason", "redo"])
        .ok();
    assert_eq!(back["status"], "claimed");
    w.ly(&one, &["work", "done", &stranded]).ok();
    assert_eq!(
        w.ly(&boss, &["work", "accept", &stranded]).ok()["status"],
        "accepted"
    );
    assert_eq!(
        w.ly(&one, &["work", "show", &stranded]).ok()["status"],
        "accepted"
    );
    w.beat(&lead);
}

fn tasks(w: &World) {
    let (lead, one, two) = (w.lead("task-lead"), w.a("task-one"), w.a("task-two"));
    let area = w.name("area");
    w.ly(&lead, &["task", "add", "seed"]).ok();
    let added = w
        .ly(
            &one,
            &[
                "task",
                "add",
                "Rate limit login",
                "--body",
                "details",
                "--priority",
                "P1",
            ],
        )
        .ok();
    assert_eq!(added["status"], "open");
    assert_eq!(added["priority"], "P1");
    assert_eq!(added["author"], json!(one.name));
    let id = w.id(&added);

    // The agent sets urgency itself, and P0 needs its category and evidence.
    w.ly(&one, &["task", "add", "x", "--priority", "P0"])
        .refused(1, "");
    let urgent = w
        .ly(
            &one,
            &[
                "task",
                "add",
                "down",
                "--priority",
                "P0",
                "--p0-category",
                "prod_outage",
                "--evidence",
                "probe 1",
            ],
        )
        .ok();
    assert_eq!(urgent["priority"], "P0");
    let planned = w.ly(&one, &["task", "plan", &id, "--priority", "P3"]).ok();
    assert_eq!(planned["priority"], "P3");
    w.ly(&one, &["task", "add", "x", "--area", &area])
        .refused(1, "no area");

    let open = w.ly(&two, &["task", "list", "--status", "open"]).ok();
    assert!(
        open.as_array()
            .unwrap()
            .iter()
            .any(|task| task["id"] == added["id"]),
        "{open}"
    );
    let claimed = w.ly(&two, &["task", "claim", &id]).ok();
    assert_eq!(
        (claimed["status"].as_str(), claimed["assignee"].as_str()),
        (Some("claimed"), Some(two.name.as_str()))
    );
    w.ly(&one, &["task", "claim", &id]).refused(1, "ready");
    w.ly(&two, &["task", "renew", &id]).ok();
    assert_eq!(w.ly(&two, &["task", "release", &id]).ok()["status"], "open");
    w.ly(&two, &["task", "claim", &id]).ok();
    let submitted = w
        .ly(&two, &["task", "submit", &id, "--evidence", "abc123"])
        .ok();
    assert_eq!(submitted["status"], "review");
    assert_eq!(submitted["evidence"], "abc123");
    w.ly(&two, &["task", "accept", &id]).refused(1, "");
    assert_eq!(
        w.ly(&lead, &["task", "reject", &id, "--reason", "no test"])
            .ok()["status"],
        "open"
    );
    w.ly(&one, &["task", "claim", &id]).ok();
    w.ly(&one, &["task", "submit", &id, "--evidence", "def456"])
        .ok();
    assert_eq!(
        w.ly(&lead, &["task", "accept", &id, "--note", "good"]).ok()["status"],
        "accepted"
    );
    let shown = w.ly(&two, &["task", "show", &id]).ok();
    assert_eq!(shown["task"]["status"], "accepted");
    let actions: Vec<&str> = shown["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["action"].as_str().unwrap())
        .collect();
    assert!(
        actions.contains(&"created") && actions.contains(&"claimed"),
        "{actions:?}"
    );
    assert_eq!(
        shown["history"].as_array().unwrap().last().unwrap()["note"],
        "good"
    );

    let doomed = w.ly(&one, &["task", "add", "not needed"]).ok();
    let doomed_id = w.id(&doomed);
    w.ly(&one, &["task", "cancel", &doomed_id]).refused(1, "");
    assert_eq!(
        w.ly(&lead, &["task", "cancel", &doomed_id, "--note", "no"])
            .ok()["status"],
        "cancelled"
    );
    let unfinished = w.ly(&two, &["task", "list"]).ok();
    assert!(
        !unfinished
            .as_array()
            .unwrap()
            .iter()
            .any(|task| task["id"] == doomed["id"])
    );
    let everything = w.ly(&two, &["task", "list", "--all"]).ok();
    assert!(
        everything
            .as_array()
            .unwrap()
            .iter()
            .any(|task| task["id"] == doomed["id"])
    );
    let status = w.ly(&two, &["status"]).ok();
    assert!(
        status["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|task| task["id"] == urgent["id"]),
        "{status}"
    );
}

fn streams(w: &World) {
    let (one, two) = (w.a("stream-one"), w.a("stream-two"));
    let after = w.last_seq(&one, "coordination").to_string();
    let path = w.name("polled");
    let start = Instant::now();
    thread::scope(|scope| {
        let poll = scope.spawn(|| {
            w.ly(
                &one,
                &[
                    "events",
                    "--after",
                    &after,
                    "--wait",
                    "15",
                    "--type",
                    "zone.claimed",
                ],
            )
        });
        thread::sleep(Duration::from_secs(2));
        w.claim(&two, &path);
        let page = poll.join().unwrap().ok();
        assert!(
            start.elapsed() >= Duration::from_secs(2),
            "the poll did not wait"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the poll missed the event"
        );
        assert_eq!(page[0]["payload"]["paths"], json!([path]));
    });
    let idle = Instant::now();
    let last = w.last_seq(&one, "coordination").to_string();
    assert_eq!(
        w.ly(&one, &["events", "--after", &last, "--wait", "1"])
            .ok(),
        json!([])
    );
    assert!(idle.elapsed() >= Duration::from_secs(1));

    // The registry has its own stream and its own sequence.
    let after = w.last_seq(&one, "registry").to_string();
    thread::scope(|scope| {
        let poll = scope.spawn(|| {
            w.ly(
                &one,
                &[
                    "events", "--stream", "registry", "--after", &after, "--wait", "15",
                ],
            )
        });
        thread::sleep(Duration::from_secs(2));
        let item = w.ly(&two, &["task", "add", "streamed"]).ok();
        let page = poll.join().unwrap().ok();
        assert_eq!(page[0]["type"], "created", "{page}");
        assert_eq!(page[0]["item_id"], json!(format!("D-{}", item["id"])));
        assert!(page[0]["seq"].as_i64().unwrap() > after.parse::<i64>().unwrap());
    });
    w.ly(&two, &["zone", "release"]).ok();
}

fn hooks(w: &World) {
    let (one, two) = (w.a("hook-one"), w.a("hook-two"));
    w.beat(&one);
    w.beat(&two);
    let machine = &w.box_b;
    machine.start_agent(&two);
    let status = machine.agent_status(&two).unwrap();
    assert_eq!(status["outbox"], 0);
    w.ran.lock().unwrap().push(vec!["agent".into()]);
    w.ran
        .lock()
        .unwrap()
        .push(vec!["agent".into(), "status".into()]);
    let path = w.name("hooked");
    let file = format!("{path}/a.rs");
    let event = machine.edit_event(&two.name, &file);

    // Free at first.
    assert_eq!(machine.hook("claude", &event).out, "");
    // The first agent claims from another machine, and the zone event reaches this process quickly.
    let claim = w.claim(&one, &path);
    let denied = Instant::now();
    wait_for(
        "a denial from the fresh view",
        Duration::from_secs(4),
        || machine.hook("claude", &event).out.contains("\"deny\""),
    );
    println!("denied after {:?}", denied.elapsed());
    let answer = machine.hook("claude", &event);
    assert!(answer.out.contains(&one.name), "{}", answer.out);
    w.on(machine, &two, &["zone", "check", &file])
        .refused(3, &one.name);
    wait_for("a clean view", Duration::from_secs(5), || {
        machine.agent_status(&two).unwrap()["view_fresh"] == true
    });

    // Fresh view: the server stops, and the answer still comes from memory.
    w.server.stop();
    assert!(machine.hook("claude", &event).out.contains("\"deny\""));
    let local = Instant::now();
    w.on(machine, &two, &["zone", "check", &file])
        .refused(3, &one.name);
    assert!(
        local.elapsed() < Duration::from_millis(600),
        "{:?}",
        local.elapsed()
    );

    // Stale view: memory is no longer trusted, the server cannot answer, so the state is unknown.
    wait_for(
        "the view to go stale",
        VIEW_LIMIT + Duration::from_secs(5),
        || machine.agent_status(&two).unwrap()["view_fresh"] == false,
    );
    let stale = machine.hook("claude", &event);
    assert_eq!(stale.code, 0);
    assert_eq!(stale.out, "", "an unknown state allows the edit");
    assert!(stale.err.contains("unknown"), "{}", stale.err);
    let unknown = w.on(machine, &two, &["zone", "check", &file]);
    assert_eq!(unknown.code, 4, "{}", unknown.err);
    assert!(unknown.out.contains("unknown"), "{}", unknown.out);

    w.server.start();
    wait_for("the denial to come back", Duration::from_secs(10), || {
        machine.hook("claude", &event).out.contains("\"deny\"")
    });
    w.ly(&one, &["zone", "release", &w.id(&claim)]).ok();
    wait_for("the edit to be free again", Duration::from_secs(4), || {
        machine.hook("claude", &event).out.is_empty()
    });

    // Two-phase mail: a reader that dies keeps the mail unread but holds the lease.
    let unread = |who: &Who| {
        w.ly(who, &["msg", "unread"]).ok()["unread"]
            .as_i64()
            .unwrap()
    };
    let waiting = unread(&two) + 1;
    w.ly(&one, &["msg", "send", &two.name, "two phase"]).ok();
    let prompt = machine.prompt_event(&two.name);
    wait_for("the unread count", Duration::from_secs(20), || {
        let dead = machine.hook_nobody_reads(&prompt);
        dead.err.contains("Broken pipe") || dead.err.contains("broken pipe")
    });
    assert_eq!(unread(&two), waiting, "nobody saw it");
    let mut second = None;
    wait_for("the active delivery lease", Duration::from_secs(5), || {
        let answer = machine.hook("claude", &prompt);
        if unread(&two) == waiting && !answer.out.contains("two phase") {
            second = Some(answer);
            true
        } else {
            false
        }
    });
    let second = second.expect("the lease check ran");
    assert!(
        !second.out.contains("two phase"),
        "the lease holds: {}",
        second.out
    );
    assert_eq!(unread(&two), waiting);

    let (mail, other) = (w.a("hook-reader"), w.a("hook-sender"));
    w.beat(&mail);
    w.ly(&other, &["msg", "send", &mail.name, "once only"]).ok();
    let prompt = machine.prompt_event(&mail.name);
    let mut rounds = Vec::new();
    wait_for(
        "the mail buffer before concurrent hooks",
        Duration::from_secs(20),
        || {
            let pair = thread::scope(|scope| {
                let left = scope.spawn(|| machine.hook("claude", &prompt));
                let right = scope.spawn(|| machine.hook("codex", &prompt));
                (left.join().unwrap(), right.join().unwrap())
            });
            let found = pair.0.out.contains("once only") || pair.1.out.contains("once only");
            rounds.extend([pair.0, pair.1]);
            found
        },
    );
    let count = rounds
        .iter()
        .filter(|hook| hook.out.contains("once only"))
        .count();
    assert_eq!(
        count,
        1,
        "{:?}",
        rounds.iter().map(|hook| &hook.out).collect::<Vec<_>>()
    );
    wait_for("the mail to be marked", Duration::from_secs(5), || {
        w.ly(&mail, &["msg", "unread"]).ok()["unread"] == 0
    });

    // Cursor spells the same event another way.
    let cursor = json!({
        "hook_event_name": "PreToolUse", "conversation_id": two.name, "tool_name": "Edit",
        "workspace_roots": [machine.dir()], "file_path": machine.dir().join(&file),
    });
    let claim = w.claim(&one, &path);
    wait_for("a denial for cursor", Duration::from_secs(4), || {
        machine.hook("cursor", &cursor).out.contains("\"deny\"")
    });
    w.ly(&one, &["zone", "release", &w.id(&claim)]).ok();
    machine.stop_agent();
}

fn outage(w: &World) {
    let (one, two) = (w.a("out-one"), w.a("out-two"));
    w.beat(&one);
    w.beat(&two);
    let machine = &w.box_b;
    machine.start_agent(&one);
    let path = w.name("outage");
    let tag = w.name("beat-client");
    w.server.stop();

    let sent: Vec<String> = (0..3).map(|n| format!("queued {n}")).collect();
    for body in &sent {
        let answer = w.on(machine, &one, &["msg", "send", &two.name, body]).ok();
        assert_eq!(answer["queued"], true, "{answer}");
    }
    let beat = w
        .on(machine, &one, &["presence", "beat", "--client", &tag])
        .ok();
    assert_eq!(beat["beat"], true);
    w.on(machine, &one, &["zone", "claim", &path])
        .refused(1, "");
    let waiting = machine.agent_status(&one).unwrap();
    assert_eq!(waiting["outbox"], 4, "{waiting}");

    // The outbox is on disk: a new process takes over the same entries.
    machine.stop_agent();
    machine.start_agent(&one);
    assert_eq!(machine.agent_status(&one).unwrap()["outbox"], 4);

    w.server.start();
    wait_for("the outbox to drain", Duration::from_secs(30), || {
        machine.agent_status(&one).unwrap()["outbox"] == 0
    });
    assert_eq!(w.inbox_bodies(&two), sent, "each lands once and in order");
    let live = w
        .ly(&two, &["presence", "list", "--active-within", "120"])
        .ok();
    let rows = live.as_array().unwrap();
    let row = rows
        .iter()
        .find(|row| row["agent"] == json!(one.name))
        .expect("the heartbeat");
    assert_eq!(row["client"], json!(tag));
    assert!(row["version"].is_string(), "{row}");
    assert!(
        w.holders(&two, &path).is_empty(),
        "the claim did not land later"
    );
    thread::sleep(Duration::from_secs(1));
    assert!(w.holders(&two, &path).is_empty());
    machine.stop_agent();
}

fn another_token_goes_around_the_agent(w: &World) {
    let (one, lead) = (w.a("around"), w.lead("around-lead"));
    let machine = &w.box_b;
    machine.start_agent(&one);
    // Through the agent this would carry the agent token and be refused.
    let key = w.name("around");
    w.on(machine, &lead, &["board", "set", &key, "v"]).ok();
    w.on(machine, &lead, &["board", "rm", &key]).ok();
    machine.stop_agent();
}

fn freeze(w: &World) {
    let (one, two) = (w.a("freeze-one"), w.a("freeze-two"));
    let boss = w.owner.clone();
    let exporter = w.who("export", &w.exporter);
    let path = w.name("frozen");
    w.beat(&two);
    let claim = w.claim(&one, &path);
    w.ly(&one, &["msg", "send", &two.name, "in the dump"]).ok();

    let dump = w.ly(&exporter, &["cloud", "export"]).ok();
    let claims = dump["claims"].as_array().unwrap();
    assert!(claims.iter().any(|row| row["id"] == claim["id"]), "{dump}");
    assert!(
        dump["threads"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["body"] == "in the dump")
    );
    w.ly(&one, &["cloud", "export"]).refused(1, "role");
    w.ly(&one, &["cloud", "freeze", "on", "--reason", "cutover"])
        .refused(1, "role");

    w.ly(&boss, &["cloud", "freeze", "on", "--reason", "cutover"])
        .ok();
    w.ly(&two, &["zone", "claim", &w.name("later")])
        .refused(1, "frozen");
    w.ly(&one, &["msg", "send", &two.name, "while frozen"])
        .refused(1, "frozen");
    assert_eq!(
        w.holders(&two, &path),
        std::slice::from_ref(&one.name),
        "reads go on"
    );
    assert!(!w.inbox_bodies(&two).contains(&"while frozen".to_string()));
    w.ly(&boss, &["cloud", "freeze", "off"]).ok();
    let later = w.claim(&two, &w.name("later"));
    w.ly(&two, &["zone", "release", &w.id(&later)]).ok();
    w.ly(&one, &["zone", "release"]).ok();
}

fn import(w: &World) {
    let one = w.a("import-one");
    w.beat(&one);
    let importer = w.who("importer", &w.importer);
    let dir = w.box_a.dir();
    let (api, web) = (w.name("api"), w.name("web"));
    let catalog = dir.join("catalog.json");
    let zone = w.name("zone-api");
    let group = w.name("group-all");
    fs::write(
        &catalog,
        json!({
            "zones": {zone.clone(): [api.clone()], "web": {"paths": [web.clone()]}},
            "groups": {group.clone(): [zone.clone(), "web"]},
        })
        .to_string(),
    )
    .unwrap();
    let registry = dir.join("registry.json");
    fs::write(&registry, json!({"items": []}).to_string()).unwrap();
    let registry = registry.to_str().unwrap();
    w.ly(&one, &["cloud", "import-registry", registry])
        .refused(1, "importer");
    w.ly(&importer, &["cloud", "import-registry", registry])
        .refused(1, "1 to 1000 items");
    let file = catalog.to_str().unwrap();
    w.ly(&one, &["cloud", "import-zones", file])
        .refused(1, "role");
    assert_eq!(
        w.ly(&importer, &["cloud", "import-zones", file]).ok()["stored"],
        true
    );
    let shown = w.ly(&one, &["zone", "catalog"]).ok();
    assert_eq!(shown["zones"][&zone], json!([api]));
    let claim = w.ly(&one, &["zone", "claim", "--zone", &group]).ok();
    assert_eq!(claim["paths"], json!([api, web]));
    w.ly(&one, &["zone", "release", &w.id(&claim)]).ok();

    let legacy = w.name("legacy");
    let bus = dir.join("bus.json");
    fs::write(
        &bus,
        json!({
            "threads": [{"legacy_id": legacy, "body": "from the old bus", "to": one.name, "kind": "ask"}],
            "board": [{"legacy_id": legacy, "key": legacy, "value": "old"}],
            "tasks": [{"legacy_id": legacy, "title": "old work", "to": one.name, "accept": "a"}],
        })
        .to_string(),
    )
    .unwrap();
    let file = bus.to_str().unwrap();
    let first = w.ly(&importer, &["cloud", "import-bus", file]).ok();
    assert_eq!(first, json!({"threads": 1, "board": 1, "tasks": 1}));
    let second = w.ly(&importer, &["cloud", "import-bus", file]).ok();
    assert_eq!(
        second,
        json!({"threads": 0, "board": 0, "tasks": 0}),
        "idempotent by legacy_id"
    );
    assert!(
        w.inbox_bodies(&one)
            .contains(&"from the old bus".to_string())
    );
    assert_eq!(w.ly(&one, &["board", "get", &legacy]).ok()["value"], "old");
    let tasks = w.ly(&one, &["work", "list"]).ok();
    assert!(
        tasks
            .as_array()
            .unwrap()
            .iter()
            .any(|task| task["title"] == "old work"),
        "{tasks}"
    );
}

fn plain(w: &World) {
    let one = w.a("plain");
    assert!(w.ly(&one, &["cloud", "trust", &w.server.url]).ok()["trusted"].is_string());
    w.beat(&one);
    let who = w.ly(&one, &["who"]).ok();
    assert!(
        who.as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == json!(one.name)),
        "{who}"
    );
    assert!(w.ly(&one, &["about"]).ok()["version"].is_string());
    for client in ["claude", "codex", "cursor"] {
        assert!(w.ly(&one, &["setup", client]).ok()["setup"].is_string());
    }
    let status = w.ly(&one, &["status"]).ok();
    assert!(status["unread"].is_number(), "{status}");
    let fresh = tempfile::tempdir().unwrap();
    let made = Command::new(BINARY)
        .current_dir(fresh.path())
        .args(["init"])
        .output()
        .unwrap();
    assert!(made.status.success());
    assert!(fresh.path().join(".lockyard").is_dir());
    w.ran.lock().unwrap().push(vec!["init".into()]);
    for tool in ["claude", "codex", "cursor"] {
        w.ran.lock().unwrap().push(vec!["hook".into(), tool.into()]);
    }
    w.ran.lock().unwrap().push(vec!["mcp".into()]);
}

struct Mcp<'a> {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next: i64,
    world: &'a World,
}

impl<'a> Mcp<'a> {
    fn start(world: &'a World, who: &Who) -> Self {
        let mut child = world
            .box_a
            .command(Some(&who.token))
            .env("LOCKYARD_AGENT", &who.name)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let (stdin, stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next: 1,
            world,
        }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next += 1;
        let request =
            json!({"jsonrpc": "2.0", "id": self.next, "method": method, "params": params});
        writeln!(self.stdin, "{request}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let answer: Value = serde_json::from_str(&line).unwrap();
        assert!(answer.get("error").is_none(), "{answer}");
        answer["result"].clone()
    }

    fn raw(&mut self, name: &str, arguments: Value) -> (bool, String) {
        self.world.tools.lock().unwrap().insert(name.to_string());
        let result = self.rpc("tools/call", json!({"name": name, "arguments": arguments}));
        let text = result["content"][0]["text"].as_str().unwrap().to_string();
        (result["isError"] == true, text)
    }

    fn ok(&mut self, name: &str, arguments: Value) -> Value {
        let (failed, text) = self.raw(name, arguments);
        assert!(!failed, "{name}: {text}");
        let body = text
            .split_once('\n')
            .map_or(text.as_str(), |(first, rest)| {
                if first.starts_with("Mail from") {
                    rest
                } else {
                    text.as_str()
                }
            });
        serde_json::from_str(body).unwrap_or_else(|_| panic!("{name}: {text}"))
    }

    fn refused(&mut self, name: &str, arguments: Value, text: &str) {
        let (failed, answer) = self.raw(name, arguments);
        assert!(failed, "{name} should fail: {answer}");
        assert!(answer.to_lowercase().contains(text), "{name}: {answer}");
    }
}

impl Drop for Mcp<'_> {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn mcp(w: &World) {
    let (one, two, lead) = (w.a("mcp-one"), w.a("mcp-two"), w.lead("mcp-lead"));
    let (mut a, mut b, mut l) = (
        Mcp::start(w, &one),
        Mcp::start(w, &two),
        Mcp::start(w, &lead),
    );
    assert_eq!(a.rpc("ping", json!({})), json!({}));
    a.ok(
        "presence_beat",
        json!({"client": "mcp", "state": "working"}),
    );
    b.ok("presence_beat", json!({"tool_running": true}));
    l.ok("presence_beat", json!({"meta": {"pid": 1}}));
    let live = b.ok("presence", json!({"active_within": 60}));
    assert!(
        live.as_array()
            .unwrap()
            .iter()
            .any(|row| row["agent"] == json!(one.name))
    );
    assert!(
        a.ok("who", json!({}))
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == json!(two.name))
    );

    let path = w.name("mcp");
    let file = format!("{path}/f");
    let claim = a.ok(
        "zone_claim",
        json!({"paths": [path], "note": "n", "ttl": 20}),
    );
    let id = claim["id"].clone();
    assert_eq!(w.holders(&two, &file), std::slice::from_ref(&one.name));
    b.refused("zone_check", json!({"path": file}), &one.name);
    b.refused("zone_claim", json!({"paths": [file]}), &one.name);
    assert_eq!(a.ok("zone_check", json!({"path": file}))["free"], true);
    assert_eq!(
        a.ok("zone_list", json!({"session": one.name}))
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let other = w.name("mcp-other");
    let grown = a.ok("zone_add_path", json!({"id": id, "path": other}));
    assert_eq!(grown["paths"].as_array().unwrap().len(), 2);
    let narrowed = a.ok("zone_narrow", json!({"id": id, "paths": [path]}));
    assert_eq!(narrowed["paths"], json!([path]));
    assert_eq!(
        a.ok("zone_renew", json!({"id": id, "ttl": 30}))["renewed"],
        1
    );
    a.ok(
        "zone_activity",
        json!({"id": id, "write": true, "paths": [file]}),
    );
    let entry = b.ok("zone_queue", json!({"paths": [path]}));
    assert_eq!(b.ok("zone_queue", json!({})).as_array().unwrap().len(), 1);
    assert_eq!(
        b.ok("zone_unwait", json!({"id": entry["id"]}))["cancelled"],
        entry["id"]
    );
    let asked = b.ok("zone_request", json!({"paths": [file], "text": "please"}));
    let answered = a.ok("zone_answer", json!({"id": asked["id"], "reply": "ok"}));
    assert_eq!(answered["reply"], "ok");
    a.ok("zone_dirty", json!({"paths": [file], "reason": "wip"}));
    assert_eq!(
        b.ok("zone_dirty_list", json!({"path": file}))[0]["owner_session"],
        json!(one.name)
    );
    a.ok("zone_dirty_disown", json!({"paths": [file]}));
    b.ok(
        "zone_dirty_adopt",
        json!({"paths": [file], "reason": "mine"}),
    );
    assert_eq!(
        a.ok("zone_dirty_list", json!({"path": file}))[0]["owner_session"],
        json!(two.name)
    );
    b.ok("zone_dirty_disown", json!({"paths": [file]}));
    a.ok("zone_handover", json!({"id": id, "to": two.name}));
    assert_eq!(
        b.ok("zone_accept", json!({"id": id}))["agent"],
        json!(two.name)
    );
    assert_eq!(
        b.ok("zone_release", json!({"id": id, "leave_dirty": true}))["released"],
        1
    );
    assert_eq!(a.ok("zone_release", json!({}))["released"], 1);
    let waited = a.ok("zone_wait", json!({"paths": [path], "seconds": 5}));
    assert_eq!(waited["agent"], json!(one.name));
    b.refused(
        "zone_takeover",
        json!({"id": waited["id"], "reason": "r"}),
        "role",
    );
    l.refused(
        "zone_takeover",
        json!({"id": waited["id"], "reason": "r"}),
        "heartbeat",
    );
    a.ok("presence_beat", json!({"state": "ended"}));
    let taken = l.ok("zone_takeover", json!({"id": waited["id"], "reason": "r"}));
    assert_eq!(taken["agent"], json!(lead.name));
    assert_eq!(a.ok("zone_lost", json!({}))[0]["reason"], "r");
    l.ok("zone_release", json!({}));
    a.ok("presence_beat", json!({"state": "working"}));
    assert!(a.ok("zone_catalog", json!({}))["zones"].is_object());

    // Earlier broadcasts reach this session too.
    b.ok("msg_inbox", json!({}));
    let sent = a.ok(
        "msg_send",
        json!({"to": two.name, "body": "over mcp", "needs": "ack"}),
    );
    assert_eq!(b.ok("msg_unread", json!({}))["unread"], 1);
    assert_eq!(
        b.ok("msg_inbox", json!({"peek": true}))[0]["body"],
        "over mcp"
    );
    assert_eq!(b.ok("msg_unread", json!({}))["unread"], 1);
    assert_eq!(b.ok("msg_inbox", json!({}))[0]["body"], "over mcp");
    assert_eq!(b.ok("msg_unread", json!({}))["unread"], 0);
    let reply = b.ok("msg_reply", json!({"id": sent["id"], "body": "answer"}));
    assert_eq!(reply["reply_to"], sent["id"]);
    assert_eq!(
        a.ok("msg_thread", json!({"id": sent["id"]}))
            .as_array()
            .unwrap()
            .len(),
        2
    );
    b.ok("msg_ack", json!({"id": sent["id"]}));
    assert_eq!(a.ok("msg_overdue", json!({})), json!([]));
    assert!(l.ok("msg_undelivered", json!({"older_than": 0})).is_array());

    let key = w.name("mcp-key");
    l.ok("board_set", json!({"key": key, "value": "v", "ttl": 5}));
    assert_eq!(a.ok("board_get", json!({"key": key}))["value"], "v");
    assert!(
        a.ok("board_list", json!({}))
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["key"] == json!(key))
    );
    assert_eq!(l.ok("board_remove", json!({"key": key}))["removed"], true);

    let offer = |lead: &mut Mcp<'_>| {
        lead.ok(
            "work_offer",
            json!({"title": "t", "to": one.name, "accept": "a"}),
        )
    };
    let task = offer(&mut l);
    assert_eq!(b.ok("work_show", json!({"id": task["id"]}))["title"], "t");
    assert!(
        b.ok("work_list", json!({}))
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == task["id"])
    );
    a.ok("work_claim", json!({"id": task["id"]}));
    a.ok("work_beat", json!({"id": task["id"]}));
    a.ok(
        "work_done",
        json!({"id": task["id"], "report": "r", "commits": ["c"]}),
    );
    l.ok("work_reject", json!({"id": task["id"], "reason": "again"}));
    a.ok("work_handoff", json!({"id": task["id"], "to": two.name}));
    let seen = b.ok("work_show", json!({"id": task["id"]}));
    b.ok(
        "work_take",
        json!({"id": task["id"], "if_version": seen["version"]}),
    );
    b.ok("work_done", json!({"id": task["id"]}));
    assert_eq!(
        l.ok("work_accept", json!({"id": task["id"]}))["status"],
        "accepted"
    );
    let refused = offer(&mut l);
    assert_eq!(
        a.ok("work_decline", json!({"id": refused["id"], "reason": "no"}))["reason"],
        "no"
    );
    let failed = offer(&mut l);
    a.ok("work_claim", json!({"id": failed["id"]}));
    assert_eq!(
        a.ok("work_fail", json!({"id": failed["id"]}))["status"],
        "failed"
    );
    let cancelled = offer(&mut l);
    assert_eq!(
        l.ok("work_cancel", json!({"id": cancelled["id"]}))["status"],
        "cancelled"
    );

    let item = a.ok("task_add", json!({"title": "over mcp", "priority": "P1"}));
    assert_eq!(item["priority"], "P1");
    assert_eq!(
        a.ok("task_plan", json!({"id": item["id"], "priority": "P2"}))["priority"],
        "P2"
    );
    assert!(
        b.ok("task_list", json!({"status": "open"}))
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == item["id"])
    );
    b.ok("task_claim", json!({"id": item["id"]}));
    b.ok("task_renew", json!({"id": item["id"]}));
    b.ok("task_release", json!({"id": item["id"]}));
    b.ok("task_claim", json!({"id": item["id"]}));
    assert_eq!(
        b.ok("task_submit", json!({"id": item["id"], "evidence": "c1"}))["status"],
        "review"
    );
    assert_eq!(
        l.ok("task_reject", json!({"id": item["id"], "reason": "no"}))["status"],
        "open"
    );
    a.ok("task_claim", json!({"id": item["id"]}));
    a.ok("task_submit", json!({"id": item["id"], "evidence": "c2"}));
    assert_eq!(
        l.ok("task_accept", json!({"id": item["id"]}))["status"],
        "accepted"
    );
    assert_eq!(
        b.ok("task_show", json!({"id": item["id"]}))["task"]["status"],
        "accepted"
    );
    let doomed = a.ok("task_add", json!({"title": "no"}));
    assert_eq!(
        l.ok("task_cancel", json!({"id": doomed["id"]}))["status"],
        "cancelled"
    );

    let events = a.ok("events", json!({"after": 0, "types": ["zone.lost"]}));
    assert!(events.is_array());
    assert!(
        a.ok("events", json!({"stream": "registry", "after": 0}))
            .is_array()
    );
    assert!(a.ok("status", json!({}))["unread"].is_number());

    let mut boss = Mcp::start(w, &w.owner);
    let dump = boss.ok("cloud_export", json!({}));
    assert!(dump["tasks"].is_array());
    boss.ok("cloud_freeze", json!({"on": true, "reason": "mcp"}));
    a.refused("zone_claim", json!({"paths": [w.name("no")]}), "frozen");
    boss.ok("cloud_freeze", json!({"on": false}));

    let listed = a.rpc("tools/list", json!({}));
    let all: HashSet<String> = listed["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect();
    let called = w.tools.lock().unwrap();
    let missed: Vec<&String> = all.difference(&called).collect();
    assert!(
        missed.is_empty(),
        "MCP tools the suite never called: {missed:?}"
    );
}

/// Every leaf command of the binary, read from its own help.
fn leaves(prefix: &[String], found: &mut Vec<Vec<String>>) {
    let output = Command::new(BINARY)
        .args(prefix)
        .arg("--help")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let names: Vec<String> = text
        .lines()
        .skip_while(|line| !line.starts_with("Commands:"))
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| *name != "help")
        .map(str::to_string)
        .collect();
    if names.is_empty() {
        found.push(prefix.to_vec());
    }
    for name in names {
        let mut next = prefix.to_vec();
        next.push(name);
        leaves(&next, found);
    }
}

/// Content is sealed on one machine, stored as ciphertext, locked on a machine without the key, and
/// readable there once the recovery phrase is imported. Runs last: it changes the whole workspace.
fn encryption(w: &World) {
    let boss = w.owner.clone();
    let (one, two) = (w.a("sealed-one"), w.a("sealed-two"));
    w.beat(&two);
    let created = w.ly(&boss, &["cloud", "key", "create"]).ok();
    let key_id = created["key_id"].as_str().expect("a key id").to_string();
    let shown = w
        .on_input(&w.box_a, &boss, &["cloud", "key", "show-phrase"], "SHOW\n")
        .ok();
    let phrase = shown["recovery_phrase"]
        .as_str()
        .expect("a phrase")
        .to_string();
    assert_eq!(phrase.split_whitespace().count(), 24);
    w.ly(&boss, &["cloud", "encryption", "require"]).ok();
    let status = w.ly(&boss, &["cloud", "encryption", "status"]);
    assert_eq!(status.code, 0, "{}", status.err);
    assert!(
        status.out.contains("required") && status.out.contains(&key_id),
        "{}",
        status.out
    );

    let secret = "sealed words for the second agent";
    w.ly(&one, &["msg", "send", &two.name, secret]).ok();
    let dump = w
        .ly(&w.who("sealed-export", &w.exporter), &["cloud", "export"])
        .ok();
    let stored = dump.to_string();
    assert!(!stored.contains(secret), "the server holds clear text");
    assert!(stored.contains("lyenc1."), "the server holds no envelope");

    let locked = w.on(&w.box_b, &two, &["msg", "inbox", "--all", "--peek"]);
    assert_eq!(locked.code, 0, "{}", locked.err);
    assert!(
        !locked.out.contains(secret) && locked.out.contains("[locked]"),
        "{}",
        locked.out
    );
    w.on_input(&w.box_b, &boss, &["cloud", "key", "import"], &phrase)
        .ok();
    let clear = w.on(&w.box_b, &two, &["msg", "inbox", "--all", "--peek"]);
    assert!(clear.out.contains(secret), "{}", clear.out);

    w.ly(&boss, &["cloud", "encryption", "off"]).ok();
}

fn every_command_ran(w: &World) {
    // `agent install` and `uninstall` write a real service unit, so no test may run them.
    let skipped = [["agent", "install"], ["agent", "uninstall"]];
    let ran = w.ran.lock().unwrap();
    let mut all = Vec::new();
    leaves(&[], &mut all);
    assert!(all.len() > 60, "{all:?}");
    let missed: Vec<String> = all
        .iter()
        .filter(|leaf| !skipped.iter().any(|skip| leaf.iter().eq(skip.iter())))
        .filter(|leaf| !ran.iter().any(|args| args.starts_with(leaf)))
        .map(|leaf| leaf.join(" "))
        .collect();
    assert!(
        missed.is_empty(),
        "commands the suite never ran: {missed:?}"
    );
}

fn world(url: String, owner: String, command: String) -> World {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let run = format!("{stamp:x}");
    let box_a = Machine::new(&url);
    let box_b = Machine::new(&url);
    World {
        owner: Who {
            name: format!("owner-{run}"),
            token: owner,
        },
        server: Server {
            url,
            command,
            child: Mutex::new(None),
        },
        run,
        box_a,
        box_b,
        lead: String::new(),
        agent: String::new(),
        exporter: String::new(),
        importer: String::new(),
        dispatcher: String::new(),
        ran: Mutex::new(Vec::new()),
        tools: Mutex::new(HashSet::new()),
    }
}

#[test]
fn the_real_client_against_the_real_server() {
    let required = std::env::var("LOCKYARD_E2E_REQUIRED").is_ok_and(|value| value == "1");
    let Ok(url) = std::env::var("LOCKYARD_E2E_URL") else {
        assert!(!required, "LOCKYARD_E2E_REQUIRED=1 needs LOCKYARD_E2E_URL");
        eprintln!("skipped: LOCKYARD_E2E_URL is not set");
        return;
    };
    let need = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    let mut w = world(
        url,
        need("LOCKYARD_E2E_OWNER_TOKEN"),
        need("LOCKYARD_E2E_SERVER"),
    );
    w.server.start();
    tokens(&mut w);
    let w = &w;
    let scenarios: [Scenario; 16] = [
        ("machine", machine),
        ("import", import),
        ("zones", zones),
        ("dirty", dirty),
        ("mail", mail),
        ("board", board),
        ("work", work),
        ("tasks", tasks),
        ("streams", streams),
        ("hooks", hooks),
        ("outage", outage),
        ("another token", another_token_goes_around_the_agent),
        ("freeze", freeze),
        ("plain", plain),
        ("mcp", mcp),
        ("encryption", encryption),
    ];
    for (name, scenario) in scenarios {
        let start = Instant::now();
        scenario(w);
        println!("{name}: {:?}", start.elapsed());
    }
    every_command_ran(w);
    println!("{} scenarios passed", scenarios.len() + 1);
}
