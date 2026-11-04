// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Device authorization: how a terminal gets a token without one being pasted into it.
//!
//! The shape is the one in `CONTRACT-device-login.md`, which both this CLI and the cloud server
//! implement. Requests go through [`DevicePost`] rather than a [`ureq`] agent directly, so the
//! whole flow — including the pacing rules, where the mistakes live — is tested without a server.

use crate::{ClientError, allowed_url};
use serde_json::{Value, json};
use std::time::Duration;

/// An unauthenticated POST to a device endpoint, answered with its status and its body.
///
/// A device call is the one thing in this crate that carries no bearer token: the whole point is
/// that the caller does not have one yet.
pub trait DevicePost {
    fn post(&self, path: &str, body: &Value) -> Result<(u16, Value), ClientError>;
}

/// What the server hands back when a login starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub interval: u64,
    pub expires_in: u64,
}

/// A granted token and the workspace it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Granted {
    pub token: String,
    pub workspace_id: String,
    pub workspace_name: String,
    pub server_url: String,
    pub role: String,
}

/// One answer to one poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    /// Nobody has approved or denied the code yet.
    Pending,
    /// Polling was too fast; the contract adds five seconds.
    SlowDown,
    Granted(Box<Granted>),
    /// The user said no. Asking again will not change it.
    Denied,
    /// The code ran out. A new login has to start from the beginning.
    Expired,
}

/// The slowest the contract lets a client poll, so a bad `interval` cannot pin a terminal.
const MAX_INTERVAL_SECONDS: u64 = 60;
/// The fastest, for the same reason in the other direction.
const MIN_INTERVAL_SECONDS: u64 = 1;
/// Added to the wait on `slow_down`, per the contract.
const SLOW_DOWN_STEP_SECONDS: u64 = 5;

fn field<'a>(body: &'a Value, name: &str) -> Result<&'a str, ClientError> {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ClientError::Decode(format!("the server left {name} out of its answer")))
}

/// Asks the server to start a login. `machine` only names the token in the panel.
pub fn start(post: &dyn DevicePost, machine: &str) -> Result<Start, ClientError> {
    let (status, body) = post.post(
        "/api/v1/auth/device",
        &json!({"client": "lockyard-cli", "machine": machine}),
    )?;
    if status != 200 {
        return Err(status_error(status, &body));
    }
    let interval = body
        .get("interval")
        .and_then(Value::as_u64)
        .unwrap_or(5)
        .clamp(MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS);
    Ok(Start {
        device_code: field(&body, "device_code")?.to_string(),
        user_code: field(&body, "user_code")?.to_string(),
        verification_uri: field(&body, "verification_uri")?.to_string(),
        verification_uri_complete: body
            .get("verification_uri_complete")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        interval,
        expires_in: body
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(600),
    })
}

/// Asks once whether the code has been approved. `fallback_url` is the server being logged into,
/// used when the answer leaves `server_url` out.
pub fn poll_once(
    post: &dyn DevicePost,
    device_code: &str,
    fallback_url: &str,
) -> Result<Poll, ClientError> {
    let (status, body) = post.post(
        "/api/v1/auth/device/token",
        &json!({"device_code": device_code}),
    )?;
    match status {
        200 => {
            let server_url = body
                .get("server_url")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or(fallback_url);
            // A token is only ever stored against a URL this client already decided to trust,
            // so a server cannot point the credentials file at somewhere else.
            if !same_server(server_url, fallback_url) {
                return Err(ClientError::Invalid(format!(
                    "the server answered for {server_url}, not the {fallback_url} that was asked"
                )));
            }
            Ok(Poll::Granted(Box::new(Granted {
                token: field(&body, "token")?.to_string(),
                workspace_id: field(&body, "workspace_id")?.to_string(),
                workspace_name: field(&body, "workspace_name")?.to_string(),
                server_url: server_url.trim_end_matches('/').to_string(),
                role: body
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or("member")
                    .to_string(),
            })))
        }
        428 => Ok(Poll::Pending),
        429 => Ok(Poll::SlowDown),
        403 => Ok(Poll::Denied),
        410 => Ok(Poll::Expired),
        other => Err(status_error(other, &body)),
    }
}

fn same_server(a: &str, b: &str) -> bool {
    a.trim_end_matches('/')
        .eq_ignore_ascii_case(b.trim_end_matches('/'))
}

fn status_error(status: u16, body: &Value) -> ClientError {
    let message = body
        .get("error")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("the device endpoint answered {status}"));
    ClientError::from_api(crate::ApiError {
        status,
        code: String::new(),
        message,
        details: Value::Null,
        retry_after: None,
    })
}

/// How long to wait before the next poll, and when to stop waiting at all.
///
/// Kept apart from the requests because this is where device flows go wrong: a `slow_down` that
/// never slows anything, or a deadline measured from the wrong moment.
#[derive(Debug, Clone)]
pub struct Pacing {
    wait: u64,
    left: u64,
}

impl Pacing {
    pub fn new(start: &Start) -> Self {
        Self {
            wait: start
                .interval
                .clamp(MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS),
            left: start.expires_in,
        }
    }

    /// The pause before the next poll, or `None` when the code has run out of time.
    pub fn next_wait(&mut self, slow_down: bool) -> Option<Duration> {
        if slow_down {
            self.wait = (self.wait + SLOW_DOWN_STEP_SECONDS).min(MAX_INTERVAL_SECONDS);
        }
        if self.left < self.wait {
            self.left = 0;
            return None;
        }
        self.left -= self.wait;
        Some(Duration::from_secs(self.wait))
    }
}

/// Runs a whole login: start, show the code, poll until the answer is final.
///
/// Waiting and printing are passed in, so the loop that decides when to stop is tested here
/// rather than only in a terminal with a real server and a real ten minutes.
pub fn login(
    post: &dyn DevicePost,
    machine: &str,
    url: &str,
    announce: &mut dyn FnMut(&Start),
    sleep: &mut dyn FnMut(Duration),
) -> Result<Granted, ClientError> {
    let begun = start(post, machine)?;
    announce(&begun);
    let mut pacing = Pacing::new(&begun);
    let mut slow_down = false;
    loop {
        let Some(wait) = pacing.next_wait(slow_down) else {
            return Err(ClientError::Invalid(
                "the login code ran out before it was approved; run `lockyard cloud login` again"
                    .into(),
            ));
        };
        sleep(wait);
        match poll_once(post, &begun.device_code, url)? {
            Poll::Granted(granted) => return Ok(*granted),
            Poll::Pending => slow_down = false,
            Poll::SlowDown => slow_down = true,
            Poll::Denied => {
                return Err(ClientError::Invalid(
                    "the login was refused in the browser".into(),
                ));
            }
            Poll::Expired => {
                return Err(ClientError::Invalid(
                    "the login code expired; run `lockyard cloud login` again".into(),
                ));
            }
        }
    }
}

/// The real transport: plain HTTPS, no token, no redirects.
pub struct HttpDevice {
    base_url: String,
    agent: ureq::Agent,
}

impl HttpDevice {
    pub fn new(base_url: &str) -> Result<Self, ClientError> {
        let base_url = base_url.trim_end_matches('/');
        if !allowed_url(base_url) {
            return Err(ClientError::Invalid(
                "cloud URL must use HTTPS (HTTP is allowed for localhost)".into(),
            ));
        }
        Ok(Self {
            base_url: base_url.into(),
            // A person is at the keyboard approving the code, so reads are allowed to be slow.
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(5))
                .timeout_read(Duration::from_secs(30))
                .redirects(0)
                .build(),
        })
    }
}

impl DevicePost for HttpDevice {
    fn post(&self, path: &str, body: &Value) -> Result<(u16, Value), ClientError> {
        let url = format!("{}{path}", self.base_url);
        match self.agent.post(&url).send_json(body.clone()) {
            Ok(response) => {
                let status = response.status();
                let text = response
                    .into_string()
                    .map_err(|error| ClientError::Transport(error.to_string()))?;
                Ok((status, parse_body(&text)))
            }
            Err(ureq::Error::Status(status, response)) => {
                let text = response.into_string().unwrap_or_default();
                Ok((status, parse_body(&text)))
            }
            Err(error) => Err(ClientError::Transport(error.to_string())),
        }
    }
}

fn parse_body(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Answers a scripted list of replies and remembers what it was asked.
    struct Script {
        replies: RefCell<Vec<(u16, Value)>>,
        seen: RefCell<Vec<(String, Value)>>,
    }

    impl Script {
        fn new(replies: Vec<(u16, Value)>) -> Self {
            Self {
                replies: RefCell::new(replies),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl DevicePost for Script {
        fn post(&self, path: &str, body: &Value) -> Result<(u16, Value), ClientError> {
            self.seen
                .borrow_mut()
                .push((path.to_string(), body.clone()));
            let mut replies = self.replies.borrow_mut();
            if replies.is_empty() {
                panic!("the flow polled more times than the test scripted");
            }
            Ok(replies.remove(0))
        }
    }

    fn started() -> Start {
        Start {
            device_code: "d".into(),
            user_code: "ABCD-EFGH".into(),
            verification_uri: "https://panel.test/device".into(),
            verification_uri_complete: None,
            interval: 5,
            expires_in: 600,
        }
    }

    #[test]
    fn a_start_reads_the_codes_and_names_the_machine() {
        let script = Script::new(vec![(
            200,
            json!({
                "device_code": "secret-code",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://panel.test/device",
                "verification_uri_complete": "https://panel.test/device?code=ABCD-EFGH",
                "interval": 5,
                "expires_in": 600
            }),
        )]);
        let start = start(&script, "laptop").unwrap();
        assert_eq!(start.device_code, "secret-code");
        assert_eq!(start.user_code, "ABCD-EFGH");
        assert_eq!(start.interval, 5);
        let seen = script.seen.borrow();
        assert_eq!(seen[0].0, "/api/v1/auth/device");
        assert_eq!(seen[0].1["machine"], "laptop");
        assert_eq!(seen[0].1["client"], "lockyard-cli");
    }

    #[test]
    fn a_start_without_the_codes_is_an_error_not_an_empty_login() {
        let script = Script::new(vec![(200, json!({"user_code": "ABCD-EFGH"}))]);
        let error = start(&script, "laptop").unwrap_err();
        assert!(format!("{error:?}").contains("device_code"), "{error:?}");
    }

    #[test]
    fn a_refused_start_carries_the_servers_reason() {
        let script = Script::new(vec![(429, json!({"error": "too many logins"}))]);
        let error = start(&script, "laptop").unwrap_err();
        assert!(matches!(error, ClientError::RateLimited(_)), "{error:?}");
    }

    #[test]
    fn an_absurd_interval_is_pulled_back_into_range() {
        let reply = |interval: Value| {
            json!({
                "device_code": "d", "user_code": "u",
                "verification_uri": "https://panel.test/device",
                "interval": interval
            })
        };
        let fast = Script::new(vec![(200, reply(json!(0)))]);
        assert_eq!(start(&fast, "m").unwrap().interval, MIN_INTERVAL_SECONDS);
        let slow = Script::new(vec![(200, reply(json!(99_999)))]);
        assert_eq!(start(&slow, "m").unwrap().interval, MAX_INTERVAL_SECONDS);
    }

    #[test]
    fn every_polling_status_in_the_contract_has_its_own_answer() {
        let cases: Vec<(u16, Value, Poll)> = vec![
            (
                428,
                json!({"error": "authorization_pending"}),
                Poll::Pending,
            ),
            (429, json!({"error": "slow_down"}), Poll::SlowDown),
            (403, json!({"error": "access_denied"}), Poll::Denied),
            (410, json!({"error": "expired_token"}), Poll::Expired),
        ];
        for (status, body, expected) in cases {
            let script = Script::new(vec![(status, body)]);
            let answer = poll_once(&script, "d", "https://cloud.test").unwrap();
            assert_eq!(answer, expected, "status {status}");
        }
    }

    #[test]
    fn a_grant_carries_the_token_and_the_workspace() {
        let script = Script::new(vec![(
            200,
            json!({
                "token": "lk_abc", "workspace_id": "w1", "workspace_name": "Team",
                "server_url": "https://cloud.test/", "role": "member"
            }),
        )]);
        let Poll::Granted(granted) = poll_once(&script, "d", "https://cloud.test").unwrap() else {
            panic!("expected a grant");
        };
        assert_eq!(granted.token, "lk_abc");
        assert_eq!(granted.workspace_name, "Team");
        assert_eq!(granted.server_url, "https://cloud.test");
        assert_eq!(script.seen.borrow()[0].1["device_code"], "d");
    }

    #[test]
    fn a_grant_for_another_server_is_refused_rather_than_stored() {
        let script = Script::new(vec![(
            200,
            json!({
                "token": "lk_abc", "workspace_id": "w1", "workspace_name": "Team",
                "server_url": "https://elsewhere.test"
            }),
        )]);
        let error = poll_once(&script, "d", "https://cloud.test").unwrap_err();
        assert!(format!("{error:?}").contains("elsewhere.test"), "{error:?}");
    }

    #[test]
    fn a_grant_without_a_server_url_belongs_to_the_server_that_was_asked() {
        let script = Script::new(vec![(
            200,
            json!({"token": "lk_abc", "workspace_id": "w1", "workspace_name": "Team"}),
        )]);
        let Poll::Granted(granted) = poll_once(&script, "d", "https://cloud.test").unwrap() else {
            panic!("expected a grant");
        };
        assert_eq!(granted.server_url, "https://cloud.test");
        assert_eq!(granted.role, "member");
    }

    #[test]
    fn an_unexpected_status_stops_the_flow() {
        let script = Script::new(vec![(500, json!({"error": "boom"}))]);
        assert!(poll_once(&script, "d", "https://cloud.test").is_err());
    }

    #[test]
    fn slow_down_lengthens_the_wait_and_the_deadline_still_arrives() {
        let mut pacing = Pacing::new(&started());
        assert_eq!(pacing.next_wait(false), Some(Duration::from_secs(5)));
        assert_eq!(pacing.next_wait(true), Some(Duration::from_secs(10)));
        assert_eq!(pacing.next_wait(true), Some(Duration::from_secs(15)));
        assert_eq!(pacing.next_wait(false), Some(Duration::from_secs(15)));
        let mut waited = 5 + 10 + 15 + 15;
        while let Some(wait) = pacing.next_wait(false) {
            waited += wait.as_secs();
            assert!(waited <= 600, "the wait ran past the expiry: {waited}");
        }
        assert!(waited > 500, "the flow gave up far too early: {waited}");
    }

    #[test]
    fn a_short_lived_code_runs_out_instead_of_polling_forever() {
        let mut pacing = Pacing::new(&Start {
            interval: 5,
            expires_in: 7,
            ..started()
        });
        assert_eq!(pacing.next_wait(false), Some(Duration::from_secs(5)));
        assert_eq!(pacing.next_wait(false), None);
        assert_eq!(pacing.next_wait(false), None, "it stays finished");
    }

    #[test]
    fn the_wait_never_grows_past_a_minute() {
        let mut pacing = Pacing::new(&Start {
            interval: 55,
            expires_in: 100_000,
            ..started()
        });
        pacing.next_wait(true);
        assert_eq!(
            pacing.next_wait(true),
            Some(Duration::from_secs(MAX_INTERVAL_SECONDS))
        );
    }

    fn begin(interval: u64, expires_in: u64) -> (u16, Value) {
        (
            200,
            json!({
                "device_code": "d", "user_code": "ABCD-EFGH",
                "verification_uri": "https://panel.test/device",
                "interval": interval, "expires_in": expires_in
            }),
        )
    }

    #[test]
    fn a_login_waits_through_pending_answers_and_comes_back_with_the_token() {
        let script = Script::new(vec![
            begin(5, 600),
            (428, json!({"error": "authorization_pending"})),
            (429, json!({"error": "slow_down"})),
            (428, json!({"error": "authorization_pending"})),
            (
                200,
                json!({"token": "lk_1", "workspace_id": "w1", "workspace_name": "Team"}),
            ),
        ]);
        let mut shown = Vec::new();
        let mut waits = Vec::new();
        let granted = login(
            &script,
            "laptop",
            "https://cloud.test",
            &mut |start| shown.push(start.user_code.clone()),
            &mut |wait| waits.push(wait.as_secs()),
        )
        .unwrap();
        assert_eq!(granted.token, "lk_1");
        assert_eq!(
            shown,
            ["ABCD-EFGH"],
            "the code is shown once, before polling"
        );
        assert_eq!(
            waits,
            [5, 5, 10, 10],
            "the wait grows only after the server asks it to"
        );
    }

    #[test]
    fn a_refusal_in_the_browser_ends_the_login_at_once() {
        let script = Script::new(vec![
            begin(5, 600),
            (403, json!({"error": "access_denied"})),
        ]);
        let error = login(
            &script,
            "laptop",
            "https://cloud.test",
            &mut |_| {},
            &mut |_| {},
        )
        .unwrap_err();
        assert!(format!("{error}").contains("refused"), "{error}");
    }

    #[test]
    fn a_login_nobody_approves_gives_up_instead_of_polling_forever() {
        let mut replies = vec![begin(5, 20)];
        replies.extend(std::iter::repeat_n(
            (428, json!({"error": "authorization_pending"})),
            4,
        ));
        let script = Script::new(replies);
        let mut waits = 0;
        let error = login(
            &script,
            "laptop",
            "https://cloud.test",
            &mut |_| {},
            &mut |_| waits += 1,
        )
        .unwrap_err();
        assert!(format!("{error}").contains("ran out"), "{error}");
        assert_eq!(waits, 4, "it polled for the whole ten minutes of its code");
    }

    #[test]
    fn a_plain_http_server_is_refused_before_anything_is_sent() {
        assert!(HttpDevice::new("http://cloud.test").is_err());
        assert!(HttpDevice::new("https://cloud.test").is_ok());
        assert!(HttpDevice::new("http://localhost:8080").is_ok());
    }
}
