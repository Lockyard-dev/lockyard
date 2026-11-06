// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Who may review a submitted task and who may accept it.
//!
//! The executor cannot accept their own work, including under another model flag.
//! Codex records PASS or REJECT. Only Claude accepts, and only after a Codex PASS.
//! An owner flag does not skip this gate.

/// Speed and effort flags. They do not make a second agent. The model name and its version stay,
/// so `cursor-grok-4.7-high` and `cursor-grok-4.7-medium` are one agent, and a different model is not.
const FLAG_TOKENS: &[&str] = &[
    "fast", "high", "xhigh", "ultra", "medium", "low", "max", "minimal", "thinking",
];

/// Product of an agent name: `claude`, `codex`, `cursor`, or `other`.
pub fn product(name: &str) -> &'static str {
    match tokens(name).first().map(String::as_str) {
        Some("claude") => "claude",
        Some("codex") => "codex",
        Some("cursor") => "cursor",
        _ => "other",
    }
}

/// Stable identity. `cursor-grok-4.7-high` and `cursor-grok-4.7-fast` are one agent.
pub fn identity(name: &str) -> String {
    let parts = tokens(name);
    let kept: Vec<&str> = parts
        .iter()
        .map(String::as_str)
        .filter(|token| !FLAG_TOKENS.contains(token))
        .collect();
    if kept.is_empty() {
        parts.first().cloned().unwrap_or_default()
    } else {
        kept.join("-")
    }
}

/// Session name carried in `token:{id}:{session}`. A bare name is itself.
pub fn agent_name(identity_text: &str) -> &str {
    let Some(rest) = identity_text.strip_prefix("token:") else {
        return identity_text;
    };
    match rest.find(':') {
        Some(index) if index + 1 < rest.len() => &rest[index + 1..],
        _ => identity_text,
    }
}

pub fn same_agent(left: &str, right: &str) -> bool {
    !left.is_empty()
        && !right.is_empty()
        && identity(agent_name(left)) == identity(agent_name(right))
}

pub fn is_executor(actor: &str, executor: &str, session: &str) -> bool {
    same_agent(actor, executor) || same_agent(actor, session)
}

/// Why this agent may not record a review, or `None` when Codex may.
pub fn review_refusal(actor: &str, executor: &str, session: &str, decision: &str, reason: &str) -> Option<String> {
    if product(agent_name(actor)) != "codex" {
        return Some("Only Codex reviews submitted work.".into());
    }
    if is_executor(actor, executor, session) {
        return Some(
            "The executor cannot review their own work, including under another flag.".into(),
        );
    }
    match decision {
        "pass" => None,
        "reject" if reason.trim().is_empty() => Some("REJECT needs a reason.".into()),
        "reject" => None,
        _ => Some("A review decision is pass or reject.".into()),
    }
}

/// Why this agent may not accept. `codex_passed` is a Codex PASS newer than the submit.
pub fn accept_refusal(actor: &str, executor: &str, session: &str, codex_passed: bool) -> Option<String> {
    if is_executor(actor, executor, session) {
        return Some("An executor cannot accept their own work.".into());
    }
    if product(agent_name(actor)) != "claude" {
        return Some("Only Claude can accept work.".into());
    }
    if !codex_passed {
        return Some("Accept requires a Codex review PASS.".into());
    }
    None
}

fn tokens(name: &str) -> Vec<String> {
    name.split(|c: char| c == '-' || c == '_' || c == '.')
        .filter(|part| !part.is_empty())
        .map(|part| part.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_model_flag_is_the_same_agent() {
        assert!(same_agent(
            "cursor-grok-4.7-high",
            "cursor-grok-4.7-fast"
        ));
        assert!(same_agent(
            "token:abc:cursor-grok-4.7-high",
            "cursor-grok-4.7-fast"
        ));
        assert!(!same_agent("claude-a", "claude-b"));
        assert!(same_agent("cursor-grok-4.7-high", "cursor-grok-4.7-xhigh"));
        assert!(same_agent("cursor-grok-4.7-high", "cursor-grok-4.7-medium"));
        assert!(same_agent(
            "claude-opus-5-5-high",
            "claude-opus-5-5-medium"
        ));
        assert!(same_agent(
            "codex-gpt-5.6-sol-high",
            "codex-gpt-5.6-sol-medium"
        ));
        assert!(!same_agent(
            "cursor-grok-4.7-high",
            "cursor-composer-2.5-fast"
        ));
        assert!(!same_agent(
            "claude-opus-5-5-high",
            "claude-sonnet-5-5-high"
        ));
        assert_eq!(product("claude-accept"), "claude");
        assert_eq!(product("codex-review"), "codex");
    }

    #[test]
    fn accept_and_review_follow_the_owner_rule() {
        let executor = "cursor-grok-4.7-high";
        assert!(accept_refusal(executor, executor, "", true).is_some());
        assert!(accept_refusal("cursor-grok-4.7-fast", executor, "", true).is_some());
        assert!(accept_refusal("codex-review", executor, "", true)
            .unwrap()
            .contains("Claude"));
        assert!(accept_refusal("claude-accept", executor, "", false)
            .unwrap()
            .contains("PASS"));
        assert!(accept_refusal("claude-accept", executor, "", true).is_none());
        assert!(accept_refusal("owner-1", executor, "", true)
            .unwrap()
            .contains("Claude"));
        assert!(review_refusal("claude-accept", executor, "", "pass", "").is_some());
        assert!(review_refusal("codex-review", executor, "", "reject", " ").is_some());
        assert!(review_refusal("codex-review", executor, "", "pass", "").is_none());
        assert!(review_refusal("codex-worker", "codex-worker-fast", "", "pass", "").is_some());
        assert!(accept_refusal(
            "claude-opus-5-5-medium",
            "claude-opus-5-5-high",
            "",
            true
        )
        .unwrap()
        .contains("executor"));
        assert!(review_refusal(
            "codex-gpt-5.6-sol-medium",
            "codex-gpt-5.6-sol-high",
            "",
            "pass",
            ""
        )
        .is_some());
    }
}
